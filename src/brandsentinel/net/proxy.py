"""Egress proxy (U18, KTD10): the only way out of the sandbox network.

Sandbox containers sit on an internal Docker network with no route out; this
proxy is the one service on both that network and the egress network. Every
request is decided by netguard, the same policy the host-side fetcher uses, and
the proxy connects only to the address netguard validated, so DNS rebinding
between check and connect is impossible.

Accepted:
- `CONNECT host:port` to an allowed port (80 and 443 by default), for TLS and
  plain tunnels. A `Host` header, if sent, must name the same authority.
- absolute-form `GET` or `HEAD` `http://host/...` to port 80, without a body.
  `Host` must name the URL's authority. Hop-by-hop headers (and those listed in
  `Connection`) are stripped, the request goes upstream with `Connection: close`
  and the response is relayed as is.

Everything else is refused: origin-form requests (no use as a reverse proxy),
other methods, request bodies, `https://` absolute-form, obsolete header folding,
oversized headers, and any destination netguard refuses (private, loopback,
link-local and metadata addresses, NAT64/6to4/mapped forms of them, mixed public
and private answers, other ports). In lab mode netguard also allows the pinned
lab subnet for lab hostnames; a lab proxy (`lab_only`) refuses everything else.

Limits: a concurrent-connection cap, a header size cap and timeout, connect and
idle timeouts, a total time budget and a byte cap per connection. Every decision
is logged as one JSON line.
"""

import asyncio
import contextlib
import ipaddress
import logging
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

from brandsentinel.config import ProxySettings
from brandsentinel.net.netguard import NetGuard, PolicyViolation, ResolutionFailed, Validated

log = logging.getLogger("brandsentinel.proxy")

Connector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]

MAX_HEADERS = 100
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_AUTHORITY = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[^\[\]/?#@\s:]+):([0-9]{1,5})$")
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)
_REASONS = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}
_CHUNK = 65536
# Marks responses the proxy generated itself, so a client (the lab-mode fetcher)
# never mistakes a refusal for the destination's answer.
REFUSAL_HEADER = "X-BrandSentinel-Proxy"


class Refused(Exception):
    def __init__(self, status: int, reason: str, detail: dict | None = None) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail or {}


class _ByteCap(Exception):
    pass


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]

    def header(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class Decision:
    """One log record per client connection."""

    client: str | None
    decision: str = "deny"
    reason: str = ""
    method: str | None = None
    host: str | None = None
    port: int | None = None
    address: str | None = None
    lab: bool = False
    status: int | None = None
    bytes_up: int = 0
    bytes_down: int = 0
    detail: dict = field(default_factory=dict)


async def _open(address: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(address, port)


def parse_head(raw: bytes) -> Request:
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError as e:  # pragma: no cover - latin-1 decodes everything
        raise Refused(400, "invalid_encoding") from e
    lines = text[:-4].split("\r\n") if text.endswith("\r\n\r\n") else text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _TOKEN.match(parts[0]) or not parts[1]:
        raise Refused(400, "invalid_request_line")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise Refused(400, "unsupported_version")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in target):
        raise Refused(400, "invalid_request_target")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line[:1] in (" ", "\t"):
            raise Refused(400, "obsolete_line_folding")
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.match(name):
            raise Refused(400, "invalid_header")
        if any(ord(c) < 0x20 and c != "\t" for c in value) or "\x7f" in value:
            raise Refused(400, "invalid_header_value")
        headers.append((name, value.strip(" \t")))
        if len(headers) > MAX_HEADERS:
            raise Refused(431, "too_many_headers")
    return Request(method, target, version, headers)


class EgressProxy:
    def __init__(
        self,
        settings: ProxySettings,
        guard: NetGuard,
        *,
        connector: Connector | None = None,
        forward_ports: Sequence[int] = (80,),
    ) -> None:
        """`connector` and `forward_ports` (the ports absolute-form requests may
        reach) are for tests; configuration cannot set them."""
        if settings.lab_only and not guard.lab_mode:
            raise ValueError("a lab-only proxy needs a lab-mode netguard")
        self.settings = settings
        self.guard = guard
        self._connect = connector or _open
        self._forward_ports = frozenset(forward_ports)
        self._active = 0
        self._per_client: dict[str, int] = {}

    async def start(self, listen: Sequence[tuple[str, int]]) -> list[asyncio.Server]:
        servers = []
        for host, port in listen:
            servers.append(
                await asyncio.start_server(
                    self.handle, host, port, limit=self.settings.max_header_bytes
                )
            )
        return servers

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        rec = Decision(client=peer[0] if peer else None)
        start = time.monotonic()
        client = rec.client or ""
        if (
            self._active >= self.settings.max_connections
            or self._per_client.get(client, 0) >= self.settings.max_connections_per_client
        ):
            await self._refuse(writer, rec, Refused(503, "too_many_connections"))
            self._log(rec, start)
            await _linger(reader, writer)  # bounded (0.5 s) so the client reads the 503
            await _close(writer)
            return
        self._active += 1
        self._per_client[client] = self._per_client.get(client, 0) + 1
        try:
            async with asyncio.timeout(self.settings.total_timeout_seconds):
                await self._serve(reader, writer, rec)
        except Refused as e:
            await self._refuse(writer, rec, e)
        except TimeoutError:
            if rec.decision == "allow":
                rec.detail["ended"] = "total_timeout"
            else:
                await self._refuse(writer, rec, Refused(504, "total_timeout"))
        except _ByteCap:
            rec.detail["ended"] = "byte_cap"
        except (ConnectionError, asyncio.IncompleteReadError):
            rec.detail.setdefault("ended", "connection_closed")
        except Exception as e:  # never let one connection take the proxy down
            rec.detail["error"] = f"{type(e).__name__}: {e}"[:300]
            log.exception("proxy connection error")
        finally:
            self._active -= 1
            self._per_client[client] -= 1
            if not self._per_client[client]:
                del self._per_client[client]
            self._log(rec, start)
            if rec.decision == "deny":
                await _linger(reader, writer)
            await _close(writer)

    # --- request handling ------------------------------------------------------------

    async def _serve(self, reader, writer, rec: Decision) -> None:
        try:
            async with asyncio.timeout(self.settings.header_timeout_seconds):
                raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError as e:
            raise Refused(431, "header_too_large") from e
        except TimeoutError as e:
            raise Refused(400, "header_timeout") from e
        except asyncio.IncompleteReadError:
            rec.reason = "client_closed"
            return
        req = parse_head(raw)
        rec.method = req.method
        if req.method == "CONNECT":
            await self._tunnel(req, reader, writer, rec)
        else:
            await self._forward(req, writer, rec)

    async def _authorize(self, url: str, rec: Decision) -> Validated:
        if self.settings.lab_only:
            # Refuse before resolving: a lab proxy never sends DNS for other names.
            try:
                parsed = self.guard.parse(url)
            except PolicyViolation as e:
                raise Refused(403, e.reason) from e
            if not self.guard.is_lab_host(parsed.host):
                rec.host, rec.port = parsed.host, parsed.port
                raise Refused(403, "not_lab_host")
        try:
            target = await self.guard.validate(url)
        except PolicyViolation as e:
            rec.detail.update({k: v for k, v in e.detail.items() if k != "blocked"})
            raise Refused(403, e.reason) from e
        except ResolutionFailed as e:
            raise Refused(502, e.reason) from e
        rec.host, rec.port, rec.lab = target.host, target.port, target.lab
        if self.settings.lab_only and not target.lab:
            raise Refused(403, "not_lab_host")
        return target

    async def _tunnel(self, req: Request, reader, writer, rec: Decision) -> None:
        m = _AUTHORITY.match(req.target)
        if not m:
            raise Refused(400, "invalid_connect_target")
        rec.host, rec.port = m.group(1).strip("[]"), int(m.group(2))
        if req.header("content-length") or req.header("transfer-encoding"):
            raise Refused(400, "request_body_not_allowed")
        scheme = "https" if rec.port == 443 else "http"
        target = await self._authorize(f"{scheme}://{req.target}/", rec)
        self._check_host_header(req, target, required=False)
        up_reader, up_writer = await self._dial(target, rec)
        try:
            rec.decision, rec.status, rec.reason = "allow", 200, "connect"
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._relay(reader, writer, up_reader, up_writer, rec)
        finally:
            await _close(up_writer)

    async def _forward(self, req: Request, writer, rec: Decision) -> None:
        if req.method not in ("GET", "HEAD"):
            raise Refused(405, "method_not_allowed")
        lowered = req.target[:8].lower()
        if lowered.startswith("https://"):
            raise Refused(400, "https_requires_connect")
        if not lowered.startswith("http://"):
            raise Refused(400, "not_a_proxy_request")
        if req.header("transfer-encoding") or any(
            v.strip() not in ("", "0") for v in req.header("content-length")
        ):
            raise Refused(400, "request_body_not_allowed")
        target = await self._authorize(req.target, rec)
        if target.port not in self._forward_ports:
            raise Refused(403, "port_not_allowed", {"port": target.port})
        self._check_host_header(req, target, required=True)
        connection_tokens = {
            t.strip().lower() for v in req.header("connection") for t in v.split(",")
        }
        lines = [f"{req.method} {target.target} HTTP/1.1", f"Host: {target.authority}"]
        for name, value in req.headers:
            low = name.lower()
            if low in _HOP_BY_HOP or low in connection_tokens:
                continue
            lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        up_reader, up_writer = await self._dial(target, rec)
        try:
            rec.decision, rec.reason = "allow", "forward"
            up_writer.write(head)
            await up_writer.drain()
            rec.bytes_up += len(head)
            counter = [len(head), time.monotonic()]
            down = await self._pipe(up_reader, writer, counter)
            rec.bytes_down = down
        finally:
            await _close(up_writer)

    def _check_host_header(self, req: Request, target: Validated, *, required: bool) -> None:
        hosts = req.header("host")
        if len(hosts) > 1:
            raise Refused(400, "duplicate_host_header")
        if not hosts:
            if required:
                raise Refused(400, "missing_host_header")
            return
        try:
            named = self.guard.parse(f"{target.scheme}://{hosts[0]}/")
        except PolicyViolation as e:
            raise Refused(400, "host_mismatch", {"host_header": hosts[0][:200]}) from e
        if (named.host, named.port) != (target.host, target.port):
            raise Refused(400, "host_mismatch", {"host_header": hosts[0][:200]})

    async def _dial(self, target: Validated, rec: Decision):
        last: str | None = None
        for address in target.addresses[: self.settings.max_addresses_tried]:
            rec.address = address
            try:
                async with asyncio.timeout(self.settings.connect_timeout_seconds):
                    r, w = await self._connect(address, target.port)
            except (OSError, TimeoutError) as e:
                last = f"{type(e).__name__}: {e}"[:200]
                continue
            peer = w.get_extra_info("peername")
            if peer and ipaddress.ip_address(peer[0].split("%")[0]) != ipaddress.ip_address(
                address
            ):
                # Defense in depth: the socket must have reached the validated address.
                await _close(w)
                raise Refused(502, "peer_mismatch", {"peer": peer[0]})
            return r, w
        raise Refused(502, "connect_failed", {"error": last})

    async def _relay(self, reader, writer, up_reader, up_writer, rec: Decision) -> None:
        counter = [0, time.monotonic()]  # bytes both ways, last activity either way
        capped = False

        async def up() -> None:
            rec.bytes_up = await self._pipe(reader, up_writer, counter)

        async def down() -> None:
            rec.bytes_down = await self._pipe(up_reader, writer, counter)

        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(up())
                tg.create_task(down())
        except* _ByteCap:
            capped = True
        except* (ConnectionError, OSError):
            rec.detail.setdefault("ended", "connection_error")
        if capped:
            raise _ByteCap()

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter) -> int:
        """Copy until EOF, or until the connection (both directions, tracked in
        `counter`) has been idle for the idle timeout. `counter` holds the bytes
        moved both ways and the time of the last activity in either direction."""
        moved = 0
        cap = self.settings.max_connection_bytes
        idle = self.settings.idle_timeout_seconds
        while True:
            try:
                async with asyncio.timeout(idle):
                    chunk = await src.read(_CHUNK)
            except TimeoutError:
                if time.monotonic() - counter[1] < idle:
                    continue  # the other direction is busy (e.g. a long download)
                break
            if not chunk:
                break
            counter[1] = time.monotonic()
            counter[0] += len(chunk)
            if counter[0] > cap:
                raise _ByteCap()
            moved += len(chunk)
            dst.write(chunk)
            await dst.drain()
        if dst.can_write_eof():
            with contextlib.suppress(OSError):
                dst.write_eof()
        return moved

    # --- responses and logging -------------------------------------------------------

    async def _refuse(self, writer, rec: Decision, e: Refused) -> None:
        rec.decision, rec.status, rec.reason = "deny", e.status, e.reason
        rec.detail.update(e.detail)
        body = f"{e.reason}\n".encode()
        head = (
            f"HTTP/1.1 {e.status} {_REASONS.get(e.status, 'Error')}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"{REFUSAL_HEADER}: {e.reason}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        with contextlib.suppress(ConnectionError, OSError):
            writer.write(head + body)
            await writer.drain()

    @staticmethod
    def _log(rec: Decision, start: float) -> None:
        fields = {
            "event": "proxy_decision",
            "decision": rec.decision,
            "reason": rec.reason,
            "status": rec.status,
            "client": rec.client,
            "method": (rec.method or "")[:20] or None,
            "host": (rec.host or "")[:255] or None,
            "port": rec.port,
            "address": rec.address,
            "lab": rec.lab,
            "bytes_up": rec.bytes_up,
            "bytes_down": rec.bytes_down,
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
        if rec.detail:
            fields["detail"] = {k: str(v)[:300] for k, v in rec.detail.items()}
        log.info("proxy decision", extra={"fields": fields})


async def _linger(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """After a refusal, half-close and briefly discard unread input, so closing
    does not reset the connection before the client reads the error."""
    with contextlib.suppress(Exception):
        if writer.can_write_eof():
            writer.write_eof()
        async with asyncio.timeout(0.5):
            for _ in range(16):
                if not await reader.read(_CHUNK):
                    break


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 5)


def parse_listen(value: str) -> tuple[str, int]:
    """`ip:port` or `[ipv6]:port`; the address must be a literal."""
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"invalid listen address {value!r}")
    host = host.strip("[]")
    ipaddress.ip_address(host)
    return host, int(port)
