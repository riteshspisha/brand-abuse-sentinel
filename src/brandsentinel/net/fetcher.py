"""Hardened static fetcher (U9, KTD7).

One fetch is a manual walk over at most `max_redirects` redirects. Every hop is
validated by netguard and connected to one of its validated addresses (the DNS
answer is pinned; the hostname still goes into SNI and `Host`). Only GET and HEAD
are ever sent, with no cookies, no credentials and no proxy: httpcore never reads
proxy environment variables. Responses stream under a wall-clock budget for the
whole fetch, a cap on bytes read from the wire, and a cap on decompressed bytes.
A body is kept only when its media type is one the caller accepts.

TLS has two modes:
- `verified`: normal certificate and hostname validation; failure ends the fetch.
  Mandatory for trusted reference collection.
- `evidence`: for suspicious sites. A verified attempt runs first; if it fails
  certificate verification, the hop is retried without verification and the
  result records `tls_verification_failed` with the error. Evidence-mode results
  are tagged untrusted and can never become reference content.

The fetcher only observes. It returns a `FetchResult`; callers decide what to
persist (through the quota-enforcing blob store and the sanitizing fact writer).
"""

import asyncio
import hashlib
import ipaddress
import ssl
import time
import zlib
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urljoin

import certifi
import httpcore

from brandsentinel.config import FetchSettings
from brandsentinel.net.netguard import NetGuard, PolicyViolation, ResolutionFailed, Validated

TlsMode = Literal["verified", "evidence"]
Purpose = Literal["untrusted", "reference"]
Outcome = Literal[
    "ok",
    "blocked",
    "blocked_redirect",
    "redirect_limit",
    "dns_error",
    "connect_error",
    "tls_error",
    "timeout",
    "protocol_error",
    "lab_transport_unavailable",
    "internal_error",
]

COLLECTOR_VERSION = "fetcher/1"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
# Outcomes worth retrying later: the site may be intermittently reachable.
TRANSIENT_OUTCOMES = frozenset({"connect_error", "timeout", "protocol_error"})
MAX_HEADERS = 100
MAX_HEADER_VALUE = 2048
# Recorded header bytes per hop, so a header flood over several redirects cannot
# push the fetch fact past the fact-size cap.
MAX_HEADER_BYTES = 16 * 1024
_CHUNK = 65536


@dataclass
class TlsInfo:
    mode: Literal["verified", "unverified"]
    version: str | None = None
    cipher: str | None = None
    peer_cert_sha256: str | None = None
    verification_error: str | None = None  # set when verification failed (evidence mode)


@dataclass
class Hop:
    url: str
    host: str
    port: int
    address: str | None = None  # the validated address actually connected to
    status: int | None = None
    location: str | None = None
    headers: list[list[str]] = field(default_factory=list)
    headers_truncated: bool = False
    tls: TlsInfo | None = None
    error: dict | None = None
    elapsed_ms: int = 0


@dataclass
class Body:
    content_type: str | None
    charset: str | None
    content_encoding: str | None
    raw_bytes: int = 0
    decoded_bytes: int = 0
    truncated: str | None = None  # raw_cap | decoded_cap | timeout
    decode_error: str | None = None
    sha256: str | None = None
    data: bytes = b""  # decoded bytes (raw when undecodable); never serialized


@dataclass
class FetchResult:
    requested_url: str
    mode: TlsMode
    purpose: Purpose
    started_at: str
    outcome: Outcome = "ok"
    error: dict | None = None
    final_url: str | None = None
    status: int | None = None
    hops: list[Hop] = field(default_factory=list)
    body: Body | None = None
    body_stored: bool = False  # set by the caller once the blob store accepted it
    tls_verification_failed: bool = False
    elapsed_ms: int = 0

    @property
    def transient(self) -> bool:
        if self.outcome == "dns_error":
            return bool(self.error and self.error.get("transient"))
        return self.outcome in TRANSIENT_OUTCOMES

    @property
    def trusted_reference(self) -> bool:
        """True only for a reference fetch whose every hop was https with
        verified TLS."""
        return (
            self.purpose == "reference"
            and self.mode == "verified"
            and self.outcome == "ok"
            and not self.tls_verification_failed
            and bool(self.hops)
            and all(h.tls is not None and h.tls.mode == "verified" for h in self.hops)
        )

    def to_fact(self) -> dict:
        d = asdict(replace(self, body=replace(self.body, data=b"")) if self.body else self)
        if self.body is not None:
            d["body"].pop("data")
        d["trusted_reference"] = self.trusted_reference
        d["collector_version"] = COLLECTOR_VERSION
        return d


def media_type(content_type: str | None) -> tuple[str | None, str | None]:
    """(lowercase media type, charset) from a Content-Type header."""
    if not content_type:
        return None, None
    parts = [p.strip() for p in content_type.split(";")]
    charset = None
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip().lower() == "charset":
            charset = v.strip().strip('"').lower()[:40] or None
    return parts[0].lower()[:100] or None, charset


def verified_context(cafile: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile or certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connects to one validated address whatever host httpcore asks for, and
    refuses anything but the expected host (and every Unix socket)."""

    def __init__(self, host: str, address: str) -> None:
        self._host = host
        self._address = address
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self._host:
            raise httpcore.ConnectError(f"refusing unexpected host {host!r}")
        return await self._inner.connect_tcp(
            self._address, port, timeout=timeout, socket_options=socket_options
        )

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _Decoder:
    """Incremental Content-Encoding decoder with an output cap."""

    def __init__(self, encoding: str | None) -> None:
        enc = (encoding or "identity").strip().lower()
        self.unsupported = False
        self._deflate = False
        self._z = None
        if enc in ("gzip", "x-gzip"):
            self._z = zlib.decompressobj(wbits=31)
        elif enc == "deflate":
            self._deflate = True  # zlib-wrapped or raw; decided on the first bytes
        elif enc not in ("identity", ""):
            self.unsupported = True  # br, zstd, stacked encodings: keep raw bytes

    def feed(self, chunk: bytes, limit: int) -> tuple[bytes, bool]:
        """Decode up to `limit` bytes. Returns (output, hit_limit)."""
        if limit <= 0:  # zlib treats max_length=0 as "unlimited"
            return b"", bool(chunk)
        if self._deflate and self._z is None and chunk:
            # RFC 9110 "deflate" is zlib-wrapped, but servers often send raw deflate.
            zlib_header = (
                len(chunk) >= 2 and chunk[0] & 0x0F == 8 and ((chunk[0] << 8) | chunk[1]) % 31 == 0
            )
            self._z = zlib.decompressobj(wbits=15 if zlib_header else -15)
        if self._z is None:
            return chunk[:limit], len(chunk) > limit
        out = self._z.decompress(self._z.unconsumed_tail + chunk, limit)
        hit = bool(self._z.unconsumed_tail) or (len(out) == limit and not self._z.eof)
        return out, hit


class _TlsVerifyFailed(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class Fetcher:
    def __init__(
        self,
        settings: FetchSettings,
        guard: NetGuard,
        *,
        verify_context: ssl.SSLContext | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """`verify_context` replaces the certifi trust store (tests pass one that
        trusts the local harness CA)."""
        self.settings = settings
        self.guard = guard
        self._verify_ctx = verify_context or verified_context()
        self._unverified_ctx = unverified_context()
        self._clock = clock

    async def fetch(
        self,
        url: str,
        *,
        mode: TlsMode = "evidence",
        purpose: Purpose = "untrusted",
        method: str = "GET",
        accept: Sequence[str] | None = None,
        max_bytes: int | None = None,
        host_allowed: Callable[[str], bool] | None = None,
    ) -> FetchResult:
        """Fetch `url`. Never raises for network or policy failures; the outcome
        and error are in the result. `host_allowed` restricts every hop's host
        (reference collection stays on official domains)."""
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(f"method {method} is never allowed")
        if purpose == "reference" and mode != "verified":
            raise ValueError("reference collection requires verified TLS")
        result = FetchResult(
            requested_url=url[:2048],
            mode=mode,
            purpose=purpose,
            started_at=datetime.fromtimestamp(self._clock(), UTC).isoformat(),
        )
        if self.guard.lab_mode:
            # Lab sites are reachable only through the lab proxy (U18, M4); until
            # that transport exists the fetcher refuses rather than go direct.
            result.outcome = "lab_transport_unavailable"
            return result
        accepted = frozenset(a.lower() for a in (accept or self.settings.accept_types))
        decoded_cap = min(
            max_bytes or self.settings.max_decoded_bytes, self.settings.max_decoded_bytes
        )
        start = time.monotonic()
        try:
            async with asyncio.timeout(self.settings.total_timeout_seconds):
                await self._walk(
                    result,
                    url,
                    method,
                    accepted,
                    decoded_cap,
                    host_allowed,
                    reference=purpose == "reference",
                )
        except TimeoutError:
            result.outcome = "timeout"
            result.error = {"kind": "total_timeout", "seconds": self.settings.total_timeout_seconds}
            if result.body is not None and result.body.truncated is None:
                result.body.truncated = "timeout"
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception as e:  # the contract: a fetch never raises for what a site does
            result.outcome = "internal_error"
            result.error = {"kind": type(e).__name__, "message": _msg(e)}
        result.elapsed_ms = int((time.monotonic() - start) * 1000)
        if result.body is not None:
            result.body.sha256 = hashlib.sha256(result.body.data).hexdigest()
            result.body.decoded_bytes = len(result.body.data)
        return result

    async def _walk(
        self, result, url, method, accepted, decoded_cap, host_allowed, *, reference=False
    ) -> None:
        current = url
        for index in range(self.settings.max_redirects + 1):
            redirected = index > 0
            try:
                target = await self.guard.validate(current)
                if host_allowed is not None and not host_allowed(target.host):
                    raise PolicyViolation("host_not_allowed", {"host": target.host})
                if reference and target.scheme != "https":
                    raise PolicyViolation("scheme_downgrade", {"scheme": target.scheme})
            except PolicyViolation as e:
                result.outcome = "blocked_redirect" if redirected else "blocked"
                result.error = {"kind": e.reason, **e.detail, "url": current[:2048]}
                return
            except ResolutionFailed as e:
                result.outcome = "dns_error"
                result.error = {"kind": e.reason, **e.detail, "transient": e.transient}
                return
            hop = Hop(url=target.url, host=target.host, port=target.port)
            result.hops.append(hop)
            result.final_url = target.url
            await self._hop(result, hop, target, method, accepted, decoded_cap)
            result.status = hop.status
            if result.outcome != "ok":
                return
            if hop.status in REDIRECT_CODES and hop.location:
                if index == self.settings.max_redirects:
                    result.outcome = "redirect_limit"
                    result.error = {"kind": "redirect_limit", "max": self.settings.max_redirects}
                    return
                try:
                    current = urljoin(target.url, hop.location.strip())
                except ValueError as e:
                    result.outcome = "blocked_redirect"
                    result.error = {
                        "kind": "invalid_url",
                        "why": str(e)[:200],
                        "url": hop.location[:2048],
                    }
                    return
                result.body = None  # redirect bodies are not evidence
                continue
            return

    async def _hop(self, result, hop, target: Validated, method, accepted, decoded_cap) -> None:
        start = time.monotonic()
        last_error: dict | None = None
        try:
            for address in target.addresses[: self.settings.max_addresses_tried]:
                hop.address = address
                verify, verification_error = True, None
                while True:
                    try:
                        await self._request(
                            result,
                            hop,
                            target,
                            address,
                            method,
                            accepted,
                            decoded_cap,
                            verify=verify,
                            verification_error=verification_error,
                        )
                        return
                    except _TlsVerifyFailed as e:
                        if result.mode == "verified":
                            self._fail(
                                result,
                                hop,
                                "tls_error",
                                {"kind": "tls_verification_failed", "message": str(e)},
                            )
                            return
                        # Evidence mode: retry this address once without verification.
                        result.tls_verification_failed = True
                        verify, verification_error = False, str(e)
                    except httpcore.ConnectTimeout:
                        last_error = {"kind": "connect_timeout", "address": address}
                        break
                    except httpcore.ConnectError as e:
                        if (cause := _ssl_cause(e)) is not None:
                            self._fail(
                                result,
                                hop,
                                "tls_error",
                                {"kind": "tls_handshake", "message": _msg(cause)},
                            )
                            return
                        last_error = {
                            "kind": "connect_error",
                            "address": address,
                            "message": _msg(e),
                        }
                        break
            timed_out = last_error is not None and last_error["kind"] == "connect_timeout"
            self._fail(result, hop, "timeout" if timed_out else "connect_error", last_error)
        except (httpcore.ReadTimeout, httpcore.WriteTimeout, httpcore.PoolTimeout) as e:
            self._fail(result, hop, "timeout", {"kind": "read_timeout", "message": _msg(e)})
            self._mark_partial(result, "timeout")
        except (
            httpcore.RemoteProtocolError,
            httpcore.LocalProtocolError,
            httpcore.ReadError,
            httpcore.WriteError,
        ) as e:
            self._fail(
                result, hop, "protocol_error", {"kind": type(e).__name__, "message": _msg(e)}
            )
            self._mark_partial(result, "read_error")
        finally:
            hop.elapsed_ms = int((time.monotonic() - start) * 1000)

    @staticmethod
    def _mark_partial(result, reason: str) -> None:
        if result.body is not None and result.body.truncated is None:
            result.body.truncated = reason

    @staticmethod
    def _fail(result, hop, outcome: Outcome, error: dict | None) -> None:
        result.outcome = outcome
        result.error = error
        hop.error = error

    async def _request(
        self,
        result,
        hop: Hop,
        target: Validated,
        address: str,
        method,
        accepted,
        decoded_cap,
        *,
        verify: bool = True,
        verification_error: str | None = None,
    ) -> None:
        s = self.settings
        https = target.scheme == "https"
        ctx = (self._verify_ctx if verify else self._unverified_ctx) if https else None
        url = httpcore.URL(
            scheme=target.scheme, host=target.host, port=target.port, target=target.target
        )
        headers = [
            (b"Host", target.authority.encode("ascii")),
            (b"User-Agent", s.user_agent.encode("ascii", "replace")),
            (b"Accept", ", ".join(sorted(accepted)).encode("ascii", "replace")),
            (b"Accept-Encoding", b"gzip, deflate"),
            (b"Accept-Language", b"en"),
            (b"Connection", b"close"),
        ]
        timeouts = {
            "connect": s.connect_timeout_seconds,
            "read": s.read_timeout_seconds,
            "write": s.read_timeout_seconds,
            "pool": s.connect_timeout_seconds,
        }
        pool = httpcore.AsyncConnectionPool(
            ssl_context=ctx,
            max_connections=1,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedBackend(target.host, address),
        )
        async with pool:
            try:
                async with pool.stream(
                    method, url, headers=headers, extensions={"timeout": timeouts}
                ) as resp:
                    self._record_response(hop, resp, https, verify, verification_error, address)
                    if method == "HEAD" or (hop.status in REDIRECT_CODES and hop.location):
                        return
                    ctype, charset = media_type(_header(resp, b"content-type"))
                    encoding = _header(resp, b"content-encoding")
                    if ctype not in accepted:
                        return  # headers only; the body type was not requested
                    body = Body(ctype, charset, encoding)
                    result.body = body
                    await self._read_body(resp, body, decoded_cap)
            except httpcore.ConnectError as e:
                cause = _ssl_cause(e)
                if https and verify and isinstance(cause, ssl.SSLCertVerificationError):
                    raise _TlsVerifyFailed(_msg(cause)) from e
                raise

    def _record_response(self, hop, resp, https, verify, verification_error, address) -> None:
        stream = resp.extensions.get("network_stream")
        peer = stream.get_extra_info("server_addr") if stream is not None else None
        if peer and ipaddress.ip_address(peer[0].split("%")[0]) != ipaddress.ip_address(address):
            # Defense in depth: the pinned connection must have gone where validated.
            raise httpcore.ConnectError(f"connected to {peer[0]}, expected {address}")
        hop.status = resp.status
        budget = MAX_HEADER_BYTES
        hop.headers = []
        for k, v in resp.headers:
            pair = [k.decode("latin-1")[:200], v.decode("latin-1")[:MAX_HEADER_VALUE]]
            budget -= len(pair[0]) + len(pair[1])
            if budget < 0 or len(hop.headers) >= MAX_HEADERS:
                hop.headers_truncated = True
                break
            hop.headers.append(pair)
        location = _header(resp, b"location")
        hop.location = location[:MAX_HEADER_VALUE] if location is not None else None
        if https:
            ssl_obj = stream.get_extra_info("ssl_object") if stream is not None else None
            tls = TlsInfo(
                mode="verified" if verify else "unverified", verification_error=verification_error
            )
            if ssl_obj is not None:
                tls.version = ssl_obj.version()
                cipher = ssl_obj.cipher()
                tls.cipher = cipher[0] if cipher else None
                der = ssl_obj.getpeercert(binary_form=True)
                tls.peer_cert_sha256 = hashlib.sha256(der).hexdigest() if der else None
            hop.tls = tls

    async def _read_body(self, resp, body: Body, decoded_cap: int) -> None:
        raw_cap = self.settings.max_raw_bytes
        decoder = _Decoder(body.content_encoding)
        if decoder.unsupported:
            body.decode_error = f"unsupported content-encoding {body.content_encoding!r}"[:200]
            decoder = _Decoder(None)  # keep the raw bytes, still capped
        buf = bytearray()
        try:
            async for chunk in resp.aiter_stream():
                body.raw_bytes += len(chunk)
                if body.raw_bytes > raw_cap:
                    chunk = chunk[: len(chunk) - (body.raw_bytes - raw_cap)]
                    body.raw_bytes = raw_cap
                    body.truncated = "raw_cap"
                try:
                    out, full = decoder.feed(chunk, decoded_cap - len(buf))
                except zlib.error as e:
                    body.decode_error = f"zlib: {e}"[:200]
                    break
                buf += out
                if full:
                    body.truncated = body.truncated or "decoded_cap"
                if body.truncated:
                    break
        finally:
            # Runs on cancellation too, so a total-timeout keeps what was read.
            body.data = bytes(buf)


def _ssl_cause(e: BaseException) -> ssl.SSLError | None:
    """The ssl error behind an httpcore exception (it is chained as context)."""
    seen = 0
    cur: BaseException | None = e
    while cur is not None and seen < 10:
        if isinstance(cur, ssl.SSLError):
            return cur
        cur = cur.__cause__ or cur.__context__
        seen += 1
    return None


def _header(resp, name: bytes) -> str | None:
    for k, v in resp.headers:
        if k.lower() == name:
            return v.decode("latin-1")
    return None


def _msg(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:500]
