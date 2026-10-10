"""Egress proxy policy against the local adversarial harness (U18, R37, R41).

The proxy runs in-process on 127.0.0.1 with a netguard that treats the harness
range 127.77.0.0/16 as public, exactly as the fetcher's security tests do. The
same proxy code runs in the egress-proxy container; its network placement and
hardening are proved on real rootless Docker in test_docker_isolation.py.
"""

import asyncio
import json
import socket
import threading
import time
import uuid

import pytest
from tests.security.harness import harness_context, harness_guard

from brandsentinel.config import Config, LabSettings, NetSettings, ProxySettings
from brandsentinel.net.netguard import NetGuard, StaticResolver
from brandsentinel.net.proxy import EgressProxy, parse_listen

pytestmark = pytest.mark.security

LAB_HOST = "donate.lumina.lab"
LAB_IP = "172.31.250.10"
PUBLIC_IP = "93.184.215.14"


class Upstream:
    """Threaded TCP server on the harness range: records each request head and
    answers with `reply`, or streams `stream_bytes` of data."""

    def __init__(self, reply: bytes = b"", stream_bytes: int = 0, drip: int = 0) -> None:
        self.reply = reply or b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        self.stream_bytes = stream_bytes
        self.drip = drip  # chunks of 16 KiB sent 0.2 s apart
        self.requests: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.77.0.9", 0))
        self.sock.listen(16)
        self.host, self.port = self.sock.getsockname()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5)
            try:
                if self.drip:
                    for _ in range(self.drip):
                        conn.sendall(b"d" * 16384)
                        time.sleep(0.2)
                    return
                if self.stream_bytes:
                    sent = 0
                    while sent < self.stream_bytes:
                        conn.sendall(b"x" * 65536)
                        sent += 65536
                    return
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                self.requests.append(data)
                conn.sendall(self.reply)
            except OSError:
                return

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def upstream():
    u = Upstream()
    yield u
    u.close()


class _Peer:
    """A stream writer that reports a chosen peer address (for connectors that
    stand in for a public destination)."""

    def __init__(self, writer, peer: str) -> None:
        self._w, self._peer = writer, peer

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return (self._peer, 0)
        return self._w.get_extra_info(name, default)

    def __getattr__(self, name):
        return getattr(self._w, name)


def redirecting_connector(host: str, port: int, calls: list, *, fake_peer: bool = True):
    """Records the (address, port) the proxy dials, and connects to a local
    server instead."""

    async def connect(address: str, dport: int):
        calls.append((address, dport))
        r, w = await asyncio.open_connection(host, port)
        return r, (_Peer(w, address) if fake_peer else w)

    return connect


def with_proxy(guard, scenario, settings: ProxySettings | None = None, **proxy_kw):
    async def main():
        proxy = EgressProxy(settings or ProxySettings(), guard, **proxy_kw)
        servers = await proxy.start([("127.0.0.1", 0)])
        port = servers[0].sockets[0].getsockname()[1]
        try:
            return await scenario(port)
        finally:
            for s in servers:
                s.close()

    return asyncio.run(main())


async def exchange(port: int, raw: bytes, timeout: float = 10) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    try:
        return await asyncio.wait_for(r.read(), timeout)
    finally:
        w.close()


def status_of(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def ask(guard, raw: bytes, **kw) -> bytes:
    return with_proxy(guard, lambda port: exchange(port, raw), **kw)


async def open_tunnel(port: int, authority: str, extra: bytes = b""):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"CONNECT {authority} HTTP/1.1\r\n".encode() + extra + b"\r\n")
    await w.drain()
    head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
    return r, w, head


# --- allowed traffic --------------------------------------------------------------


def test_connect_tunnel_reaches_the_validated_address_and_is_logged(harness, decisions):
    authority = f"site.harness.test:{harness.http.port}"

    async def scenario(port):
        r, w, head = await open_tunnel(port, authority)
        assert head.startswith(b"HTTP/1.1 200")
        w.write(b"GET /ok HTTP/1.1\r\nHost: site.harness.test\r\nConnection: close\r\n\r\n")
        await w.drain()
        body = await asyncio.wait_for(r.read(), 10)
        w.close()
        return body

    body = with_proxy(harness_guard(harness), scenario)
    assert b"Lumina Foundation Donate" in body
    rec = decisions.last()
    assert rec["decision"] == "allow" and rec["reason"] == "connect"
    assert rec["host"] == "site.harness.test" and rec["address"] == "127.77.0.1"
    assert rec["bytes_down"] > 0 and json.dumps(rec)


def test_connect_tunnel_carries_tls_end_to_end(harness):
    authority = f"secure.harness.test:{harness.secure.port}"

    async def scenario(port):
        r, w, head = await open_tunnel(port, authority)
        assert head.startswith(b"HTTP/1.1 200")
        await w.start_tls(harness_context(harness), server_hostname="secure.harness.test")
        w.write(b"GET /ok HTTP/1.1\r\nHost: secure.harness.test\r\nConnection: close\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(), 10)
        w.close()
        return data

    assert b"200 OK" in with_proxy(harness_guard(harness), scenario)


@pytest.mark.parametrize("port", [443, 80])
def test_connect_to_a_public_host_on_443_and_80_dials_the_validated_ip(harness, decisions, port):
    guard = NetGuard(NetSettings(), StaticResolver({"public.example": [PUBLIC_IP]}))
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls)

    async def scenario(proxy_port):
        _r, w, head = await open_tunnel(proxy_port, f"public.example:{port}")
        w.close()
        return head

    head = with_proxy(guard, scenario, connector=connector)
    assert head.startswith(b"HTTP/1.1 200")
    assert calls == [(PUBLIC_IP, port)]
    assert decisions.last()["address"] == PUBLIC_IP


def test_absolute_form_get_is_forwarded_without_hop_by_hop_headers(upstream):
    guard = harness_guard_for(upstream)
    raw = (
        f"GET http://127.77.0.9:{upstream.port}/path?q=1 HTTP/1.1\r\n"
        f"Host: 127.77.0.9:{upstream.port}\r\n"
        "Proxy-Authorization: Basic c2VjcmV0\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Connection: keep-alive, X-Drop\r\n"
        "Keep-Alive: 5\r\nTE: trailers\r\nUpgrade: websocket\r\n"
        "X-Drop: 1\r\nX-Keep: 1\r\n\r\n"
    ).encode()
    response = ask(guard, raw, forward_ports=[upstream.port])
    assert status_of(response) == 200 and response.endswith(b"ok")
    sent = upstream.requests[0].decode()
    assert sent.startswith("GET /path?q=1 HTTP/1.1\r\n")
    assert f"Host: 127.77.0.9:{upstream.port}\r\n" in sent
    assert "X-Keep: 1" in sent and "Connection: close" in sent
    for dropped in ("Proxy-", "X-Drop", "Keep-Alive", "TE:", "Upgrade", "keep-alive"):
        assert dropped not in sent


def harness_guard_for(upstream: Upstream) -> NetGuard:
    from tests.security.harness import TEST_NET

    return NetGuard(
        NetSettings(),
        StaticResolver({}),
        test_networks=[TEST_NET],
        allowed_ports=[80, 443, upstream.port],
    )


# --- refused traffic --------------------------------------------------------------


@pytest.mark.parametrize(
    ("authority", "reason"),
    [
        ("169.254.169.254:80", "blocked_address"),
        ("10.0.0.1:443", "blocked_address"),
        ("[::1]:443", "blocked_address"),
        ("[::ffff:127.0.0.1]:443", "blocked_address"),
        ("[64:ff9b::a00:1]:443", "blocked_address"),
        ("[fd00:ec2::254]:80", "blocked_address"),
        ("2130706433:80", "blocked_address"),
        ("0x7f.1:443", "blocked_address"),
        ("127.0.0.1:80", "blocked_address"),
        ("private.harness.test:80", "blocked_address"),
        ("metadata.harness.test:80", "blocked_address"),
        ("loopback6.harness.test:443", "blocked_address"),
        ("mapped.harness.test:443", "blocked_address"),
        ("mixed.harness.test:80", "dns_mixed_private"),
        ("site.harness.test:22", "port_not_allowed"),
    ],
)
def test_connect_to_blocked_destinations_is_refused_logged_and_never_dialled(
    harness, decisions, authority, reason
):
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls)
    response = ask(
        harness_guard(harness),
        f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode(),
        connector=connector,
    )
    assert status_of(response) == 403 and reason.encode() in response
    assert calls == []
    rec = decisions.last()
    assert rec["decision"] == "deny" and rec["reason"] == reason and rec["status"] == 403


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "http://metadata.harness.test/",
    ],
)
def test_absolute_form_get_to_blocked_destinations_is_refused(harness, url):
    host = url.split("/")[2]
    response = ask(harness_guard(harness), f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    assert status_of(response) == 403


def test_a_name_that_rebinds_to_private_is_never_connected_to(harness, decisions):
    # The first answer is public, the second (a rebinding attempt) is loopback.
    name = f"rebind-{uuid.uuid4().hex[:8]}.harness.test"
    harness.dns.set(name, A=[["127.77.0.1"], ["127.0.0.1"]])
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls)
    guard = harness_guard(harness)

    async def scenario(port):
        _r, w, head = await open_tunnel(port, f"{name}:{harness.http.port}")
        w.close()
        second = await exchange(port, f"CONNECT {name}:80 HTTP/1.1\r\n\r\n".encode())
        return head, second

    head, second = with_proxy(guard, scenario, connector=connector)
    assert head.startswith(b"HTTP/1.1 200")
    assert calls == [("127.77.0.1", harness.http.port)]  # one lookup, pinned
    assert status_of(second) == 403  # the rebound answer is refused, not dialled
    assert harness.dns.count(name, "A") == 2


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("GET http://{up}/ HTTP/1.1\r\nHost: other.example\r\n\r\n", "host_mismatch"),
        ("GET http://{up}/ HTTP/1.1\r\nHost: 127.77.0.9\r\n\r\n", "host_mismatch"),
        ("GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\nHost: {up}\r\n\r\n", "duplicate_host_header"),
        ("GET http://{up}/ HTTP/1.1\r\n\r\n", "missing_host_header"),
        ("CONNECT {up} HTTP/1.1\r\nHost: evil.example:443\r\n\r\n", "host_mismatch"),
    ],
)
def test_host_header_must_match_the_request_target(upstream, raw, reason):
    up = f"127.77.0.9:{upstream.port}"
    response = ask(
        harness_guard_for(upstream), raw.format(up=up).encode(), forward_ports=[upstream.port]
    )
    assert status_of(response) == 400 and reason.encode() in response
    assert upstream.requests == []


@pytest.mark.parametrize(
    ("raw", "status", "reason"),
    [
        ("POST http://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n", 405, "method_not_allowed"),
        ("PUT http://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n", 405, "method_not_allowed"),
        ("GET / HTTP/1.1\r\nHost: {up}\r\n\r\n", 400, "not_a_proxy_request"),
        ("GET https://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n", 400, "https_requires_connect"),
        ("GET ftp://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n", 400, "not_a_proxy_request"),
        (
            "GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\nContent-Length: 5\r\n\r\nhello",
            400,
            "request_body_not_allowed",
        ),
        (
            "GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
            "request_body_not_allowed",
        ),
        (
            "GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\nX-A: 1\r\n  folded\r\n\r\n",
            400,
            "obsolete_line_folding",
        ),
        ("GET http://{up}/ HTTP/2.0\r\nHost: {up}\r\n\r\n", 400, "unsupported_version"),
        ("GET  http://{up}/ HTTP/1.1\r\n\r\n", 400, "invalid_request_line"),
        ("CONNECT {up}/x HTTP/1.1\r\n\r\n", 400, "invalid_connect_target"),
        ("CONNECT user@{up} HTTP/1.1\r\n\r\n", 400, "invalid_connect_target"),
        ("CONNECT 127.77.0.9 HTTP/1.1\r\n\r\n", 400, "invalid_connect_target"),
    ],
)
def test_malformed_and_unsupported_requests_are_refused(upstream, raw, status, reason):
    up = f"127.77.0.9:{upstream.port}"
    response = ask(
        harness_guard_for(upstream), raw.format(up=up).encode(), forward_ports=[upstream.port]
    )
    assert status_of(response) == status and reason.encode() in response
    assert upstream.requests == []


def test_absolute_form_is_limited_to_port_80_by_default(upstream):
    up = f"127.77.0.9:{upstream.port}"
    response = ask(
        harness_guard_for(upstream), f"GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n".encode()
    )
    assert status_of(response) == 403 and b"port_not_allowed" in response


def test_oversized_request_header_is_refused(harness):
    raw = b"CONNECT site.harness.test:80 HTTP/1.1\r\nX-Big: " + b"a" * 20000 + b"\r\n\r\n"
    response = ask(harness_guard(harness), raw)
    assert status_of(response) == 431


def test_too_many_header_fields_are_refused(harness):
    raw = b"CONNECT site.harness.test:80 HTTP/1.1\r\n" + b"X: 1\r\n" * 101 + b"\r\n"
    assert status_of(ask(harness_guard(harness), raw)) == 431


# --- lab mode ---------------------------------------------------------------------


def lab_guard(enabled: bool = True) -> NetGuard:
    hosts = {LAB_HOST: LAB_IP} if enabled else {}
    return NetGuard(
        NetSettings(lab=LabSettings(enabled=enabled, hosts=hosts)),
        # An attacker-controlled DNS answer pointing a name at the lab subnet.
        StaticResolver({"public.example": [PUBLIC_IP], LAB_HOST: [LAB_IP]}),
    )


@pytest.mark.parametrize(
    ("authority", "status", "dialled"),
    [
        (f"{LAB_HOST}:80", 200, (LAB_IP, 80)),
        ("127.0.0.1:80", 403, None),
        ("169.254.169.254:80", 403, None),
        ("10.0.0.5:80", 403, None),
        (f"{LAB_IP}:80", 403, None),  # the lab subnet only for lab hostnames
        ("public.example:443", 403, None),  # a lab proxy serves only the lab
    ],
)
def test_lab_proxy_allows_only_lab_hostnames(harness, authority, status, dialled):
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls)

    async def scenario(port):
        _r, w, head = await open_tunnel(port, authority)
        w.close()
        return head

    head = with_proxy(
        lab_guard(), scenario, settings=ProxySettings(lab_only=True), connector=connector
    )
    assert status_of(head) == status
    assert calls == ([dialled] if dialled else [])


def test_outside_lab_mode_the_lab_hostname_is_refused(harness):
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls)
    response = ask(
        lab_guard(enabled=False),
        f"CONNECT {LAB_HOST}:80 HTTP/1.1\r\n\r\n".encode(),
        connector=connector,
    )
    assert status_of(response) == 403 and b"blocked_address" in response and calls == []


def test_lab_only_proxy_requires_a_lab_mode_guard():
    with pytest.raises(ValueError, match="lab-mode"):
        EgressProxy(ProxySettings(lab_only=True), lab_guard(enabled=False))
    with pytest.raises(ValueError, match="lab_only requires"):
        Config(proxy=ProxySettings(lab_only=True))


# --- limits -----------------------------------------------------------------------


def test_connections_beyond_the_cap_are_refused(harness, decisions):
    async def scenario(port):
        _r1, w1 = await asyncio.open_connection("127.0.0.1", port)  # holds the only slot
        await asyncio.sleep(0.1)
        second = await exchange(port, b"CONNECT site.harness.test:80 HTTP/1.1\r\n\r\n")
        w1.close()
        return second

    settings = ProxySettings(max_connections=1, header_timeout_seconds=5)
    response = with_proxy(harness_guard(harness), scenario, settings=settings)
    assert status_of(response) == 503
    assert any(r["reason"] == "too_many_connections" for r in decisions.records)


def test_slow_request_header_times_out(harness):
    async def scenario(port):
        return await exchange(port, b"CONNECT site.harness.test:80 HTTP/1.1\r\n")

    settings = ProxySettings(header_timeout_seconds=0.3)
    response = with_proxy(harness_guard(harness), scenario, settings=settings)
    assert status_of(response) == 400 and b"header_timeout" in response


def test_tunnel_beyond_the_byte_cap_is_closed(decisions):
    source = Upstream(stream_bytes=4 * 1024 * 1024)
    try:

        async def scenario(port):
            r, w, _head = await open_tunnel(port, f"127.77.0.9:{source.port}")
            received = 0
            while chunk := await asyncio.wait_for(r.read(65536), 10):
                received += len(chunk)
            w.close()
            return received

        settings = ProxySettings(max_connection_bytes=256 * 1024)
        received = with_proxy(harness_guard_for(source), scenario, settings=settings)
    finally:
        source.close()
    assert received <= 256 * 1024
    assert decisions.last()["detail"]["ended"] == "byte_cap"


def test_idle_tunnel_is_closed(harness):
    async def scenario(port):
        r, w, head = await open_tunnel(port, f"blackhole.harness.test:{harness.blackhole.port}")
        data = await asyncio.wait_for(r.read(), 5)  # EOF once idle
        w.close()
        return head, data

    settings = ProxySettings(idle_timeout_seconds=0.3)
    head, data = with_proxy(harness_guard(harness), scenario, settings=settings)
    assert head.startswith(b"HTTP/1.1 200") and data == b""


def test_tunnel_is_closed_at_the_total_time_budget(harness, decisions):
    async def scenario(port):
        r, w, _head = await open_tunnel(port, f"blackhole.harness.test:{harness.blackhole.port}")
        data = await asyncio.wait_for(r.read(), 5)
        w.close()
        return data

    settings = ProxySettings(total_timeout_seconds=0.5, idle_timeout_seconds=30)
    assert with_proxy(harness_guard(harness), scenario, settings=settings) == b""
    assert decisions.last()["detail"]["ended"] == "total_timeout"


def test_socket_that_reaches_another_address_than_validated_is_dropped(harness):
    guard = NetGuard(NetSettings(), StaticResolver({"public.example": [PUBLIC_IP]}))
    calls: list = []
    connector = redirecting_connector("127.77.0.1", harness.http.port, calls, fake_peer=False)
    response = ask(guard, b"CONNECT public.example:443 HTTP/1.1\r\n\r\n", connector=connector)
    assert status_of(response) == 502 and b"peer_mismatch" in response


def test_unresolvable_destination_is_a_gateway_error(harness):
    response = ask(harness_guard(harness), b"CONNECT nope.harness.test:80 HTTP/1.1\r\n\r\n")
    assert status_of(response) == 502 and b"dns_nxdomain" in response


def test_listen_addresses_must_be_ip_literals():
    assert parse_listen("172.31.251.2:3128") == ("172.31.251.2", 3128)
    assert parse_listen("[::1]:3128") == ("::1", 3128)
    for bad in ("proxy:3128", "1.2.3.4", "1.2.3.4:0", "1.2.3.4:70000"):
        with pytest.raises(ValueError):
            parse_listen(bad)


# --- review regressions -----------------------------------------------------------


def test_lab_proxy_refuses_other_hosts_without_resolving_them():
    resolver = StaticResolver({"public.example": [PUBLIC_IP]})
    guard = NetGuard(NetSettings(lab=LabSettings(enabled=True, hosts={LAB_HOST: LAB_IP})), resolver)
    response = ask(
        guard,
        b"CONNECT public.example:443 HTTP/1.1\r\n\r\n",
        settings=ProxySettings(lab_only=True),
    )
    assert status_of(response) == 403 and b"not_lab_host" in response
    assert resolver.calls == []  # no DNS query left the lab proxy


def test_refusals_carry_the_proxy_marker_header(harness):
    response = ask(harness_guard(harness), b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n")
    assert b"\r\nX-BrandSentinel-Proxy: blocked_address\r\n" in response


def test_one_client_cannot_take_every_connection_slot(harness, decisions):
    async def scenario(port):
        _r, w1 = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        second = await exchange(port, b"CONNECT site.harness.test:80 HTTP/1.1\r\n\r\n")
        w1.close()
        return second

    settings = ProxySettings(max_connections=8, max_connections_per_client=1)
    assert status_of(with_proxy(harness_guard(harness), scenario, settings=settings)) == 503


def test_idle_timeout_does_not_cut_a_busy_one_way_download():
    source = Upstream(drip=8)  # ~1.6 s of data while the client stays silent
    try:

        async def scenario(port):
            r, w, _head = await open_tunnel(port, f"127.77.0.9:{source.port}")
            received = 0
            while chunk := await asyncio.wait_for(r.read(65536), 10):
                received += len(chunk)
            w.close()
            return received

        settings = ProxySettings(idle_timeout_seconds=0.5)
        received = with_proxy(harness_guard_for(source), scenario, settings=settings)
    finally:
        source.close()
    assert received == 8 * 16384
