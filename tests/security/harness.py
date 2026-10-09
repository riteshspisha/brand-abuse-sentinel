"""Local adversarial network harness for netguard, the fetcher and enrichment.

Everything binds to 127.77.0.0/16, which tests pass to netguard as a test-only
"public" range by constructor. The rest of loopback (127.0.0.1 in particular)
stays blocked, so a redirect or DNS answer pointing there is still refused.

- `DnsStub`: a UDP DNS server answering from a zone map. An answer can be a
  sequence (one entry per query, for rebinding), or `servfail`, `nxdomain`, or
  `drop` (no reply: the resolver times out). Queries are counted per name/type.
- `HttpServer`: a threaded HTTP(S) server with adversarial routes. Every request
  line is recorded so tests can assert which methods were sent.
- `RawServer`: writes fixed bytes on connect (malformed responses).
- Certificates: a test CA, CA-signed leaves (valid, expired) and a self-signed leaf.
"""

import datetime as dt
import gzip
import http.server
import ipaddress
import json
import socket
import socketserver
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from brandsentinel.config import DnsSettings, FetchSettings, NetSettings
from brandsentinel.net.fetcher import Fetcher
from brandsentinel.net.netguard import DnsResolver, NetGuard, make_dns_resolver

TEST_NET = ipaddress.ip_network("127.77.0.0/16")

# --- certificates ------------------------------------------------------------


@dataclass
class CertPair:
    cert_pem: bytes
    key_pem: bytes
    der: bytes

    def write(self, directory: Path, name: str) -> tuple[Path, Path]:
        c, k = directory / f"{name}.crt", directory / f"{name}.key"
        c.write_bytes(self.cert_pem)
        k.write_bytes(self.key_pem)
        return c, k


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    cn: str,
    sans: list[str],
    *,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    days: tuple[int, int] = (-1, 30),
    ca: bool = False,
) -> tuple[CertPair, x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    issuer_name = issuer[0].subject if issuer else _name(cn)
    signing_key = issuer[1] if issuer else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=days[0]))
        .not_valid_after(now + dt.timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    pair = CertPair(
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        cert.public_bytes(serialization.Encoding.DER),
    )
    return pair, cert, key


# --- DNS stub ------------------------------------------------------------------


class DnsStub:
    def __init__(self, host: str = "127.77.0.53") -> None:
        self.zone: dict[str, dict[str, object]] = {}
        self.queries: dict[tuple[str, str], int] = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.host, self.port = self.sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def set(self, name: str, **records) -> None:
        """records: A=[...], AAAA=[...], MX=[...], ... Values: a list, a list of
        lists (answers per successive query), or 'servfail' / 'nxdomain' / 'drop'."""
        self.zone[name.lower().rstrip(".")] = records

    def count(self, name: str, rdtype: str) -> int:
        return self.queries.get((name, rdtype), 0)

    def _answer(self, name: str, rdtype: str, n: int):
        entry = self.zone.get(name)
        if entry is None:
            return "nxdomain"
        value = entry.get(rdtype, entry.get("*", []))
        if isinstance(value, str):
            return value
        if value and isinstance(value[0], list):  # a sequence: one answer per query
            return value[min(n, len(value) - 1)]
        return value

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            try:
                q = dns.message.from_wire(data)
            except Exception:  # noqa: S112 - a stub ignores garbage
                continue
            question = q.question[0]
            name = question.name.to_text().rstrip(".").lower()
            rdtype = dns.rdatatype.to_text(question.rdtype)
            key = (name, rdtype)
            n = self.queries.get(key, 0)
            self.queries[key] = n + 1
            answer = self._answer(name, rdtype, n)
            if answer == "drop":
                continue
            r = dns.message.make_response(q)
            r.flags |= dns.flags.AA
            if answer == "servfail":
                r.set_rcode(dns.rcode.SERVFAIL)
            elif answer == "nxdomain":
                r.set_rcode(dns.rcode.NXDOMAIN)
            elif answer:
                r.answer.append(
                    dns.rrset.from_text_list(question.name, 60, "IN", rdtype, list(answer))
                )
            self.sock.sendto(r.to_wire(), addr)

    def close(self) -> None:
        self._stop = True
        self._thread.join(timeout=2)
        self.sock.close()


# --- HTTP server ---------------------------------------------------------------

PAGE = b"""<!doctype html><html><head><title>Lumina Foundation Donate</title>
<meta http-equiv="refresh" content="5; url=/next">
<link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="https://cdn.example/s.css">
<link rel="canonical" href="https://lumina.example/donate">
<script src="/app.js"></script></head>
<body><img src="logo.png"><img src="data:image/png;base64,AAAA">
<iframe src="//frame.example/x"></iframe>
<a href="javascript:alert(1)">x</a><p>Give now</p></body></html>"""


@dataclass
class Recorder:
    requests: list[tuple[str, str, dict]] = field(default_factory=list)
    hits: dict[str, int] = field(default_factory=dict)
    pages: dict[str, bytes] = field(default_factory=dict)
    rdap: dict[str, dict] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def methods(self) -> set[str]:
        return {m for m, _, _ in self.requests}


def _handler(recorder: Recorder, bomb: bytes):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "harness"

        def log_message(self, *args) -> None:
            pass

        def _send(
            self,
            status: int,
            body: bytes = b"",
            ctype: str = "text/html; charset=utf-8",
            headers: dict | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:  # recorded so a test would catch any POST
            self._record()
            self._send(405)

        def _record(self) -> tuple[str, dict]:
            parts = urlsplit(self.path)
            with recorder.lock:
                recorder.requests.append((self.command, self.path, dict(self.headers)))
                # Keyed by path and query, so tests can use their own counters.
                recorder.hits[self.path] = recorder.hits.get(self.path, 0) + 1
                n = recorder.hits[self.path]
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            q["_n"] = n
            return parts.path, q

        def do_GET(self) -> None:
            path, q = self._record()
            if path == "/ok":
                self._send(200, PAGE)
            elif path == "/redirect":
                self._send(int(q.get("code", 302)), headers={"Location": q.get("to", "")})
            elif path.startswith("/chain/"):
                n = int(path.rsplit("/", 1)[1])
                if n > 0:
                    self._send(302, headers={"Location": f"/chain/{n - 1}"})
                else:
                    self._send(200, b"<title>end</title>")
            elif path == "/gzip-bomb":
                self._send(200, bomb, headers={"Content-Encoding": "gzip"})
            elif path == "/gzip":
                self._send(200, gzip.compress(PAGE), headers={"Content-Encoding": "gzip"})
            elif path == "/deflate-raw":
                z = zlib.compressobj(wbits=-15)
                raw = z.compress(PAGE) + z.flush()
                self._send(200, raw, headers={"Content-Encoding": "deflate"})
            elif path == "/headers":
                self.send_response(200)
                for i in range(int(q.get("n", 10))):
                    self.send_header(f"X-Flood-{i}", "v" * 100)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif path == "/brotli":
                self._send(200, b"\x0b\x02\x80hello\x03", headers={"Content-Encoding": "br"})
            elif path == "/big":
                self._send(200, b"x" * (3 * 1024 * 1024), ctype="text/plain")
            elif path == "/slow":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "100000")
                self.end_headers()
                try:
                    for _ in range(200):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass
            elif path == "/mutable":  # content set by the test (rechecks)
                body = recorder.pages.get(q.get("k", ""), b"<title>none</title>")
                self._send(200, body)
            elif path == "/json":
                self._send(200, json.dumps({"a": 1}).encode(), ctype="application/json")
            elif path.startswith("/status/"):
                self._send(int(path.rsplit("/", 1)[1]), b"<title>err</title>")
            elif path == "/flaky":
                if q["_n"] <= int(q.get("fail", 1)):
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)  # drop without a response
                    return
                self._send(200, b"<title>back</title>")
            elif path.startswith("/rdap/domain/"):
                name = path.rsplit("/", 1)[1]
                doc = recorder.rdap.get(name)
                if doc is None:
                    self._send(404, b"{}", ctype="application/rdap+json")
                elif isinstance(doc, dict) and "redirect" in doc:
                    self._send(302, headers={"Location": doc["redirect"]})
                else:
                    self._send(200, json.dumps(doc).encode(), ctype="application/rdap+json")
            else:
                self._send(404, b"<title>nf</title>")

    return Handler


class _Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        pass  # clients that hang up early (caps, timeouts) are expected here


class HttpServer:
    def __init__(
        self, host: str, recorder: Recorder, bomb: bytes, tls: tuple[Path, Path] | None = None
    ) -> None:
        self.server = _Threaded((host, 0), _handler(recorder, bomb))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.server.socket = ctx.wrap_socket(
                self.server.socket, server_side=True, do_handshake_on_connect=False
            )
        self.host, self.port = self.server.server_address[:2]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class RawServer:
    """Accepts connections and writes `payload`, then closes. With payload None
    it accepts and stays silent (a black hole that forces read timeouts)."""

    def __init__(self, host: str, payload: bytes) -> None:
        self.payload = payload
        self.sock = socket.socket()
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.host, self.port = self.sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                try:
                    conn.settimeout(1)
                    conn.recv(65536)
                    if self.payload is None:
                        time.sleep(3)
                    else:
                        conn.sendall(self.payload)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop = True
        self._thread.join(timeout=2)
        self.sock.close()


def closed_port(host: str) -> int:
    """A port on `host` with nothing listening."""
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


@dataclass
class Harness:
    dns: DnsStub
    recorder: Recorder
    http: HttpServer  # 127.77.0.1, plain HTTP
    selfsigned: HttpServer  # 127.77.0.2, self-signed cert for selfsigned.harness.test
    secure: HttpServer  # 127.77.0.3, test-CA cert for secure.harness.test
    expired: HttpServer  # 127.77.0.4, expired test-CA cert
    garbage: RawServer  # 127.77.0.5, malformed status line
    huge_header: RawServer  # 127.77.0.6, header beyond the parser limit
    blackhole: RawServer  # 127.77.0.8, accepts and never answers
    ca_pem: bytes
    cert_der: dict[str, bytes]
    dead_port: int

    @property
    def ports(self) -> list[int]:
        return [
            80,
            443,
            self.http.port,
            self.selfsigned.port,
            self.secure.port,
            self.expired.port,
            self.garbage.port,
            self.huge_header.port,
            self.blackhole.port,
            self.dead_port,
        ]

    def close(self) -> None:
        for s in (
            self.dns,
            self.http,
            self.selfsigned,
            self.secure,
            self.expired,
            self.garbage,
            self.huge_header,
            self.blackhole,
        ):
            s.close()


def start_harness(tmp: Path) -> Harness:
    ca_pair, ca_cert, ca_key = make_cert("BrandSentinel Test CA", [], ca=True, days=(-1, 3650))
    secure, _, _ = make_cert(
        "secure.harness.test",
        ["secure.harness.test", "isha.sadhguru.org"],
        issuer=(ca_cert, ca_key),
    )
    expired, _, _ = make_cert(
        "expired.harness.test", ["expired.harness.test"], issuer=(ca_cert, ca_key), days=(-30, -1)
    )
    selfsigned, _, _ = make_cert("selfsigned.harness.test", ["selfsigned.harness.test"])
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024), compresslevel=9)
    recorder = Recorder()
    h = Harness(
        dns=DnsStub(),
        recorder=recorder,
        http=HttpServer("127.77.0.1", recorder, bomb),
        selfsigned=HttpServer("127.77.0.2", recorder, bomb, tls=selfsigned.write(tmp, "self")),
        secure=HttpServer("127.77.0.3", recorder, bomb, tls=secure.write(tmp, "secure")),
        expired=HttpServer("127.77.0.4", recorder, bomb, tls=expired.write(tmp, "expired")),
        garbage=RawServer("127.77.0.5", b"HTTP/1.1 abc garbage\r\n\r\n"),
        huge_header=RawServer(
            "127.77.0.6", b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 200_000 + b"\r\n\r\n"
        ),
        blackhole=RawServer("127.77.0.8", None),
        ca_pem=ca_pair.cert_pem,
        cert_der={"secure": secure.der, "selfsigned": selfsigned.der, "expired": expired.der},
        dead_port=closed_port("127.77.0.7"),
    )
    z = h.dns.set
    z("site.harness.test", A=["127.77.0.1"])
    z("selfsigned.harness.test", A=["127.77.0.2"])
    z("secure.harness.test", A=["127.77.0.3"])
    z("wronghost.harness.test", A=["127.77.0.3"])
    z("expired.harness.test", A=["127.77.0.4"])
    z("garbage.harness.test", A=["127.77.0.5"])
    z("hugeheader.harness.test", A=["127.77.0.6"])
    z("dead.harness.test", A=["127.77.0.7"])
    z("blackhole.harness.test", A=["127.77.0.8"])
    z("private.harness.test", A=["10.0.0.5"])
    z("metadata.harness.test", A=["169.254.169.254"])
    z("loopback6.harness.test", AAAA=["::1"])
    z("mapped.harness.test", AAAA=["::ffff:127.0.0.1"])
    z("mixed.harness.test", A=["127.77.0.1", "192.168.1.10"])
    z("rebind.harness.test", A=[["127.77.0.1"], ["127.0.0.1"]])
    z("servfail.harness.test", A="servfail", AAAA="servfail")
    z("timeout.harness.test", **{"*": "drop"})
    return h


# --- netguard, fetcher and resolver wired to the harness ------------------------


def harness_resolver(h: Harness, **dns_kw):
    settings = DnsSettings(nameservers=[h.dns.host], **dns_kw)
    return make_dns_resolver(settings, port=h.dns.port)


def harness_guard(h: Harness, **net_kw) -> NetGuard:
    """A guard that resolves through the DNS stub and treats 127.77.0.0/16 as public."""
    dns_kw = net_kw.pop("dns", {"timeout_seconds": 0.5, "lifetime_seconds": 1.0})
    return NetGuard(
        NetSettings(**net_kw),
        DnsResolver(harness_resolver(h, **dns_kw)),
        test_networks=[TEST_NET],
        allowed_ports=h.ports,
    )


def harness_context(h: Harness) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=h.ca_pem.decode())
    return ctx


def harness_fetcher(h: Harness, **fetch_kw) -> Fetcher:
    settings = FetchSettings(
        **{
            "total_timeout_seconds": 5,
            "read_timeout_seconds": 2,
            "connect_timeout_seconds": 2,
            **fetch_kw,
        }
    )
    return Fetcher(settings, harness_guard(h), verify_context=harness_context(h))


def rdap_bootstrap(h: Harness, base: str | None = None) -> dict:
    """An IANA-style bootstrap sending every `.test` domain to the harness."""
    base = base or f"https://secure.harness.test:{h.secure.port}/rdap/"
    return {"version": "1.0", "services": [[["test"], [base]]]}


def harness_stages(
    h: Harness, store, registry, *, clock=None, tls_port=None, bootstrap=None, **fetch_kw
):
    """AnalysisStages whose DNS, fetches, RDAP and TLS all go to the harness."""
    import time as _time

    from brandsentinel.enrich.rdap import RdapClient
    from brandsentinel.pipeline.stages import AnalysisStages

    clock = clock or _time.time
    fetcher = harness_fetcher(h, **fetch_kw)
    rdap = RdapClient(
        fetcher,
        store.config.enrich,
        store.config.cache_dir,
        bootstrap=bootstrap or rdap_bootstrap(h),
        clock=clock,
    )
    return AnalysisStages(
        store,
        registry,
        guard=fetcher.guard,
        fetcher=fetcher,
        resolver=harness_resolver(h, timeout_seconds=0.5, lifetime_seconds=1.0),
        rdap=rdap,
        verify_context=harness_context(h),
        tls_port=tls_port or h.secure.port,
        clock=clock,
    )
