"""Hardened static fetcher against the local adversarial harness (U9, AE8)."""

import asyncio
import socket

import pytest
from tests.security.harness import harness_fetcher

from brandsentinel.config import FetchSettings, LabSettings, NetSettings
from brandsentinel.net.fetcher import ALLOWED_METHODS, Fetcher
from brandsentinel.net.netguard import NetGuard, StaticResolver

pytestmark = pytest.mark.security


def fetch(h, url, **kw):
    fetch_kw = kw.pop("settings", {})
    return asyncio.run(harness_fetcher(h, **fetch_kw).fetch(url, **kw))


def site(h, path):
    return f"http://site.harness.test:{h.http.port}{path}"


def test_plain_fetch_records_final_url_status_headers_and_body(harness):
    r = fetch(harness, site(harness, "/ok"))
    assert r.outcome == "ok" and r.status == 200
    assert r.final_url == site(harness, "/ok")
    hop = r.hops[0]
    assert hop.address == "127.77.0.1" and hop.status == 200
    assert ["Content-Type", "text/html; charset=utf-8"] in hop.headers
    assert r.body.content_type == "text/html" and r.body.charset == "utf-8"
    assert b"Lumina Foundation Donate" in r.body.data and len(r.body.sha256) == 64
    fact = r.to_fact()
    assert "data" not in fact["body"] and fact["trusted_reference"] is False


def test_redirect_to_metadata_address_stops_at_that_hop(harness):
    # Covers AE8.
    r = fetch(harness, site(harness, "/redirect?to=http://169.254.169.254/latest/meta-data/"))
    assert r.outcome == "blocked_redirect"
    assert r.error["kind"] == "blocked_address" and r.error["class"] == "link_local"
    assert len(r.hops) == 1 and r.hops[0].status == 302


def test_candidate_resolving_to_private_address_is_refused_without_connecting(harness):
    # Covers AE8.
    for host, cls in [
        ("private", "private"),
        ("metadata", "link_local"),
        ("loopback6", "loopback"),
        ("mapped", "ipv4_mapped:loopback"),
    ]:
        r = fetch(harness, f"http://{host}.harness.test/")
        assert r.outcome == "blocked" and r.error["class"] == cls and r.hops == []


def test_mixed_answers_are_refused(harness):
    r = fetch(harness, site(harness, "/ok").replace("site.", "mixed."))
    assert r.outcome == "blocked" and r.error["kind"] == "dns_mixed_private"


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "gopher://site.harness.test/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://2130706433/",
        "http://user:pw@site.harness.test/",
        "http://site.harness.test:22/",
    ],
)
def test_unsafe_redirect_targets_are_refused(harness, location):
    from urllib.parse import quote

    r = fetch(harness, site(harness, "/redirect?to=" + quote(location, safe="")))
    assert r.outcome == "blocked_redirect"
    assert r.body is None


def test_redirect_chain_longer_than_the_limit_stops(harness):
    r = fetch(harness, site(harness, "/chain/6"))
    assert r.outcome == "redirect_limit" and len(r.hops) == 6
    ok = fetch(harness, site(harness, "/chain/5"))
    assert ok.outcome == "ok" and len(ok.hops) == 6 and ok.final_url.endswith("/chain/0")
    assert [h.status for h in ok.hops] == [302] * 5 + [200]


def test_dns_is_resolved_once_per_hop_and_pinned(harness):
    # The first answer is public; the second (a rebinding attempt) is loopback.
    import uuid

    name = f"rebind-{uuid.uuid4().hex[:8]}.harness.test"
    harness.dns.set(name, A=[["127.77.0.1"], ["127.0.0.1"]])
    r = fetch(harness, f"http://{name}:{harness.http.port}/ok")
    assert r.outcome == "ok" and r.hops[0].address == "127.77.0.1"
    assert harness.dns.count(name, "A") == 1
    # A redirect back to the same host re-resolves and gets the private answer.
    r2 = fetch(harness, site(harness, f"/redirect?to=http://{name}:{harness.http.port}/ok"))
    assert r2.outcome == "blocked_redirect" and r2.error["class"] == "loopback"


def test_gzip_bomb_is_truncated_at_the_decoded_cap(harness):
    r = fetch(harness, site(harness, "/gzip-bomb"), settings={"max_decoded_bytes": 1024 * 1024})
    assert r.outcome == "ok"
    assert r.body.truncated == "decoded_cap"
    assert r.body.decoded_bytes == 1024 * 1024 and r.body.raw_bytes < 200_000


def test_gzip_body_is_decoded(harness):
    r = fetch(harness, site(harness, "/gzip"))
    assert r.body.content_encoding == "gzip" and b"<title>Lumina" in r.body.data
    assert r.body.truncated is None


def test_unsupported_encoding_keeps_raw_bytes_and_says_so(harness):
    r = fetch(harness, site(harness, "/brotli"))
    assert r.outcome == "ok" and "br" in r.body.decode_error
    assert r.body.data == b"\x0b\x02\x80hello\x03"


def test_raw_cap_truncates_large_bodies(harness):
    r = fetch(
        harness, site(harness, "/big"), accept=["text/plain"], settings={"max_raw_bytes": 100_000}
    )
    assert r.body.truncated == "raw_cap" and r.body.raw_bytes == 100_000
    assert len(r.body.data) == 100_000


def test_slow_drip_is_cut_off_by_the_total_budget(harness):
    r = fetch(
        harness,
        site(harness, "/slow"),
        settings={"total_timeout_seconds": 0.5, "read_timeout_seconds": 5},
    )
    assert r.outcome == "timeout" and r.error["kind"] == "total_timeout"
    assert r.body.truncated == "timeout" and 0 < r.body.decoded_bytes < 100_000
    assert r.transient


def test_self_signed_https_in_evidence_mode_falls_back_and_records_failure(harness):
    url = f"https://selfsigned.harness.test:{harness.selfsigned.port}/ok"
    r = fetch(harness, url, mode="evidence")
    assert r.outcome == "ok" and r.tls_verification_failed
    tls = r.hops[0].tls
    assert tls.mode == "unverified" and "CERTIFICATE_VERIFY_FAILED" in tls.verification_error
    assert len(tls.peer_cert_sha256) == 64 and tls.version.startswith("TLS")
    assert r.body is not None and not r.trusted_reference


def test_self_signed_https_in_verified_mode_is_refused_and_nothing_kept(harness):
    url = f"https://selfsigned.harness.test:{harness.selfsigned.port}/ok"
    r = fetch(harness, url, mode="verified")
    assert r.outcome == "tls_error" and r.error["kind"] == "tls_verification_failed"
    assert r.body is None


@pytest.mark.parametrize(("host", "port_attr"), [("wronghost", "secure"), ("expired", "expired")])
def test_hostname_mismatch_and_expired_certs_fail_verification(harness, host, port_attr):
    port = getattr(harness, port_attr).port
    r = fetch(harness, f"https://{host}.harness.test:{port}/ok", mode="verified")
    assert r.outcome == "tls_error"
    r2 = fetch(harness, f"https://{host}.harness.test:{port}/ok", mode="evidence")
    assert r2.outcome == "ok" and r2.tls_verification_failed


def test_valid_certificate_uses_sni_and_verifies(harness):
    r = fetch(
        harness,
        f"https://secure.harness.test:{harness.secure.port}/ok",
        mode="verified",
        purpose="reference",
    )
    assert r.outcome == "ok" and not r.tls_verification_failed
    assert r.hops[0].tls.mode == "verified" and r.trusted_reference


def test_reference_purpose_requires_verified_tls(harness):
    with pytest.raises(ValueError):
        fetch(harness, site(harness, "/ok"), mode="evidence", purpose="reference")


def secure(h, path):
    return f"https://secure.harness.test:{h.secure.port}{path}"


def test_reference_collection_cannot_leave_allowed_hosts(harness):
    url = secure(harness, f"/redirect?to=https://dead.harness.test:{harness.dead_port}/")
    r = fetch(
        harness,
        url,
        mode="verified",
        purpose="reference",
        host_allowed=lambda h: h == "secure.harness.test",
    )
    assert r.outcome == "blocked_redirect" and r.error["kind"] == "host_not_allowed"


def test_reference_collection_refuses_plain_http_and_downgrades(harness):
    r = fetch(harness, site(harness, "/ok"), mode="verified", purpose="reference")
    assert r.outcome == "blocked" and r.error["kind"] == "scheme_downgrade"
    to = f"http://secure.harness.test:{harness.http.port}/ok"
    r2 = fetch(
        harness,
        secure(harness, f"/redirect?to={to}"),
        mode="verified",
        purpose="reference",
        host_allowed=lambda h: h == "secure.harness.test",
    )
    assert r2.outcome == "blocked_redirect" and r2.error["kind"] == "scheme_downgrade"
    assert not r2.trusted_reference


def test_untrusted_fetch_across_schemes_is_never_trusted(harness):
    to = f"http://site.harness.test:{harness.http.port}/ok"
    r = fetch(harness, secure(harness, f"/redirect?to={to}"), mode="verified")
    assert r.outcome == "ok" and not r.trusted_reference


@pytest.mark.parametrize("location", ["http://[x/", "http://[::1"])
def test_unparseable_redirect_location_is_recorded_not_raised(harness, location):
    from urllib.parse import quote

    r = fetch(harness, site(harness, "/redirect?to=" + quote(location, safe="")))
    assert r.outcome == "blocked_redirect" and r.error["kind"] == "invalid_url"
    assert r.hops[0].status == 302


def test_empty_location_ends_the_walk(harness):
    r = fetch(harness, site(harness, "/redirect?to="))
    assert r.outcome == "ok" and r.status == 302 and len(r.hops) == 1


def test_header_flood_is_bounded_per_hop(harness):
    r = fetch(harness, site(harness, "/headers?n=400"))
    hop = r.hops[0]
    assert hop.headers_truncated
    assert sum(len(k) + len(v) for k, v in hop.headers) <= 16 * 1024


def test_raw_deflate_bodies_are_decoded(harness):
    r = fetch(harness, site(harness, "/deflate-raw"))
    assert r.body.decode_error is None and b"<title>Lumina" in r.body.data


def test_unexpected_internal_errors_become_an_outcome(harness, monkeypatch):
    from brandsentinel.net import fetcher as fetcher_mod

    def boom(*a, **k):
        raise ValueError("surprise")

    monkeypatch.setattr(fetcher_mod.Fetcher, "_record_response", boom)
    r = fetch(harness, site(harness, "/ok"))
    assert r.outcome == "internal_error" and r.error["kind"] == "ValueError"


def test_proxy_environment_variables_are_ignored(harness, monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, f"http://127.77.0.7:{harness.dead_port}")
    r = fetch(harness, site(harness, "/ok"))
    assert r.outcome == "ok" and r.hops[0].address == "127.77.0.1"


def test_json_is_stored_only_when_accepted(harness):
    r = fetch(harness, site(harness, "/json"), accept=["application/json"])
    assert r.body.data == b'{"a": 1}'
    r2 = fetch(harness, site(harness, "/json"))
    assert r2.outcome == "ok" and r2.body is None
    assert ["Content-Type", "application/json"] in r2.hops[0].headers


def test_only_get_and_head_are_ever_sent(harness):
    fetch(harness, site(harness, "/ok"), method="HEAD")
    with pytest.raises(ValueError):
        fetch(harness, site(harness, "/ok"), method="POST")
    assert {"GET", "HEAD"} == ALLOWED_METHODS
    assert harness.recorder.methods() <= {"GET", "HEAD"}


def test_requests_carry_no_cookies_or_credentials(harness):
    fetch(harness, site(harness, "/ok"))
    for _, _, headers in harness.recorder.requests:
        lowered = {k.lower() for k in headers}
        assert not lowered & {"cookie", "authorization", "proxy-authorization"}


def test_unreachable_site_is_a_transient_connect_error(harness):
    r = fetch(harness, f"http://dead.harness.test:{harness.dead_port}/")
    assert r.outcome == "connect_error" and r.transient
    assert r.hops[0].error["kind"] == "connect_error"


def test_intermittent_site_reports_then_succeeds(harness):
    url = site(harness, "/flaky?fail=1")
    first = fetch(harness, url)
    assert first.outcome == "protocol_error" and first.transient
    assert fetch(harness, url).outcome == "ok"


@pytest.mark.parametrize("host", ["garbage", "hugeheader"])
def test_malformed_responses_are_protocol_errors(harness, host):
    port = getattr(harness, "garbage" if host == "garbage" else "huge_header").port
    r = fetch(harness, f"http://{host}.harness.test:{port}/")
    assert r.outcome == "protocol_error" and r.body is None


def test_http_error_status_is_a_successful_observation(harness):
    r = fetch(harness, site(harness, "/status/503"))
    assert r.outcome == "ok" and r.hops[0].status == 503 and not r.transient


def test_dns_failures_are_reported(harness):
    r = fetch(harness, "http://nope.harness.test/")
    assert r.outcome == "dns_error" and r.error["kind"] == "dns_nxdomain" and not r.transient
    r = fetch(harness, "http://servfail.harness.test/")
    assert r.outcome == "dns_error" and r.error["kind"] == "dns_servfail" and r.transient
    r = fetch(harness, "http://timeout.harness.test/")
    assert r.outcome == "dns_error" and r.error["kind"] == "dns_timeout" and r.transient


def test_lab_mode_refuses_until_the_lab_transport_exists():
    guard = NetGuard(
        NetSettings(lab=LabSettings(enabled=True, hosts={"x.lab": "172.31.250.9"})),
        StaticResolver({}),
    )
    r = asyncio.run(Fetcher(FetchSettings(), guard).fetch("http://x.lab/"))
    assert r.outcome == "lab_transport_unavailable" and r.hops == []


def _ipv6_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback")
def test_ipv6_target_connects_to_the_pinned_address(harness):
    import ipaddress
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class V6(HTTPServer):
        address_family = socket.AF_INET6

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"v6")

        def log_message(self, *a):
            pass

    srv = V6(("::1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        guard = NetGuard(
            NetSettings(),
            StaticResolver({"v6.test": ["::1"]}),
            test_networks=[ipaddress.ip_network("::1/128")],
            allowed_ports=[port],
        )
        f = Fetcher(FetchSettings(total_timeout_seconds=5), guard)
        r = asyncio.run(f.fetch(f"http://v6.test:{port}/", accept=["text/plain"]))
        assert r.outcome == "ok" and r.hops[0].address == "::1" and r.body.data == b"v6"
        r2 = asyncio.run(f.fetch(f"http://[::1]:{port}/", accept=["text/plain"]))
        assert r2.outcome == "ok" and r2.final_url == f"http://[::1]:{port}/"
    finally:
        srv.shutdown()
