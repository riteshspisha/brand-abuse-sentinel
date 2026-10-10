"""Lab-mode fetch transport (U18, KTD13): the host fetcher reaches lab sites only
through the lab proxy, and refuses everything that is not a lab hostname.

The fetcher and a lab-only proxy run in-process; the proxy's dial to the lab
address is redirected to the harness HTTP server (the lab network itself exists
only inside the rootless runtime, see tests/lab/).
"""

import asyncio

import pytest
from tests.security.test_proxy import LAB_HOST, LAB_IP, redirecting_connector

from brandsentinel.config import FetchSettings, LabSettings, NetSettings, ProxySettings
from brandsentinel.net.fetcher import Fetcher
from brandsentinel.net.netguard import NetGuard, StaticResolver
from brandsentinel.net.proxy import EgressProxy

pytestmark = pytest.mark.security


def lab_guard() -> NetGuard:
    return NetGuard(
        NetSettings(lab=LabSettings(enabled=True, hosts={LAB_HOST: LAB_IP})),
        StaticResolver({"public.example": ["93.184.215.14"]}),
    )


def lab_fetch(harness, url: str, calls: list, *, proxy: bool = True):
    async def main():
        egress = EgressProxy(
            ProxySettings(lab_only=True),
            lab_guard(),
            connector=redirecting_connector("127.77.0.1", harness.http.port, calls),
        )
        servers = await egress.start([("127.0.0.1", 0)])
        port = servers[0].sockets[0].getsockname()[1]
        fetcher = Fetcher(
            FetchSettings(total_timeout_seconds=10),
            lab_guard(),
            lab_proxy=f"http://127.0.0.1:{port}" if proxy else None,
        )
        try:
            return await fetcher.fetch(url)
        finally:
            for s in servers:
                s.close()

    return asyncio.run(main())


def test_lab_page_is_fetched_through_the_lab_proxy(harness, decisions):
    calls: list = []
    r = lab_fetch(harness, f"http://{LAB_HOST}/ok", calls)
    assert r.outcome == "ok" and r.status == 200
    assert b"Lumina Foundation Donate" in r.body.data
    hop = r.hops[0]
    assert hop.address == LAB_IP and hop.via.startswith("http://127.0.0.1:")
    assert calls == [(LAB_IP, 80)]  # the proxy, not the fetcher, dialled the lab
    rec = decisions.last()
    assert rec["decision"] == "allow" and rec["reason"] == "forward" and rec["lab"] is True


def test_public_url_is_refused_in_lab_mode_without_contacting_anything(harness, decisions):
    calls: list = []
    r = lab_fetch(harness, "http://public.example/", calls)
    assert r.outcome == "blocked" and r.error["kind"] == "not_lab_host"
    assert r.hops == [] and calls == [] and decisions.records == []


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/", "http://127.0.0.1/", f"http://{LAB_IP}/", "http://[::1]/"]
)
def test_private_and_lab_literals_stay_blocked_in_lab_mode(harness, url):
    calls: list = []
    r = lab_fetch(harness, url, calls)
    assert r.outcome == "blocked" and calls == []


def test_lab_redirect_to_metadata_is_refused_before_the_proxy(harness, decisions):
    calls: list = []
    r = lab_fetch(harness, f"http://{LAB_HOST}/redirect?to=http://169.254.169.254/", calls)
    assert r.outcome == "blocked_redirect" and r.error["class"] == "link_local"
    assert calls == [(LAB_IP, 80)]  # only the first hop went out


def test_lab_mode_without_a_lab_proxy_fetches_nothing(harness):
    calls: list = []
    r = lab_fetch(harness, f"http://{LAB_HOST}/ok", calls, proxy=False)
    assert r.outcome == "lab_transport_unavailable" and calls == []


@pytest.mark.parametrize(
    "url", ["http://lab-proxy:3129", "https://127.0.0.1:3129", "http://127.0.0.1"]
)
def test_lab_proxy_must_be_an_http_ip_and_port(url):
    with pytest.raises(ValueError):
        Fetcher(FetchSettings(), lab_guard(), lab_proxy=url)


def failing_connector(calls: list):
    async def connect(address: str, port: int):
        calls.append((address, port))
        raise ConnectionRefusedError("lab site down")

    return connect


def lab_fetch_with(connector, url: str):
    async def main():
        egress = EgressProxy(ProxySettings(lab_only=True), lab_guard(), connector=connector)
        servers = await egress.start([("127.0.0.1", 0)])
        port = servers[0].sockets[0].getsockname()[1]
        fetcher = Fetcher(
            FetchSettings(total_timeout_seconds=10),
            lab_guard(),
            lab_proxy=f"http://127.0.0.1:{port}",
        )
        try:
            return await fetcher.fetch(url)
        finally:
            for s in servers:
                s.close()

    return asyncio.run(main())


def test_lab_proxy_failure_is_a_transport_error_not_the_sites_answer():
    from brandsentinel.pipeline.stages import HTTP_FALLBACK

    calls: list = []
    r = lab_fetch_with(failing_connector(calls), f"http://{LAB_HOST}/")
    assert r.outcome == "connect_error" and r.status is None
    assert r.error["kind"] == "lab_proxy_refused" and r.error["status"] == 502
    assert r.outcome in HTTP_FALLBACK and calls == [(LAB_IP, 80)]


def test_https_lab_url_refused_by_the_proxy_falls_back_cleanly():
    from brandsentinel.pipeline.stages import HTTP_FALLBACK

    calls: list = []
    r = lab_fetch_with(failing_connector(calls), f"https://{LAB_HOST}/")
    assert r.outcome == "connect_error" and r.error["kind"] == "lab_proxy_refused"
    assert r.outcome in HTTP_FALLBACK  # the fetch stage then tries http://
