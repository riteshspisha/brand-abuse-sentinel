"""The controlled lab on the real rootless runtime (U11, U18, KTD13).

Proves every lab site answers as its expected.yaml says from inside bs_lab, that
the host reaches the lab only through the lab proxy (and nothing else through
it), and that production sandboxes cannot reach the lab at all. The lab project
(docker/lab.compose.yaml) and the sandbox stack are brought up if needed.
"""

import asyncio
from pathlib import Path

import pytest
import yaml
from tests.docker_support import (
    LAB_WEB_IP,
    PROXY_IP,
    REPO,
    compose,
    docker_json,
    make_runner,
    probe,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import load_config
from brandsentinel.net.fetcher import Fetcher
from brandsentinel.pipeline.stages import build_network
from brandsentinel.sandbox import preflight

pytestmark = [pytest.mark.lab, pytest.mark.docker, pytest.mark.security]

SITES = [yaml.safe_load(p.read_text()) for p in sorted((REPO / "labsites").glob("*/expected.yaml"))]
FETCHER_UA = "BrandSentinel/0.1 (brand-protection research)"


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    compose(d, "compose.yaml", "--profile", "sandbox", "up", "-d")
    for name in ("bs-lab-web", "bs-lab-proxy", "bs-egress-proxy"):
        wait_running(d, name)
    return d


@pytest.fixture(scope="module")
def lab_runner(docker):
    return make_runner(docker, networks=["bs_lab"])


def http_check(cid, host, path="/", ua=FETCHER_UA, method="GET"):
    return {
        "id": cid,
        "kind": "http",
        "host": LAB_WEB_IP,
        "port": 80,
        "target": path,
        "host_header": host,
        "user_agent": ua,
        "method": method,
    }


def test_every_lab_site_answers_with_its_expected_status(lab_runner):
    checks = [http_check(s["site"], s["hostname"]) for s in SITES]
    for s in SITES:
        for p in s.get("paths", []):
            checks.append(http_check(f"{s['site']}{p['path']}", s["hostname"], p["path"]))
    results = probe(lab_runner, "bs_lab", checks)
    for s in SITES:
        assert results[s["site"]] == f"status:{s['http_status']}", (s["site"], results)
        for p in s.get("paths", []):
            assert results[f"{s['site']}{p['path']}"] == f"status:{p['status']}"


def test_unknown_hosts_get_404_and_the_lab_accepts_no_submissions(lab_runner):
    results = probe(
        lab_runner,
        "bs_lab",
        [
            http_check("unknown", "example.com"),
            http_check("post", "donate-luminafoundation.test", "/", method="POST"),
        ],
    )
    assert results == {"unknown": "status:404", "post": "status:405"}


def test_cloaking_site_serves_different_bodies_by_user_agent(lab_runner):
    site = next(s for s in SITES if s["site"] == "cloaking")
    checks = [
        {
            "id": ua,
            "kind": "body",
            "host": LAB_WEB_IP,
            "port": 80,
            "target": "/",
            "host_header": site["hostname"],
            "user_agent": ua,
        }
        for ua in site["user_agents"]
    ]
    results = probe(lab_runner, "bs_lab", checks)
    for ua, marker in site["user_agents"].items():
        assert marker in results[ua]
    assert len(set(results.values())) == 2


def lab_fetcher() -> Fetcher:
    config = load_config(REPO / "config" / "lab.yaml")
    _, fetcher = build_network(config)
    return fetcher


def test_host_fetcher_reaches_lab_pages_through_the_lab_proxy(docker):
    r = asyncio.run(lab_fetcher().fetch("http://donate-luminafoundation.test/"))
    assert r.outcome == "ok" and r.status == 200
    assert b"rivers.relief.fund@quickpaybank" in r.body.data
    assert r.hops[0].via == "http://127.0.0.1:3129" and r.hops[0].address == LAB_WEB_IP


def test_host_fetcher_refuses_public_urls_in_lab_mode(docker):
    r = asyncio.run(lab_fetcher().fetch("http://example.com/"))
    assert r.outcome == "blocked" and r.error["kind"] == "not_lab_host" and r.hops == []


def test_lab_redirects_to_metadata_and_loopback_are_blocked(docker):
    fetcher = lab_fetcher()
    for path in ("/to-metadata", "/to-loopback"):
        r = asyncio.run(fetcher.fetch(f"http://go-luminafoundation.test{path}"))
        assert r.outcome == "blocked_redirect", (path, r.error)


def test_lab_proxy_serves_only_lab_hostnames(docker):
    async def connect(authority: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", 3129)
        writer.write(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        writer.close()
        return head

    assert asyncio.run(connect("donate-luminafoundation.test:80")).startswith(b"HTTP/1.1 200")
    for authority in (
        "example.com:443",
        "127.0.0.1:3128",
        "169.254.169.254:80",
        f"{LAB_WEB_IP}:80",
    ):
        assert asyncio.run(connect(authority)).startswith(b"HTTP/1.1 403"), authority


def test_the_host_has_no_direct_route_to_the_lab(docker):
    async def reach() -> str:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(LAB_WEB_IP, 80), 3)
        except (OSError, TimeoutError) as e:
            return type(e).__name__
        w.close()
        return "connected"

    assert asyncio.run(reach()) != "connected"


def test_production_sandboxes_cannot_reach_the_lab(docker):
    via = {"proxy_host": PROXY_IP, "proxy_port": 3128}
    results = probe(
        make_runner(docker),
        "bs_sandbox",
        [
            {"id": "direct", "kind": "tcp", "host": LAB_WEB_IP, "port": 80},
            {"id": "proxy ip", "kind": "connect", "authority": f"{LAB_WEB_IP}:80", **via},
            {
                "id": "proxy name",
                "kind": "connect",
                "authority": "donate-luminafoundation.test:80",
                **via,
            },
        ],
    )
    assert results["direct"] != "connected"
    assert results["proxy ip"] == "status:403"
    assert results["proxy name"] in ("status:403", "status:502")  # not a lab host here


def test_lab_containers_are_hardened(docker):
    web = docker_json(docker, "container", "inspect", "bs-lab-web")[0]
    proxy = docker_json(docker, "container", "inspect", "bs-lab-proxy")[0]
    assert preflight.proxy_hardening_problems(proxy) == []
    host = web["HostConfig"]
    assert host["ReadonlyRootfs"] and "ALL" in host["CapDrop"] and host["Memory"]
    assert set(web["NetworkSettings"]["Networks"]) == {"bs_lab"}
    assert all(not m["RW"] for m in web["Mounts"] + proxy["Mounts"])
    bindings = proxy["HostConfig"]["PortBindings"]["3128/tcp"]
    assert bindings == [{"HostIp": "127.0.0.1", "HostPort": "3129"}]


def test_lab_network_is_internal_with_the_pinned_subnet(docker):
    net = docker_json(docker, "network", "inspect", "bs_lab")[0]
    assert net["Internal"] is True
    assert net["IPAM"]["Config"][0]["Subnet"] == "172.31.250.0/24"


def test_expected_files_cover_every_site():
    dirs = {p.name for p in (REPO / "labsites").iterdir() if p.is_dir()}
    assert dirs == {s["site"] for s in SITES}
    assert all(Path(REPO, "labsites", s["site"]).is_dir() for s in SITES)
