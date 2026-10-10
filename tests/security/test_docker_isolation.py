"""Sandbox network isolation on the real rootless runtime (U18, R41, AE11).

A probe container on bs_sandbox tries every way out that does not go through
the egress proxy: direct TCP to public addresses (IPv4 and IPv6), UDP to a STUN
server, DNS to a public resolver and through the container's default resolver,
TCP to the Docker gateway and the rootless host address, and the metadata
address. Then it asks the proxy for blocked destinations. A positive control
runs the same probe on an ordinary network and must see the leaks, so a pass
here cannot come from a broken probe or a missing Internet connection.

The stack (bs_sandbox, bs_egress, egress-proxy) is brought up with
`docker compose --profile sandbox up -d` if it is not running.
"""

import asyncio
import ipaddress
import json
import time

import pytest
from tests.docker_support import (
    PROXY_IP,
    compose,
    docker_json,
    labelled,
    make_runner,
    probe,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import SandboxSettings
from brandsentinel.sandbox import preflight

pytestmark = [pytest.mark.docker, pytest.mark.security]

PUBLIC_V4 = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 80)]
PUBLIC_V6 = [("2606:4700:4700::1111", 443), ("2001:4860:4860::8888", 53)]
STUN = ("74.125.250.129", 19302)  # stun.l.google.com
ROOTLESS_HOST = "10.0.2.2"  # slirp4netns' address for the host
GATEWAY_PORTS = [22, 53, 80, 443, 2375, 2376, 3128, 8080]
TEST_NET = "bs_isolation_control"


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "compose.yaml", "--profile", "sandbox", "up", "-d")
    wait_running(d, "bs-egress-proxy")
    yield d
    assert labelled(d) == []


@pytest.fixture(scope="module")
def gateway(docker) -> str:
    net = docker_json(docker, "network", "inspect", "bs_sandbox")[0]
    return net["IPAM"]["Config"][0]["Gateway"]


def escape_checks(gateway: str) -> list[dict]:
    checks = [{"id": f"tcp {h}:{p}", "kind": "tcp", "host": h, "port": p} for h, p in PUBLIC_V4]
    checks += [{"id": f"tcp6 {h}:{p}", "kind": "tcp", "host": h, "port": p} for h, p in PUBLIC_V6]
    checks += [
        {"id": "udp stun", "kind": "udp_stun", "host": STUN[0], "port": STUN[1]},
        {"id": "udp dns 8.8.8.8", "kind": "udp_dns", "host": "8.8.8.8"},
        {"id": "udp dns 1.1.1.1", "kind": "udp_dns", "host": "1.1.1.1"},
        {"id": "resolve default", "kind": "resolve", "name": "example.com"},
        {"id": "tcp metadata", "kind": "tcp", "host": "169.254.169.254", "port": 80},
        {"id": "tcp rootless host", "kind": "tcp", "host": ROOTLESS_HOST, "port": 22},
    ]
    checks += [
        {"id": f"tcp gateway:{p}", "kind": "tcp", "host": gateway, "port": p} for p in GATEWAY_PORTS
    ]
    return checks


def test_no_direct_route_out_of_the_sandbox_network(docker, gateway):
    # Covers AE11: direct IP, IPv6, UDP STUN, DNS, gateway and host addresses.
    runner = make_runner(docker)
    results = probe(runner, "bs_sandbox", escape_checks(gateway))
    leaks = {k: v for k, v in results.items() if v in ("connected", "answered")}
    leaks |= {k: v for k, v in results.items() if str(v).startswith("resolved:")}
    assert leaks == {}, results


def test_positive_control_the_probe_sees_leaks_on_an_ordinary_network(docker, gateway):
    docker.call_sync("network", "rm", TEST_NET)
    created = docker.call_sync("network", "create", TEST_NET)
    assert created.ok, created.stderr
    try:
        runner = make_runner(docker, networks=[TEST_NET])
        results = probe(runner, TEST_NET, escape_checks(gateway))
    finally:
        docker.call_sync("network", "rm", TEST_NET)
    # Each kind of escape the sandbox test relies on is detectable when a route exists.
    assert "connected" in {results["tcp 1.1.1.1:443"], results["tcp 9.9.9.9:80"]}, results
    assert "answered" in {results["udp stun"], results["udp dns 8.8.8.8"]}, results
    assert results["resolve default"].startswith("resolved:"), results


def proxy_checks() -> list[dict]:
    via = {"proxy_host": PROXY_IP, "proxy_port": 3128}
    return [
        {"id": "connect metadata", "kind": "connect", "authority": "169.254.169.254:80", **via},
        {"id": "connect private", "kind": "connect", "authority": "10.0.0.1:443", **via},
        {"id": "connect loopback", "kind": "connect", "authority": "127.0.0.1:3128", **via},
        {"id": "connect proxy self", "kind": "connect", "authority": f"{PROXY_IP}:3128", **via},
        {"id": "connect v6 loopback", "kind": "connect", "authority": "[::1]:443", **via},
        {"id": "connect mapped", "kind": "connect", "authority": "[::ffff:10.0.0.1]:443", **via},
        {"id": "connect port 22", "kind": "connect", "authority": "example.com:22", **via},
        {"id": "connect public 443", "kind": "connect", "authority": "example.com:443", **via},
        {"id": "connect public 80", "kind": "connect", "authority": "example.com:80", **via},
        {
            "id": "get metadata",
            "kind": "http",
            "host": PROXY_IP,
            "port": 3128,
            "target": "http://169.254.169.254/latest/meta-data/",
            "host_header": "169.254.169.254",
        },
        {
            "id": "get host mismatch",
            "kind": "http",
            "host": PROXY_IP,
            "port": 3128,
            "target": "http://example.com/",
            "host_header": "internal.example",
        },
        {
            "id": "get public",
            "kind": "http",
            "host": PROXY_IP,
            "port": 3128,
            "target": "http://example.com/",
            "host_header": "example.com",
        },
    ]


def test_proxy_refuses_blocked_destinations_and_allows_public_ones(docker):
    results = probe(make_runner(docker), "bs_sandbox", proxy_checks())
    for refused in (
        "connect metadata",
        "connect private",
        "connect loopback",
        "connect proxy self",
        "connect v6 loopback",
        "connect mapped",
        "connect port 22",
        "get metadata",
    ):
        assert results[refused] == "status:403", (refused, results)
    assert results["get host mismatch"] == "status:400"
    assert results["connect public 443"] == "status:200", results
    assert results["connect public 80"] == "status:200", results
    assert results["get public"].startswith("status:"), results


def test_proxy_decisions_are_logged_with_the_validated_address(docker):
    since = docker_json(docker, "container", "inspect", "bs-egress-proxy")[0]["State"]["StartedAt"]
    probe(
        make_runner(docker),
        "bs_sandbox",
        [
            {
                "id": "c",
                "kind": "connect",
                "authority": "example.com:443",
                "proxy_host": PROXY_IP,
                "proxy_port": 3128,
            }
        ],
    )
    # A decision is logged when its connection ends; a half-closed tunnel ends at
    # the proxy's idle timeout (30 s), so wait for it.
    deadline = time.monotonic() + 60
    allowed = []
    while not allowed and time.monotonic() < deadline:
        logs = docker.call_sync("logs", "--since", since, "bs-egress-proxy")
        records = [json.loads(line) for line in logs.stderr.splitlines() if line.startswith("{")]
        allowed = [
            r
            for r in records
            if r.get("host") == "example.com" and r["decision"] == "allow" and r["port"] == 443
        ]
        if not allowed:
            time.sleep(2)
    assert allowed and ipaddress.ip_address(allowed[-1]["address"]).is_global


def test_proxy_container_is_hardened(docker):
    inspect = docker_json(docker, "container", "inspect", "bs-egress-proxy")[0]
    assert preflight.proxy_hardening_problems(inspect) == []
    networks = set(inspect["NetworkSettings"]["Networks"])
    assert networks == {"bs_sandbox", "bs_egress"}
    assert inspect["HostConfig"]["PortBindings"] in ({}, None)


def test_network_preflight_passes_with_the_direct_egress_probe(docker):
    settings = SandboxSettings(instance="test")
    runner = make_runner(docker)
    report = asyncio.run(preflight.check_network(docker, settings, runner))
    assert report.ok, report.reasons()
    assert any(c.name == "direct_egress_blocked" and c.ok for c in report.checks)


def test_network_preflight_fails_for_a_sandbox_network_without_internal(docker):
    docker.call_sync("network", "rm", TEST_NET)
    assert docker.call_sync("network", "create", TEST_NET).ok
    try:
        settings = SandboxSettings(instance="test")
        runner = make_runner(docker, networks=[TEST_NET])
        report = asyncio.run(preflight.check_network(docker, settings, runner, network=TEST_NET))
    finally:
        docker.call_sync("network", "rm", TEST_NET)
    names = {c.name for c in report.failures}
    assert "network_internal" in names and "proxy_attached" in names


def test_direct_egress_probe_detects_a_leaking_network(docker):
    docker.call_sync("network", "rm", TEST_NET)
    assert docker.call_sync("network", "create", TEST_NET).ok
    try:
        runner = make_runner(docker, networks=[TEST_NET])
        check = asyncio.run(preflight._egress_probe(runner, TEST_NET))
    finally:
        docker.call_sync("network", "rm", TEST_NET)
    assert not check.ok and "direct egress possible" in check.detail
