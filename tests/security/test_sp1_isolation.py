"""SP1 on the real rootless runtime of the account running pytest: no gateway
from the sandbox network into the rootless namespace, the proxy still reachable,
no IPv6 on the sandbox interface, and one untrusted container per network.

The tests taking `sandbox_net` run for production `bs_sandbox` and for the
lab-mode `bs_lab_sandbox` (M7), which is built the same way.

Run under the dedicated service account for SP1 acceptance
(scripts/service-account/validate.sh); under a developer account they prove the
same controls on that account's runtime.
"""

import asyncio
import json
from pathlib import Path

import pytest
from tests.docker_support import (
    INSTANCE,
    SANDBOX_NETS,
    SandboxNet,
    compose,
    docker_json,
    job_id,
    make_runner,
    namespace_listener,
    net_settings,
    probe,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import SandboxSettings
from brandsentinel.sandbox import preflight
from brandsentinel.sandbox.netns import RootlessNamespace, is_loopback
from brandsentinel.sandbox.runner import SandboxNetworkBusy, SandboxSpec

pytestmark = [pytest.mark.docker, pytest.mark.security]

CONTROL_NET = "bs_sp1_control"
CONTROL_SUBNET = "172.31.249.0/24"
CONTROL_GATEWAY = "172.31.249.1"
IMAGE = "brandsentinel-sandbox:local"


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "compose.yaml", "--profile", "sandbox", "up", "-d")
    wait_running(d, "bs-egress-proxy")
    return d


@pytest.fixture(scope="module", params=SANDBOX_NETS, ids=lambda n: n.name)
def sandbox_net(request, docker) -> SandboxNet:
    request.param.up(docker)
    return request.param


@pytest.fixture
def control_network(docker):
    """An ordinary internal network (with a gateway): the positive control."""
    docker.call_sync("network", "rm", CONTROL_NET)
    created = docker.call_sync(
        "network", "create", "--internal", "--subnet", CONTROL_SUBNET,
        "--label", "brandsentinel.test=sp1", CONTROL_NET,
    )  # fmt: skip
    assert created.ok, created.stderr
    yield CONTROL_NET
    docker.call_sync("network", "rm", CONTROL_NET)


def test_sandbox_network_declares_inhibit_ipv4_and_holds_no_gateway(docker, sandbox_net):
    net = docker_json(docker, "network", "inspect", sandbox_net.name)[0]
    assert net["Internal"] is True and net["EnableIPv6"] is False
    assert net["Options"].get(preflight.INHIBIT_IPV4) == "true"
    assert net["IPAM"]["Config"][0]["Gateway"] == sandbox_net.gateway  # reserved only
    prefix = sandbox_net.gateway.rsplit(".", 1)[0] + "."
    local = RootlessNamespace.for_endpoint(docker.host).local_ipv4()
    assert not [a for a in local if a.startswith(prefix)], local


def test_namespace_listener_unreachable_from_sandbox_but_reachable_on_control(
    docker, sandbox_net, control_network
):
    ns = RootlessNamespace.for_endpoint(docker.host)
    targets = sorted(a for a in ns.local_ipv4() if not is_loopback(a))
    with namespace_listener(docker) as port:
        checks = [
            {"id": f"tcp {a}:{port}", "kind": "tcp", "host": a, "port": port}
            for a in [*targets, sandbox_net.gateway]
        ]
        sandbox = probe(make_runner(docker, net=sandbox_net), sandbox_net.name, checks)
        control = probe(
            make_runner(docker, networks=[control_network]),
            control_network,
            [{"id": "gateway", "kind": "tcp", "host": CONTROL_GATEWAY, "port": port}],
        )
        # Defense in depth notices the careless listener too.
        report = asyncio.run(
            preflight.check_network(
                docker,
                net_settings(sandbox_net),
                make_runner(docker, net=sandbox_net),
                probe=False,
            )
        )
    assert "connected" not in sandbox.values(), sandbox
    assert control == {"gateway": "connected"}, control  # the listener and probe work
    failed = {c.name for c in report.failures}
    assert "rootless_listeners" in failed and "gateway_inhibited" not in failed


def test_proxy_reachable_while_direct_egress_and_namespace_are_not(docker, sandbox_net):
    via = {"proxy_host": sandbox_net.proxy_ip, "proxy_port": 3128}
    results = probe(
        make_runner(docker, net=sandbox_net),
        sandbox_net.name,
        [
            {"id": "proxy tcp", "kind": "tcp", "host": sandbox_net.proxy_ip, "port": 3128},
            {"id": "proxy refuses metadata", "kind": "connect",
             "authority": "169.254.169.254:80", **via},
            {"id": "direct 1.1.1.1", "kind": "tcp", "host": "1.1.1.1", "port": 443},
            {"id": "rootless host", "kind": "tcp", "host": "10.0.2.2", "port": 22},
            {"id": "slirp address", "kind": "tcp", "host": "10.0.2.100", "port": 22},
            {"id": "ipv6", "kind": "ipv6"},
        ],
    )  # fmt: skip
    assert results["proxy tcp"] == "connected"
    assert results["proxy refuses metadata"] == "status:403"
    for k in ("direct 1.1.1.1", "rootless host", "slirp address"):
        assert results[k] != "connected", results
    assert all(iface == "lo" for iface, _ in results["ipv6"]), results["ipv6"]


def test_every_tcp_port_of_every_namespace_address_is_closed_to_sandboxes(docker, sandbox_net):
    ns = RootlessNamespace.for_endpoint(docker.host)
    targets = sorted(a for a in ns.local_ipv4() if not is_loopback(a))
    # Every address the namespace holds. The reserved gateway address is held by
    # nothing (test_sandbox_network_declares_...), so it has no ports to scan.
    checks = [{"id": a, "kind": "scan", "host": a, "start": 1, "end": 65535} for a in targets]
    runner = make_runner(docker, net=sandbox_net, wall_seconds=300)
    results = probe(runner, sandbox_net.name, checks)
    assert all(v == [] for v in results.values()), results


def _start_extra(docker, name: str, network: str = "bs_sandbox") -> None:
    started = docker.call_sync(
        "run", "--detach", "--rm", "--name", name, "--network", network,
        "--label", "brandsentinel.test=sp1", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--entrypoint", "sleep", IMAGE, "120",
    )  # fmt: skip
    assert started.ok, started.stderr


@pytest.mark.parametrize("name", ["bs-sp1-manual-launch", "bs-other-probe-orphan-0"])
def test_a_second_untrusted_container_blocks_jobs_on_the_sandbox_network(docker, sandbox_net, name):
    # A container started by hand, or a job orphaned by another instance (which
    # this instance's sweep does not remove), makes the run refuse.
    runner = make_runner(docker, net=sandbox_net)
    spec = SandboxSpec(role="probe", command=("python3", "-c", "print('{}')"),
                       network=sandbox_net.name)  # fmt: skip
    _start_extra(docker, name, sandbox_net.name)
    try:
        with pytest.raises(SandboxNetworkBusy, match=name):
            asyncio.run(runner.run(spec, job=job_id(), attempt=0))
        report = asyncio.run(
            preflight.check_network(docker, net_settings(sandbox_net), runner, probe=False)
        )
        # The preflight cannot tell one orphaned job from a running one: an orphaned
        # job leaves the structural membership checks healthy, a container that is
        # not a job does not. The isolation guarantee is the runner's refusal above.
        status = {c.name: c.ok for c in report.checks}
        orphan = name.startswith("bs-other-")
        assert status["network_members"] is orphan, report.reasons()
        assert status["single_untrusted_container"] is True, report.reasons()
    finally:
        docker.call_sync("rm", "--force", name)
    ok = asyncio.run(runner.run(spec, job=job_id(), attempt=0))
    assert ok.status == "ok" and ok.output == {}


def test_media_style_jobs_have_no_network_at_all(docker):
    results = probe(make_runner(docker), "none", [{"id": "facts", "kind": "facts"},
                                                  {"id": "ipv6", "kind": "ipv6"}])  # fmt: skip
    assert results["facts"]["interfaces"] == ["lo"]
    assert json.dumps(results["ipv6"]).count("eth") == 0


# --- the examined namespace is the bridge namespace (SP1 acceptance, 2026-10-11) -----


def test_examined_namespace_contains_the_sandbox_bridge_and_is_not_the_host(docker):
    import os

    ns = RootlessNamespace.for_endpoint(docker.host)
    net = docker_json(docker, "network", "inspect", "bs_sandbox")[0]
    assert ns.inode != os.stat("/proc/self/ns/net").st_ino
    interfaces = ns.interfaces()
    assert preflight.bridge_name(net) in interfaces, (ns.describe(), interfaces)
    from brandsentinel.sandbox.netns import parse_interfaces

    host_only = parse_interfaces(Path("/proc/self/net/dev").read_text()) - {"lo", "docker0"}
    host_only = {i for i in host_only if not i.startswith(("br-", "veth"))}
    assert not host_only & interfaces, host_only & interfaces


def test_reading_through_nsenter_agrees_with_reading_directly(docker):
    # The service account reads through nsenter (its child sits outside the bridge
    # namespace); prove that path sees the same namespace here.
    from dataclasses import replace

    ns = RootlessNamespace.for_endpoint(docker.host)
    via_nsenter = replace(ns, direct=False)
    assert via_nsenter.interfaces() == ns.interfaces()
    assert via_nsenter.local_ipv4() == ns.local_ipv4()


def test_exposed_listener_in_bridge_namespace_is_detected_host_listener_is_not(docker):
    import socket

    ns = RootlessNamespace.for_endpoint(docker.host)
    settings = SandboxSettings(instance=INSTANCE)
    host_sock = socket.socket()  # negative control: a host-only listener on all addresses
    host_sock.bind((".".join(["0"] * 4), 0))
    host_sock.listen(1)
    host_port = host_sock.getsockname()[1]
    try:
        clean = asyncio.run(
            preflight.check_network(docker, settings, make_runner(docker), probe=False)
        )
        assert {c.name: c.ok for c in clean.checks}["rootless_listeners"], clean.reasons()
        assert host_port not in {li.port for li in ns.exposed_listeners()}
        with namespace_listener(docker, port=18766) as port:  # positive control
            exposed = {li.port for li in ns.exposed_listeners()}
            dirty = asyncio.run(
                preflight.check_network(docker, settings, make_runner(docker), probe=False)
            )
        assert port in exposed and host_port not in exposed
        failed = {c.name: c.detail for c in dirty.failures}
        assert f":{port}" in failed["rootless_listeners"]
        assert str(host_port) not in failed["rootless_listeners"]
    finally:
        host_sock.close()
