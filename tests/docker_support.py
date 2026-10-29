"""Helpers for tests that need the rootless sandbox runtime (marker `docker`).

Tests use instance `test`, so they never touch containers of a real instance.
The runtime is the default rootless endpoint of the account running pytest;
if the preflight runtime checks fail, the tests are skipped (and reported as
skipped, never as passed).
"""

import asyncio
import json
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from brandsentinel.config import SandboxLimits, SandboxSettings
from brandsentinel.sandbox import preflight
from brandsentinel.sandbox.runner import DockerCli, SandboxRunner, SandboxSpec

REPO = Path(__file__).parents[1]
PROBE = (Path(__file__).parent / "probe.py").read_text()
INSTANCE = "test"
PROXY_IP = "172.31.251.2"
LAB_WEB_IP = "172.31.250.10"
LAB_PROXY_IP = "172.31.250.2"  # bs-lab-proxy on bs_lab (the host's lab transport)
LAB_SANDBOX_PROXY_IP = "172.31.254.2"


@dataclass(frozen=True)
class SandboxNet:
    """One sandbox network and its proxy, as a sandbox sees them. The isolation
    suites run once per network: production (bs_sandbox) and lab (bs_lab_sandbox)."""

    name: str
    proxy_ip: str
    proxy_container: str
    gateway: str  # reserved only (inhibit_ipv4): no container or namespace holds it
    proxy_networks: frozenset[str]
    compose_file: str
    compose_args: tuple[str, ...] = ()

    @property
    def settings(self) -> dict:
        return {
            "network": self.name,
            "proxy_url": f"http://{self.proxy_ip}:3128",
            "proxy_container": self.proxy_container,
        }

    def up(self, docker: "DockerCli") -> None:
        compose(docker, self.compose_file, *self.compose_args, "up", "-d")
        wait_running(docker, self.proxy_container)


PRODUCTION_NET = SandboxNet(
    "bs_sandbox", PROXY_IP, "bs-egress-proxy", "172.31.251.1",
    frozenset({"bs_sandbox", "bs_egress"}), "compose.yaml", ("--profile", "sandbox"),
)  # fmt: skip
LAB_SANDBOX_NET = SandboxNet(
    "bs_lab_sandbox", LAB_SANDBOX_PROXY_IP, "bs-lab-sandbox-proxy", "172.31.254.1",
    frozenset({"bs_lab_sandbox", "bs_lab"}), "lab.compose.yaml",
)  # fmt: skip
SANDBOX_NETS = (PRODUCTION_NET, LAB_SANDBOX_NET)


def runtime_or_skip() -> DockerCli:
    docker = DockerCli()
    report = asyncio.run(preflight.check_runtime(docker, SandboxSettings()))
    if not report.ok:
        pytest.skip("rootless sandbox runtime unavailable: " + "; ".join(report.reasons()))
    return docker


def make_runner(
    docker: DockerCli, networks=(), *, net: SandboxNet = PRODUCTION_NET, **limits
) -> SandboxRunner:
    """A test-instance runner whose own sandbox network (exclusive lease,
    untrusted-member checks) is `net`."""
    return SandboxRunner(net_settings(net, **limits), docker, networks=networks)


def net_settings(net: SandboxNet = PRODUCTION_NET, **limits) -> SandboxSettings:
    return SandboxSettings(
        instance=INSTANCE,
        limits=SandboxLimits(**{"wall_seconds": 60, **limits}),
        **net.settings,
    )


def job_id(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def probe(runner: SandboxRunner, network: str, checks: list[dict]) -> dict:
    spec = SandboxSpec(role="probe", command=("python3", "-c", PROBE), network=network)
    result = asyncio.run(
        runner.run(spec, job=job_id("probe"), attempt=0, stdin=json.dumps(checks).encode())
    )
    assert result.status == "ok", result.summary() | {"stderr": result.stderr[-2000:]}
    return result.output


def docker_json(docker: DockerCli, *args: str):
    r = docker.call_sync(*args)
    assert r.ok, r.stderr
    return json.loads(r.stdout)


def labelled(docker: DockerCli, instance: str = INSTANCE) -> list[str]:
    r = docker.call_sync(
        "ps",
        "--all",
        "--format",
        "{{.Names}}",
        "--filter",
        f"label=brandsentinel.instance={instance}",
    )
    assert r.ok, r.stderr
    return [n for n in r.stdout.split() if n]


def compose(docker: DockerCli, file: str, *args: str, timeout: float = 300) -> None:
    cmd = docker.argv("compose", "-f", str(REPO / "docker" / file), *args)
    r = subprocess.run(  # noqa: S603 - fixed argv
        cmd, capture_output=True, text=True, timeout=timeout, env=docker.env(), check=False
    )
    assert r.returncode == 0, r.stderr[-3000:]


def wait_running(docker: DockerCli, name: str, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = docker.call_sync("container", "inspect", "--format", "{{.State.Running}}", name)
        if r.ok and r.stdout.strip() == "true":
            return
        time.sleep(0.5)
    raise AssertionError(f"{name} is not running")


LISTENER = """
import socket, sys, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(64)
s.settimeout(1)
deadline = time.time() + float(sys.argv[2])
while time.time() < deadline:
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        pass
"""


class namespace_listener:
    """A deliberately careless service: a TCP listener on every address (`::`,
    dual-stack) inside the account's rootless network namespace, as a future
    service bound to all addresses would be. Tests use it to prove what sandboxes
    can and cannot reach."""

    def __init__(self, docker: DockerCli, port: int = 18765, seconds: float = 120) -> None:
        from brandsentinel.sandbox.netns import RootlessNamespace

        self.ns = RootlessNamespace.for_endpoint(docker.host)
        self.port, self.seconds = port, seconds

    def __enter__(self) -> int:
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [
                *self.ns.nsenter_prefix(),
                sys.executable,
                "-c",
                LISTENER,
                str(self.port),
                str(self.seconds),
            ]
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if any(li.port == self.port for li in self.ns.listeners()):
                return self.port
            time.sleep(0.1)
        self.proc.kill()
        raise RuntimeError("namespace listener did not start")

    def __exit__(self, *exc) -> None:
        self.proc.kill()
        self.proc.wait()
