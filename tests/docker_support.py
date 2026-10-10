"""Helpers for tests that need the rootless sandbox runtime (marker `docker`).

Tests use instance `test`, so they never touch containers of a real instance.
The runtime is the default rootless endpoint of the account running pytest;
if the preflight runtime checks fail, the tests are skipped (and reported as
skipped, never as passed).
"""

import asyncio
import json
import subprocess
import time
import uuid
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


def runtime_or_skip() -> DockerCli:
    docker = DockerCli()
    report = asyncio.run(preflight.check_runtime(docker, SandboxSettings()))
    if not report.ok:
        pytest.skip("rootless sandbox runtime unavailable: " + "; ".join(report.reasons()))
    return docker


def make_runner(docker: DockerCli, networks=(), **limits) -> SandboxRunner:
    settings = SandboxSettings(
        instance=INSTANCE, limits=SandboxLimits(**{"wall_seconds": 60, **limits})
    )
    return SandboxRunner(settings, docker, networks=networks)


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
