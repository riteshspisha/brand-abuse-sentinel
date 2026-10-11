"""SP1: one untrusted container on the shared sandbox network (runner network lease).

Against the fake Docker CLI: the lease file, contention between processes, the
membership check before create, and the post-start check. The same boundary on
real rootless Docker is in tests/security/test_sp1_isolation.py.
"""

import asyncio
import os
import stat

import pytest

from brandsentinel.config import SandboxLimits, SandboxSettings
from brandsentinel.sandbox.runner import (
    DockerCli,
    NetworkLease,
    SandboxNetworkBusy,
    SandboxRunner,
    SandboxSpec,
    lease_dir,
)

pytestmark = pytest.mark.security

NET = "bs_sandbox"


@pytest.fixture(autouse=True)
def runtime_dir(tmp_path, monkeypatch):
    d = tmp_path / "run"
    d.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(d))
    return d


def runner(fake) -> SandboxRunner:
    settings = SandboxSettings(limits=SandboxLimits(wall_seconds=10), kill_grace_seconds=5)
    return SandboxRunner(settings, DockerCli("unix:///fake.sock", str(fake.binary)))


def members(fake, *names: str) -> None:
    fake.set_network(NET, {"Name": NET, "Containers": {n: {"Name": n} for n in names}})


def spec(image="fake/echo", network=NET) -> SandboxSpec:
    return SandboxSpec(role="browser", command=("run",), image=image, network=network)


def run(r, s, job="7"):
    return asyncio.run(r.run(s, job=job, attempt=1))


def test_lease_file_is_private_and_exclusive(runtime_dir):
    first = NetworkLease(NET)
    path = lease_dir() / f"sandbox-network-{NET}.lock"
    assert lease_dir() == runtime_dir / "brandsentinel"
    assert stat.S_IMODE(os.stat(lease_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with pytest.raises(SandboxNetworkBusy, match="leased by another job"):
        NetworkLease(NET)
    first.release()
    NetworkLease(NET).release()  # released, so available again


def test_a_held_lease_refuses_the_job_without_creating_anything(fake_docker):
    members(fake_docker, "bs-egress-proxy")
    held = NetworkLease(NET)  # another process (or worker) is running a job
    try:
        with pytest.raises(SandboxNetworkBusy):
            run(runner(fake_docker), spec())
        assert not [c for c in fake_docker.calls() if c[:1] == ["create"]]
    finally:
        held.release()
    assert run(runner(fake_docker), spec()).status == "ok"


def test_lease_is_released_after_every_run(fake_docker):
    members(fake_docker, "bs-egress-proxy")
    r = runner(fake_docker)
    for job in ("1", "2"):
        assert run(r, spec(), job=job).status == "ok"
    NetworkLease(NET).release()


@pytest.mark.parametrize("other", ["bs-other-browser-3-0", "somebody-by-hand"])
def test_any_other_untrusted_member_refuses_before_create(fake_docker, other):
    members(fake_docker, "bs-egress-proxy", other)
    with pytest.raises(SandboxNetworkBusy, match=other):
        run(runner(fake_docker), spec())
    assert not [c for c in fake_docker.calls() if c[:1] == ["create"]]
    NetworkLease(NET).release()  # the refusal released the lease


def test_uninspectable_network_counts_as_busy(fake_docker):
    with pytest.raises(SandboxNetworkBusy, match="cannot inspect"):
        run(runner(fake_docker), spec())


def test_post_start_check_kills_the_job_when_another_container_joined(fake_docker, monkeypatch):
    r = runner(fake_docker)

    async def nobody(network, own=None):
        return []  # the pre-create check passed; something joined in between

    monkeypatch.setattr(r, "untrusted_members", nobody)
    members(fake_docker, "bs-egress-proxy", "bs-main-browser-7-1", "intruder")
    result = run(r, spec(image="fake/sleep"))
    assert result.status == "network_shared" and result.killed
    assert "intruder" in result.error and result.removed


def test_media_jobs_without_network_take_no_lease(fake_docker):
    held = NetworkLease(NET)
    try:
        assert run(runner(fake_docker), spec(network="none")).status == "ok"
    finally:
        held.release()
