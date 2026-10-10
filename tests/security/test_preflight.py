"""Sandbox preflight (U23, U18): every failed check keeps sandboxes disabled.

Account and runtime checks run against injected values and a fake Docker CLI.
The network check's behaviour on a real rootless runtime is in
tests/security/test_docker_isolation.py.
"""

import asyncio
import copy

import pytest

from brandsentinel.config import Config, RuntimeSettings, SandboxSettings
from brandsentinel.sandbox import preflight
from brandsentinel.sandbox.runner import DockerCli, SandboxRunner

pytestmark = pytest.mark.security

ROOTLESS_INFO = {
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
    "CgroupVersion": "2",
    "MemoryLimit": True,
    "PidsLimit": True,
    "CpuCfsQuota": True,
}


def cfg(**runtime) -> Config:
    return Config(runtime=RuntimeSettings(**runtime))


def account(config, tmp_path, *, uid=None, owner=False, sockets=()):
    """Account checks for a code directory owned (or not) by the checked uid."""
    code = tmp_path / "code"
    code.mkdir(exist_ok=True)
    code_uid = code.stat().st_uid
    if uid is None:
        uid = code_uid if owner else code_uid + 1
    return preflight.check_account(
        config, uid=uid, paths=[code], sockets=sockets, access=lambda p, mode: True
    )


def test_uid_0_always_fails_even_with_the_developer_override(tmp_path):
    r = account(cfg(allow_developer_account=True), tmp_path, uid=0)
    assert not r.ok and [c.name for c in r.failures] == ["not_root"]


def test_code_owner_fails_unless_the_developer_override_is_set(tmp_path):
    r = account(cfg(), tmp_path, owner=True)
    assert [c.name for c in r.failures] == ["not_code_owner"]
    r = account(cfg(allow_developer_account=True), tmp_path, owner=True)
    assert r.ok and [c.name for c in r.warnings] == ["not_code_owner"]


def test_accessible_rootful_socket_fails_unless_the_developer_override_is_set(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    r = account(cfg(), tmp_path, sockets=[str(sock)])
    assert [c.name for c in r.failures] == ["no_rootful_docker"]
    r = account(cfg(allow_developer_account=True), tmp_path, sockets=[str(sock)])
    assert r.ok and [c.name for c in r.warnings] == ["no_rootful_docker"]


def test_dedicated_account_passes_cleanly(tmp_path):
    r = account(cfg(), tmp_path, sockets=[str(tmp_path / "absent.sock")])
    assert r.ok and not r.warnings


def runtime(fake, info=None, settings=None):
    if info is not None:
        fake.set_info(info)
    docker = DockerCli("unix:///fake.sock", str(fake.binary))
    return asyncio.run(preflight.check_runtime(docker, settings or SandboxSettings()))


def test_rootless_runtime_with_delegated_controllers_passes(fake_docker):
    assert runtime(fake_docker, ROOTLESS_INFO).ok


def test_rootful_endpoint_disables_sandboxes(fake_docker):
    info = dict(ROOTLESS_INFO, SecurityOptions=["name=seccomp,profile=builtin", "name=cgroupns"])
    r = runtime(fake_docker, info)
    assert [c.name for c in r.failures] == ["rootless"]


@pytest.mark.parametrize(
    ("key", "controller"),
    [("MemoryLimit", "memory"), ("PidsLimit", "pids"), ("CpuCfsQuota", "cpu")],
)
def test_missing_cgroup_controller_disables_sandboxes(fake_docker, key, controller):
    r = runtime(fake_docker, dict(ROOTLESS_INFO, **{key: False}))
    assert [c.name for c in r.failures] == ["cgroup_controllers"]
    assert controller in r.failures[0].detail


def test_cgroup_v1_and_missing_seccomp_disable_sandboxes(fake_docker):
    info = dict(ROOTLESS_INFO, CgroupVersion="1", SecurityOptions=["name=rootless"])
    assert {c.name for c in runtime(fake_docker, info).failures} == {"cgroup_v2", "seccomp"}


def test_unreachable_endpoint_and_missing_image_disable_sandboxes(fake_docker):
    (fake_docker.state / "no-image").write_text("")
    assert [c.name for c in runtime(fake_docker, ROOTLESS_INFO).failures] == ["sandbox_image"]
    (fake_docker.state / "unreachable").write_text("")
    assert [c.name for c in runtime(fake_docker).failures] == ["endpoint"]


def test_prepare_runtime_returns_no_runner_on_failure(fake_docker):
    (fake_docker.state / "unreachable").write_text("")
    config = Config(runtime=RuntimeSettings(docker_binary=str(fake_docker.binary)))
    runner, report = asyncio.run(preflight.prepare_runtime(config))
    assert runner is None and not report.ok and report.reasons()


# --- network check ----------------------------------------------------------------

HARDENED_PROXY = {
    "State": {"Running": True},
    "Config": {"User": "pwuser"},
    "HostConfig": {
        "CapDrop": ["ALL"],
        "CapAdd": None,
        "Privileged": False,
        "ReadonlyRootfs": True,
        "SecurityOpt": ["no-new-privileges:true"],
        "Memory": 268435456,
        "PidsLimit": 128,
        "NanoCpus": 1000000000,
        "NetworkMode": "bs_egress",
    },
    "Mounts": [],
}
INTERNAL_NET = {
    "Name": "bs_sandbox",
    "Internal": True,
    "Containers": {"a": {"Name": "bs-egress-proxy"}, "b": {"Name": "bs-main-browser-9-1"}},
}


def network(fake, net=INTERNAL_NET, proxy=HARDENED_PROXY):
    fake.set_network("bs_sandbox", net)
    if proxy is not None:
        fake.set_container("bs-egress-proxy", proxy)
    docker = DockerCli("unix:///fake.sock", str(fake.binary))
    settings = SandboxSettings()
    runner = SandboxRunner(settings, docker)
    return asyncio.run(preflight.check_network(docker, settings, runner, probe=False))


def test_internal_network_with_only_the_hardened_proxy_passes(fake_docker):
    assert network(fake_docker).ok


def test_network_recreated_without_internal_fails(fake_docker):
    r = network(fake_docker, dict(INTERNAL_NET, Internal=False))
    assert [c.name for c in r.failures] == ["network_internal"]


def test_unexpected_long_running_container_on_the_sandbox_network_fails(fake_docker):
    net = copy.deepcopy(INTERNAL_NET)
    net["Containers"]["c"] = {"Name": "some-web-app"}
    r = network(fake_docker, net)
    assert [c.name for c in r.failures] == ["network_members"]


def test_missing_network_or_proxy_fails(fake_docker):
    docker = DockerCli("unix:///fake.sock", str(fake_docker.binary))
    settings = SandboxSettings()
    r = asyncio.run(
        preflight.check_network(docker, settings, SandboxRunner(settings, docker), probe=False)
    )
    assert [c.name for c in r.failures] == ["network_exists"]
    net = copy.deepcopy(INTERNAL_NET)
    del net["Containers"]["a"]
    r = network(fake_docker, net, proxy=None)
    assert {c.name for c in r.failures} == {"proxy_attached", "proxy_hardened"}


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda p: p["Config"].update(User=""), "runs as root"),
        (lambda p: p["Config"].update(User="0:0"), "runs as root"),
        (lambda p: p["HostConfig"].update(CapDrop=[]), "capabilities not dropped"),
        (lambda p: p["HostConfig"].update(CapAdd=["NET_ADMIN"]), "capabilities added"),
        (lambda p: p["HostConfig"].update(Privileged=True), "privileged"),
        (lambda p: p["HostConfig"].update(ReadonlyRootfs=False), "root filesystem writable"),
        (lambda p: p["HostConfig"].update(SecurityOpt=[]), "no-new-privileges not set"),
        (lambda p: p["HostConfig"].update(Memory=0), "no memory limit"),
        (lambda p: p["HostConfig"].update(PidsLimit=-1), "no PID limit"),
        (lambda p: p["HostConfig"].update(NanoCpus=0), "no CPU limit"),
        (lambda p: p.update(Mounts=[{"RW": True}]), "writable mount"),
        (lambda p: p["State"].update(Running=False), "not running"),
    ],
)
def test_proxy_hardening_problems_are_named(change, problem):
    p = copy.deepcopy(HARDENED_PROXY)
    change(p)
    assert preflight.proxy_hardening_problems(p) == [problem]


# --- production wiring: preflight and orphan sweep before startup (AE18) -----------


def prepare(fake, store, info, **sandbox):
    from brandsentinel.pipeline.orchestrator import Orchestrator, _prepare_sandbox

    fake.set_info(info)
    config = Config(
        runtime=RuntimeSettings(docker_binary=str(fake.binary)),
        sandbox=SandboxSettings(**sandbox),
    )
    orch = Orchestrator(store)
    asyncio.run(_prepare_sandbox(orch, config))
    return orch


ORPHAN = {"brandsentinel.instance": "main", "brandsentinel.job": "7"}


def test_passing_preflight_sweeps_orphans_and_enables_sandboxes(fake_docker, store):
    fake_docker.add_container("bs-main-browser-7-1", ORPHAN)
    orch = prepare(fake_docker, store, ROOTLESS_INFO)
    assert orch.sandbox is not None and orch.sandbox_disabled == []
    assert fake_docker.containers() == {}


def test_orphans_are_swept_even_when_a_non_safety_check_fails(fake_docker, store):
    fake_docker.add_container("bs-main-browser-7-1", ORPHAN)
    (fake_docker.state / "no-image").write_text("")
    orch = prepare(fake_docker, store, ROOTLESS_INFO)
    assert orch.sandbox is None and any("sandbox_image" in r for r in orch.sandbox_disabled)
    assert fake_docker.containers() == {}


def test_nothing_is_touched_on_an_endpoint_that_is_not_rootless(fake_docker, store):
    fake_docker.add_container("bs-main-browser-7-1", ORPHAN)
    rootful = dict(ROOTLESS_INFO, SecurityOptions=["name=seccomp,profile=builtin"])
    orch = prepare(fake_docker, store, rootful)
    assert orch.sandbox is None and "bs-main-browser-7-1" in fake_docker.containers()


def test_failed_sweep_disables_sandboxes(fake_docker, store, monkeypatch):
    from brandsentinel.sandbox.runner import SandboxError

    def broken(self):
        raise SandboxError("orphan removal failed: daemon error")

    monkeypatch.setattr(SandboxRunner, "sweep_orphans", broken)
    orch = prepare(fake_docker, store, ROOTLESS_INFO)
    assert orch.sandbox is None and any("orphan_sweep" in r for r in orch.sandbox_disabled)


def test_missing_docker_binary_disables_sandboxes_without_crashing(tmp_path):
    config = Config(runtime=RuntimeSettings(docker_binary=str(tmp_path / "nope")))
    runner, report = asyncio.run(preflight.prepare_runtime(config))
    assert runner is None and [c.name for c in report.failures] == ["endpoint"]


def test_job_containers_of_other_instances_are_expected_network_members(fake_docker):
    net = copy.deepcopy(INTERNAL_NET)
    net["Containers"]["c"] = {"Name": "bs-lab-browser-12-2"}
    assert network(fake_docker, net).ok
