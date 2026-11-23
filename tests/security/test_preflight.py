"""Sandbox preflight (U23, U18): every failed check keeps sandboxes disabled.

Account and runtime checks run against injected values and a fake Docker CLI.
The network check's behaviour on a real rootless runtime is in
tests/security/test_docker_isolation.py.
"""

import asyncio
import copy
import os
import types
from pathlib import Path

import pytest
from tests.fake_docker import image_id

from brandsentinel.config import Config, RuntimeSettings, SandboxSettings
from brandsentinel.sandbox import preflight
from brandsentinel.sandbox.runner import DockerCli, SandboxRunner
from brandsentinel.store import approval, identity, image_selection, policy

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
    config = Config(data_dir=fake.state / "data", sandbox=settings or SandboxSettings())
    return asyncio.run(preflight.check_runtime(docker, config))


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
    "Id": "6af1c7b4f3690000000000000000000000000000000000000000000000000000",
    "Internal": True,
    "Options": {"com.docker.network.bridge.inhibit_ipv4": "true"},
    "IPAM": {"Config": [{"Subnet": "172.31.251.0/24", "Gateway": "172.31.251.1"}]},
    "Containers": {"a": {"Name": "bs-egress-proxy"}, "b": {"Name": "bs-main-browser-9-1"}},
}


class FakeNamespace:
    """A rootless namespace view: the addresses it holds and its exposed listeners."""

    def __init__(
        self,
        local=("10.0.2.100", "127.0.0.1", "172.31.252.1"),
        exposed=(),
        interfaces=("lo", "tap0", "br-6af1c7b4f369"),
    ):
        self.local, self.exposed, self.ifaces = set(local), list(exposed), set(interfaces)

    def describe(self):
        return "net:[1] (fake)"

    def interfaces(self):
        return self.ifaces

    def local_ipv4(self):
        return self.local

    def exposed_listeners(self):
        return self.exposed


def network(fake, net=INTERNAL_NET, proxy=HARDENED_PROXY, namespace=None):
    fake.set_network("bs_sandbox", net)
    if proxy is not None:
        fake.set_container("bs-egress-proxy", proxy)
    docker = DockerCli("unix:///fake.sock", str(fake.binary))
    settings = SandboxSettings()
    runner = SandboxRunner(settings, docker)
    return asyncio.run(
        preflight.check_network(
            docker, settings, runner, probe=False, namespace=namespace or FakeNamespace()
        )
    )


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
        preflight.check_network(
            docker, settings, SandboxRunner(settings, docker), probe=False,
            namespace=FakeNamespace(),
        )
    )  # fmt: skip
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


def prepare(fake, store, info, account=None, lab=False, **sandbox):
    from brandsentinel.pipeline.orchestrator import Orchestrator, _prepare_sandbox

    # The account checks see the real test account; inject the dedicated
    # account's (clean) result unless a test supplies one.
    if account is None:
        account = preflight.Report()
        account.add("not_root", True)
    fake.set_info(info)
    config = Config(
        runtime=RuntimeSettings(docker_binary=str(fake.binary)),
        sandbox=SandboxSettings(**sandbox),
    )
    if lab:
        config = config.model_copy(
            update={"net": config.net.model_copy(update={"lab": config.net.lab.model_copy(
                update={"enabled": True})})}
        )  # fmt: skip
    orch = Orchestrator(store)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preflight, "check_account", lambda config: account)
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
    net["Containers"]["b"] = {"Name": "bs-lab-browser-12-2"}
    assert network(fake_docker, net).ok
    # ...but never two untrusted containers at once (SP1).
    net["Containers"]["c"] = {"Name": "bs-main-browser-9-1"}
    assert [c.name for c in network(fake_docker, net).failures] == ["single_untrusted_container"]


# --- SP1: gateway, listeners, single untrusted container, dedicated account --------


def test_network_without_inhibit_ipv4_fails_gateway_check(fake_docker):
    net = copy.deepcopy(INTERNAL_NET)
    net["Options"] = {}
    r = network(fake_docker, net)
    assert [c.name for c in r.failures] == ["gateway_inhibited"]
    assert "lacks com.docker.network.bridge.inhibit_ipv4" in r.failures[0].detail


def test_namespace_holding_a_sandbox_address_fails_gateway_check(fake_docker):
    r = network(fake_docker, namespace=FakeNamespace(local={"172.31.251.1", "10.0.2.100"}))
    assert [c.name for c in r.failures] == ["gateway_inhibited"]
    assert "172.31.251.1" in r.failures[0].detail


def test_exposed_namespace_listener_fails(fake_docker):
    from brandsentinel.sandbox.netns import Listener

    r = network(fake_docker, namespace=FakeNamespace(exposed=[Listener("tcp6", "::", 8080)]))
    assert [c.name for c in r.failures] == ["rootless_listeners"]
    assert "tcp6 [::]:8080" in r.failures[0].detail


def test_uninspectable_namespace_fails_closed(fake_docker):
    from brandsentinel.sandbox.netns import NamespaceUnavailable

    class Broken(FakeNamespace):
        def local_ipv4(self):
            raise NamespaceUnavailable("no child_pid")

    r = network(fake_docker, namespace=Broken())
    assert {c.name for c in r.failures} == {"gateway_inhibited", "rootless_listeners"}


def test_two_job_containers_on_the_sandbox_network_fail(fake_docker):
    net = copy.deepcopy(INTERNAL_NET)
    net["Containers"]["c"] = {"Name": "bs-main-browser-10-1"}
    r = network(fake_docker, net)
    assert [c.name for c in r.failures] == ["single_untrusted_container"]


def _account(ok=True, warning=False):
    report = preflight.Report()
    report.add("not_code_owner", ok, "" if ok else "UID 1000 owns the code", warning=warning)
    return report


def test_developer_override_keeps_sandbox_stages_disabled(fake_docker, store):
    orch = prepare(fake_docker, store, ROOTLESS_INFO, account=_account(warning=True))
    assert orch.sandbox is None
    assert any(r.startswith("dedicated_account") for r in orch.sandbox_disabled)


def test_failing_account_checks_keep_sandbox_stages_disabled(fake_docker, store):
    orch = prepare(fake_docker, store, ROOTLESS_INFO, account=_account(ok=False))
    assert orch.sandbox is None


def test_lab_mode_may_use_the_developer_override(fake_docker, store):
    orch = prepare(fake_docker, store, ROOTLESS_INFO, account=_account(warning=True), lab=True)
    assert orch.sandbox is not None


def test_a_namespace_without_the_sandbox_bridge_fails_closed(fake_docker):
    # The SP1 acceptance failure: the host namespace was examined. It has no
    # sandbox bridge, so neither check may pass or fail on its contents.
    r = network(fake_docker, namespace=FakeNamespace(interfaces=("lo", "wlan0", "virbr0")))
    failed = {c.name: c.detail for c in r.failures}
    assert set(failed) == {"gateway_inhibited", "rootless_listeners"}
    assert "does not contain bs_sandbox's bridge br-6af1c7b4f369" in failed["gateway_inhibited"]


# --- image identity (B7 U14, KTD12 option C) --------------------------------------------
#
# Selection (store/image_selection.py) and the approval record (store/approval.py) are
# exercised for real against a temporary chain root; Docker is the fake CLI, in which
# images exist only by ID and `create` refuses a tag (tests/fake_docker.py).

ME = os.getuid()
ACCOUNT_UID = ME + 4242
OTHER_UID = ME + 4343
ECHO = image_id("echo")  # what the default sandbox tag names in the fake
OTHER_ID = image_id("fail")
TAG = SandboxSettings().image


class PolicyHost:
    """A temporary `/` with the anchor and the approval record slots, a production store
    path and a development store path. Replaces tests/conftest.py's empty root."""

    def __init__(self, tmp_path, monkeypatch) -> None:
        self.root = tmp_path / "root"
        self.etc = self.root / "etc" / "brandsentinel"
        self.etc.mkdir(parents=True)
        for d in (self.root, self.root / "etc", self.etc):
            d.chmod(0o755)
        self.anchor = self.etc / "production.yaml"
        self.record = self.etc / "image-approval.yaml"
        self.store = tmp_path / "srv" / "data"
        self.dev = tmp_path / "dev" / "data"
        self.mp = monkeypatch
        monkeypatch.setattr(identity, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(identity, "ANCHOR_PATH", self.anchor)
        monkeypatch.setattr(identity, "TRUSTED_UID", ME)
        monkeypatch.setattr(identity, "install_record_candidates", lambda: [])
        monkeypatch.setattr(approval, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(approval, "APPROVAL_PATH", self.record)
        monkeypatch.setattr(approval, "TRUSTED_UID", ME)
        self.users(OTHER_UID, OTHER_UID)
        monkeypatch.setattr(
            policy, "account_uid", lambda a: {"brandsentinel": ACCOUNT_UID}.get(a.account)
        )

    def write_anchor(self, account: str = "brandsentinel", mode: int = 0o644) -> None:
        self.anchor.write_text(
            f"account: {account}\n"
            f"store_path: {self.store}\n"
            "config_path: /opt/brandsentinel/config/service.yaml\n"
            "install_prefix: /opt/brandsentinel\n"
            "complete: true\n"
        )
        self.anchor.chmod(mode)

    def write_record(self, image: str = ECHO, mode: int = 0o644) -> None:
        self.record.write_text(f"image_id: {image}\ncomplete: true\n")
        self.record.chmod(mode)

    def users(self, euid: int, ruid: int) -> None:
        # Only the selection sees these IDs; the rest of the process keeps the real ones.
        fake_os = types.SimpleNamespace(geteuid=lambda: euid, getuid=lambda: ruid)
        self.mp.setattr(image_selection, "os", fake_os)

    def as_account(self) -> None:
        self.write_anchor()
        self.users(ACCOUNT_UID, ACCOUNT_UID)


@pytest.fixture
def host(tmp_path, monkeypatch) -> PolicyHost:
    return PolicyHost(tmp_path, monkeypatch)


def image_config(fake, data_dir, *, lab=False, **sandbox) -> Config:
    fake.set_info(ROOTLESS_INFO)
    config = Config(
        data_dir=data_dir,
        runtime=RuntimeSettings(docker_host="unix:///fake.sock", docker_binary=str(fake.binary)),
        sandbox=SandboxSettings(**sandbox),
    )
    if lab:
        config = config.model_copy(
            update={"net": config.net.model_copy(update={"lab": config.net.lab.model_copy(
                update={"enabled": True})})}
        )  # fmt: skip
    return config


def prepared(fake, data_dir, **kw):
    return asyncio.run(preflight.prepare_runtime(image_config(fake, data_dir, **kw)))


def failed(report) -> dict[str, str]:
    return {c.name: c.detail for c in report.failures}


def creates(fake) -> list[list[str]]:
    return [c for c in fake.calls() if "create" in c]


def test_a_development_host_binds_the_runner_to_the_resolved_id(fake_docker, host):
    runner, report = prepared(fake_docker, host.dev)
    assert report.ok, report.reasons()
    assert runner is not None and runner.image_id == ECHO and not runner.image_enforced
    assert report.image_id == ECHO and report.image_enforced is False
    names = [c.name for c in report.checks]
    assert "image_selection" in names and "image_approval" not in names


def test_a_development_host_needs_no_record_even_when_one_is_unsafe(fake_docker, host):
    host.write_record(mode=0o666)  # never read when not enforcing
    runner, report = prepared(fake_docker, host.dev)
    assert runner is not None and report.ok


def test_enforcing_without_a_record_disables_sandboxes(fake_docker, host):
    host.as_account()
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and report.image_id is None
    assert failed(report) == {"image_approval": "approval_missing"}


@pytest.mark.parametrize(
    ("damage", "check"),
    [
        ("symlink", "approval_unsafe"),
        ("writable", "approval_unsafe"),
        ("not_root_owned", "approval_unsafe"),
        ("malformed", "approval_malformed"),
        ("truncated", "approval_malformed"),
    ],
)
def test_an_unsafe_or_malformed_record_disables_sandboxes(
    fake_docker, host, tmp_path, damage, check
):
    host.as_account()
    if damage == "symlink":
        real = tmp_path / "elsewhere.yaml"
        real.write_text(f"image_id: {ECHO}\ncomplete: true\n")
        host.record.symlink_to(real)
    elif damage == "writable":
        host.write_record(mode=0o666)
    elif damage == "not_root_owned":
        host.write_record()
        host.mp.setattr(approval, "TRUSTED_UID", ME + 1)
    elif damage == "malformed":
        host.record.write_text(f"image_id: {TAG}\ncomplete: true\n")
        host.record.chmod(0o644)
    else:
        host.record.write_text(f"image_id: {ECHO}\n")
        host.record.chmod(0o644)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None
    assert failed(report) == {"image_approval": check}


def test_a_tag_resolving_to_another_id_disables_sandboxes(fake_docker, host):
    host.as_account()
    host.write_record(OTHER_ID)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and list(failed(report)) == ["image_approved"]
    assert not creates(fake_docker)


def test_the_approved_id_enables_an_enforcing_runner(fake_docker, host):
    host.as_account()
    host.write_record(ECHO)
    runner, report = prepared(fake_docker, host.dev)
    assert report.ok, report.reasons()
    assert runner.image_id == ECHO and runner.image_enforced
    assert report.image_enforced is True


def test_a_production_class_store_is_enforced_for_another_account(fake_docker, host):
    host.write_anchor()  # the developer's IDs, but the configured store is production
    host.write_record(ECHO)
    runner, report = prepared(fake_docker, host.store)
    assert report.ok, report.reasons()
    assert runner.image_enforced and runner.image_id == ECHO
    host.write_record(OTHER_ID)
    runner, report = prepared(fake_docker, host.store)
    assert runner is None and list(failed(report)) == ["image_approved"]


def test_a_tag_moved_to_the_approved_id_after_a_mismatch_is_seen_on_the_next_preflight(
    fake_docker, host
):
    host.as_account()
    host.write_record(OTHER_ID)
    assert prepared(fake_docker, host.dev)[0] is None
    fake_docker.set_tag(TAG, OTHER_ID)
    runner, _ = prepared(fake_docker, host.dev)
    assert runner is not None and runner.image_id == OTHER_ID


@pytest.mark.parametrize(
    ("euid", "ruid", "store", "enforced"),
    [
        (ACCOUNT_UID, ACCOUNT_UID, "dev", True),
        (ACCOUNT_UID, OTHER_UID, "dev", True),  # D3: either user ID enforces
        (OTHER_UID, ACCOUNT_UID, "dev", True),
        (OTHER_UID, OTHER_UID, "dev", False),  # a developer on a host with an anchor
        (OTHER_UID, OTHER_UID, "store", True),  # a production-class store
    ],
)
def test_selection_by_user_ids_and_store(fake_docker, host, euid, ruid, store, enforced):
    host.write_anchor()
    host.users(euid, ruid)
    runner, report = prepared(fake_docker, host.store if store == "store" else host.dev)
    if enforced:  # no record: enforcing refuses
        assert runner is None and failed(report) == {"image_approval": "approval_missing"}
    else:
        assert runner is not None and not runner.image_enforced


@pytest.mark.parametrize(
    ("setup", "check"),
    [
        ("unsafe_anchor", "anchor_unsafe"),
        ("unknown_account", "anchor_account_unknown"),
        ("marked_store_without_anchor", "anchor_missing"),
        ("installation_without_anchor", "anchor_missing"),
    ],
)
def test_a_refused_selection_disables_sandboxes_and_is_never_development(
    fake_docker, host, setup, check
):
    data_dir = host.dev
    if setup == "unsafe_anchor":
        host.write_anchor(mode=0o666)
    elif setup == "unknown_account":
        host.write_anchor(account="nobody-here")
    elif setup == "marked_store_without_anchor":
        data_dir.mkdir(parents=True)
        (data_dir / identity.MARKER_NAME).write_text("brandsentinel_store: 1\nclass: production\n")
    else:
        record = host.root / "INSTALL"
        record.write_text("installed\n")
        host.mp.setattr(identity, "install_record_candidates", lambda: [record])
    runner, report = prepared(fake_docker, data_dir)
    assert runner is None and report.image_id is None
    assert failed(report) == {"image_selection": check}
    # The Docker checks still ran, so the startup sweep can still clean up orphans.
    passed = {c.name for c in report.checks if c.ok}
    assert {"endpoint", "rootless"} <= passed


def test_an_unexpected_selection_error_is_named_and_never_development(
    fake_docker, host, monkeypatch
):
    def broken(data_dir):
        raise RuntimeError("/secret/path is weird")

    monkeypatch.setattr(image_selection, "select", broken)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and failed(report) == {
        "image_selection": "selection_error (RuntimeError)"
    }
    assert "/secret" not in " ".join(report.reasons())


def test_an_unexpected_record_error_is_named(fake_docker, host, monkeypatch):
    host.as_account()

    def broken():
        raise OSError("/etc/brandsentinel: I/O error")

    monkeypatch.setattr(approval, "load_approval", broken)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and failed(report) == {"image_approval": "approval_error (OSError)"}
    assert "/etc" not in " ".join(report.reasons())


@pytest.mark.parametrize("output", ["sha256:fake", f"{ECHO}\n{OTHER_ID}", ECHO.upper(), ""])
def test_an_unusable_image_resolution_disables_sandboxes(fake_docker, host, output):
    fake_docker.set_tag(TAG, output)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and list(failed(report)) == ["sandbox_image"]


def test_the_selection_runs_before_any_docker_call(fake_docker, host, monkeypatch):
    seen = []
    real = image_selection.select

    def spy(data_dir):
        seen.append(len(fake_docker.calls()))
        return real(data_dir)

    monkeypatch.setattr(image_selection, "select", spy)
    prepared(fake_docker, host.dev)
    assert seen == [0]


def test_a_stub_report_without_an_id_yields_no_runner(fake_docker, host, monkeypatch):
    async def ok_without_id(docker, config):
        return preflight.Report()

    monkeypatch.setattr(preflight, "check_runtime", ok_without_id)
    runner, report = prepared(fake_docker, host.dev)
    assert runner is None and list(failed(report)) == ["sandbox_image"]


# --- the egress proxy runs the approved image (enforcing only) --------------------------


def network_with(fake, runner, settings, proxy_image, net=INTERNAL_NET):
    fake.set_network(settings.network, dict(net, Name=settings.network))
    proxy = copy.deepcopy(HARDENED_PROXY)
    if proxy_image is not None:
        proxy["Image"] = proxy_image
    fake.set_container(settings.proxy_container, proxy)
    docker = runner.docker
    return asyncio.run(
        preflight.check_network(docker, settings, runner, probe=False, namespace=FakeNamespace())
    )


def id_runner(fake, settings=None, *, enforced: bool, image: str = ECHO) -> SandboxRunner:
    docker = DockerCli("unix:///fake.sock", str(fake.binary))
    return SandboxRunner(
        settings or SandboxSettings(), docker, image_id=image, image_enforced=enforced
    )


def test_an_enforced_proxy_on_the_approved_id_passes(fake_docker):
    r = network_with(fake_docker, id_runner(fake_docker, enforced=True), SandboxSettings(), ECHO)
    assert r.ok and "proxy_image" in [c.name for c in r.checks]


@pytest.mark.parametrize("proxy_image", [OTHER_ID, TAG, None, ""])
def test_an_enforced_proxy_on_another_image_disables_the_browser_gate(fake_docker, proxy_image):
    settings = SandboxSettings()
    r = network_with(fake_docker, id_runner(fake_docker, enforced=True), settings, proxy_image)
    assert list(failed(r)) == ["proxy_image"]
    assert f"{settings.proxy_container} does not run the approved image" in r.failures[0].detail


def test_a_development_proxy_is_not_compared(fake_docker):
    r = network_with(
        fake_docker, id_runner(fake_docker, enforced=False), SandboxSettings(), OTHER_ID
    )
    assert r.ok and "proxy_image" not in [c.name for c in r.checks]


def test_the_lab_sandbox_proxy_is_the_one_checked_when_enforcing(fake_docker):
    lab = SandboxSettings(network="bs_lab_sandbox", proxy_container="bs-lab-sandbox-proxy")
    net = dict(INTERNAL_NET, Containers={"a": {"Name": "bs-lab-sandbox-proxy"}})
    fake_docker.set_container("bs-egress-proxy", dict(HARDENED_PROXY, Image=ECHO))
    r = network_with(fake_docker, id_runner(fake_docker, lab, enforced=True), lab, OTHER_ID, net)
    assert list(failed(r)) == ["proxy_image"] and "bs-lab-sandbox-proxy" in r.failures[0].detail


# --- lab mode, the orchestrator and the startup sweep -----------------------------------


def test_lab_mode_as_the_account_is_enforced(fake_docker, host):
    host.as_account()
    runner, report = prepared(fake_docker, host.dev, lab=True)
    assert runner is None and failed(report) == {"image_approval": "approval_missing"}
    host.write_record(ECHO)
    runner, _ = prepared(fake_docker, host.dev, lab=True)
    assert runner is not None and runner.image_enforced


def test_lab_mode_as_the_developer_is_not_enforced(fake_docker, host):
    host.write_anchor()  # an anchor on the host, but another account runs the lab
    runner, _ = prepared(fake_docker, host.dev, lab=True)
    assert runner is not None and not runner.image_enforced and runner.image_id == ECHO


def orchestrate(fake, store, data_dir, *, lab=False):
    from brandsentinel.pipeline.orchestrator import Orchestrator, _prepare_sandbox

    account = preflight.Report()
    account.add("not_root", True)
    orch = Orchestrator(store)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preflight, "check_account", lambda config: account)
        asyncio.run(_prepare_sandbox(orch, image_config(fake, data_dir, lab=lab)))
    return orch


def test_the_orchestrator_disables_sandboxes_with_the_named_refusal_and_still_sweeps(
    fake_docker, host, store
):
    host.as_account()
    fake_docker.add_container("bs-main-browser-7-1", ORPHAN)
    orch = orchestrate(fake_docker, store, host.dev)
    assert orch.sandbox is None
    assert "image_approval: approval_missing" in orch.sandbox_disabled
    assert fake_docker.containers() == {}  # the fallback sweeper still removed the orphan
    assert not creates(fake_docker)


def test_the_orchestrator_fallback_sweeper_cannot_create(fake_docker, host, store, monkeypatch):
    host.as_account()
    built = []
    real_init = SandboxRunner.__init__

    def spy(self, *a, **kw):
        real_init(self, *a, **kw)
        built.append(self)

    monkeypatch.setattr(SandboxRunner, "__init__", spy)
    orch = orchestrate(fake_docker, store, host.dev)
    assert orch.sandbox is None and len(built) == 1
    from brandsentinel.sandbox.runner import SandboxError, SandboxSpec

    with pytest.raises(SandboxError, match="no resolved image ID"):
        built[0].validate(SandboxSpec(role="media", command=("x",)))


def test_the_orchestrator_runs_jobs_by_the_approved_id(fake_docker, host, store):
    host.as_account()
    host.write_record(ECHO)
    orch = orchestrate(fake_docker, store, host.dev)
    assert orch.sandbox is not None and orch.sandbox.image_enforced
    assert orch.sandbox.image_id == ECHO


# --- the CLI entry points ---------------------------------------------------------------


def cli_config(fake, tmp_path, data_dir) -> Path:
    fake.set_info(ROOTLESS_INFO)
    path = tmp_path / "scratch.yaml"
    path.write_text(
        f"data_dir: {data_dir}\n"
        "runtime:\n"
        "  docker_host: unix:///fake.sock\n"
        f"  docker_binary: {fake.binary}\n"
    )
    return path


def invoke(monkeypatch, *args):
    from typer.testing import CliRunner

    from brandsentinel.cli import app

    clean = preflight.Report()
    clean.add("not_root", True)
    monkeypatch.setattr(preflight, "check_account", lambda config: clean)
    return CliRunner().invoke(app, list(args))


def test_sandbox_check_reports_the_approval_state_when_enforced(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()
    host.write_record(ECHO)
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check", "--no-network", "--strict")
    assert r.exit_code == 0, r.output
    assert f"image: enforced (anchor_account), approved {ECHO[:19]}" in r.output
    assert str(host.record) not in r.output and "brandsentinel\n" not in r.output


def test_sandbox_check_strict_fails_without_a_record_and_names_it(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check", "--no-network", "--strict")
    assert r.exit_code == 1
    assert "FAIL image_approval: approval_missing" in r.output
    assert "image: enforced (anchor_account), REFUSED" in r.output
    assert str(host.record) not in r.output and str(host.anchor) not in r.output


def test_sandbox_check_reports_development_when_not_enforced(
    fake_docker, host, tmp_path, monkeypatch
):
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check", "--no-network", "--strict")
    assert r.exit_code == 0, r.output
    assert f"image: not enforced (development), resolved {ECHO[:19]}" in r.output


def test_sandbox_selftest_requires_the_record_when_enforced(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "selftest", "media")
    assert r.exit_code == 1 and "FAIL image_approval: approval_missing" in r.output
    assert not creates(fake_docker)


def test_sandbox_check_network_probe_runs_by_the_resolved_id(
    fake_docker, host, tmp_path, monkeypatch
):
    runtime_dir = tmp_path / "run"
    runtime_dir.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    only_proxy = dict(INTERNAL_NET, Containers={"a": {"Name": "bs-egress-proxy"}})
    fake_docker.set_network("bs_sandbox", only_proxy)
    fake_docker.set_container("bs-egress-proxy", HARDENED_PROXY)
    monkeypatch.setattr(
        "brandsentinel.sandbox.netns.RootlessNamespace.for_endpoint",
        staticmethod(lambda host: FakeNamespace()),
    )
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check")
    assert r.exit_code == 0, r.output
    assert "probe:" in r.output
    made = creates(fake_docker)
    assert len(made) == 1 and made[0][made[0].index("--") + 1] == ECHO


def test_status_shows_the_image_refusal(fake_docker, host, tmp_path, monkeypatch):
    host.as_account()
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "status")
    assert "sandbox: DISABLED" in r.output, r.output
    assert "FAIL image_approval: approval_missing" in r.output


def test_sandbox_check_fails_on_a_proxy_running_another_image_when_enforced(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()
    host.write_record(ECHO)
    only_proxy = dict(INTERNAL_NET, Containers={"a": {"Name": "bs-egress-proxy"}})
    fake_docker.set_network("bs_sandbox", only_proxy)
    fake_docker.set_container("bs-egress-proxy", dict(HARDENED_PROXY, Image=OTHER_ID))
    monkeypatch.setattr(
        "brandsentinel.sandbox.netns.RootlessNamespace.for_endpoint",
        staticmethod(lambda host: FakeNamespace()),
    )
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check")
    assert r.exit_code == 1 and "FAIL proxy_image" in r.output
    assert not creates(fake_docker)  # no probe container once a check failed


def test_sandbox_check_with_a_refused_runtime_starts_no_probe(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()  # no record
    fake_docker.set_network("bs_sandbox", INTERNAL_NET)
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check")
    assert r.exit_code == 1 and "network bs_sandbox" not in r.output
    assert not creates(fake_docker)


def test_the_image_line_names_a_refused_selection(fake_docker, host, tmp_path, monkeypatch):
    host.write_anchor(mode=0o666)
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check", "--no-network")
    assert r.exit_code == 1 and "image: REFUSED (anchor_unsafe)" in r.output


def test_the_image_line_does_not_blame_the_image_for_an_unreachable_endpoint(
    fake_docker, host, tmp_path, monkeypatch
):
    host.as_account()
    host.write_record(ECHO)
    cfg_path = cli_config(fake_docker, tmp_path, host.dev)
    (fake_docker.state / "unreachable").write_text("")
    r = invoke(monkeypatch, "-c", str(cfg_path), "sandbox", "check", "--no-network")
    assert r.exit_code == 1 and "FAIL endpoint" in r.output
    assert "image: enforced (anchor_account), not resolved" in r.output


def test_the_image_line_says_not_checked_when_the_selection_never_ran(capsys):
    from brandsentinel.cli import _print_image

    report = preflight.Report()
    report.add("endpoint", False, "the Docker endpoint must be a unix socket")
    _print_image(report)
    assert "image: not checked" in capsys.readouterr().out


def test_the_configured_tag_cannot_be_read_as_an_option(fake_docker, host):
    prepared(fake_docker, host.dev, image="--help")
    lookups = [c for c in fake_docker.calls() if c[2:4] == ["image", "inspect"]]
    assert lookups and all(c[-2:] == ["--", "--help"] for c in lookups)
