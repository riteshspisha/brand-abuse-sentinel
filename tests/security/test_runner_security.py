"""Sandbox runner security properties (U23, R49, R50).

The container configuration the runner produces is fixed: these tests pin it and
prove a caller cannot widen it. Real-runtime enforcement of the same settings is
in tests/integration/test_runner.py and tests/security/test_docker_isolation.py.
"""

import asyncio

import pytest
from tests.fake_docker import image_id

from brandsentinel.config import Config, RuntimeSettings, SandboxLimits, SandboxSettings
from brandsentinel.sandbox import preflight
from brandsentinel.sandbox.runner import DockerCli, SandboxError, SandboxRunner, SandboxSpec

pytestmark = pytest.mark.security

APPROVED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
TAG = SandboxSettings().image


def runner(**kw) -> SandboxRunner:
    kw.setdefault("image_id", APPROVED)
    return SandboxRunner(SandboxSettings(), DockerCli("unix:///fake.sock"), **kw)


def args_for(spec: SandboxSpec) -> list[str]:
    r = runner()
    r.validate(spec)
    return r.create_args(spec, "bs-main-media-1-0", "1", 0)


def opt(args: list[str], flag: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == flag]


BASE = SandboxSpec(role="media", command=("python3", "-c", "print(1)"))


def test_container_configuration_is_hardened_by_default():
    a = args_for(BASE)
    sep = a.index("--")
    head = a[:sep]
    assert "--read-only" in head and "--init" in head and "--interactive" in head
    assert opt(head, "--cap-drop") == ["ALL"]
    assert opt(head, "--security-opt") == ["no-new-privileges=true"]
    assert opt(head, "--network") == ["none"]
    assert opt(head, "--log-driver") == ["none"]
    assert opt(head, "--memory") == opt(head, "--memory-swap") == ["512m"]  # no swap
    assert opt(head, "--pids-limit") == ["128"] and opt(head, "--cpus") == ["1"]
    assert opt(head, "--ipc") == ["private"] and opt(head, "--pull") == ["never"]
    assert opt(head, "--tmpfs") == ["/tmp:rw,nosuid,nodev,noexec,size=64m"]
    assert "core=0" in opt(head, "--ulimit")
    assert a[sep + 1] == APPROVED  # the resolved ID, never the tag (B7 U14)


def test_no_option_can_mount_escalate_or_share_host_namespaces():
    spec = SandboxSpec(
        role="browser",
        command=("x",),
        network="bs_sandbox",
        env=(("HTTPS_PROXY", "http://172.31.251.2:3128"),),
        user="pwuser",
    )
    head = args_for(spec)[: args_for(spec).index("--")]
    forbidden = {
        "-v",
        "--volume",
        "--mount",
        "--volumes-from",
        "--privileged",
        "--cap-add",
        "--device",
        "--pid",
        "--uts",
        "--userns",
        "--cgroupns",
        "--publish",
        "-p",
        "--add-host",
        "--group-add",
    }
    assert not forbidden & set(head)
    assert not any("docker.sock" in a for a in head)


@pytest.mark.parametrize("network", ["host", "bridge", "default", "container:proxy", "bs_egress"])
def test_sandbox_never_joins_host_default_or_egress_networks(network):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role="media", command=("x",), network=network))


@pytest.mark.parametrize("network", ["host", "bridge", "container:x"])
def test_runner_refuses_construction_with_a_forbidden_network(network):
    with pytest.raises(SandboxError):
        runner(networks=[network])


@pytest.mark.parametrize(
    "user",
    [
        "0",
        "00",
        "0000",
        "root",
        "0:0",
        "root:root",
        "pwuser:0",
        "pwuser:root",
        "a:b:c",
        "../x",
        "a b",
    ],
)
def test_sandbox_never_runs_as_root(user):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role="media", command=("x",), user=user))


@pytest.mark.parametrize(
    "env", [(("lower", "x"),), (("X", "a\nb"),), (("X", "a\0b"),), (("A=B", "x"),)]
)
def test_environment_cannot_inject_options_or_lines(env):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role="media", command=("x",), env=env))


@pytest.mark.parametrize("profile", ["unconfined", "relative.json", "/nonexistent/x.json"])
def test_seccomp_cannot_be_disabled_or_point_nowhere(profile):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role="media", command=("x",), seccomp_profile=profile))


@pytest.mark.parametrize("image", ["-v/:/host", "--privileged", "img with space", "a\nb"])
def test_image_reference_cannot_smuggle_options(image):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role="media", command=("x",), image=image))


# --- image identity (B7 U14, KTD12 option C: F5) ---------------------------------------


def image_of(args: list[str]) -> str:
    return args[args.index("--") + 1]


def test_containers_are_created_by_the_resolved_id_never_by_the_tag():
    a = args_for(BASE)
    assert image_of(a) == APPROVED
    assert TAG not in a and not any(TAG in x for x in a)


@pytest.mark.parametrize(
    "image",
    [
        TAG,  # the configured tag itself: mutable
        OTHER,  # another, immutable, image
        "brandsentinel-sandbox@" + APPROVED,  # a digest reference is still a name lookup
        APPROVED.upper(),
        APPROVED[:19],  # a short ID prefix
        "",
    ],
)
def test_a_spec_cannot_name_any_image_but_the_runners_id(image):
    spec = SandboxSpec(role="media", command=("x",), image=image or None)
    if image == "":
        assert image_of(args_for(spec)) == APPROVED  # no override: the runner's ID
        return
    with pytest.raises(SandboxError, match="another image"):
        runner().validate(spec)
    with pytest.raises(SandboxError, match="another image"):
        runner().create_args(spec, "bs-main-media-1-0", "1", 0)


def test_a_spec_may_repeat_the_runners_own_id():
    spec = SandboxSpec(role="media", command=("x",), image=APPROVED)
    assert image_of(args_for(spec)) == APPROVED


def test_an_enforcing_runner_also_refuses_a_spec_override():
    r = runner(image_enforced=True)
    with pytest.raises(SandboxError, match="another image"):
        r.validate(SandboxSpec(role="media", command=("x",), image=OTHER))


@pytest.mark.parametrize(
    "bad",
    [
        TAG,
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 64 + "\n",
        "sha512:" + "a" * 64,
        " sha256:" + "a" * 64,
        "sha256:" + "g" * 64,
        "sha256:" + "\u0661" * 64,  # non-ASCII digits
    ],
)
def test_a_runner_takes_only_a_full_image_id(bad):
    with pytest.raises(SandboxError, match="image ID"):
        runner(image_id=bad)


def test_the_runners_image_cannot_be_rebound_after_construction():
    r = runner(image_enforced=True)
    with pytest.raises(AttributeError):
        r.image_id = TAG
    with pytest.raises(AttributeError):
        r.image_enforced = False
    assert r.image_id == APPROVED and r.image_enforced


def test_an_enforcing_runner_needs_an_id():
    with pytest.raises(SandboxError, match="image ID"):
        runner(image_id=None, image_enforced=True)


def test_a_runner_built_without_an_id_cannot_create_containers(fake_docker):
    # `sandbox sweep` and the orchestrator's sweep fallback build runners outside the
    # preflight: they may list and remove containers, never create one.
    docker = DockerCli("unix:///fake.sock", str(fake_docker.binary))
    r = SandboxRunner(SandboxSettings(), docker)
    assert r.image_id is None and not r.image_enforced
    with pytest.raises(SandboxError, match="no resolved image ID"):
        r.validate(BASE)
    with pytest.raises(SandboxError, match="no resolved image ID"):
        r.create_args(BASE, "bs-main-media-1-0", "1", 0)
    with pytest.raises(SandboxError, match="no resolved image ID"):
        asyncio.run(r.run(BASE, job="1", attempt=0))
    assert not any("create" in c for c in fake_docker.calls())
    assert r.sweep_orphans() == 0  # sweeping still works


def _prepared(fake, tmp_path):
    fake.set_info(
        {
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless"],
            "CgroupVersion": "2",
            "MemoryLimit": True,
            "PidsLimit": True,
            "CpuCfsQuota": True,
        }
    )
    config = Config(
        data_dir=tmp_path / "data",
        runtime=RuntimeSettings(docker_host="unix:///fake.sock", docker_binary=str(fake.binary)),
        sandbox=SandboxSettings(limits=SandboxLimits(wall_seconds=10), kill_grace_seconds=5),
    )
    runner, report = asyncio.run(preflight.prepare_runtime(config))
    assert runner is not None, report.reasons()
    return runner


def test_a_tag_moved_after_preflight_does_not_change_the_created_image(fake_docker, tmp_path):
    runner = _prepared(fake_docker, tmp_path)
    resolved = runner.image_id
    assert resolved == image_id("echo")
    fake_docker.set_tag(TAG, image_id("fail"))  # the tag moves between preflight and create
    result = asyncio.run(runner.run(BASE, job="7", attempt=0))
    assert result.status == "ok" and result.output == {"echo": ""}
    creates = [c for c in fake_docker.calls() if "create" in c]
    assert len(creates) == 1 and image_of(creates[0]) == resolved
    assert not any(TAG in arg for c in fake_docker.calls() if "create" in c for arg in c)


def test_the_tag_is_resolved_once_per_preflight(fake_docker, tmp_path):
    runner = _prepared(fake_docker, tmp_path)
    for job in ("1", "2"):
        asyncio.run(runner.run(BASE, job=job, attempt=0))
    lookups = [c for c in fake_docker.calls() if c[2:4] == ["image", "inspect"]]
    assert len(lookups) == 1


@pytest.mark.parametrize("role", ["Media", "media-1", "", "a" * 17])
def test_role_is_a_plain_lowercase_word(role):
    with pytest.raises(SandboxError):
        runner().validate(SandboxSpec(role=role, command=("x",)))


def test_image_and_command_come_after_end_of_options():
    a = args_for(SandboxSpec(role="media", command=("--privileged",)))
    sep = a.index("--")
    # image, then the best-effort self-deadline, then the job's own argv
    assert a[sep + 2 : sep + 5] == ["timeout", "--signal=KILL", "71s"]
    assert a[sep + 5] == "--privileged"  # an argument to the job, not to docker


def test_endpoint_must_be_a_unix_socket():
    with pytest.raises(SandboxError):
        DockerCli("tcp://127.0.0.1:2375")


def test_docker_cli_environment_carries_no_docker_variables(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "default")
    env = DockerCli("unix:///run/user/1/docker.sock").env()
    assert not any(k.startswith("DOCKER_") and k != "DOCKER_CLI_HINTS" for k in env)
    argv = DockerCli("unix:///run/user/1/docker.sock").argv("ps")
    assert argv[1:3] == ["--host", "unix:///run/user/1/docker.sock"]


def test_default_endpoint_is_the_accounts_rootless_socket(monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1234")
    assert DockerCli().host == "unix:///run/user/1234/docker.sock"
