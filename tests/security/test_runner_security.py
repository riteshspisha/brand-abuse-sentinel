"""Sandbox runner security properties (U23, R49, R50).

The container configuration the runner produces is fixed: these tests pin it and
prove a caller cannot widen it. Real-runtime enforcement of the same settings is
in tests/integration/test_runner.py and tests/security/test_docker_isolation.py.
"""

import pytest

from brandsentinel.config import SandboxSettings
from brandsentinel.sandbox.runner import DockerCli, SandboxError, SandboxRunner, SandboxSpec

pytestmark = pytest.mark.security


def runner(**kw) -> SandboxRunner:
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
    assert a[sep + 1] == SandboxSettings().image


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
