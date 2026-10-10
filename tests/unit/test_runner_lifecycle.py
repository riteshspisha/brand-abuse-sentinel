"""Sandbox runner lifecycle against a fake Docker CLI (U23, KTD8).

These prove the runner's own logic: naming, labels, caps, wall time, kill by
name, removal and the orphan sweep. That the runtime enforces the limits is
proved against real rootless Docker in tests/integration/test_runner.py.
"""

import asyncio

import pytest

from brandsentinel.config import SandboxLimits, SandboxSettings
from brandsentinel.sandbox.runner import (
    LABEL_INSTANCE,
    LABEL_JOB,
    DockerCli,
    SandboxBusy,
    SandboxError,
    SandboxRunner,
    SandboxSpec,
)

LIMITS = SandboxLimits(wall_seconds=5, stdout_max_bytes=1024 * 1024, stderr_max_bytes=4096)


def make_runner(fake, instance="main", limits=LIMITS) -> SandboxRunner:
    settings = SandboxSettings(instance=instance, limits=limits, kill_grace_seconds=5)
    return SandboxRunner(settings, DockerCli("unix:///fake.sock", str(fake.binary)))


def spec(image: str, **kw) -> SandboxSpec:
    return SandboxSpec(role="media", command=("run",), image=image, **kw)


def run(runner, s, job="42", attempt=1, stdin=b""):
    return asyncio.run(runner.run(s, job=job, attempt=attempt, stdin=stdin))


def test_job_runs_with_stdin_in_and_one_json_document_out(fake_docker):
    r = run(make_runner(fake_docker), spec("fake/echo"), stdin=b"payload")
    assert r.status == "ok" and r.exit_code == 0
    assert r.output == {"echo": "payload"}
    assert r.name == "bs-main-media-42-1"
    assert r.removed and fake_docker.containers() == {}


def test_container_is_named_and_labelled_for_its_instance_job_and_attempt(fake_docker):
    run(make_runner(fake_docker, instance="lab"), spec("fake/echo"), job="7", attempt=3)
    create = next(c for c in fake_docker.calls() if "create" in c)
    assert create[create.index("--name") + 1] == "bs-lab-media-7-3"
    labels = [create[i + 1] for i, a in enumerate(create) if a == "--label"]
    assert f"{LABEL_INSTANCE}=lab" in labels and f"{LABEL_JOB}=7" in labels
    assert "brandsentinel.attempt=3" in labels


def test_every_docker_call_names_the_configured_endpoint(fake_docker):
    run(make_runner(fake_docker), spec("fake/echo"))
    calls = fake_docker.calls()
    assert calls and all(c[:2] == ["--host", "unix:///fake.sock"] for c in calls)


def test_wall_time_expiry_kills_the_container_by_name_and_removes_it(fake_docker):
    runner = make_runner(fake_docker, limits=LIMITS.model_copy(update={"wall_seconds": 1}))
    r = run(runner, spec("fake/sleep"))
    assert r.status == "timeout" and r.killed and r.removed
    assert ["kill", "--signal", "KILL", "bs-main-media-42-1"] in [
        c[2:] for c in fake_docker.calls()
    ]
    assert fake_docker.containers() == {}
    assert r.elapsed_ms < 8000


def test_stdout_beyond_its_cap_is_rejected_and_the_container_killed(fake_docker):
    r = run(make_runner(fake_docker), spec("fake/flood"))
    assert r.status == "stdout_overflow" and r.killed and r.removed
    assert r.output is None and r.stdout == b""


def test_stderr_flood_beyond_its_cap_is_rejected_and_the_container_killed(fake_docker):
    r = run(make_runner(fake_docker), spec("fake/stderr"))
    assert r.status == "stderr_overflow" and r.killed and r.removed


def test_memory_limit_kill_is_reported_as_oom(fake_docker):
    r = run(make_runner(fake_docker), spec("fake/oom"))
    assert r.status == "oom" and r.oom_killed and r.exit_code == 137 and r.removed


def test_non_zero_exit_and_non_json_output_are_failures(fake_docker):
    runner = make_runner(fake_docker)
    assert run(runner, spec("fake/fail")).status == "exit_error"
    r = run(runner, spec("fake/text"))
    assert r.status == "invalid_output" and r.output is None
    assert run(runner, spec("fake/text", expect_json=False)).status == "ok"


def test_missing_image_is_a_start_error_and_leaves_nothing(fake_docker):
    r = run(make_runner(fake_docker), spec("fake/missing"))
    assert r.status == "start_error" and r.removed
    assert fake_docker.containers() == {}


def test_earlier_attempt_container_is_removed_before_a_retry(fake_docker):
    fake_docker.add_container(
        "bs-main-media-42-1", {LABEL_INSTANCE: "main", LABEL_JOB: "42"}, status="running"
    )
    r = run(make_runner(fake_docker), spec("fake/echo"), attempt=2)
    assert r.status == "ok"
    calls = [c[2:] for c in fake_docker.calls()]
    rm_old = calls.index(["rm", "--force", "bs-main-media-42-1"])
    create = next(i for i, c in enumerate(calls) if c[0] == "create")
    assert rm_old < create


def test_retry_is_refused_while_an_earlier_container_survives(fake_docker, monkeypatch):
    fake_docker.add_container("bs-main-media-42-1", {LABEL_INSTANCE: "main", LABEL_JOB: "42"})
    runner = make_runner(fake_docker)

    async def stuck(name):  # the runtime fails to remove it
        return False

    monkeypatch.setattr(runner, "remove", stuck)
    with pytest.raises(SandboxBusy):
        run(runner, spec("fake/echo"), attempt=2)
    assert not any(c[2] == "create" for c in fake_docker.calls())


def test_orphan_sweep_removes_only_this_instances_containers(fake_docker):
    fake_docker.add_container("bs-main-media-1-1", {LABEL_INSTANCE: "main", LABEL_JOB: "1"})
    fake_docker.add_container("bs-main-browser-2-1", {LABEL_INSTANCE: "main", LABEL_JOB: "2"})
    fake_docker.add_container("bs-other-media-1-1", {LABEL_INSTANCE: "other", LABEL_JOB: "1"})
    fake_docker.add_container("unrelated", {})
    assert make_runner(fake_docker).sweep_orphans() == 2
    assert set(fake_docker.containers()) == {"bs-other-media-1-1", "unrelated"}


def test_orphan_sweep_with_nothing_to_remove(fake_docker):
    assert make_runner(fake_docker).sweep_orphans() == 0


def test_hostile_deeply_nested_json_is_invalid_output_not_a_crash(fake_docker):
    r = run(
        make_runner(fake_docker, limits=LIMITS.model_copy(update={"stdout_max_bytes": 1 << 20})),
        spec("fake/nested"),
    )
    assert r.status == "invalid_output" and r.removed


def test_removal_is_not_reported_while_the_daemon_is_unreachable(fake_docker):
    runner = make_runner(fake_docker)
    (fake_docker.state / "unreachable").write_text("")
    assert asyncio.run(runner.remove("bs-main-media-1-0")) is False


def test_missing_docker_binary_is_a_failed_call_not_an_exception(tmp_path):
    cli = DockerCli("unix:///fake.sock", str(tmp_path / "no-such-docker"))
    r = asyncio.run(cli.call("info"))
    assert r.returncode == -1 and "cannot run docker" in r.stderr
    runner = SandboxRunner(SandboxSettings(), cli)
    with pytest.raises(SandboxError, match="cannot run docker"):
        asyncio.run(runner.run(spec("fake/echo"), job="1", attempt=0))


def test_docker_output_beyond_one_pipe_read_is_read_completely(fake_docker):
    big = {"Padding": "x" * 300_000, "SecurityOptions": ["name=rootless"]}
    fake_docker.set_info(big)
    r = asyncio.run(DockerCli("unix:///fake.sock", str(fake_docker.binary)).call("info"))
    assert r.ok and len(r.stdout) > 300_000
