"""Sandbox runner against the real rootless runtime (U23, R49, AE18).

These prove the limits are enforced by the runtime, not just requested: a memory
hog is OOM-killed, a fork bomb is held at the PID limit, wall time and output
caps kill the container by name, and orphans from a crashed application are
removed before work resumes.
"""

import asyncio
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from tests.docker_support import (
    INSTANCE,
    REPO,
    job_id,
    labelled,
    make_runner,
    probe,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import SandboxLimits, SandboxSettings
from brandsentinel.pipeline.orchestrator import Orchestrator
from brandsentinel.sandbox.runner import SandboxRunner, SandboxSpec

pytestmark = [pytest.mark.docker, pytest.mark.security]


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    yield d
    leftovers = labelled(d)
    if leftovers:
        d.call_sync("rm", "--force", *leftovers)
    assert leftovers == [], f"labelled containers left behind: {leftovers}"


def py(code: str, **kw) -> SandboxSpec:
    return SandboxSpec(role="media", command=("python3", "-c", textwrap.dedent(code)), **kw)


def run(runner, spec, stdin=b""):
    return asyncio.run(runner.run(spec, job=job_id(), attempt=0, stdin=stdin))


def test_container_runs_unprivileged_read_only_without_capabilities_or_network(docker):
    out = probe(make_runner(docker), "none", [{"id": "f", "kind": "facts"}])["f"]
    assert out["uid"] != 0
    assert int(out["cap_eff"], 16) == 0 and int(out["cap_bnd"], 16) == 0
    assert out["no_new_privs"] == "1" and out["seccomp"] == "2"  # seccomp filter mode
    assert out["root_writable"] is False and out["tmp_exec"] is False
    assert out["interfaces"] == ["lo"] and out["docker_sock"] is False


def test_memory_hog_is_killed_by_the_memory_limit(docker):
    runner = make_runner(docker, memory_mb=64)
    r = run(runner, py("blocks = []\nwhile True:\n    blocks.append(bytearray(8 * 1024 * 1024))"))
    # The kernel killed it (SIGKILL, not the runner) long before the wall time.
    assert r.exit_code == 137 and not r.killed and r.removed, r.summary()
    assert r.elapsed_ms < 30_000
    # Docker's OOMKilled flag trails the exit (the runner re-inspects); it is
    # reported as an OOM whenever Docker has recorded it.
    assert r.status == "oom" if r.oom_killed else r.status == "exit_error", r.summary()


def test_fork_bomb_is_held_at_the_pid_limit(docker):
    code = """
        import json, os, time
        children = 0
        for _ in range(500):
            try:
                pid = os.fork()
            except OSError:
                break
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children += 1
        print(json.dumps({"children": children}))
        os._exit(0)
    """
    r = run(make_runner(docker, pids=32), py(code))
    assert r.status == "ok", r.summary()
    assert r.output["children"] < 32  # fork failed at the limit, far below 500


def test_wall_time_expiry_kills_by_name_and_leaves_no_container(docker):
    runner = make_runner(docker, wall_seconds=3)
    start = time.monotonic()
    r = run(runner, py("import time\ntime.sleep(120)"))
    assert r.status == "timeout" and r.killed and r.removed
    assert time.monotonic() - start < 30
    assert r.name not in labelled(docker)


def test_stdout_beyond_cap_is_rejected_and_the_container_killed(docker):
    runner = make_runner(docker, stdout_max_bytes=1024 * 1024)
    r = run(runner, py("import sys\nwhile True:\n    sys.stdout.write('x' * 65536)"))
    assert r.status == "stdout_overflow" and r.killed and r.removed
    assert r.name not in labelled(docker)


def test_stderr_flood_beyond_cap_is_rejected_and_the_container_killed(docker):
    runner = make_runner(docker, stderr_max_bytes=16 * 1024)
    r = run(runner, py("import sys\nwhile True:\n    sys.stderr.write('e' * 65536)"))
    assert r.status == "stderr_overflow" and r.killed and r.removed


def test_job_input_and_output_round_trip(docker):
    r = run(
        make_runner(docker),
        py("import json, sys\nprint(json.dumps({'n': len(sys.stdin.buffer.read())}))"),
        stdin=b"x" * 300_000,
    )
    assert r.status == "ok" and r.output == {"n": 300_000}


CRASHING_APP = """
import asyncio, sys
from brandsentinel.config import SandboxSettings
from brandsentinel.sandbox.runner import DockerCli, SandboxRunner, SandboxSpec
runner = SandboxRunner(SandboxSettings(instance=sys.argv[1]), DockerCli())
spec = SandboxSpec(role="browser", command=("sleep", "300"))
asyncio.run(runner.run(spec, job=sys.argv[2], attempt=1))
"""


def start_crashing_app(instance: str, job: str) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", CRASHING_APP, instance, job],
        cwd=REPO,
        start_new_session=True,
    )


def test_restart_removes_the_orphaned_container_before_jobs_are_recovered(docker, store):
    # Covers AE18: the application is killed while a sandbox job runs.
    job = job_id("ae18")
    app = start_crashing_app(INSTANCE, job)
    name = f"bs-{INSTANCE}-browser-{job}-1"
    try:
        wait_running(docker, name)
        os.killpg(app.pid, signal.SIGKILL)  # the app and its docker CLI die at once
        app.wait()
        assert name in labelled(docker)  # the container outlived the application

        runner = SandboxRunner(SandboxSettings(instance=INSTANCE), docker)
        seen_at_recovery = []
        orch = Orchestrator(store)
        orch.startup_hooks.insert(0, runner.sweep_orphans)
        real_recover = store.jobs.recover_expired

        def recover():
            seen_at_recovery.append(labelled(docker))
            return real_recover()

        store.jobs.recover_expired = recover
        orch.startup()
        assert seen_at_recovery == [[]]  # removed before any lease was recovered
    finally:
        if app.poll() is None:
            os.killpg(app.pid, signal.SIGKILL)
        docker.call_sync("rm", "--force", name)


def test_orphan_sweep_leaves_another_instances_containers_running(docker):
    other = "testother"
    job = job_id("other")
    app = start_crashing_app(other, job)
    name = f"bs-{other}-browser-{job}-1"
    try:
        wait_running(docker, name)
        SandboxRunner(SandboxSettings(instance=INSTANCE), docker).sweep_orphans()
        assert name in labelled(docker, other)
    finally:
        os.killpg(app.pid, signal.SIGKILL)
        app.wait()
        docker.call_sync("rm", "--force", name)
    assert labelled(docker, other) == []


def test_retry_removes_the_earlier_attempts_container_first(docker):
    job = job_id("retry")
    app = start_crashing_app(INSTANCE, job)
    first = f"bs-{INSTANCE}-browser-{job}-1"
    try:
        wait_running(docker, first)
        os.killpg(app.pid, signal.SIGKILL)
        app.wait()
        runner = SandboxRunner(
            SandboxSettings(instance=INSTANCE, limits=SandboxLimits(wall_seconds=30)), docker
        )
        spec = SandboxSpec(role="browser", command=("python3", "-c", "print('{}')"))
        r = asyncio.run(runner.run(spec, job=job, attempt=2))
        assert r.status == "ok"
        assert first not in labelled(docker)  # only one container per job, ever
    finally:
        docker.call_sync("rm", "--force", first)
