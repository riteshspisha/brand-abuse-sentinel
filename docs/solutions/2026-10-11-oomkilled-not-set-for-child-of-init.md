# Docker does not flag OOMKilled when the kernel kills a child of `--init`

**Context.** Sandbox jobs run with `--init` (tini as PID 1) and a memory limit
without swap. The runner reports `oom` when `docker inspect` shows
`State.OOMKilled`.

**Problem.** A decompression bomb that passed the header checks (pixel cap
raised for the test) was killed by the kernel OOM killer every time, but the
result was `exit_error` with exit code 137 and `OOMKilled: false`, even after the
runner's three re-inspections. The OOM killer chose the worker (tini's child),
not the container's init process; tini then exits 137, and rootless Docker on
cgroup v2 sets OOMKilled only for an OOM kill of the init process.

**Fix.** The media client reports a SIGKILL that the runner did not send
(`exit_code == 137`, not `killed`) as `sandbox_killed` with the explanation, and
the case records the image as `media_rejected` either way (AE12). The runner's
own classification is unchanged. Test:
`tests/integration/test_media_sandbox.py::test_ae12_bomb_that_passes_the_header_check_...`.

**Lesson.** Treat exit 137 without a runner kill as "killed by a limit", not as a
crash, whatever the OOMKilled flag says.
