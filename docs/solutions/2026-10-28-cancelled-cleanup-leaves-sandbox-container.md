# A shutdown during cleanup left a finished sandbox container behind

**Context.** `SandboxRunner._run` removes every job container in a `finally`
block, and the orchestrator stops by cancelling its stage workers.

**Problem.** The M6 lab demo, which stops the service as soon as media work is
done, left an exited browser container from a render that was still finishing.
Cancelling renders at 20 ms steps reproduced it in a window of about 40 ms: the
cancellation arrived while the job was already in `finally`, awaiting
`remove()`. `DockerCli.call` kills its CLI process on any `BaseException`, so the
interrupted `docker rm --force` never ran and nothing retried it. The startup
sweep and the in-container `timeout --signal=KILL` still bounded the orphan
(R49), but a clean shutdown should leave nothing.

**Fix.** `SandboxRunner._remove_despite_cancel`: run `remove()` as its own task,
await it through `asyncio.shield`, and on `CancelledError` wait for the removal
to finish before re-raising. `docker rm --force` also stops a running container,
so this covers jobs cancelled at any point. Regression:
`tests/integration/test_runner.py::test_a_shutdown_during_removal_still_removes_the_container`
(delays the first `rm` and cancels inside it; fails on the old code).

**Lesson.** Cleanup that awaits can itself be cancelled. When the cleanup
releases an external resource, shield it and finish it before propagating.
