# An unread attached stream makes `docker kill` hang

**Context.** The sandbox runner (M4) attaches to each job container
(`docker start --attach --interactive`) and stops reading stdout or stderr once a
cap is exceeded, then runs `docker kill --signal KILL <name>`.

**Problem.** On real (rootless) Docker the container died at once (exit 137), but
`docker kill` did not return until its 30 s timeout, and the job hung. dockerd
copies container output to the attached client; when nobody reads, that copy
blocks, and the kill request waits for the container's stream handling to finish.
A fake Docker CLI without back-pressure passed the same unit test.

**Fix.** From the moment the runner decides to stop (cap overflow, wall time, or
normal end), it keeps discarding both streams in background tasks until the CLI
exits (`sandbox/runner.py:_attach`, `_discard`). Kill and removal now take ~0.2 s.
The regression test is `tests/integration/test_runner.py::test_stdout_beyond_cap_...`
on real Docker; fakes cannot reproduce dockerd's back-pressure.

**Also.** Squid silently ignores an ACL entry that overlaps another one in the same
ACL (only a cache-log warning), so a hand-mirrored deny list can lose a range.
