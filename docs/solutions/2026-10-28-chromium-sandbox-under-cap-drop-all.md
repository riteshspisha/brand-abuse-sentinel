# Chromium's own sandbox needs `clone`, `unshare` and `chroot` with `--cap-drop ALL`

**Context.** The browser container drops every capability and must keep
Chromium's internal sandbox (never `--no-sandbox`, never `SYS_ADMIN`).
Playwright publishes a seccomp profile for this.

**Problem.** Playwright's profile is an old copy of Docker's default plus
`clone`, `setns` and `unshare`. Under Docker's default profile Chromium crashed
at launch (SIGTRAP), and under a profile built from Docker's current default
plus Playwright's three syscalls the zygote failed with
`Check failed: sys_chroot("/proc/self/fdinfo/") == 0`. Docker generates its rules
from the container's capabilities: with `--cap-drop ALL`, the `chroot` rule
(gated on `CAP_SYS_CHROOT`) is dropped too. Playwright's instructions keep
Docker's default capabilities, which include `CAP_SYS_CHROOT`.

**Fix.** Docker's current default profile (`moby/profiles` `seccomp/v0.2.4`
for Docker 29.9.1) plus one unconditional rule for `clone`, `unshare` and
`chroot` (`src/brandsentinel/sandbox/chromium-seccomp.json`). Each is needed
(removing any one breaks the zygote); `setns` is not. Allowing the syscalls
grants nothing by itself: the kernel checks `CAP_SYS_CHROOT` in the caller's
user namespace, which only Chromium's new namespace has. Renderers then run in
their own user, PID and network namespaces (`brandsentinel sandbox selftest
browser`).

**Lesson.** A seccomp profile written for default capabilities can silently
depend on them. Test a profile with the capability set it will run with, and
take the base profile from the Docker version in use, not from a copy.
