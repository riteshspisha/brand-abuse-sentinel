# Residual review findings: production-store enforcement (B3, 2026-11-10)

The plan had three document reviews; the code had a full-depth review (correctness,
security, adversarial, reliability, testing, maintainability, project standards,
learnings, agent-native). Fixed from the code review, each with a regression test shown
failing first:

- a data directory written as `<dir>/<symlink>/..` was collapsed lexically and classified
  by the wrong directory, so it could reach the live store as a development store
  (security, P1). Classification now resolves the path as the kernel does;
- the configuration was opened non-blocking, closed and reopened for a non-regular file,
  which could close a descriptor twice or lose a FIFO's writer and hang. It is now opened
  exactly once, as before;
- a refusal from the store layer's repeated check, an `OSError` while deciding (an I/O
  error, a deleted working directory), a deeply nested anchor or marker, and an
  unreadable `sys.path` entry escaped as tracebacks. Each is now a named exit-2 refusal;
- `check_anchor.py` honoured `$BRANDSENTINEL_CONFIG` and `$BRANDSENTINEL_DATA_DIR`, so
  its comparison could judge the wrong file. It now refuses to run with them set.

## Accepted limits

- **Accident controls, not a boundary.** A deliberate service account or root can defeat
  every check: copy the bytes, remove the marker, use code without B3, or edit the store.
  File permissions are the boundary between accounts.
- **The marker is a misuse signal.** It can be removed by whoever writes the directory.
  Database-only copies (`.backup`, `VACUUM INTO`, `cp brandsentinel.db`), copies that skip
  it, and copies made before the live store was marked are development stores elsewhere.
- **Check, then open.** The checks and the SQLite open are separate system calls. The
  authorization binds the store's device and inode and `open_store` repeats the checks,
  but a swap in the remaining window needs write access to an account-owned directory.
  Links created after a store is opened, during a long `run`, are not seen.
- **Root ownership is simulated in the offline suite.** The user-namespace tests prove
  real ownership where namespaces with subordinate IDs exist; `REQUIRE_USERNS=1` makes an
  unavailable namespace a failure. Behaviour on the production host is a B7 item.
- **Subprocess tests read the host's anchor and installation**, unlike in-process tests.
- **One anchor governs the host.** A malformed anchor refuses every store command,
  development included; installed code with no anchor refuses them all. A deliberate
  account able to mount over `/etc/brandsentinel` in a user namespace can hide the anchor
  from a checkout; the marker then still applies.
- **The device-and-inode signal** is skipped when the caller cannot reach the live store
  (the developer behind the 0700 home); the lexical and resolved-path signals still apply.
- **Only the configuration file's own directory** is checked for ownership, not its
  whole chain; `/opt/brandsentinel` is root-owned by the installation.
- **A development data directory that is itself a symlink** is accepted: it opens the
  store it names. Only its contents are checked.
- **Not checked:** `DOCKER_HOST`, `XDG_RUNTIME_DIR`, `PATH`, `HOME`, `LD_PRELOAD`; report
  and export destinations; hard links to existing report files.
- **The classification tripwire** follows bare-name calls in `cli.py` (B1's limit). The
  structural tests now also require every store command to open through `_open_store`.
- **`store check` prints text, not JSON**; an agent reads the check names from stderr.
- **A FIFO given as `-c` blocks until a writer appears**, as it always has; it is then
  refused at the production store (`config_not_regular`).

## Not run

The `docker or security` gate (SP3) was not run: nothing under `net/` or `sandbox/`
changed, and Docker needs separate approval.
