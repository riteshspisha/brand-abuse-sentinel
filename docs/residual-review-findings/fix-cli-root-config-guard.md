# Residual review findings: fix/cli-root-config-guard (2026-11-09)

The plan had a document review (coherence, feasibility, security, adversarial). The code
had a full-depth review (correctness, testing, maintainability, project standards,
security, adversarial, agent-native, learnings). Neither found a way past the guard. The
findings fixed were in the plan's test design and in documentation wording.

## Accepted limits

- **An explicit source can still name a relative location.** `-c` naming a file with no
  `data_dir` (or an empty file, or `/dev/null`), a relative `data_dir`, or a relative
  `BRANDSENTINEL_DATA_DIR` satisfies the guard and resolves against the
  working directory. This follows from the owner's decision on explicit sources. A test
  pins the behaviour. Enforcing an absolute production `-c` is backlog item B3.
- **The guard is a check, not a boundary.** It stops an accidental root invocation. A
  privileged user who deliberately enters a user namespace with a non-zero effective UID
  passes it, and the files stay owned by the real user.
- **The guard runs after import.** A root invocation can still write bytecode into the
  code tree, even when refused (backlog item B2).
- **Non-store commands still run as root,** and any non-root account can open a store it
  can write to (backlog item B3).
- **The classification test is a tripwire.** It follows bare-name calls within `cli.py`,
  so a store opened through an attribute call or another module would not be classified.
  The runtime tests cover the current commands.
- **Root is simulated in the suite** by patching `os.geteuid`. A real effective UID of 0
  was checked once by hand, in an unprivileged user namespace, on scratch paths.
- **A mistyped variable reads as a missing source.** `BRANDSENTINEL_CONFIGS` alone gets
  the no-configuration refusal rather than the unknown-variable error. It fails closed.
