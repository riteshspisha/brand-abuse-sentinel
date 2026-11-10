# Residual findings: installation bytecode hardening (B2)

Accepted limits after a full-depth review. The control is bytecode-write prevention. It is not installation immutability.

- **Root can still change the tree.** Non-Python writes and deliberate changes are unaffected. Kernel-level immutability is owner decision O5.
- **Other root entry points.** The bare interpreter, base-interpreter `bin/` wrappers and children started through `sys.executable` without `-B` (for example `sandbox/netns.py`) rely on precompilation alone, so they can regenerate a damaged or missing `.pyc`. `python -O` writes optimized bytecode even on an intact tree.
- **A pass is point-in-time.** A root run through a hardened launcher leaves no trace, so a pass is not evidence that no root run occurred.
- **Native files and activation scripts** in `venv/bin` are accepted by file type or name and are not inspected further.
- **Simulated root.** Tests use a user namespace over test-owned files. Behaviour on a real root-owned tree is a B7 acceptance item.
- **Skips.** Installed-layout tests skip without `uv` or user namespaces. A promotion gate must set `REQUIRE_INSTALLED_LAYOUT=1`.
- **`INSTALL` durability.** The record is published by rename without `fsync`. A power loss could leave an empty record, which `validate.sh` accepts only as present; the verifier still runs.
- **A failed install** leaves a non-empty prefix with no record and must be rebuilt from an empty directory.
