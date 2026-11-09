---
title: CLI root and configuration guard - Plan
type: fix
date: 2026-11-09
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-plan-bootstrap
execution: code
origin: docs/plans/2026-11-09-001-post-i1-engineering-backlog.md
---

# CLI root and configuration guard - Plan

## Goal Capsule

- **Objective:** every BrandSentinel command that opens a store refuses, before any store is opened or created, when it runs as UID 0 or without an explicit configuration source. This removes both mechanisms of the 2026-11-06 incident from the CLI: a root-owned write into the live store, and a stray `./data` store.
- **Authority:**
  1. this plan;
  2. `AGENTS.md` (§3 invariants, §6 approval boundaries);
  3. the security model, `docs/concepts/security.md`;
  4. backlog item B1 in `docs/plans/2026-11-09-001-post-i1-engineering-backlog.md`.
- **Decisions D1 and D2 (below)** are the planner's recommendations. The owner confirms them when reviewing this plan. If either changes, revise the plan before `ce-work` starts.
- **Stop and ask if:**
  - the work needs a change under `src/brandsentinel/net/` or `src/brandsentinel/sandbox/`;
  - a root override seems necessary;
  - `run`'s existing exit codes or account checks would change;
  - a test would have to be skipped, deleted or loosened;
  - any push, PR, merge, or production or installation action comes up.
- **Execution profile:** inline, serial, two units. Invoke as `ce-work mode:return-to-caller docs/plans/2026-11-09-002-cli-root-and-config-guard-plan.md`.
- **Tail ownership:** the owner. After local verification: `ce-code-review` with `depth:full` (a privilege boundary), fixes, a local commit with `ce-commit`, then stop. No push or PR without the owner's word.

## Product Contract

### Summary
Fifteen commands open a store:
- `status`, `run`, `submit`, `sweep`, `replay`, `analyze`;
- `cases list`, `cases show`, `cases label`, `cases rescore`;
- `report`, `export csv`;
- `registry collect`, `registry corpus`.

Today, of these, only `run` and `registry collect` check the account. Every one of them runs as root. Without `-c` or an environment variable, every one creates `./data` in the current directory.

After this change, all fifteen refuse both conditions with exit 2 and a one-line message, before reading or creating anything under the data directory. Commands that do not open a store are unchanged:
- `version`, `match`, `eval`;
- `registry validate`;
- `sandbox check`, `sandbox selftest`, `sandbox sweep`;
- `proxy`.

### Problem Frame
**What the incident showed.** The installed CLI was run through `sudo` as root:
- a `submit` wrote root-owned rows and a raw-log segment into the live store;
- a `cases list` without `-c` created a second store inside the installation tree.

The procedural rule in `docs/operations/deployment.md` did not prevent it. The guard makes the rule mechanical.

### Requirements

**Refusing root**
- R1. A store-opening command run with an effective UID of 0 exits 2 before any store is opened or created. The message names the cause and the remedy (run as the service account in production, or as yourself in development), and prints no paths from the configuration.
- R2. There is no override: no flag, no environment variable, no configuration key (D1).

**Requiring an explicit configuration source**
- R3. A store-opening command exits 2 before any store is opened or created when none of these is given: `-c`/`--config`, a non-empty `BRANDSENTINEL_CONFIG`, or a non-empty `BRANDSENTINEL_DATA_DIR` (D2). The message says that the default would create `./data` and that `-c` is required.
- R4. With an explicit source, behaviour is unchanged. That includes a relative `data_dir` inside a configuration file (`config/lab.yaml`).

**Order and scope**
- R5. The root check runs before the configuration check, and both run before configuration loading has any effect on the filesystem. Neither creates `./data`, the configured `data_dir`, or any file.
- R6. `run` and `registry collect` keep their existing account checks, messages and exit codes. The new refusal comes first.
- R7. Non-store commands behave exactly as before, including as root.

**Documentation**
- R8. The security model's enforcement table, `AGENTS.md` (§3 invariant 3, §4, §10), `README.md` if it states the old behaviour, `docs/operations/deployment.md` (production CLI rules), status and roadmap all describe the new behaviour in the same change. The CLI reference is regenerated if the help text changes.

### Acceptance Examples
- AE1. `sudo brandsentinel -c /opt/brandsentinel/etc/service.yaml cases list` → exit 2, the "refusing to open a store as root" message, and no write.
- AE2. `cd /tmp/x && brandsentinel cases list` → exit 2, the "no configuration" message, and no `/tmp/x/data`.
- AE3. `brandsentinel -c config/lab.yaml status` as the developer → as today.
- AE4. `sudo brandsentinel version` and `sudo brandsentinel match example.org` → as today.

### Scope Boundaries
- **Out of scope** (each is a separate backlog item):
  - refusing the code owner or a rootful-Docker user on a production store (B3, owner decision O2);
  - bytecode written at import time before the guard runs (B2, installer);
  - a guard in library entry points other than the CLI. Python code importing `brandsentinel.store` directly is not covered, which is accepted;
  - `sandbox sweep` as root (SP2 area).
- **Not changed:** the meaning of `BRANDSENTINEL_*` variables; `load_config` semantics for non-store commands.

### Outstanding Questions
- **Deferred (non-blocking):** whether a later revision should resolve a relative `data_dir` against the configuration file's directory instead of the working directory. That would be a behaviour change for `config/lab.yaml` users; record it in the residuals if review raises it.

## Planning Contract

### Key Technical Decisions
- **D1: no root override (recommended).**
  - Root has no legitimate use of a store-opening command. Recovery and forensics read stores as bytes, never through the CLI (`docs/operations/deployment.md`).
  - An override variable would contradict `load_config`'s rule that only path variables are accepted from the environment, and it is easy to paste.
  - *Rejected alternative:* `BRANDSENTINEL_ALLOW_ROOT=1`.
- **D2: the explicit sources are `-c`, `BRANDSENTINEL_CONFIG` and `BRANDSENTINEL_DATA_DIR` (recommended).**
  - All three are deliberate choices of a store location.
  - The existing tests and the offline demo use them, as does the I1-style operator tooling (`-c`).
  - *Rejected alternative:* requiring `-c` only. It would break documented and tested `BRANDSENTINEL_DATA_DIR` use with no security gain.
- **Effective UID** (`os.geteuid()`), read through one module-level function so tests can inject it. sudo sets both IDs, so either would do; the effective UID is what governs file ownership.
- **One entry point.** A helper (working name `_load_for_store(ctx)`) performs the root check, then the configuration-source check, then returns `_load(ctx)`.
  - Every store-opening command calls it instead of `_load`.
  - `open_store` itself is not changed: library and test callers keep working, and the guard stays a CLI policy.
- **Exit code 2,** the same as `run`'s refusal and `_load`'s configuration errors. Messages go to stderr, escaped with `escape_terminal`.

### Implementation Constraints
- No change under `net/` or `sandbox/`. `sandbox/preflight.py` `check_account` is not modified.
- Test changes add explicit configuration to tests that relied on the implicit `./data`. They never skip, delete or loosen an assertion.

### Sequencing
U1 (code and tests), then U2 (documentation and the docs test). One commit each, or one combined commit if the docs test fails without both.

## Implementation Units

### U1. Guard helper and wiring
- **Goal:** R1–R7.
- **Files:** `src/brandsentinel/cli.py`; a new `tests/unit/test_cli_guard.py`; existing tests under `tests/` that call a store-opening command with no explicit source, if any.
- **Approach:**
  - Add the helper beside `_load`. Replace `_load(ctx)` with it in the 15 store-opening commands listed in the Summary.
  - Leave `run`'s and `registry collect`'s existing account checks after it, unchanged.
- **Test scenarios:**
  - For each of the 15 commands, parametrized:
    - as an injected euid 0 with a valid temporary `-c` → exit 2, and neither the configured `data_dir` nor `./data` (cwd = a temporary directory) exists afterwards;
    - with no source (both variables removed, cwd = a temporary directory) → exit 2, and no `./data`;
    - with an empty `BRANDSENTINEL_CONFIG` and nothing else → exit 2.
  - With euid 0 and no source, the root message wins.
  - `open_store` patched to raise → never reached in the refused cases.
  - **Non-store commands as euid 0:** `version`, `match` and `registry validate --path …` succeed as before (R7).
  - **Positive:** `status` with `-c` (temporary config), with `BRANDSENTINEL_CONFIG`, and with `BRANDSENTINEL_DATA_DIR` → exit 0 and a schema v5 store.
  - **Structural:** every leaf command whose body references `open_store` also references the helper and does not call `_load` directly; and the set of such commands equals the 15 above. A new store-opening command without the guard fails the test.
- **Verification:** the new tests fail on the parent commit (record the failing count), then pass; the offline suite passes.

### U2. Documentation in the same change
- **Goal:** R8.
- **Files:**
  - `docs/concepts/security.md` (the enforcement table and the paragraph after it);
  - `AGENTS.md` §3, §4, §10;
  - `docs/operations/deployment.md` (production CLI operations);
  - `docs/project/status.md`, `docs/project/roadmap.md` (item 1 to implemented, not accepted);
  - `README.md` if it states the old behaviour;
  - `tests/unit/test_docs.py`;
  - `docs/reference/cli.md` (regenerate if the help text changed).
- **Approach:**
  - **The table:** add a column, or a line, stating that all 15 store-opening commands refuse root and a missing configuration source. The account checks of `run` and `registry collect` are unchanged.
  - **The docs test:** recognize the helper as a documented gate for those commands; the table must still list every command.
  - **The procedural rule stays** in deployment.md: still never `sudo` as root. Add that the CLI now refuses root, and that this does not make a root run safe, because the bytecode issue is B2.
- **Test scenarios:** `tests/unit/test_docs.py` passes, including the enforcement test.
- **Verification:** the strict site build passes.

## Verification Contract
| Gate | Command | Expectation |
|---|---|---|
| Lint | `uv run ruff check` | clean |
| New tests on the old code | `git stash` the `cli.py` change or check out the parent, then `uv run pytest tests/unit/test_cli_guard.py` | fail (count recorded) |
| Offline suite | `uv run pytest -m "not docker and not lab and not models"` | all pass; counts, commit and date reported. The one existing skip stays the only skip |
| Docs | `uv run pytest tests/unit/test_docs.py` | pass |
| CLI reference | `uv run python docs/tools/gen_cli_reference.py`, then `git diff --exit-code docs/reference/cli.md` | no diff left |
| Site | `uv run --no-project --with-requirements docs/requirements.txt mkdocs build --strict` | pass |
| SP3 | not required: no change under `net/` or `sandbox/`. State this in the report | |

No BrandSentinel command is run against any real store. Every test uses temporary directories.

## Definition of Done
- R1–R8 are met. U1 and U2 are verified as above, with counts, commit and date reported.
- **Threat-boundary note in the report:**
  - **boundary:** privilege and the store;
  - **invariant:** §3 item 3, which this strengthens;
  - **failure mode:** fail-closed, exit 2;
  - **new privilege, egress or dependency:** none;
  - **logs:** none added.
- `ce-code-review depth:full` has run, and its findings are fixed or recorded as Known Residuals.
- **Cleanup:** no experimental code or unused helper left in the diff.
- **Local commits on a feature branch only.** The owner decides push, PR, merge and the later gated promotion (B7).
