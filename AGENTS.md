# AGENTS.md: working on BrandSentinel

This guide is for coding agents and new contributors who know nothing about this
project. It is meant to be enough to work safely without earlier conversations. When it
disagrees with the code, the code wins, and fixing this file is part of your change.

## 1. What this is

A local-first brand-abuse detection pipeline (Python 3.12, SQLite, rootless Docker
sandboxes). It discovers candidate domains, collects evidence without trusting them, and
ranks cases with explanations. Start with [README.md](README.md), then
[docs/concepts/architecture.md](docs/concepts/architecture.md).

## 2. Repository map and authoritative sources

| Path | What it is | Authority |
|---|---|---|
| `src/brandsentinel/` | the application (`cli.py` is the entry point) | **the behaviour** |
| `src/brandsentinel/store/migrations/` | numbered SQLite migrations (schema v5) | the schema |
| `config/policy.yaml`, `src/brandsentinel/policy/rules.py` | scoring points/thresholds and the rules | the scoring |
| `config/brandsentinel.example.yaml` | every configuration key with its default (validated by tests) | config reference |
| `config/service.yaml` | production configuration (installed read-only) | production; do not edit casually |
| `config/lab.yaml`, `labsites/`, `registry/lab-overlay.yaml` | the synthetic lab ("Lumina Foundation") | lab fixtures |
| `registry/brands.yaml` | the real Brand Registry (Isha ecosystem) | maintained by the organization |
| `tests/unit`, `tests/integration`, `tests/security`, `tests/lab` | pytest suites; markers in `pyproject.toml` | the evidence that code works |
| `docker/` | sandbox image, egress proxy and lab Compose files | the container runtime |
| `scripts/` | image build, disk budget, service-account install/validate | privileged operations |
| `docs/plans/` | design plans (product and planning contracts, requirement IDs R*, KTD*, AE*, U*) | design intent; check them against the code |
| `docs/runbooks/` | operational procedures and verification records | operations |
| `docs/solutions/`, `docs/residual-review-findings/` | lessons learned; accepted review limits per milestone | history |
| `legacy/` | the original proof of concept, **unmodified on purpose** | reference only; never edit |

Requirement IDs such as `R37`, `KTD13`, `AE18` or `U19` in code comments refer to
`docs/plans/2026-10-08-001-feat-brandsentinel-local-pipeline-plan.md`.

## 3. Invariants you must not break

1. **Every connection to an untrusted host** goes through `net/netguard.py` (public
   unicast only, ports 80/443, pinned DNS, per-hop redirect validation) and the hardened
   fetcher (`net/fetcher.py`: GET/HEAD only, no cookies, no proxy env, caps). Never add
   an HTTP client call that bypasses them.
2. **The host never decodes untrusted images or renders untrusted pages.** Images go to
   the media sandbox (`--network none`); pages render only in the browser sandbox, whose
   only way out is the egress proxy (`net/proxy.py`, which applies netguard again). A test
   asserts that the host does not import image libraries.
3. **Containers are rootless and locked down**: `--cap-drop ALL`, `no-new-privileges`,
   read-only root, limits, `--pull never`, labelled per instance (`sandbox/runner.py`).
   Every store-opening command refuses effective UID 0 and a missing configuration
   source (`cli.py: _load_for_store`), with no override. This is in the code here and
   **not yet installed in production**, and it does not check for the service account. Only `run` and `registry
   collect` also check the account. `run` refuses to start as the code owner or with
   rootful Docker access (unless `runtime.allow_developer_account` is set, development
   only). Its sandbox stages, and `registry collect` outside lab mode, also need clean
   checks with no override. **The non-store commands still run as root, and any non-root
   account can open a store it can write to**
   ([docs/concepts/security.md](docs/concepts/security.md#which-commands-enforce-it)).
4. **Observe only.** BrandSentinel never submits forms, logs in, pays or contacts a
   suspect site except to fetch it. The browser stops non-GET requests.
5. **Scoring is deterministic and explainable.** Every point cites evidence refs. Context
   labels never change a score. Page-provided signals are never relief. A priority is
   not a finding of fraud.
6. **Unknown is not benign.** Missing or failed evidence stays visible (`unknowns`,
   `needs_media`, `needs_render`). Never turn a failure into a clean result.
7. **Untrusted text is escaped everywhere**: terminal (`textsafe.py`), HTML (autoescape
   plus CSP), CSV (formula neutralizing). Logs carry no URLs, queries, page data or
   exception messages (job telemetry allowlist, `pipeline/orchestrator.py`).
8. **Stored scores are never rewritten.** Rescoring adds rows labelled with the policy
   and bundle versions. Bump `version:` in `config/policy.yaml` when you change a number.
9. **Exactly-once per (case, stage, round)**: facts and the `stage_runs` marker are
   written in one transaction. Delivery is at-least-once, so handlers must stay idempotent.

## 4. Setup and test workflow (developer machine)

```sh
uv sync                                                   # .venv from uv.lock, dev group included
uv run ruff check                                         # lint (also blocks Trojan-Source bidi characters)
uv run pytest -m "not docker and not lab and not models"  # ~1500 tests, ~1 min, no Docker, no network
uv run python docs/demo/offline_demo.py /tmp/bs-demo      # end-to-end demo on synthetic pages
```

- `-m security` runs the network-policy and fetcher suites against a local adversarial
  harness. Linux only, because it binds `127.77.0.0/24`.
- `-m "docker or security"` needs rootless Docker, the sandbox image and the lab stack
  (`docs/runbooks/sandbox.md`). It must pass with **zero skipped tests** for any change
  under `src/brandsentinel/net/` or `src/brandsentinel/sandbox/` (standing gate SP3).
- `-m models` needs Kev or Laya servers, which do not exist in this repository yet.

Always run CLI commands that touch a store with an explicit, scratch config:
`brandsentinel -c <scratch.yaml> ...`. Without `-c`, `$BRANDSENTINEL_CONFIG` or
`$BRANDSENTINEL_DATA_DIR` they refuse to run. A file with no `data_dir` still means
`./data`. Never point
a command at `/var/lib/brandsentinel/data`. **Inspection commands such as `status` and
`cases list` write, too.** Opening a store (`store/__init__.py: open_store`):

- creates the data directory and the database if they are missing;
- resets the directory to 0700 and switches the database to WAL;
- applies pending migrations;
- deletes unreferenced blobs older than one hour (`store/blobs.py: sweep_orphans`).

## 5. Development versus production

| | Development (your checkout) | Production (installed, owner-operated) |
|---|---|---|
| Code | the working tree | `/opt/brandsentinel`, root-owned, installed from a commit |
| Account | the developer, with `allow_developer_account: true` in a local config | dedicated `brandsentinel` account, its own rootless Docker |
| Data | `./data`, `data-lab/`, or a temp dir | `/var/lib/brandsentinel/data` (live store) |
| Config | your own file or `config/lab.yaml` | `config/service.yaml`, installed read-only |

Agents work in development only. Production state, its evidence and the trial tooling
live outside this repository and are operated by the owner.

## 6. Approval boundaries: never without explicit owner approval

- Anything under `/opt/brandsentinel*`, `/var/lib/brandsentinel`, `/var/backups/brandsentinel`,
  or the `brandsentinel` account (including `sudo`, `systemd-run -M`, `machinectl`).
- Any `brandsentinel` command against a production store or installation, **including
  `status` and `cases list`**. Production CLI use is by the owner, as the dedicated
  service account, with explicit `-c`, never through `sudo` as root
  ([docs/operations/deployment.md](docs/operations/deployment.md#production-cli-operations)).
- Starting live collection: `run` with CertStream or dnstwist, `sweep`, `submit` against
  real targets, `registry collect`, or `analyze` on real domains (these contact third
  parties).
- Any Docker action on the service account's daemon, and on your own daemon:
  `compose up/down`, retagging or removing images, `system prune`.
- Restores, rollbacks, migrations of a real store, and deleting evidence directories or
  backups.
- Promotions and other security-sensitive deployment actions: installing a new wheel or
  image, replacing the egress proxy, and changing production configuration, service units
  or sudo policy.
- Weakening a security control or test: removing a test from the SP3 gate, adding a skip,
  widening netguard, or relaxing container flags. Stop and ask instead.
- `git push`, merging PRs and publishing the documentation site.
- Changing `registry/brands.yaml` statuses. Brand and domain confirmation belongs to the
  organization.

Authorization is explicit and specific to the action. Approving a plan, a PR or an earlier
step does not authorize the next one. A workflow, a checklist or a passing test never
does.

## 7. Definition of done

Use this list to find gaps, not to replace judgment. A fully ticked list does not make a
change safe. If something looks wrong and no item covers it, stop and raise it. Apply
each item in proportion to the risk; "not applicable, because…" is a valid answer for all
but D8 and D9. Rationale: the
[post-I1 backlog](docs/plans/2026-11-09-001-post-i1-engineering-backlog.md).

| # | Item | What it means | Report |
|---|---|---|---|
| D1 | **Requirements and scope** | A plan in `docs/plans/`, or a bounded request with stop conditions, says what is wanted and what is not. The diff stays inside it, or the deviation is explained | the plan or request |
| D2 | **Trust boundaries** | Which boundary is touched (untrusted host, sandbox or container, privilege and account, the store, operator input)? Which section 3 invariant could break? Does every new failure fail closed? Is any privilege, egress, file write or dependency added? | the answers, or why none apply |
| D3 | **Adversarial and failure cases** | A boundary change has a test of the refused case and of hostile input, beside the positive test. Think through partial failure, interruption and concurrency | test names |
| D4 | **Tests and regressions** | Tests land with the code: `tests/unit` for pure logic, `tests/integration` for the queue, stages and store, `tests/security` for anything touching the network policy. A bug or security fix has a regression test **shown failing on the old code** | the failing result, then the passing one |
| D5 | **Implementation verified** | The smallest change that follows existing patterns, with abandoned attempts removed. `uv run ruff check` and the offline suite pass. Under `net/` or `sandbox/`, the `docker or security` gate passes with no skips; if you cannot run it, say so and do not claim it. Scoring changes bump the policy `version`, then run `tests/unit/test_policy*.py` and the lab expectations (`tests/unit/test_lab_fixtures.py`, `tests/lab/` with the lab stack) | commands, counts, commit, date (section 8) |
| D6 | **Observability** | A new failure mode has a named error and a stable exit code. Log fields stay on the allowlist (section 3, item 7). `status` shows new persistent state. Unknown stays visible | a test or sample output |
| D7 | **Documentation** | Updated in the same change (section 9), with `uv run pytest tests/unit/test_docs.py` and the strict site build passing | the changed pages |
| D8 | **Review** | `ce-code-review` or a human review of every non-mechanical diff, at full depth for a D2 change. Findings are fixed, or recorded in the PR's known residuals and in `docs/residual-review-findings/` | the review summary |
| D9 | **Operational acceptance and authorization** | What production needs is written down as a promotion item, and is never done as part of development. Section 6 applies throughout | the promotion item, or "none" |

CI (`.github/workflows/checks.yml`) runs lint and the D7 checks on every pull request. It
does not run the offline suite or the `docker or security` gate, so those stay your job.

### Four stages of "done"

Each stage claims nothing about the next one. Report the stage reached, and never round up.

| Stage | Reached when | Who | [Status](docs/project/status.md) level |
|---|---|---|---|
| **Development complete** | D1–D8 hold on a local branch, with evidence | developer or agent | Development-tested |
| **PR accepted** | reviewed and merged to `main` | owner | Implemented |
| **Production promoted** | installed through a gated promotion, with its evidence ([Deployment](docs/operations/deployment.md#promotion)) | owner | Production-accepted |
| **Operationally validated** | shown doing its real job in production, under a separate authorization | owner | Operational |

Passing tests, a merge or a promotion is not evidence for a later stage. An isolated-copy
trial shows only what it exercised.

### Working with Compound Engineering

These workflows organize the work. They grant no authority: section 6 overrides any
default of theirs. Plans are public, so they use repo-relative paths and contain no host
paths, evidence names or personal data.

| Need | Command | Use here |
|---|---|---|
| Scope is unclear | `ce-brainstorm` | requirements only |
| More than one module, or any boundary | `ce-plan`, then `ce-doc-review` | the review is required for a security plan. A one-file fix can be a bounded request |
| Implement | `ce-work mode:return-to-caller <plan-path>` | **the default.** Always name the plan: a blank invocation picks the newest one. Plain `ce-work` ends by pushing and opening a PR, so use it only when the owner has approved pushing that branch |
| Failing tests | `ce-debug` | |
| Isolate from the main checkout | `ce-worktree` | it may hold the owner's untracked files; leave them alone |
| Review | `ce-code-review` | run it yourself after return-to-caller, which skips it; `depth:full` for a D2 change |
| Commit | `ce-commit` | feature branches only, never `main` |
| Push and open a PR | `ce-commit-push-pr` | **only after the owner approves it for that branch** |
| Record a lesson | `ce-compound` | a flat `docs/solutions/YYYY-MM-DD-<slug>.md`, added to the `mkdocs.yml` navigation |
| Hands-off pipeline | `lfg` | **do not use**: it runs through to a pushed PR |

A bounded session: the owner approves the plan; implement; review; fix; commit locally;
report D1–D9 evidence and the stage reached; **stop**. Push, merge and promotion are the
owner's separate decisions. Production work stays outside these workflows, in the owner's
gated tooling.

## 8. Collecting and interpreting evidence

- Report exact commands, the commit, the pass/fail/skip counts and the date. "Passed"
  without counts is not evidence.
- Distinguish where something was verified: the developer's runtime, the service
  account, or production. Lab results come from synthetic pages; they say nothing about
  real-world detection rates.
- For case-level claims, use `cases show --json N` (bundle, policy result, evidence
  refs), not a summary line.
- Store evidence you produce outside the repository (or in the scratchpad your harness
  provides). Never overwrite an existing evidence directory.

## 9. Documentation

- Sources are Markdown under `docs/`, built with MkDocs Material (`mkdocs.yml`):
  `uv run --no-project --with-requirements docs/requirements.txt mkdocs build --strict`.
- `docs/reference/cli.md` is generated: `uv run python docs/tools/gen_cli_reference.py`.
- **Rule:** a change that affects public behaviour, configuration, architecture, security
  properties or deployment updates the relevant pages in the same change, and the
  project status page when maturity changes.
  `tests/unit/test_docs.py` catches:
  - a stale CLI reference;
  - commands or options in the docs that do not exist;
  - config examples that do not validate;
  - an example config missing a key;
  - broken repository links;
  - host-specific paths or personal data in published pages;
  - a command gaining or losing an account check without the security model's
    enforcement table changing with it.
- Never present a planned or pending capability as done.
  `docs/project/status.md` separates implemented, development-tested, production-accepted,
  experimental and planned.

## 10. Known traps

- Only `run` and `registry collect` check the account. The guard refuses root for
  store-opening commands only, and runs after import. Bytecode-write prevention (checked-hash
  precompilation and `-B` launchers, `scripts/service-account/harden-bytecode.sh`) is in the
  repository and **not installed in production**. It covers console scripts only and does not
  make the installation immutable. A command that succeeds tells you nothing about
  whether the account was right.
- `brandsentinel eval` is an unimplemented stub, and its message still says "planned for M8".
  The M8 that shipped is analyst render and telemetry; the decision-model work (U20/U21)
  is outstanding.
- The production Brand Registry has no confirmed domains or reference assets yet, so
  nothing is suppressed as official and visual matching is inert outside the lab.
- Lab mode refuses to start with CertStream or dnstwist enabled, and fetches only through
  the lab proxy on `127.0.0.1:3129`.
- SQLite is used from one asyncio thread. Don't share the connection across threads.
- The sandbox image contains the whole wheel. Any code change means a new image for
  production, which needs a separate, gated promotion.
