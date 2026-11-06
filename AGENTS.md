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
   The application refuses to run as root or with rootful Docker access, unless
   `runtime.allow_developer_account` is set, which is for development only.
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
uv run pytest -m "not docker and not lab and not models"  # ~1350 tests, ~1 min, no Docker, no network
uv run python docs/demo/offline_demo.py /tmp/bs-demo      # end-to-end demo on synthetic pages
```

- `-m security` runs the network-policy and fetcher suites against a local adversarial
  harness. Linux only, because it binds `127.77.0.0/24`.
- `-m "docker or security"` needs rootless Docker, the sandbox image and the lab stack
  (`docs/runbooks/sandbox.md`). It must pass with **zero skipped tests** for any change
  under `src/brandsentinel/net/` or `src/brandsentinel/sandbox/` (standing gate SP3).
- `-m models` needs Kev or Laya servers, which do not exist in this repository yet.

Always run CLI commands that touch a store with an explicit, scratch config:
`brandsentinel -c <scratch.yaml> ...`. The default `data_dir` is `./data`. Never point
a command at `/var/lib/brandsentinel/data`. Note that **every store-opening command,
including read-only ones such as `status` and `cases list`, deletes unreferenced blobs
older than one hour** (`store/blobs.py: sweep_orphans`).

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
- Starting live collection: `run` with CertStream or dnstwist, `sweep`, `submit` against
  real targets, `registry collect`, or `analyze` on real domains (these contact third
  parties).
- Any Docker action on the service account's daemon, and on your own daemon:
  `compose up/down`, retagging or removing images, `system prune`.
- Restores, rollbacks, migrations of a real store, and deleting evidence directories or
  backups.
- Weakening a security control or test: removing a test from the SP3 gate, adding a skip,
  widening netguard, or relaxing container flags. Stop and ask instead.
- `git push`, merging PRs and publishing the documentation site.
- Changing `registry/brands.yaml` statuses. Brand and domain confirmation belongs to the
  organization.

## 7. How to validate a change

1. `uv run ruff check` and the offline suite pass.
2. Add tests next to the code you change (`tests/unit` for pure logic,
   `tests/integration` for the queue, stages and store, `tests/security` for anything
   touching the network policy). Regression tests should fail on the old code.
3. Under `net/` or `sandbox/`: run the `docker or security` gate with no skips. If you
   cannot (no Docker), say so explicitly in your report. Do not claim the gate.
4. Scoring changes: bump the policy `version`, then run `tests/unit/test_policy*.py` and
   the lab expectations (`tests/unit/test_lab_fixtures.py`, `tests/lab/` with the lab stack).
5. Documentation: `uv run pytest tests/unit/test_docs.py` and the strict site build
   (section 9).

CI (`.github/workflows/checks.yml`) runs steps 1 and 5 on every pull request. It does not
run the `docker or security` gate, so step 3 stays your job.

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
  - host-specific paths or personal data in published pages.
- Never present a planned or pending capability as done.
  `docs/project/status.md` separates implemented, development-tested, production-accepted,
  experimental and planned.

## 10. Known traps

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
