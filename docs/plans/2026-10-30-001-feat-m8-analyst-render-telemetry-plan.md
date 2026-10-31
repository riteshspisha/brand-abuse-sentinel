---
title: "M8 PR: analyst-requested rendering, render explanations, job telemetry, stop-on-idle"
date: 2026-10-30
status: plan (not implemented)
base: d3adbe9 (M7, deployed)
---

# M8 PR: analyst-requested rendering, render explanations, job telemetry, stop-on-idle

## Problem frame
The first supervised live trial (T1, `iamritesh.in`) and the lab trials (T2a-dev, T2a on the account) showed four gaps. All happened on M7 as deployed:
1. An analyst-submitted script-built page outside brand scope ends as `needs_render` with no render ever scheduled. The `js_shell` trigger requires a brand-matching domain, and the only other route is the 10% sample.
2. The case doesn't say why no render is coming.
3. The run log has almost nothing per job. T1 logged 5 records in 906 s, and stage attribution needed proxy logs and score sequences.
4. Bounded manual or lab runs sit idle until `--duration` ends: 6 s of work in a 900 s run.

Scope is these four, smallest coherent change each. **Out of scope:**
- the U20/U21 M8 items;
- new frameworks or new tables;
- discovery changes;
- registry and corpus work;
- SP2 and M9 supervision;
- any change to sandbox, proxy, netguard or limits.

## Architecture facts the design relies on (verified at d3adbe9)
- **`sandbox/triggers.py` `decide`** is pure. It skips official domains, cases without an OK static response, and a disabled browser. `js_shell` and `little_text` need `domain_match` strong or weak; `sample` covers strong cases at `browser.sample_rate`.
- **`pipeline/stages.py` `decide_render`** records exactly one `render_decision` fact per analysis round, inside `transaction()` (`BEGIN IMMEDIATE`, so writers serialize), and schedules the render job in that same transaction. It runs inside fetch handlers, which have 4 workers.
- **Rounds:** round 0 starts at ingest. Rounds 1 and 2 are the rechecks: `deferred_jobs` rows (`reason recheck`, future `not_before`, dedupe `enrich:case:N:rK`) created by the round-0 enrich handler.
- **Every handler schedules its successor before its own job completes:**
  - enrich → fetch;
  - fetch → media and render decisions;
  - render → screenshot media and scoring.

  So while a case still has work, at least one job is always `pending` or `running`. `scheduling.promote` moves due deferred rows into `jobs` atomically.
- **`Orchestrator.run_job`** is the single path for every job: claim → `_locked` → complete, `_fail` or lease lost.
- **`_fail` logs ERROR `job failed` with `error[:500]`.** For netguard refusals, the fetcher's error dict carries `"url": current[:2048]`, so URLs, queries included, can reach the log today.
- **Facts** are generic `(case_id, name, value_json, observed_at)`. No migration is needed.
- **Image impact:** the sandbox image installs the whole wheel (`docker/Dockerfile.sandbox`). This PR therefore changes the image, and deploying it is a **separate, gated M8 promotion**, following the M7 pattern. Nothing here touches the deployed M7.

## 1. Analyst-requested rendering: explicit, budgeted, no bypass
**Mechanism**
- `brandsentinel submit --render TARGET…` ingests as today, then writes one `render_request` fact `{round, requested_at, via: "cli"}` for the round the request applies to:
  - a **new case**: round 0;
  - an **open case whose current round already has a `render_decision`** (for example T1's case #1): the **next scheduled recheck round**. The case shows when that is due.
- **No new round is created, and recheck times never move.** That preserves the one-decision-per-round invariant and the recheck schedule.
  - Trade-off: an already-decided case renders only at its next recheck (about 1 day). An on-demand round is deferred: it needs round semantics for fingerprint comparison and adds a new scheduling path.

**`triggers.decide(…, analyst_request: bool, budget_left: bool)`**
- The existing skips run first and are unchanged:
  - `official_domain`;
  - `no_static_response`. The browser only renders a URL the hardened static fetcher already got an OK response for, through netguard. **This is the SSRF boundary**: private, loopback and metadata addresses, other ports, and credential URLs are refused before any render.
  - browser disabled.
- If requested, the budget is left, and no other reason applies, the reason is `analyst_request`.
- If requested and the budget is used up, the decision records `skipped: analyst_budget_exhausted`; it never silently drops the request.
- If another reason also applies, both are recorded. The budget is spent only when `analyst_request` is the reason that triggers the render.
- `triggers.VERSION` is bumped.

**Budget:** one new setting, `browser.analyst_renders_per_day`.
- Default **0**, meaning off. Enabling it in production is an explicit config decision. `config/lab.yaml` sets 5 for the lab tests.
- Counted inside `decide_render`'s existing `BEGIN IMMEDIATE` transaction: `render_decision` facts from the last 24 h whose `reasons` contain `analyst_request` (`json_each`). Concurrent fetch workers therefore can't overspend.
- **Rechecks don't inherit a request.** It is bound to one round.

**Unchanged:** the render job itself:
- `bs_sandbox` plus `bs-egress-proxy`: TLS-only CONNECT to 443, plain GET/HEAD, netguard on every hop;
- `browser.limits`: 60 s wall, 1.5 GiB, 512 pids, 300 requests, 15 s navigation;
- `stages.render: 1`, leases, 3 attempts.

**Files**
- `cli.py`: the `--render` flag; `submit` prints `render requested for round N (due …)`.
- `discovery/submit.py`: the request fact.
- `config.py`: `BrowserConfig.analyst_renders_per_day: int = Field(0, ge=0, le=1000)`.
- `sandbox/triggers.py`.
- `pipeline/stages.py` (`decide_render`: look up the request, apply the budget).
- `docs/runbooks/browser.md`.

## 2. Observable reason when `needs_render` has no scheduled render
`policy/scorer.py`, where `needs_render` is set: when `render.status == "not_triggered"`, also add the flag `render_not_scheduled`. The "unknowns" text then states `render.skipped` and what to do. Proposed wording:
- `no_trigger`: "js_shell renders automatically only on brand-matching domains; not in the sample; request with `submit --render`";
- `analyst_budget_exhausted`: "analyst render budget exhausted (N per 24 h)";
- `browser disabled`;
- if a request is pending for a future round: "render requested for round N".

This is explanation only, with no score or priority change, so `policy/5` is kept (`config/policy.yaml` only versions numbers). The text appears in `cases show` and in the `cases list` flags.

## 3. Minimal privacy-conscious job telemetry
**`Orchestrator.run_job`:** one INFO `job started` and one INFO `job finished` per job.
- Fields come from a fixed allowlist: `job`, `stage`, `case_id`, `round`, `attempt`, `domain` (the registrable domain, i.e. the group key), `outcome` (completed / retry / failed / lease_lost / cancelled), `duration_ms`.
- Built from the payload keys `case_id`, `round` and `registrable_domain`. Never `name` or `subject_url`, never `lease_token`, never error text.
- That gives the hostname-level "where" through `domain`, without paths, queries or page content.

**`_fail`'s ERROR `job failed`:** it keeps `job`, `stage`, `status` and `attempt`. `error` becomes `error_type` (exception class) plus, for `TransientFetchFailure`, its `outcome` (for example `timeout`).
- The full message stays in `jobs.last_error` in the store, as today, and no longer goes to the log.
- **Operator impact:** the trial classifier's single expected-error rule changes from `error` starting with `TransientFetchFailure:` to `error_type == "TransientFetchFailure"`. Documented in the runbook.

## 4. Optional stop-on-idle for bounded runs
**`brandsentinel run --until-idle`**
- Refused, exit 2, unless CertStream and dnstwist are both off for the run (flags or config). Continuous discovery is never "idle", so behaviour there is unchanged.
- `--duration` stays the hard bound.

**Idle**, from one read snapshot:
- no `jobs` row `pending` or `running` for a **registered** stage, whether due now or with a future `available_at` (a queued retry counts as outstanding work);
- and no `deferred_jobs` row with `not_before <= now`.

Future rechecks (future `not_before`) are ignored by construction and stay untouched. Pending jobs of **unregistered** stages (for example media while the sandbox is unavailable) never block, and are reported in the stop record, as today's design intends ("they wait for a restart").

**Race safety**
- Successors are enqueued before their predecessor completes, and promotion is atomic, so no gap exists inside a case's chain.
- The check must hold twice, with a settle interval of at least `promote_interval_seconds` + 2 × the largest `poll_seconds` (default 7 s) between, and only after startup (lease recovery, replay).
- On success it sets the existing `stop` event: workers are idle, so nothing is cancelled mid-job. The normal shutdown and maintenance path runs, and an INFO `run idle; stopping` lists the not-yet-due deferred count and any blocked stages.

**Files:** `cli.py` (flag and refusal), `pipeline/orchestrator.py` (`run_service(…, until_idle)` adds one task), and a small `idle_snapshot(conn, stages, now)` in `pipeline/scheduling.py`, beside `deferred_summary`.

## Test plan (developer host first; adversarial cases required)
**Render authorization (`tests/unit/test_triggers.py`, `tests/integration/test_render_pipeline.py`, `tests/unit/test_submit.py`, `tests/unit/test_cli.py`)**
- No flag: unchanged decisions. All existing trigger tests pass untouched.
- The flag on a non-brand JS shell gives `analyst_request`, and exactly one render job.
- Official domain plus a request: still skipped `official_domain`.
- No OK static response plus a request: `no_static_response`, and no render job.
- Browser disabled: no job.
- Budget 0 (the default): `analyst_budget_exhausted` and no job.
- An open case already decided: the request lands on the next recheck round, and recheck `not_before` values are unchanged.
- The request isn't reused on a later round. A request for a case that doesn't exist is rejected.

**SSRF boundaries (`tests/security/test_netguard.py`, `test_fetcher.py`, integration)**
- Requested targets resolving to 127.0.0.1, 169.254.169.254, RFC1918, `[::1]`, or port 8080 get no render. Neither does a URL with userinfo, which `submit` rejects.
- A redirect to a private address: the static fetch is refused and there is no render.
- Existing `tests/integration/test_browser_client.py::test_redirects_to_metadata…` stays green, without edits.

**Budget and concurrency**
- N+3 requested cases decided concurrently by 4 fetch workers on one store: exactly N triggered, the rest `analyst_budget_exhausted`, so no overspend.
- The 24 h window rolls with an injected clock.
- `stages.render` concurrency is still 1 under a burst.

**Sensitive-data logging (`tests/unit/test_logging.py`, `tests/integration/test_orchestrator.py`)**
- Submit `https://x.test/path?session=SECRET123#frag`, with fetch and render failing in various ways. Then:
  - no log record contains `SECRET123`, `session=`, `/path`, `lease_token` or page text;
  - lifecycle records carry only the allowlisted keys;
  - `job failed` carries `error_type`, never the message;
  - `jobs.last_error` still holds the full message.
- One start and one finish per job, including lease loss and cancellation.

**Idle races (`tests/integration/test_orchestrator.py`, `tests/integration/test_scheduling.py`)**
- A handler that enqueues its successor after a delay never yields a false idle.
- A deferred row becoming due during the settle window prevents the stop.
- A retry pending with a future `available_at` prevents the stop until done or `--duration`.
- After an idle stop:
  - recheck rows are byte-identical (dedupe keys, `not_before`);
  - no job is left `running`;
  - the store closes cleanly.
- Pending jobs of an unregistered stage don't block, and are reported.
- `--until-idle` with CertStream or dnstwist enabled exits 2 before opening the store.
- `--duration` still ends a run that never goes idle.

**Lab (docker) checks: extending existing tests, no new framework**
- In `tests/lab/test_browser_cases.py`, request a render for a non-brand static lab site (`unrelated-tourism`): render `complete` with reason `analyst_request`.
- With budget 0 in a config copy: `analyst_budget_exhausted` and the `render_not_scheduled` flag.
- `tests/lab/test_static_demo.py`: the `--until-idle` CLI run of the static sites ends on idle, well under `--duration`.

## Development and validation steps
1. Branch `feat/m8-analyst-render` from `main` (d3adbe9). Implement in this order, each with its tests: 3 (telemetry) → 2 (explanation) → 1 (requests and budget) → 4 (idle).
2. Developer gates: the full offline suite; `-m "security or docker"` on the developer daemon with **0 skipped**; the T2a-dev procedure (`--until-idle`) re-run against a scratch store, with `tools/t2a-check.py` still 28/28 for the two lab cases; and a new lab case for the analyst request.
3. Review: code review; confirm the default `analyst_renders_per_day: 0` and the classifier note in the runbook; update the handoff.
4. Deployment is **not** part of this PR. M8 needs its own gated promotion (new wheel and image, P1–P5 pattern, kit revision). Until then production stays on M7 d3adbe9, and the live store and its two rechecks stay as they are.

## Trade-offs
- **Request applies to the next round** rather than an on-demand round: smaller and invariant-preserving, but an already-decided case waits for its recheck.
- **Default budget 0:** safe and explicit, at the cost of one more config decision before analysts can use the feature in production.
- **Error text out of the log** (kept in the store): better privacy, at the cost of one classifier rule change for operators.
- **A queued retry blocks idle:** fewer surprises, so a bounded run may last until the retry or `--duration`.
- **Any code change means a new image:** unavoidable with the single-wheel image. Splitting host and worker packages would avoid it, but is not proposed here.
