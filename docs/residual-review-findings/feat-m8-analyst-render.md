# Residual review findings: feat/m8-analyst-render (2026-10-30)

The review covered correctness, security, adversarial and testing. One finding
was fixed (`9905f80`): a render request could bind to a round that never
decides, and that stranded request blocked later ones. It was found
independently by correctness and adversarial, and confirmed by experiment.
Testing gaps that were raised and closed: the refusal paths, render
concurrency 1, and per-target SSRF stop points. The security review found
nothing in the diff.

## Deviations from the plan

- **Round binding.** The plan's "first round without a decision" became "the
  next round after every decided one that can still decide (its work is
  queued)". The plan's version could strand a request.
- **Analyst keys.** They appear in `render_decision` only when a request
  exists, so decisions without a request are unchanged apart from
  `render_decision/2`.
- **Budget count.** It uses an `analyst_budget_spent` flag on the decision,
  not `json_each` over `reasons`. Searching only escalated cases keeps it on
  the facts index.
- **No bundle bump (pre-merge review).** An earlier revision bumped to
  `bundle/5` for two display fields. M7 could then read no case M8 had scored
  (schema-version `ValidationError`) until an M7 rescore. The fields were
  removed: pending requests are shown by the triage layer from facts, and the
  budget explanation names the setting, not its value. Verified across
  versions: the M7 code at `d3adbe9` reads and rescores M8-written stores with
  identical results, and M8 reads M7-written stores.
- **Browser disabled.** With a request and the browser disabled, the decision
  is recorded as triggered and `disabled`, and spends no budget. It is not
  `analyst_budget_exhausted`.
- **Other job-path error logs.** Beyond `job failed`, these error records also
  dropped their messages and tracebacks: `could not record job failure`,
  `stage worker error`, task crash, lease renewal, media/render decision,
  scoring, render processing, and invalid browser/media worker output. A
  chained traceback would repeat a URL. They carry `error_type` and `error_at`
  (code locations) instead.
- **`fetch_outcome`.** `job failed` names the fetch outcome `fetch_outcome`,
  so it is not confused with the lifecycle `outcome`.
- **Lab site.** The analyst-request lab case uses `unrelated-yoga`, not
  `unrelated-tourism`. Tourism is a weak brand match with little text, so it
  renders without any request.
- **No lab flag check.** The `render_not_scheduled` flag is not asserted in
  lab: no lab site is a non-brand JS shell. The integration tests cover it,
  against the harness through the real fetch path.

## Residual risks (accepted, not fixed here)

1. **Budget timing.** The budget is spent when the round decides. A request
   bound to a recheck is charged on that day, so several rechecks falling due
   on one day can exhaust it together. A render that fails later neither
   refunds nor re-spends the budget.
2. **Escalation invariant.** `analyst_renders` counts only cases with
   `escalated = 1`. That holds because `submit` is the only writer of
   requests and escalates in the same transaction, and nothing de-escalates.
   A future second writer, or a de-escalation path, must revisit the count.
3. **Unchanged M7 logs.** Logs outside the job path still carry exception
   text: `net/proxy.py` `log.exception("proxy connection error")` (egress
   proxy container), discovery `log.exception` sites, and the sandbox
   runner's `result.error` in `sandbox job finished`. `JsonFormatter` still
   formats `exc_info` for any future `log.exception`.
4. **Host as `domain`.** `domain` falls back to the group key, which is the
   host when there is no registrable domain (the host is itself a public
   suffix).
5. **Outcome label on cancel.** A `CancelledError` while `run_job` waits for
   the renewer after a recorded failure labels the finished record
   `cancelled`. The failure itself is stored correctly.
6. **Replay race.** If a starting service replays the discovery log and
   ingests the `submit --render` event first, `submit` sees a duplicate and
   refuses the request ("no case was opened"). Re-submitting works.
7. **`--until-idle` with other processes.**
   - It waits on running jobs owned by another process sharing the store.
   - A job that process enqueues between the final look and shutdown can be
     claimed and cancelled; lease recovery covers it.
   - Due deferred work that promotion can never move (an allowance of 0)
     holds the run until `--duration`.
8. **Timing-based tests.** The idle tests use short wall-clock windows
   (0.03 to 0.6 s) and could flake on a heavily loaded host.
9. **No automated T2a checker.** The pinned T2a checker is not part of the
   test suite; it is run by hand against the T2a-dev evidence.

## Pre-merge review (2026-10-31)

- **Rollback boundary.**
  - No migration: the database stays schema v5 (the store migration number,
    not the bundle version).
  - M8 writes only rows M7 reads: `render_decision/2` facts (extra keys, read
    with `.get`), `render_request` facts (ignored by M7), and score rows with
    the extra `render_not_scheduled` flag (a list of strings).
  - A code-only rollback leaves the store readable. An M7 rescore drops the
    flag.
  - Requests pending at rollback are inert under M7, and render jobs already
    queued by an analyst decision still run under M7.
  - The one rollback requirement is config: M7 refuses a config containing
    `browser.analyst_renders_per_day` (extra keys are forbidden), so remove
    that key before or with the rollback.
- **Classifiers.** `tools/t1-trial.sh` and `tools/t2a-lab.sh`, in the
  promotion work dir, accept an expected fetch `job failed` by reading
  `r["fields"]["error"]`. `JsonFormatter` merges fields into the top level,
  so that rule never matched, even on M7: any `job failed` is a STOP. That is
  fail-closed, so safe. Under M8 it stays fail-closed. A revision for M8 must
  read the top-level `stage` and `error_type == "TransientFetchFailure"`.
