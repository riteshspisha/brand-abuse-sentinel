# Pipeline and data flow

From a name seen somewhere to an explained, prioritized case. Module references are to
`src/brandsentinel/`.

## End to end

```mermaid
sequenceDiagram
  autonumber
  participant S as Source (CertStream / dnstwist / submit)
  participant I as Intake + matcher
  participant Q as SQLite (jobs, facts)
  participant E as enrich
  participant F as fetch
  participant M as media (sandbox)
  participant R as render (sandbox)
  participant P as policy scorer
  S->>I: discovery event (host, source, raw record)
  I->>I: normalize + match against the registry
  I->>Q: candidate, case, enrich job (round 0) + recheck rows (rounds 1, 2)
  Q->>E: claim (lease)
  E->>Q: DNS / RDAP / TLS / similarity facts; schedule fetch
  Q->>F: claim
  F->>Q: http_fetch fact, page blob, extractor features
  F->>P: score (bundle from stored records)
  F->>Q: media_decision, render_decision; schedule media / render
  Q->>M: claim (only if the sandbox preflight passed)
  M->>P: visual + image-text features; re-score
  Q->>R: claim (only if the network check passed)
  R->>P: rendered features, screenshot, cloaking; re-score
```

## 1. Discovery and intake

| Source | Module | Notes |
|---|---|---|
| CertStream (certificate transparency) | `discovery/certstream.py` | websocket to a certstream-server-go instance; dedupe by fingerprint; reconnect with backoff; coverage gaps recorded |
| dnstwist | `discovery/dnstwist_runner.py` | scheduled permutation sweeps of registry targets (24 h default), bounded output and time |
| Manual | `discovery/submit.py` | `brandsentinel submit URL…`: always creates or reuses a case, **never suppressed**; bypasses per-domain backlog limits |

Every discovery record is appended to a raw log first (`store/rawlog.py`), so
`brandsentinel replay` can re-ingest it idempotently.

The matcher (`matching/`) normalizes the host and matches it against the Brand Registry:

- normalization covers IDN/punycode, confusable characters, and folded or hyphenated
  forms;
- keywords are tiered (high or low distinctiveness), and low-tier tokens such as `isha`
  need context terms;
- exclusions are scoped to the low-distinctiveness keyword they guard;
- official-lookalike detection;
- only **confirmed** official domains suppress.

The result has a strength (`strong` or `weak`), hits with provenance, and notes such as
`excluded:odisha`.

## 2. Jobs, leases and fairness

- **Queue** (`store/jobs.py`): a worker claims a job with a time-limited lease and a
  unique token. Renewal, completion and failure are accepted only with the current
  token. Expired leases return the job to pending, or to failed after `jobs.max_attempts`
  (3).
- **Workers** (`pipeline/orchestrator.py`): `stages.*` workers per stage (enrich 8,
  fetch 4, media 2, render 1). A lost lease cancels the handler.
- **Fairness** (`pipeline/scheduling.py`): per registrable domain, at most
  `stages.per_domain_*` running jobs, and at most `scheduling.max_queued_per_domain_*`
  live jobs per stage. Further work goes to `deferred_jobs` with its reason. It is never
  dropped, and is promoted as the domain's jobs finish. This bounds subdomain flooding:
  30 sightings of `sadhguru-N.evil-flood.com` keep 30 cases but queue only 16 enrichment
  jobs at once (`tests/integration/test_scheduling.py`).

## 3. Analysis rounds and rechecks

Round 0 is the first analysis. The round-0 enrich handler also writes recheck rows for
rounds 1 and 2, `scheduling.recheck_after_days` = 1 and 7 days later. They are deferred
jobs with a future `not_before`, keyed `enrich:case:N:rK`. When a recheck's fetch sees
changed DNS answers, status, final URL, title or body hash, it records a `material_change`
fact and the case is re-scored. Facts carry `analysis_round`.

## 4. Stages

| Stage | Module | Does | Registered when |
|---|---|---|---|
| `enrich` | `pipeline/stages.py`, `enrich/` | DNS records, RDAP (bootstrap + cache), TLS certificate, name similarity; schedules the fetch | when enrichment or the fetch is on. With enrichment off (`enrich.enabled: false` or `--no-enrich`) only the offline similarity source runs, so cases still reach the fetch. With both off no analysis stage is registered |
| `fetch` | `pipeline/stages.py`, `net/fetcher.py` | one hardened static fetch in evidence mode; stores the body as an inert blob; runs the extractors; scores the case; records `media_decision` and `render_decision`. Transient failures (connect error, timeout, protocol error) are retried after `fetch.retry_delay_seconds` | `fetch.enabled` and not `--no-fetch` |
| `media` | `pipeline/media.py`, `sandbox/media_*` | fetches up to 8 selected images through the hardened fetcher; decode, hash, OCR, QR in a `--network none` container; visual matching against the reference corpus | the sandbox preflight passed (rootless runtime, account gate, orphan sweep) |
| `render` | `pipeline/render.py`, `sandbox/browser_*` | Chromium render behind the egress proxy; rendered HTML and screenshot stored inert; rendered extractor features; screenshot to the media sandbox; static-vs-rendered cloaking comparison | as media, plus the network check with its direct-egress probe |

A stage that is not registered leaves its jobs pending. The case then shows the gap
(`media_pending`, `render pending`), never a clean result.

### When a page is rendered

`sandbox/triggers.py` decides after the final static fetch and records every reason
(`render_decision/2`):

- **Never rendered:** confirmed official domains, and cases without a static HTTP
  response. A fetch that netguard refused is never retried through the browser.
- **Triggers:** `js_shell`, `static_error`, `decoy_page`, `script_redirect`,
  `form_hints_without_forms`, `little_text`, `no_static_images`, and a deterministic
  `sample` of strong cases (`browser.sample_rate`, default 0.1).
- **`analyst_request` (M8):** `submit --render` asks for the next undecided round. When no
  other trigger applies, the request spends `browser.analyst_renders_per_day` (default
  **0**: requests are recorded and refused as `analyst_budget_exhausted`).
- **No render coming:** when none is scheduled although static analysis could not see the
  content, the case carries `render_not_scheduled` with the reason.

## 5. Scoring

After each final fetch, media result and render, `policy/scorer.py` rebuilds the case's
EvidenceBundle from stored records and evaluates the policy. A new `scores` row is written
only when something changed. See [Evidence and scoring](scoring.md).

## 6. Bounded and idle runs

- `run --duration S` stops after S seconds.
- `run --until-idle` (M8, needs CertStream and dnstwist off) also stops when no stage this
  run serves has pending or running work and no deferred work is due. Rechecks that are
  not yet due stay queued. Jobs of stages this run does not serve, such as media without
  a sandbox, are reported as `unserved_jobs` in the final `run idle; stopping` record,
  not waited for.

## 7. Telemetry

`run` logs JSON records (`logging.py`). Each claimed job logs `job started` and
`job finished` from a fixed allowlist: job id, stage, case id, round, attempt,
registrable domain, outcome, duration. A failed attempt logs `job failed` with
`error_type` (the exception class) and, for fetches, `fetch_outcome`. Host names,
URLs, queries, lease tokens and exception messages are never logged; the message stays in
`jobs.last_error`. See the [telemetry runbook](../runbooks/telemetry.md).

## 8. Lab mode

`net.lab.enabled: true` (see `config/lab.yaml`):

- merges the synthetic Lumina overlay into the registry;
- lets netguard accept exactly the pinned lab subnet, and only for the listed hostnames;
- sends host fetches only through the lab proxy on `127.0.0.1:3129`;
- pins the lab sandbox network and proxy;
- refuses to start with CertStream or dnstwist enabled.
