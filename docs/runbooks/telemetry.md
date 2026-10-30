# Run telemetry and bounded runs (M8)

## Job lifecycle records

Every claimed job logs one INFO `job started` and one INFO `job finished`
(`pipeline/orchestrator.py`, `job_fields`). Fields come from a fixed allowlist:

| Field | Meaning |
|---|---|
| `job`, `stage`, `attempt` | the job row, its stage and this attempt (1-based) |
| `case_id`, `round` | from the payload, only when they are integers |
| `domain` | the job's group key: the registrable domain, or the host when it has none (a public suffix); only when it looks like a domain name |
| `outcome` (finished) | `completed`, `retry`, `failed` (out of attempts), `lease_lost`, `cancelled` (shutdown), `unrecorded` (the failure could not be stored), `error` (the store failed on completion) |
| `duration_ms` (finished) | wall time from claim to finish |

Never logged: the host name (beyond that group key), the subject URL (path, query, fragment), the
lease token, page content, or any exception message.

## Errors

- `job failed` (ERROR) carries `job`, `stage`, `status`, `attempt`,
  `error_type` (the exception class), `error_at` (code locations,
  `file.py:line`) and, for `TransientFetchFailure`, `fetch_outcome` (for
  example `timeout`). The message is **not** logged: fetch errors can contain
  the URL with its query. It stays in the store, `jobs.last_error`, and
  `brandsentinel status` shows it.
- The other job-path error records (`could not record job failure`, `stage
  worker error`, `background task crashed; restarting`, `lease renewal
  failed`, `media decision failed`, `render decision failed`, `scoring
  failed`, `render processing failed`, `invalid browser worker output`,
  `invalid media worker output`) carry `error_type` and `error_at` only, never
  a formatted traceback (a chained traceback would repeat the handler's
  message).
- **Operator impact (trial classifiers).** A rule that accepted the
  domain-level fetch error by `error` starting with `TransientFetchFailure:`
  must now match `error_type == "TransientFetchFailure"` (optionally with
  `fetch_outcome`). The `error` field no longer exists.

Not changed in M8: the egress proxy's `proxy decision` records (host and port,
in the proxy container's log), discovery logs, and the reference collector.

## Bounded runs: `--until-idle`

```sh
brandsentinel submit --render https://site.test/
brandsentinel run --no-certstream --no-dnstwist --until-idle --duration 900
```

- Refused with exit 2, before the store is opened, unless CertStream and
  dnstwist are both off for the run (flags or config).
- Idle means: no pending or running job of a stage this run serves (a retry
  waiting for its `available_at` counts) and no deferred work of those stages
  already due. It must hold twice, `scheduling.promote_interval_seconds` plus
  two worker polls apart (7 s by default), after startup.
- Rechecks not yet due stay in `deferred_jobs` untouched. Jobs of stages the
  run does not serve (for example media or render while the sandbox is
  unavailable) do not hold the run; they wait for a run that serves them.
- The stop is logged as INFO `run idle; stopping` with `deferred_not_due` and
  `unserved_jobs` (per stage). Shutdown and maintenance run as on any stop.
- `--duration` stays the hard bound: a run whose work never finishes (a retry
  due after the duration, a stage that keeps failing) ends there.
