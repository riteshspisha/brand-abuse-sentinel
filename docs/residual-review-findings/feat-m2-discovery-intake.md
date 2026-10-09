# Residual review findings - M2 (U5, U6, U7)

Review run `20261009-111433-109b0f0f`: correctness, security, reliability and adversarial
reviewers on `feat/m2-discovery-intake` against the M1 commit. Testing, maintainability,
standards and agent-native personas were not run (reduced roster); findings were verified
by the implementer rather than a per-finding validator wave.

## Fixed before commit

- A CertStream event whose ingest failed could be checkpointed past and never replayed.
  It now holds the replay checkpoint (`hold_replay`) until the next startup replay.
  The fingerprint is cached only after success, so a redelivery retries it.
- A non-network error in the CertStream consumer (SQLite, unexpected exception) killed the
  task without a coverage gap. It is now treated as a disconnect, and SQLite errors are
  contained per message.
- Stage workers died permanently on a store error. Lease renewal now survives transient
  errors and also covers the time a job waits for its registrable-domain lock.
- Each matching SAN re-stored the certificate's full SAN list (N-squared storage). The
  list is now kept once per certificate (`san_count` on every event).
- Starting `run` during a CLI `sweep` marked the live sweep abandoned and started a
  duplicate. Only `running` rows older than the maximum sweep wall time are abandoned.
- A `partial` sweep was re-run every `retry_hours` indefinitely; it now counts as settled.
- Full `replay` after event-row pruning could count old events again. Replay now skips
  records older than the event retention age.
- Malformed submission URLs (bad IPv6 literal, invalid port) raised instead of being
  rejected. C1 and bidi characters are refused, and a full disk during `submit` reports
  an error.
- `max_names_per_cert` above 1000 would fail event validation; it is now capped at 1000.

## Deferred (decisions for M3 / M5)

- **Subdomain flooding.** Candidate identity is the host, per the plan (R9, AE4). One
  attacker-owned registrable domain with many matching subdomains opens one case and one
  enrich job per host, for example `*.anthemishackingfinanceretreat.com` in the live run.
  M3 should cap cases or jobs per registrable domain (attach further hosts as observations)
  before enrichment makes each case cost network work.
- **Dismissed lookalikes reopen.** Once analysts can close cases (M5), a daily dnstwist
  re-sweep opens a new case for a closed candidate. `_open_case` should respect recent
  closure or labels unless a material fact changed (U7 recheck rules).
- **Recheck scheduler (U7).** Rechecks at 1 and 7 days and material-change detection need
  facts from enrichment and fetching, which do not exist yet; deferred to M3/M5.
- **Concurrent `submit` crash window.** `submit` runs in its own process. If it dies
  between its log write and ingest, the running service's checkpoint may pass the record.
  `brandsentinel replay --since-hours N` recovers it.
- **Graceful shutdown burns an attempt** for each job interrupted by a restart (default
  3 attempts). Release leases on SIGTERM when long stages exist (M4+).
- **SQLite work on the event loop.** A large dnstwist batch (one transaction per record)
  or a long startup replay can stall the loop beyond the websocket ping timeout. Measured
  sweeps (49 records) are fine; batch the transaction if sweeps grow large.
- **Reconnect without jitter, unrate-limited malformed-message logs**, and no
  single-instance guard on `run`. Address with U22 supervision.
- **Wall-clock jumps** can delay the sweep schedule or the replay window.
- **Manual `subject_url`** is stored as given (after control-character checks). The M3
  fetcher must re-derive the host and require it to equal the candidate host.
- **Matcher quality from the live sample** (M1 residuals confirmed): context terms match
  anywhere in the name (`...financeretreat.com`), and distance-2 fuzzy matches such as
  `makesoil.de` are noisy. Tune with a longer M2 sample.
- **Confirming an official domain** in the registry does not close cases already open
  under it.
