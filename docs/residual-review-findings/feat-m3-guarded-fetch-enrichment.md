# Residual review findings - M3 (U8, U9, U10, subdomain flooding control)

Review run `20261009-133435-f28d04f6`. Five reviewers ran on the M3 diff against
`ebf5c49`: correctness, security, reliability, adversarial and testing. This is a
reduced roster: the maintainability, standards, agent-native and learnings
reviewers did not run. The implementer verified each finding by reading the code
or running a probe. There was no per-finding validator wave and no cross-model pass.

## Fixed before commit

- **P1, malformed redirect.** A `Location` such as `http://[x/` made `urljoin` raise
  `ValueError` and lost every recorded fact for the fetch. It is now
  `blocked_redirect` / `invalid_url`. As a backstop, any unexpected exception now
  becomes outcome `internal_error`; the fetcher never raises for site behaviour.
- **P1, hostile charset.** A `charset=idna` label (or any non-text codec) raised in
  `decode_body` and rolled back the whole fetch transaction. Only text codecs are
  used now, with UTF-8 as the fallback.
- **P1, oversize fetch facts.** A header flood over several redirect hops could
  push the `http_fetch` fact past the fact-size cap, which replaced it with a bare
  stub. Recorded headers are now capped at 16 KiB per hop (`headers_truncated`).
  An oversize fact or feature keeps its small top-level fields (outcome, status,
  round) and names the fields it dropped.
- **P1/P2, deferred-work starvation.** The promoter could spend its whole batch on
  domains still at their allowance, so other due work and rechecks starved. It now
  selects only groups that can move: escalated groups, or groups under the
  allowance of their best class.
- **P1/P2, escalation stopped after enrichment.** A manual case's fetch and rechecks
  queued behind a flooded domain. Escalation is now persisted as `cases.escalated`
  and applies to all of the case's work.
- **P2, M2 backlog without a group.** Jobs queued before M3 had no group key and
  bypassed the per-domain limits. Migration 0003 backfills the key from the payload.
- **P2, reference fetch trusted after a downgrade.** An `https` to `http` redirect
  kept a reference fetch trusted. Reference collection now refuses non-https hops
  (`scheme_downgrade`), and `trusted_reference` requires every hop to have verified
  TLS.
- **P2/P3, IPv4-translated addresses.** `::ffff:0:a.b.c.d` (SIIT, `::ffff:0:0:0/96`)
  was treated as public; Python's `is_global` agrees. It is now `ipv4_translated`
  and blocked.
- **P3, forged lines in `analyze` output.** U+2028, NEL, VT and FF in fact values
  could start new lines because the output used `splitlines()`. It now splits only
  on `\n`, so `escape_terminal` makes those characters visible.
- **P3, RDAP over plain HTTP.** Bootstrap services listed only over `http://` are no
  longer used.
- **P3, RDAP bootstrap retries.** Bootstrap refreshes now run one at a time and back
  off for 10 minutes after a failure. A stale copy is reused during the backoff
  instead of refetching on every lookup.
- **P3, stage idempotency and blob storage.** The `stage_runs` check is repeated
  inside the write transaction, and the page blob is stored in the same transaction
  as its facts.
- **P3, smaller fetch and DNS fixes.**
  - An empty `Location` no longer loops to `redirect_limit`.
  - A read timeout or protocol error mid-body marks the partial body truncated.
  - Raw-deflate bodies decode.
  - DNS values are sorted before the 50-record cap, so recheck comparisons are
    stable.
- **P2, material change during outages.** A failed lookup or fetch made
  `material_change` report a change. Fields missing on either side are now
  reported as `unknown_fields` instead.
- **Testing gaps closed:**
  - retries by outcome (transient vs permanent)
  - DNS rebinding between the enrich and fetch stages
  - a redelivered fetch writing one result and one artifact
  - a manual case bypassing a flooded domain
  - promotion past saturated domains
  - the pre-M3 backfill
  - fairness under a generous allowance
  - the exact job id on restart
  - per-name rebinding zones
  - TLS failure kinds (expired certificate, hostname mismatch, non-TLS port)
  - RDAP bootstrap backoff
  - empty and unparseable `Location`
  - header floods
  - raw deflate
  - hostile charsets

## Deferred

- **Final-attempt lease loss.** If the process dies or stalls during a fetch's last
  attempt, the job fails at claim time and no `http_fetch` fact or `stage_runs` row
  is written. The case gets its next look at the 1-day recheck. Fix: on
  final-attempt failure in `claim()`, write an outcome for stages that have one.
- **An enrich job that fails all its attempts** on a non-source error (for example
  a persistent store error) schedules neither the fetch nor the rechecks, and
  nothing re-drives that case.
- **Private public-suffix entries** (`duckdns.org`, `eu.org` sub-suffixes and
  similar) make each customer label its own registrable domain. One operator
  there gets one allowance, blob quota and claim slot per label. This is bounded
  per label and preserves evidence. A future control could group by the operator
  of the private suffix.
- **Strong-first claiming.** Names the attacker chooses to match strongly can delay
  weak work. Per-domain concurrency bounds this but does not remove it.
  `privileged=True` for strong cases lets them use the blob reserve; consider
  limiting the reserve to manual cases.
- **RDAP lookup errors are not cached per registrable domain.** Failing lookups
  repeat per subdomain until the bootstrap backoff applies.
- **`tls_verification_failed`** stays true if the first address fails verification
  and a later address is used.
- **Blocking work on the event loop.** SQLite writes, blob fsync (up to the blob
  cap) and HTML parsing run on the event loop and can delay CertStream pings and
  lease renewal.
- **Promoter scan cost.** The promoter groups every due deferred row every 5 s.
  Recheck rows accumulate at about two per case for 7 days.
- **No retention yet** for `enrichment_cache`, finished jobs and `job_groups`
  (job_groups rows are pruned after 30 days). This belongs with U22.
- **`material_change` is coarse.** Dynamic pages (CSRF tokens, timestamps) change
  the body hash on every fetch. A normalized content hash belongs with the M5
  policy gate.
- **The honest User-Agent** lets sites cloak static fetches. The plan accepts this
  and adds browser comparison in M7.
- **NFKC/IDNA folding** can map exotic input such as circled letters to
  `localhost`. That name goes to DNS rather than being refused by name;
  connections still go only to validated public addresses.
- **Untested paths:**
  - The IPv6 pinned-connect test is skipped where IPv6 loopback is unavailable.
  - Chunked or lying `Content-Length` responses and TLS handshake stalls in the
    fetcher are not covered.
  - The session harness keeps per-path hit counters, so tests use unique paths
    rather than a reset fixture.
