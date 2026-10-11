# Residual review findings - M4 (U23, U11, U18)

Review run `20261009-210225-65501d6f`. Seven reviewers ran on the M4 diff against
`94df6dd`: security, adversarial, correctness, reliability, testing,
maintainability and learnings. Project-standards and agent-native did not run:
the repository has no CLAUDE.md or AGENTS.md, and M4 has no agent-facing surface.
There was no cross-model pass and no per-finding validator wave. The implementer
verified each finding by reading the code, and reproduced the P1s.

## Found during real-container testing (before review)

- **P1, overflow kill hang.** After a cap overflow the runner stopped reading the
  attached streams, so dockerd blocked and `docker kill` timed out (30 s) while
  the job hung. Fixed: both streams are discarded until the CLI exits
  (docs/solutions/2026-10-09-docker-attach-backpressure-blocks-kill.md).

## Fixed before commit

- **P1, missing docker binary** (correctness, reliability). `DockerCli.call` raised
  FileNotFoundError, which crashed `run` and `status`. It now returns a failed
  call, so the preflight disables sandboxes.
- **P1, lab https fetch** (correctness, reliability). A refused CONNECT raised
  `httpcore.ProxyError`. That became `internal_error`, which skipped the http
  fallback. It is now `connect_error` / `lab_proxy_refused`.
- **P2, proxy refusals recorded as the site's answer** (adversarial, correctness).
  Refusals now carry `X-BrandSentinel-Proxy`, and the lab-mode fetcher maps them
  to transport outcomes.
- **P2, orphans surviving a failed preflight** (adversarial, reliability).
  - The sweep now runs eagerly in `_prepare_sandbox`, before stages and lease
    recovery.
  - It also runs when only non-safety checks fail.
  - A sweep failure disables sandboxes before any stage exists.
  - A best-effort in-container `timeout` was added.
- **P2, `remove()` reporting success with the daemon down** (reliability). Only
  "No such container" now counts as gone.
- **P2, single-read Docker output** (correctness, reliability). Output is now read
  to EOF under a cap.
- **P2, deeply nested JSON** (adversarial). It is now `invalid_output`, not an
  escaping RecursionError.
- **P2, lab mode sharing `bs_sandbox`** (adversarial residual). Config now refuses
  it, and `config/lab.yaml` disables sandboxes.
- **P2, global proxy slots held by one sandbox** (adversarial). A per-client cap
  was added.
- **P3, DNS from the lab-only proxy for any name** (security, adversarial). The
  proxy now refuses before resolving.
- **P2 (security, latent), UID-0 aliases** (`00`, `pwuser:0`, `pwuser:root`). Now
  refused.
- **Reliability residuals fixed:**
  - The idle timeout counts both tunnel directions, so a busy one-way download is
    not cut.
  - The byte cap no longer raises inside `except*`.
- **Preflight:**
  - Job containers of any instance are accepted on `bs_sandbox`.
  - The egress-probe job id is unique per run.
- **Testing gaps closed:**
  - production wiring of the sweep (`_prepare_sandbox` success, image missing,
    rootful endpoint, sweep failure)
  - positive-control coverage for UDP, DNS and the resolver
  - a missing binary
  - large Docker output
  - an unreachable daemon in `remove()`
  - lab proxy failures over http and https
  - lab-only refusal without DNS
  - the per-client cap
  - the refusal header
  - the one-way download under the idle timeout
- **Test races found while looping the Docker suites:**
  - The proxy-log test now waits for its record.
  - The OOM test asserts the kernel kill and tolerates Docker's late `OOMKilled`
    flag; the runner re-inspects.

## Deferred / accepted

- **Inter-container traffic on `bs_sandbox`.** It cannot be disabled without
  cutting off the proxy on the same bridge. The browser concurrency is 1. Revisit
  in M7, for example with one network per job.
- **Maintainability (P2/P3):**
  - `Orchestrator.sandbox` is typed `object`, to avoid an import cycle.
  - The lab-proxy URL is validated in both config and the fetcher (kept as
    defense in depth).
  - The DockerCli and registry-overlay construction is repeated in the CLI.
  - There is sync/async Docker plumbing in parallel.
- **Concurrent `sandbox sweep` or `sandbox check` against a running service of the
  same instance** can remove its live job containers. Operator guidance is in the
  runbook. A service lock is a follow-up.
- **Pre-existing flaky tests, unrelated to M4.** Both reproduce at `94df6dd`:
  - `tests/integration/test_scheduling.py::test_one_flooding_domain_cannot_starve_others_end_to_end`
    (1 in 8 at base);
  - `tests/integration/test_migrations.py::test_concurrent_first_start_migrates_exactly_once`
    ("database is locked", 1 in 30 at base).

## Post-merge correction: Host header checked before DNS

Found on 2026-10-11 while investigating an intermittent failure of
`test_docker_isolation.py::test_proxy_refuses_blocked_destinations_and_allows_public_ones`
during M5 testing.

- **Defect (P2).** For both an absolute-form GET and a CONNECT, the proxy
  resolved the target before it checked the `Host` header. A request it must
  refuse for its own framing (a mismatched, malformed, duplicate or missing
  `Host`) therefore still sent a DNS query for the target. Its 400 also waited
  for that query: up to the resolver lifetime, 6.2 s. Nothing was ever
  forwarded, so no refusal was lost. But the lookup leaked the target name, and
  the outcome depended on upstream DNS.
- **How it surfaced.** On a network with IPv6 only, through NAT64, the egress
  proxy's DNS lookups timed out (`dns_timeout`, 502, in its decision log). The
  probe's 3 s client timeout expired before the host-mismatch request's 400 could
  arrive, so the test reported `TimeoutError`. All refusal assertions (403)
  still held. On an ordinary IPv4 network the same image passed. The in-process
  host-header test used an IP-literal target, which needs no lookup, so it never
  exercised the ordering.
- **Fix.** The `Host` header is now checked against the parsed target, before
  any lookup, for both forwarding and CONNECT. The decision log records the
  target host for these refusals.
- **Regression tests** (`tests/security/test_proxy.py`):
  - `test_bad_host_header_is_refused_before_any_dns_lookup` covers mismatched,
    wrong-port, malformed, duplicate and missing `Host`, over GET and CONNECT.
    It uses a resolver that never answers, and requires a 400 with no lookup
    within 3 s. All nine cases fail on the previous code.
  - `test_good_host_header_goes_on_to_dns` is the control: a matching `Host` does
    reach the resolver.
- **Deferred: deterministic positive control.** The docker test's positive checks
  (`connect public 443/80` returning 200, and `get public`) need public DNS and
  egress. Split them from the refusal assertions into a test that first checks
  the proxy's upstream reachability and fails with an explicit "no upstream DNS
  or egress" message. A fully deterministic control needs a test-only resolver
  and upstream on `bs_egress` that the proxy treats as public, as the in-process
  tests do with 127.77.0.0/16.
