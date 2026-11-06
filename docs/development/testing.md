# Testing and security validation

Tests are pytest suites under `tests/`, selected by markers declared in `pyproject.toml`.

| Marker | Meaning | Needs |
|---|---|---|
| (none) | unit and integration tests | Python only |
| `security` | security-control tests: netguard, fetcher, proxy, quotas, leases, sandbox clients | Linux loopback range `127.77.0.0/24` (the local harness) |
| `docker` | real containers: isolation, limits, sandbox workers | rootless Docker, the sandbox image, `bs_sandbox` and the egress proxy |
| `lab` | the controlled lab sites | the lab Compose stack |
| `models` | Kev or Laya servers | **not available**: no provider is implemented |

## Suites and recorded results

| Command | What it covers | Last recorded result |
|---|---|---|
| `uv run pytest -m "not docker and not lab and not models"` | everything that runs without containers | 1524 passed, 1 skipped, 118 deselected, 56.3 s: clean clone on the developer machine, 2026-11-06, `87c0d16` |
| `uv run pytest -m security` | network policy and fetcher against the adversarial harness | included in the line above |
| `uv run pytest -m "docker or security"` | the standing security gate (SP3) | 517 passed, 0 skipped: developer's rootless runtime, M8 branch (*reported* in `docs/runbooks/handoff.md`) |
| `uv run pytest -m lab` | lab-site expectations (static, media, browser) | passing at M7 and M8 on the developer runtime (*reported*) |
| `uv run ruff check` | lint, including Trojan-Source bidi characters | clean |
| `uv run pytest tests/unit/test_docs.py tests/integration/test_offline_demo.py` | documentation checks and the offline demo | see [Documentation system](documentation.md) |

Results marked *reported* come from milestone records and were not re-run while writing
this page. Re-run them before relying on them.

## Rules

- **Zero skips on the security gate.** For any change under `src/brandsentinel/net/` or
  `src/brandsentinel/sandbox/`, `-m "docker or security"` must pass with no skipped tests.
  A skipped Docker test means Docker was unreachable, and that is not a pass. Removing or
  weakening one of these tests needs an explicit review note (SP3).
- **Regression tests fail on the old code.** Several suites are built this way. For
  example, the page-sockets test (`tests/lab/test_browser_sockets.py`) fails on the M7
  image without the fix.
- **Synthetic ≠ field.** Lab and harness results show the controls and rules behave as
  designed on pages written for them. They are not detection-rate measurements.

## Where the security evidence lives

| Control | Tests |
|---|---|
| netguard ranges, literals, rebinding, mixed answers | `tests/security/test_netguard.py` |
| fetcher caps, redirects, TLS modes, decompression bombs | `tests/security/test_fetcher.py` |
| proxy framing, CONNECT rules, Host/target match, exhaustion | `tests/security/test_proxy.py` |
| artifact quotas, lease safety | `tests/security/test_quotas.py`, `tests/security/test_network_lease.py` |
| container isolation: no route out, positive control | `tests/security/test_docker_isolation.py`, `tests/security/test_sp1_isolation.py` |
| runner limits: OOM, PIDs, wall time, output caps, orphans | `tests/security/test_runner_security.py`, `tests/integration/test_runner.py` |
| media and browser worker limits | `tests/security/test_media_limits.py`, `tests/security/test_browser_limits.py` |
| sandbox preflight | `tests/security/test_preflight.py` |
| lab transport refusals | `tests/security/test_lab_transport.py` |
| detection evasion (static extractors) | `tests/unit/test_detection_evasion.py` |

## Adding tests

- **Pure logic** (matcher, extractors, rules): `tests/unit/`.
  `tests/detection_support.py` builds bundles from real HTML without a database.
- **Queue, stages, store:** `tests/integration/`. `tests/integration/test_orchestrator.py`
  has `drain()`.
- **Anything a hostile server could do:** `tests/security/`, using the harness in
  `tests/security/harness.py`. Its DNS stub can map any name to a loopback test address.
- **Real containers:** mark the test `docker`. `tests/docker_support.py` has the helpers.

## CI

[`.github/workflows/checks.yml`](../../.github/workflows/checks.yml) runs on every pull
request. It runs lint, `tests/unit/test_docs.py`, the offline demo test, the CLI
reference check and the strict documentation build. It uses no Docker and no secrets.

The full offline suite is not in CI yet. On GitHub's `ubuntu-24.04` runner (2026-11-06,
commit `5d9bcc7`) it reported 6 failed, 1518 passed, 1 skipped. On the developer machine
the same tests pass:

| Test | Observed on the runner | Likely cause |
|---|---|---|
| `test_media_worker.py::test_ae12_decompression_bomb_is_rejected_quickly` | took 2.5 s, limit 2 s | wall-clock bound; also fails locally with CPU throttled to 30 % |
| `test_cli.py::test_status_reports_sandbox_disabled_with_reasons` | no `FAIL endpoint` line | the runner has a reachable Docker daemon; the test assumes none |
| `test_analysis_pipeline.py::test_unreachable_site_records_failure_after_last_attempt` | job still `running` | not diagnosed |
| `test_orchestrator.py::test_lease_is_renewed_while_waiting_for_the_domain_lock` | a second attempt ran | not diagnosed (timing) |
| `test_render_requests.py::test_a_round_fetched_without_a_decision_is_skipped_not_stranded`, `::test_a_stale_request_for_a_dead_round_does_not_hide_a_later_one` | request stayed on round 0 | not diagnosed |

Fix these as test or code changes of their own, then add the suite to the workflow. Do
not skip them or loosen their bounds to make CI green.
