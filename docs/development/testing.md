# Testing and security validation

Tests are pytest suites under `tests/`, selected by markers declared in `pyproject.toml`.

| Marker | Meaning | Needs |
|---|---|---|
| (none) | unit and integration tests | Python only |
| `security` | security-control tests: netguard, fetcher, proxy, quotas, leases, sandbox clients | Linux loopback range `127.77.0.0/24` (the local harness) |
| `docker` | real containers: isolation, limits, sandbox workers | rootless Docker, the sandbox image, `bs_sandbox` and the egress proxy |
| `lab` | the controlled lab sites | the lab Compose stack |
| `installed_layout` | a real installed layout, with root simulated by a user namespace | `uv` and unprivileged user namespaces; skipped without them, unless `REQUIRE_INSTALLED_LAYOUT=1` makes that a failure |
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
| sandbox image contents: package, bytecode, metadata, dependencies, identity (`image_manifest.py`; Docker faked, the in-image script run for real) | `tests/unit/test_image_manifest.py` |
| dependency export bound to the named project's committed `uv.lock`: no `UV_*` variable, configuration file or ancestor workspace selects another lock (`image_manifest.py`, `scripts/uv-export-locked.sh`; the real uv, offline) | `tests/unit/test_lock_export_boundary.py` |
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
| `test_analysis_pipeline.py::test_unreachable_site_records_failure_after_last_attempt` | job still `running` | diagnosed 2026-11-11: the stop-condition race below; fixed in the test |
| `test_orchestrator.py::test_lease_is_renewed_while_waiting_for_the_domain_lock` | a second attempt ran | not diagnosed (timing) |
| `test_render_requests.py::test_a_round_fetched_without_a_decision_is_skipped_not_stranded`, `::test_a_stale_request_for_a_dead_round_does_not_hide_a_later_one` | request stayed on round 0 | diagnosed 2026-11-11: the stop-condition race below; fixed in the tests |

Fix these as test or code changes of their own, then add the suite to the workflow. Do
not skip them or loosen their bounds to make CI green.

**The stop-condition race (diagnosed 2026-11-11).** These three tests stopped the
orchestrator as soon as the fetch stage's `stage_runs` row existed. That row commits
inside the handler; the orchestrator then waits for the job's lease renewer to stop
before it calls `jobs.complete()`. A stop in that window cancels the worker there, so
the fetch job stays `running`. `request_render` counts a recorded round as live while
its fetch job is `pending` or `running`, so the request binds to round 0 (the values
observed above). A slow runner, or tracing, widens the window. Scope of the fix:

- **Tests only.** They now stop on `fetch_settled()`
  (`tests/integration/test_analysis_pipeline.py`): the fetch is recorded *and* no fetch
  job for the round is `pending` or `running`. Assertions and timeouts are unchanged.
- **Reproduced deterministically.** The two render-request tests run with
  `slow_job_completion`, which delays the renewer's stop by 200 ms: with the old stop
  condition both fail with the values above; with `fetch_settled` they pass.
- **Product behaviour is unchanged.** In production the same window leaves a job
  `running` until its lease expires; the job is then redelivered, and the stage
  handlers write nothing twice (`test_redelivered_*` in
  `tests/integration/test_analysis_pipeline.py`). On a job's final attempt, an
  expired lease marks the job `failed` ("lease expired") even though its work was
  recorded; that is not fixed here.
- `test_orchestrator.py::test_lease_is_renewed_while_waiting_for_the_domain_lock` is a
  different test and stays undiagnosed.

## Name resolution in tests

The offline suite never asks the host's resolver anything. `tests/conftest.py` installs
`tests/resolver_tripwire.py` before collection. A dnspython resolver built from the
host's configuration (`make_dns_resolver` with no nameservers) can still be built, but
any query is refused before a socket opens. Name lookups through Python's `socket`
functions (`getaddrinfo` and `gethostbyname*` for anything but an IP literal,
`getfqdn` and `gethostbyaddr` always, `getnameinfo` unless numeric) are refused too.
A refusal fails the test that made it, or the next test when it happened outside one,
and a refusal after the last test, or a module holding an unwrapped copy of one of
these functions, fails the run. Resolvers with explicit nameservers, such as the
harness stub, are untouched.

It cannot see lookups in subprocesses (the CLI subprocess tests, `uv`, containers), in
native code that does not go through those Python functions, or a query a test sends
itself over a socket (for example `dns.query.udp` to an explicit server), a hostname
passed straight to a socket method such as `connect`, or a process-wide resolver
replacement. `tests/resolver_tripwire.py` lists every gap. Those need a network boundary
or a trace. To give a test DNS
answers, inject a resolver: `StaticResolver` for `NetGuard`, or a double with
dnspython's `resolve()` for `AnalysisStages(resolver=...)`.

## Reproducible wheels

The image wheel (`scripts/build-sandbox-image.sh`) and the installed wheel
(`scripts/service-account/install.sh`) are built separately. Both pass
[`build-constraints.txt`](../../build-constraints.txt) with
`uv build --no-config --wheel --build-constraints build-constraints.txt --require-hashes`.
That file pins hatchling and every package in its build environment, exactly and with
hashes. A wrong hash, a build dependency missing from the file, or a cache without the
pinned files fails the build; uv never substitutes another backend.

Build isolation is what makes uv apply the pin: without it, uv builds with whatever
backend the active environment holds and ignores the file. So both scripts run the build
under `env -u` for `UV_NO_BUILD_ISOLATION`, `UV_NO_BUILD_ISOLATION_PACKAGE`,
`UV_NO_VERIFY_HASHES`, `UV_CONFIG_FILE` and `SOURCE_DATE_EPOCH`, and pass `--no-config`,
so no inherited variable, `uv.toml` or `[tool.uv]` table can switch isolation or hash
checks off, or change the wheel's timestamps.

The image script prints the commit it built (marked when the tree has uncommitted
changes), the wheel's sha256 and its `Generator` line before it deletes `docker/dist`, and
refuses a wheel whose backend is not the pinned one. Only clean builds of the same commit
are comparable: `install.sh` builds a `git archive` of `HEAD`.
`tests/unit/test_build_backend_pin.py` checks the pin file, the shared command and that
record statically. Accepted limits are in the
[residual findings](../residual-review-findings/fix-b7-build-backend-pin.md).

The scripts do not force `--offline`. The release build runs them with `UV_OFFLINE=1` and
`UV_CACHE_DIR` set to a private copy of the pinned uv cache, inside a boundary with no
network (B7 U3). Use the uv the release pins, by absolute path or first on `PATH`: a
different uv version may use another cache layout and then finds nothing offline.

Evidence of 2026-11-16 (development only, uv 0.12.20, private copies of the pinned cache,
empty network namespace): each script's own build lines gave byte-equal wheels with
`Generator: hatchling 1.32.4`. A changed hash for hatchling or for a build dependency, a
missing entry, a missing pin file and a cache without hatchling 1.32.4 each failed the
build. Without the pin, a cache holding only hatchling 1.33.0 built a different wheel.
Before the review fix, `UV_NO_BUILD_ISOLATION=1` (or a `uv.toml` setting it) with an
active environment holding hatchling 1.33.0 made the pinned command build that backend's
wheel; with the fix, both paths still built the pinned, byte-equal wheel in that
environment.

To change the backend, update every entry of the pin file and the expected closure in
the test together, then repeat that evidence. The acceptance evidence for a release is
taken on its release commit (B7 U3), not here.
