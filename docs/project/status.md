# Status and maturity

As of **2026-11-06**. This page separates what is implemented from what is accepted in
production, and both from what is only planned. Production facts come from the owner's
gated operations, whose evidence is kept outside this repository; they are marked
*operator-reported*.

## Maturity levels

| Level | Meaning |
|---|---|
| **Planned** | designed in a plan; no code |
| **Implemented** | merged to `main` with tests |
| **Development-tested** | its suites pass on the developer's machine or rootless runtime |
| **Production-accepted** | installed under the service account and accepted through gated operations |
| **Operational** | running for its real purpose (live collection, unattended) |
| **Experimental** | present but with known gaps that limit use |

## Capability matrix

| Capability | Implemented | Dev-tested | Prod-accepted | Operational | Notes |
|---|---|---|---|---|---|
| Registry and tiered matching (M1) | yes | yes | yes | no | the production registry has no confirmed domains yet |
| Discovery: CertStream, dnstwist, submit, raw log (M2) | yes | yes (short live smoke runs) | yes (installed) | **no** | live collection has not been authorized as an ongoing activity |
| Guarded fetch and passive enrichment (M3) | yes | yes | yes | no | |
| Sandbox runtime, egress proxy, lab (M4) | yes | yes | yes (proxy running) | n/a | |
| Static detection, policy, reports, CSV (M5) | yes | yes | yes | no | |
| Media sandbox and visual matching (M6) | yes | yes | yes | no | **experimental in production**: the reference corpus is empty, so visual matching is inert |
| Isolated browser and cloaking (M7) | yes | yes | yes | no | |
| Analyst render request, render explanations, job telemetry, `--until-idle` (M8) | yes | yes | yes | no | analyst budget 0 in production |
| Decision models: Kev-0.8B, Laya (U20) | **no** | | | | planned; `eval` is a stub |
| Labelled evaluation (U21) | **no** | | | | planned; no detection-rate measurement exists |
| Instance lock (SP2) | **no** | | | | blocks M9 |
| Unattended operation, supervision, soak (M9, U22) | **no** | | | | |

## Milestone history and provenance

| Milestone | Scope | Merged (PR, merge commit) | Production |
|---|---|---|---|
| M0 | config, CLI, store, job queue, raw logs, artifacts | `b1bef5c` (2026-10-08) | |
| M1 | Brand Registry, tiered matcher | `1783218` (2026-10-09) | |
| M2 | CertStream, dnstwist, submit, durable intake | #1 `ebf5c49` (2026-10-09) | |
| M3 | netguard, hardened fetcher, enrichment | #2 `94df6dd` (2026-10-09) | |
| M4 | rootless runtime and runner, egress proxy, lab | #3 `2aafc09`, #4, #6 (2026-10-10/11) | |
| M5 | extractors, EvidenceBundle, policy, reports | #5 `a7d6611` (2026-10-11) | |
| SP1 | dedicated service account | #8 `f943177` (2026-10-11) | validated under the account (*operator-reported*) |
| M6 | media sandbox, reference corpus, visual matching | #9 `358bf40` (2026-10-17) | deployed 2026-10-28 (*operator-reported*) |
| M7 | isolated browser, triggers, cloaking | #12 `d3949a7`, #13 `d3adbe9` (2026-10-29) | promoted and accepted 2026-10-30 (*operator-reported*) |
| M8 | `submit --render`, render explanations, job telemetry, `run --until-idle`; version 0.2.0 | #14 `49340fa`, #15 `e40ffcb` (2026-10-31) | promoted 2026-11-05; promotion gates P0–P5 accepted (*operator-reported*) |

!!! note "What 'M8' means"
    The original plan defined M8 as decision models and evaluation (U20, U21). The M8 that
    shipped is a different, smaller scope, analyst-requested rendering and telemetry
    ([M8 plan](../plans/2026-10-30-001-feat-m8-analyst-render-telemetry-plan.md)), chosen
    after the first supervised trials. **U20 and U21 remain outstanding.** The `eval`
    command's stub message still says "planned for M8". That text predates the change and
    is inaccurate.

## Trials

| Trial | What | Outcome |
|---|---|---|
| T1 (M7) | first supervised live run, one owner-controlled domain | ran on M7; the four gaps it showed are the M8 scope |
| T2a-dev / T2a (M7, M8) | lab scenarios, developer runtime and service account | 28 detection criteria pass (M8 re-run on the developer runtime) |
| I1 r1 (M8) | bounded offline run on an isolated **copy** of a recovery point: no discovery, enrichment, fetch, sandbox or browser | **stopped before processing** (2026-11-05). A launch-ordering defect in the trial tooling: sudo after `setsid` lost the cached credential. Not accepted. A read-only post-check of the copy and production is pending |
| I1 r2 | corrected trial tooling (sudo first, chain probed before any copy) | prepared; development tests pass. **Real-host validation and the second attempt are pending**, each needing separate authorization |

The trial tooling and its evidence live outside this repository.

## What is not true yet

- BrandSentinel has not run live collection unattended, and has no soak result.
- No real-world detection accuracy has been measured.
- No advisory model is integrated.
- The production Brand Registry has no maintainer-confirmed official domains, payees or
  reference assets.
