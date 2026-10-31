---
title: BrandSentinel roadmap alignment after M8 v0.2.0
date: 2026-10-31
type: roadmap
status: accepted. Owner decision of 2026-10-31 recorded below; tracks 5-8 remain proposals.
supersedes: nothing. The 2026-10-08 plan and its requirement IDs stand unchanged.
---

# BrandSentinel roadmap alignment after M8 v0.2.0

## Why this exists
The product contract is `2026-10-08-001-feat-brandsentinel-local-pipeline-plan.md`. It defines:
- **M8** "Decision models and evaluation": U20, U21; demo: the comparison report of rules-only vs Kev-0.8B vs Laya;
- **M9** "Unattended operation": U22; demo: the 24-hour soak report.

The release shipped as **M8 v0.2.0** (`2026-10-30-001-feat-m8-analyst-render-telemetry-plan.md`; main `e40ffcb`) delivers different work: analyst-requested rendering, render explanations, job telemetry and `run --until-idle`.

**Deviation record.** Narrowing the scope was intentional and recorded at plan time: that plan lists "the U20/U21 M8 items" and "SP2 and M9 supervision" as out of scope. Not carrying it into the roadmap was an omission: the milestone name was reused without updating the plan's milestone table.

This document records the deviation. It does not renumber M8 v0.2.0. It does not mark U20 or U21 complete, and it keeps every original requirement and acceptance criterion.

## Owner decision (2026-10-31): SP2 and M9 before U20/U21

**Decided by the repository owner.**
1. **Order.** SP2 and M9 (U22) come before the original U20/U21 (Kev-0.8B and Laya) work.
2. **The first M9 24-hour soak runs rules-only.** `status` explicitly reports the model provider as **not configured**.
3. **U20/U21 stay open.** All their requirements and evaluation acceptance criteria are unchanged: R24–R27, R30, R31, FA8, and the original M8 demo (a comparison of rules-only, Kev-0.8B and Laya on at least 50 cases, with sufficiency verdicts and the policy section).
4. **A separate model-enabled soak** is planned for after those capabilities land.

**What this amends, and what it doesn't.**
- It amends M9's dependency and acceptance contract in the 2026-10-08 plan. Those parts are listed below; everything else stands as written.
- It is **not** completion of the original M8 milestone, and the historical plan text is unchanged.

| Original contract | Amended (first M9 acceptance only) |
|---|---|
| Milestones: M9 depends on M2–M8. Diagram: `U21 --> M9`. | M9 depends on M2–M7 and **SP2**. U21 is no longer a prerequisite of the first M9 acceptance. |
| U22 dependencies: U7, U15, U19, **U21** | U7, U15, U19, and SP2 |
| U22 soak: "the default single model provider enabled" | The provider is not configured. `status` reports model availability (R35) as `not configured`, which is neither healthy nor failed. |
| M9 demo and verification: "The 24-hour soak passes" | Unchanged, run rules-only, and the report says so. |

**Consequences.**
- **R45** ("fit for unattended 24×7 operation") may be declared after the rules-only soak, explicitly for the **rules-only configuration**. Enabling a model provider afterwards is a configuration change outside that declaration until the model-enabled soak passes.
- **The model-enabled soak becomes part of the U20/U21 milestone's acceptance.** Recommended: 24 h with the provider enabled. It must cover the provider's down and timeout path (`judgment_unavailable`, AE9) under load, because the rules-only soak cannot exercise it.
- **Still open:**
  - final acceptance FA8;
  - the plan's Definition of Done ("FA1–FA10 demonstrated");
  - the original M8 demo.

  "Plan complete" requires them.
- **R35 implementation note.** M9 must add an explicit `not configured` provider state. A missing provider must never read as healthy.
- **Kept as before:**
  - SP2's done-when criterion is unchanged;
  - SP3 remains a standing gate for any change under `net/` or `sandbox/`.

## Status against the original milestones (2026-10-31)

| Original milestone | Status |
|---|---|
| M0–M7 | Delivered. M7 (`d3adbe9`) is in production (promotion accepted 2026-10-30). SP1 is closed by the service-account deployment. SP3 is a standing gate. |
| **M8 (original): U20, U21** | **Not started.** There is no `decision/`, `evaluation/` or `eval/`. Open: R24, R25, R26, R27, R30, R31, FA8, the M8 demo, and R35's "model availability". |
| **M9: U22** | **Partly in place from M2**, which provides discovery health and firehose/discovery-log retention (`pipeline/health.py`, `store/retention.py`). Missing: health thresholds with `status` failing; blob and `no_action` retention with a disk-guard pause; the systemd user unit; the soak. Open: R45 and the 24-hour soak (DoD). R33 and R49 are implemented, but proving them over a 24 h soak is still open. |
| **SP2** (instance lock) | **Open.** It blocks M9 (original plan; `docs/runbooks/handoff.md`). |

## Roadmap, as tracks

| # | Track | Scope | Source and IDs | State |
|---|---|---|---|---|
| 1 | **M8 v0.2.0: release, acceptance, promotion** | B1–B5 build and acceptance (done). Kit M8 r1, rehearsal R1–R7, root install, then a gated P0–P5 promotion. Extends FA5 with an analyst-request trigger (budgeted, reason recorded), R36 (job telemetry) and bounded runs. | M8 v0.2.0 plan; promotion plan to follow | In progress. Not promoted. |
| 2 | **SP2: instance locking** | `sandbox sweep`/`check` and a second process of the same instance must not remove a running service's job containers. | Original SP2 (done-when unchanged) | Committed; prerequisite of M9; **next after track 1** (owner decision) |
| 3 | **M9: supervision, health, retention, soak** | U22 as written, except that the first soak runs rules-only (amendment above). | U22; R33, R35, R36, R45, R49; M9 demo; DoD soak report | Committed; amended dependency and acceptance (owner decision) |
| 4 | **Decision models and evaluation (original M8 U20/U21)** | Kev-0.8B and Laya DecisionProvider; the labelled evaluation (≥ 50 cases, ≥ 40% benign, sufficiency verdicts, policy section). **A separate milestone after M9** (owner decision; its number is still open, "M10" is proposed). It keeps the original acceptance criteria verbatim **plus** the model-enabled soak. | U20, U21; R24–R27, R30, R31; FA8; the original M8 demo | Committed requirements; re-sequenced after M9 (owner decision) |
| 5 | Dashboard, case-investigation UX, report generation | A local web UI and richer reports. U15 (HTML report, CSV) already exists. | **Proposed.** Originally deferred: "Web UI beyond a generated report and CLI" | Proposed |
| 6 | Verified Isha Foundation brand/reference corpus | Seed confirmed official URLs and build the corpus with U17's collector. Possibly Scrapling for bounded discovery of *candidate* asset URLs. | U17 code exists (R13, R14, R22). The open question "which official reference URLs are seeded first and who confirms them" stands. Scrapling: **proposed** | Committed (corpus); proposed (Scrapling) |
| 7 | MISP enrichment (optional) | Pull indicators as an enrichment source. | **Proposed** | Proposed |
| 8 | macOS installation and local-model feasibility | A feasibility study first. | Originally deferred ("Mac deployment hardware sizing and launchd packaging"). **Proposed** | Proposed |

## Watchdog notes: decisions this creates (recommendations, not blocks)

1. **Resolved by the owner decision above.** The first M9 soak runs rules-only; U20/U21 move after M9 with a model-enabled soak added to their acceptance.
2. **Final acceptance FA8 and the original DoD stay open until track 4 lands.** "Fit for unattended 24×7 operation" (R45) can be declared after M9. "Plan complete" cannot.
3. **Track 6 and Scrapling.**
   - R13 requires reference retrieval only from approved HTTPS URLs through the hardened fetcher, refusing off-registry redirects. Scrapling's fetchers, including the stealth and browser modes, must not replace that path.
   - Acceptable use: parsing pages already fetched by U17, or proposing candidate URLs for **organizational confirmation**. Brand and domain verification belongs to the organization (Goal Capsule).
   - Its browser modes on the host would bypass R41 isolation.
   - It is a new dependency, so it needs a supply-chain review.
4. **Track 7 (MISP).** Pulling is an enrichment source (it must use the netguard-pinned client). **Publishing to MISP is "submitting anything to a remote site", a plan stop condition, and needs its own decision.** Indicator sharing also needs a data-handling decision.
5. **Track 8 (macOS).** R49 and R50 assume Linux rootless Docker with delegated cgroups, a dedicated account and internal networks. Docker Desktop runs a VM, so the sandbox, egress and bypass suites must be re-proven there. Treat it as feasibility, not a port.
6. **Track 5.** A local HTTP service is a new attack surface. R40's autoescape and CSP apply, and it needs a listener and authentication decision.

## Sequence
1. Track 1: R1 (passed 2026-10-31) → R2–R7 (by 2026-11-05T23:59Z) → kit seal and root install → M8 promotion.
2. Track 2: SP2.
3. Track 3: M9, with the first soak rules-only.
4. Track 4: U20/U21, then the model-enabled soak.
5. Tracks 5–8 when the owner selects them.

Track 6's corpus seeding can run in parallel once the URLs are confirmed, because it improves detection (T1 showed no corpus).
