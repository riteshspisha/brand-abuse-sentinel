# Roadmap and known limitations

The roadmap follows the
[implementation plan](../plans/2026-10-08-001-feat-brandsentinel-local-pipeline-plan.md)'s
milestones. Nothing below is implemented unless [Status](status.md) says so.

## Next

The order below follows the post-I1 backlog
([`2026-11-09-001-post-i1-engineering-backlog.md`](../plans/2026-11-09-001-post-i1-engineering-backlog.md)).
Security remediation of the [2026-11-06 incident](status.md#incident-2026-11-06) comes first.

| Item | Plan ref | Depends on | Status |
|---|---|---|---|
| **1. CLI guard:** every store-opening command refuses UID 0 and refuses to run without an explicit configuration or data directory, before any store is opened ([security model](../concepts/security.md#which-commands-enforce-it)) | incident remediation; [plan](../plans/2026-11-09-002-cli-root-and-config-guard-plan.md) | owner confirmation of the plan's two decisions (done) | implemented; not promoted (item 4) |
| **2. Installation bytecode:** prevent bytecode writes by console scripts (checked-hash precompilation of the venv and the bundled interpreter, `-B` launchers) and verify the bytecode and launchers | incident remediation | 1 (same promotion) | implemented; not promoted (item 4) |
| **3. Production-store enforcement:** a root-owned anchor and a store marker identify the production store; only the service account with the approved absolute configuration and the installed code may open it; marked copies elsewhere are refused; store integrity for every store; root refused for Docker and listener commands; read-only `store check` ([security model](../concepts/security.md#production-store-enforcement)) | incident remediation; [plan](../plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md) | 1; owner decisions O2 (done) | developed on a branch; not merged or promoted |
| 4. Promotion of 1–3: new wheel and image, gated promotion. Item 3 is a required gate: no live-production promotion without it | (operations) | 1, 2 and 3 | not started |
| Production Brand Registry confirmation: official domains, payees, reference assets and pages | R6, U17 | the organization | open decision |
| Instance lock so a sweep or check cannot remove another process's job containers | SP2 | sequenced after 1–2 (owner order: SP2, then M9) | not started |
| Continuous monitoring: health samples, thresholds that make `status` exit non-zero (so a supervisor or cron can alert), heartbeat, free-disk pause | U22 / M9 (R35, R36) | SP2 | not started |
| Unattended operation: supervision unit, retention, 24 h soak (the first soak runs rules-only) | U22 / M9 | SP2 ([owner decision 2026-10-31](../plans/2026-10-31-001-roadmap-alignment.md)) | not started |
| DecisionProvider with Kev-0.8B and Laya (advisory only) | U20 | model servers | not started |
| Labelled evaluation dataset and runner; rules-only vs models comparison | U21 | U20; labels; after M9 | not started |

## Known limitations

Carried from the review findings and runbooks:

- **Detection**
  - Lazy-loaded images (`data-src`, `srcset`, CSS backgrounds) are not collected.
  - Cropped, mirrored or transformed assets evade whole-image matching.
  - Changes behind an unchanged image URL may not be re-fetched on rechecks.
  - Matcher false positives exist for context terms appearing anywhere in a name.
- **Isolation**
  - Containers share the host kernel.
  - HTML is parsed on the host.
  - Egress is attributable.
  - The proxy's TLS check is a prefix filter.

  See [Security model](../concepts/security.md#limits-and-residual-risks).
- **Operations**
  - There is no supervision unit and no instance lock.
  - Until item 4 is promoted, production checks the account only in `run` and
    `registry collect`. After it, store commands refuse root (the cause of the 2026-11-06
    incident) and open the production store only for the account (item 3); `version`,
    `match`, `registry validate` and `eval` still run as root.
  - An explicit configuration with no `data_dir`, or a relative one, resolves against the
    current directory.
  - Every store open writes: it creates missing files, applies migrations and sweeps
    orphan blobs.
- **Product**
  - The CLI has no offline or fixture mode. The [offline demo](../guide/demo.md) uses the
    test harness instead. An explicit, clearly-labelled demo mode would be a product
    decision.
  - No analyst UI beyond the CLI, static HTML reports and CSV.

## Documentation follow-ups

- Decide whether the service-account runbook and the session handoff can be published
  after removing host-specific records. They are excluded from the site for now, but
  they are public in the repository and its history either way.
- Fix the `eval` stub text ("planned for M8") in `src/brandsentinel/cli.py` to name the
  outstanding U20/U21 work. This is a one-line code change and not made here.
- Add a license.
- Make the full offline suite pass on a hosted CI runner, then add it to
  `.github/workflows/checks.yml` (see [Testing](../development/testing.md#ci)). The
  `docker or security` gate is not in CI: it needs the rootless sandbox runtime.
