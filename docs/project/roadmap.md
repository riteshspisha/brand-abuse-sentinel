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
| **1. CLI guard:** every store-opening command refuses UID 0 and refuses to run without an explicit configuration or data directory, before any store is opened ([security model](../concepts/security.md#which-commands-enforce-it)) | incident remediation; [plan](../plans/2026-11-09-002-cli-root-and-config-guard-plan.md) | owner confirmation of the plan's two decisions | planned |
| **2. Installation bytecode:** install with precompiled bytecode for the venv and the bundled interpreter, and verify that no `.pyc` is missing | incident remediation | 1 (same promotion) | not started |
| 3. Account enforcement for a production store: refuse the code owner or a rootful-Docker user on a production store | incident remediation | 1; a decision on how a developer checkout opts out | not started |
| 4. Promotion of 1–3: new wheel and image, gated promotion | (operations) | 1–3 | not started |
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
  - Only `run` and `registry collect` check the account. Other commands, including those
    that write the store, run as root (the cause of the 2026-11-06 incident).
  - A store-opening command without a configuration creates `./data` in the current
    directory.
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
