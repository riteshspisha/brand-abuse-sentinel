# Roadmap and known limitations

The roadmap follows the
[implementation plan](../plans/2026-10-08-001-feat-brandsentinel-local-pipeline-plan.md)'s
milestones. Nothing below is implemented unless [Status](status.md) says so.

## Next

| Item | Plan ref | Depends on | Status |
|---|---|---|---|
| Real-host validation of the corrected trial tooling, then I1 r2 on an isolated copy | (operations) | owner authorization | prepared |
| Production Brand Registry confirmation: official domains, payees, reference assets and pages | R6, U17 | the organization | open decision |
| Instance lock so a sweep or check cannot remove another process's job containers | SP2 | | not started |
| Account enforcement for every command: refuse root, and the wrong account for a production store, before any store is opened ([security model](../concepts/security.md#which-commands-enforce-it)) | (security; no plan ID yet) | a decision on how a developer checkout opts out | not started |
| DecisionProvider with Kev-0.8B and Laya (advisory only) | U20 | model servers | not started |
| Labelled evaluation dataset and runner; rules-only vs models comparison | U21 | U20; labels | not started |
| Unattended operation: supervision, health thresholds, retention, 24 h soak | U22 / M9 | SP2, U21 | not started |

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
    that write the store, run as root.
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
