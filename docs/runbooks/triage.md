# Analyst triage (M5)

BrandSentinel ranks cases for analyst attention from evidence it collected
itself. A priority is not a finding of fraud, and the tool never initiates a
takedown or contacts a site beyond one guarded static fetch.

## Commands

```sh
brandsentinel cases list [--priority P1 --priority P2] [--category donation_fraud]
                         [--label editorial_or_critical] [--source manual]
                         [--strength strong] [--status open] [--since 2026-10-01]
brandsentinel cases show <id> [--json]          # reasons, evidence, unknowns
brandsentinel report <id>... | --index [--out DIR]   # static HTML, owner-only files
brandsentinel export csv [-o cases.csv] [same filters as cases list]
brandsentinel cases label <id> --verdict abusive|suspicious|benign|unrelated|unsure
brandsentinel cases label <id> --question payment_or_donation_abuse --value yes|no|unsure
brandsentinel cases rescore <id>... | --all [--reextract]   # offline; nothing is fetched
```

Labels are stored for the M8 evaluation and never change a priority. Run
`cases rescore --all` after changing `config/policy.yaml` or confirming registry
entries, and add `--reextract` after an extractor change.

## Reading a case

- **Priority** P1–P4 or `no_action`, from `score = abuse + supporting − relief`
  with thresholds in `config/policy.yaml`. Only abuse-evidence rules can reach P1
  or P2; without one a case is capped at P3.
- **Category**: the highest-precedence fired abuse rule (`credential_phishing`,
  `payment_fraud`, `donation_fraud`, `impersonation`, `false_association`,
  `unauthorized_commerce`), else `typosquat_parked`, `editorial_or_critical`,
  `insufficient_evidence`, `benign_related` or `unrelated`.
- **Why**: every fired rule with its points, a plain explanation and evidence
  references: `fact:<id>`, `feature:<id>`, `artifact:<sha256>` (the stored page),
  `discovery_event:<id>`, `registry:<kind>:<name>`.
- **Context labels** (`editorial_or_critical`, `disclaimer_present`, `commerce`,
  `payment_gateway_present`, `parked`, ...) describe the page and never change the
  score. Article markup, bylines, parody labels and disclaimers are written by the
  page and can be written by an attacker, so they never lower a score.
- **Flags**: `manual_review` (with reasons), `needs_render` (script-built page;
  browser rendering is M7), `needs_media` (images or QR codes; media analysis is
  M6), `model_suggests_review` (M8).
- **Payment** rows separate the observed fact (provider, payee identifier, payee
  name, destination), the attribution (`registry_known_payee`,
  `claims_brand_unconfirmed`, `unrelated`) and the evidence references.
- **Discovery** (how the name matched) is shown apart from the page's behaviour.

## What only a registry change fixes

Only confirmed registry entries give relief: official domains, payees and
relationships. When a report says a host or final URL is under a registry domain
with status `candidate` or `legacy-unverified`, confirm or reject that entry in
`registry/brands.yaml`, then `cases rescore --all`.

## Output safety

Reports are static HTML with escaped content, a `default-src 'none'` CSP, no
scripts and no links to candidate URLs (URLs are text). Terminal output shows
control and bidi characters as visible escapes. CSV cells that a spreadsheet
would evaluate (`=`, `+`, `-`, `@`, leading tab or CR) are prefixed with `'`.
