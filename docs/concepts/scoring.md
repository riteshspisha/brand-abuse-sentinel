# Evidence and scoring

A case's priority is a pure function of its **EvidenceBundle** and the **policy**. Both are
versioned and stored with every score, so any decision can be audited and reproduced
without reading code. The scoring is deterministic and rule-based, and no model is
involved.

## The EvidenceBundle (`bundle/4`)

Built by `evidence/bundle.py` from the case's stored records and the registry. The same
inputs always produce identical bytes; the bundle's sha256 is stored with the score.

| Block | Contents |
|---|---|
| `subject` | the case's host, URL and registrable domain |
| `discovery` | how the **name** matched: sources, strength, hits (kept separate from page behaviour) |
| `registry` | what the registry says about this host (official, related, unknown) |
| `infrastructure` | DNS, RDAP, TLS, closest official domains, enrichment errors |
| `http` | the static fetch: outcome, status, redirect chain with the validated address per hop, content hash |
| `page` | title, headings, brand references, which brand the page presents |
| `credential` | forms, password fields, their destinations |
| `payment` | UPI, bank and gateway observations, payee names, and each one's **attribution** (confirmed, claims the brand unconfirmed, unrelated) |
| `association` | claims of partnership or endorsement |
| `commerce` | shop and checkout signals |
| `editorial` | article markup, bylines, disclaimers (context only) |
| `visual` | image and screenshot matches against the reference corpus, image text, QR payees |
| `render` | what the browser did and saw, and the cloaking comparison |

Every block carries `refs` (`fact:<id>`, `feature:<id>`, `artifact:<sha256>`,
`discovery_event:<id>`). Untrusted text is sanitized and capped again here. When a browser
render completed, the page-level blocks describe the rendered page. The exception is when
only the static page showed abuse indicators; then the static view is kept.

## The policy (`policy/5`)

Rules live in [`policy/rules.py`](../../src/brandsentinel/policy/rules.py). Points and
thresholds live in `config/policy.yaml`, which must list every rule. Three kinds:

- **abuse**: independently observed abuse tied to a protected brand. For example, a
  credential form whose surrounding text names the brand, or a payee that claims the brand
  but is not a confirmed registry payee. **Only abuse rules can lift a case to P1 or P2.**
- **supporting**: risk signals that cannot reach P1/P2 alone: name similarity, recent
  registration, parking, lure language, redirects.
- **relief**: registry-derived facts only: a confirmed official domain, payee or
  relationship. Page-provided signals (article markup, bylines, parody labels,
  disclaimers) are **never** relief.

```text
score    = max(0, abuse + supporting − relief)
priority = P1 if score ≥ 80, P2 ≥ 50, P3 ≥ 25, P4 ≥ 1, else no_action
           capped at P3 when no abuse rule fired
```

Two destination rules (`credential_unapproved_destination`,
`payee_unapproved_on_vouched_host`) are **not offset by relief**. A confirmed official or
partner site that sends credentials or money somewhere the registry does not confirm still
ranks, which is how a compromised official site is caught.

### Category and labels

- **Category:** the highest fired abuse category by fixed precedence: `credential_phishing`,
  `payment_fraud`, `donation_fraud`, `impersonation`, `false_association`,
  `unauthorized_commerce`, `typosquat_parked`. Without abuse evidence the category is
  `editorial_or_critical`, `insufficient_evidence` (static analysis could not see the
  content), `benign_related` or `unrelated`.
- **Labels** (`commerce`, `editorial_or_critical`, `official_domain`, …) describe the case
  and **never** change its score.
- **Flags** name follow-up work or gaps: `needs_media`, `needs_render`, `manual_review`,
  `render_not_scheduled`.
- **Unknowns** list what could not be observed. A case whose content static analysis could
  not observe and that shows no abuse evidence is kept at **P4 or above**, never
  `no_action`.

### The current numbers

The file below is included verbatim from `config/policy.yaml` at build time:

```yaml
--8<-- "config/policy.yaml"
```

## Versioning and rescoring

- Change any number and bump `version:` in `config/policy.yaml`.
- Stored scores keep their `policy_version` and `bundle_schema`.
- `brandsentinel cases rescore` rebuilds bundles from stored facts and adds **new** rows.
  It never rewrites old ones, and nothing is fetched.

## Advisory models (planned, not implemented)

The plan reserves `model_review_threshold` (0.8 above) for advisory judgments from local
Kev-0.8B and Laya models (U20). A judgment could add the flag `model_suggests_review` but
would never change a priority. The scorer already reads the `judgments` table and
implements that flag (`policy/scorer.py`), but no provider exists, so nothing writes
judgments yet.

## Interpreting results responsibly

- A P1 means "look at this first", not "this is fraud".
- Lab results show the rules behave as designed on synthetic pages written alongside
  them. Real-world precision and recall have **not** been measured (U21, labelled
  evaluation, is not implemented).
- Analyst labels (`cases label`) are recorded for future evaluation and never change a
  decision.
