# Residual review findings - M5 (U12, U13, U14, U15)

Review run `20261010-131302-fb730f88`. Nine reviewers ran on the staged M5 diff
against `5a232c4`: correctness, security, adversarial, reliability, performance,
testing, maintainability, data-migration and learnings. Project-standards and
agent-native did not run: the repository has no CLAUDE.md or AGENTS.md, and M5 has
no agent-facing surface. No peer CLI was installed, so there was no cross-model
pass. There was also no per-finding validator wave. The implementer verified each
finding by reading the code, or by reproducing it with
`tests/detection_support.score_html`, before fixing it.

## Fixed before commit

- **P1, claim evasion by an earlier possessive** (security, correctness). Any
  "<Brand>'s" earlier in a sentence suppressed every later claim. The possessive
  must now sit directly before the claim ("Lumina Foundation's official website").
- **P1, claim evasion by an unrelated negation** (security, adversarial,
  correctness). A "no"/"not" within 40 characters turned a claim into a
  disclaimer ("No fees, we are the official site for ..."). A negation now counts
  only within the same clause and at most two words before the claim.
- **P1, masked password inputs** (adversarial). A text input styled with
  `-webkit-text-security`, or named `pwd`/`password`, is now a credential field,
  both in forms and in the page-wide count.
- **P1, uppercase Cyrillic/Greek homoglyphs** (adversarial). An all-caps brand
  written with `М`, `Α` and similar letters escaped page-text matching. Page text
  now maps uppercase lookalikes before the shared skeleton. The M1 matcher is
  unchanged, because domain labels are lowercase.
- **P1, brand split across inline elements** (adversarial). `Lum<span>ina</span>`
  read as two words. Headings, body text and form context are now also matched in
  a rendering with inline text joined.
- **P1, VPA followed by punctuation** (adversarial, correctness). `x@okaxis.` was
  rejected as if it were an e-mail domain. Sentence punctuation is now allowed,
  while `info@site.org` is still not a VPA.
- **P1, quadratic byline scan** (performance). The scan took deep text of every
  `p/span/div`. It now reads each element's own text, capped at 2000 elements.
  20,000 nested divs extract in about 0.4 s.
- **P2, decoy registry payee** (adversarial, correctness). A hidden copy of the
  real payee earned relief beside a scam payee. `confirmed_payee` relief now
  applies only when every payee on the page is confirmed.
- **P2, weak term ties a form to the brand** (correctness). The form-context route
  now needs a strong brand mention.
- **P2, form directly under `<body>`** (adversarial residual). A form there took
  the first 2000 characters of the page as its context. It now gets its own text
  and the tails of the three elements just before it.
- **P2, form padding** (adversarial residual). Credential forms are kept whatever
  their position among up to 200 forms.
- **P2, grouped account numbers and UPI links outside `<a>`** (adversarial).
  `0001 2345 6789` is normalized, and UPI deep links are found anywhere in the
  markup with entities decoded: `<area>`, `onclick`, data attributes and comments.
  Values are no longer percent-decoded twice.
- **P2, redirect to the official domain gave relief** (security). The redirect is
  the candidate's own behaviour, so `redirects_to_official` is now 0 points (an
  explained reason only). Content rules still skip the official page, because the
  observed content is the official site's.
- **P2, confirmed partners scored as abuse** (correctness residual). Credential
  and payment rules now skip hosts with a confirmed relationship, as the
  association, lookalike and commerce rules already did. `credential_cross_origin`
  also honours official redirects.
- **P2, case left unscored after a crash or scoring error** (reliability). A
  redelivered fetch job now scores the case without fetching again.
- **P2, raw tracebacks for a bad policy or catalog** (reliability). The catalog
  raises `CatalogError`, and `run`, `analyze` and `cases rescore` exit 2 with the
  message.
- **P2, extraction on the event loop** (performance). Extractors now run in a
  worker thread. Database writes stay on the loop thread.
- **P2, whitespace runs in claim matching** (performance). The page-text skeleton
  collapses whitespace, and claim matching reads at most 2000 characters per
  sentence.
- **P3, `cases rescore`** (reliability). One failing case no longer stops the
  batch, and a missing or failed case exits 1.
- **P3, CSV piped to stdout** (security residual). Piped output is now the exact
  CSV, identical to `--out`. A terminal still gets visible escapes.
- **P3, report writes** (security residual). Report writes use `O_NOFOLLOW`.
- **P3, CSV export memory** (performance). The export streams cases one at a time.
- **Maintainability:**
  - shared `host_of`, `registrable_of`, `unique_matches` and `iso` helpers;
  - one `registry_cleared` guard in the rules.
- **Testing gaps closed:**
  - every `cases list` filter;
  - CLI escaping of hostile text that bypasses the sanitizing writer;
  - rescore exit codes and a bad policy;
  - piped CSV;
  - redelivery scoring;
  - an evasion suite (`tests/unit/test_detection_evasion.py`) with a time budget
    on hostile structure.

## Deferred / accepted

- **Proximity-based credential tie.** A login form placed right after a very
  short paragraph naming the brand reads like the disguised-credential lab page.
  Real news layouts put login in the header, which is not tied. Lure language and
  M7 rendering will refine this.
- **Static-only limits.** These need M6/M7 and are flagged `needs_media` or
  `needs_render`:
  - QR codes and image-only appeals are not decoded;
  - script-built pages are not rendered;
  - a cloaked site serves its decoy to the fetcher;
  - a cloaking redirect to the official domain hides abuse until rendering.
- **Dismissed cases reopen** (M2 residual, learnings). `cases label` records
  verdicts, but `_open_case` does not yet respect them on a re-sweep.
- **`material_change` uses the raw body hash** (M3 residual). It is not yet a
  normalized content hash, so dynamic pages re-score on every recheck (harmlessly:
  an unchanged result inserts no row).
- **Growth without retention.** Scores keep a bundle per distinct result, and
  `rescore --reextract` appends features each run (latest wins). Retention belongs
  with U22.
- **Maintainability:**
  - `evidence/bundle.py` (`build_bundle` is about 190 lines) and `cli.py` (about
    950 lines) should be split before more extractors and commands are added;
  - the facts SQL in `reextract` duplicates what the evidence loaders do;
  - `AnalysisStages.offline_enrich` has a config default overridden by `register`.
- **Untested:**
  - the event loop's responsiveness during extraction is not measured.
- **Lab demo test** (`tests/lab/test_static_demo.py`) runs only with the lab and
  Docker markers.

## Independent PR review: affiliation is not authorization

A review of PR #5 found that `registry_cleared()` (official domain, redirect to
an official domain, or a confirmed relationship) suppressed every credential and
payment rule, and that official-domain relief (1000 points) cancelled any
remaining abuse points. A compromised official or partner site could therefore
send brand credentials to an unknown domain, or direct donations to an unknown
payee, and still score `no_action`. This came from the overbroad fix for
"confirmed partners scored as abuse" above. Each finding below was reproduced
end to end (real extractors and policy) before it was fixed.

- **P1, compromised official or partner site cleared** (security). Registry
  affiliation now clears only the rules about presenting the brand: lookalike,
  false association, commerce, and the on-site credential and payment rules. Two
  destination rules apply to vouched hosts:
  - `credential_unapproved_destination` (55 points): a brand-tied credential
    form submits to a registrable domain that no confirmed registry domain (any
    kind) or relationship approves.
  - `payee_unapproved_on_vouched_host` (50 points): a donation appeal in the
    brand's name, or a payee named for the brand, uses a payee the registry does
    not confirm.

  Both rules are `offset_by_relief=False`, so registry relief cannot cancel them.
- **Destination approval is per brand.** The bundle records each off-site
  credential destination and which brands confirmed registry entries approve it
  for (`registry.credential_destinations`), plus the brands the host is vouched
  under (`registry.vouching_brands`). A destination is approved only for the
  brands the form is tied to (or, when the tie names none, the host's vouching
  brands). A domain confirmed only for another brand approves nothing, even when
  the host is also affiliated with that brand. A confirmed relationship that
  names no brand (domain to domain) is reported for manual review and does not
  approve the destination.
- **Versioning.** The policy is now `policy/2` and the bundle `bundle/2`. Stored
  results are never re-evaluated: reports and score history show each row's own
  policy and bundle versions. Rescoring adds a new row and never rewrites an old
  one. `bundle/1` still parses, so earlier rows load with their original labels.
- **P2, one payee counted twice** (correctness). On a donation page,
  `payment_brand_unconfirmed_payee` (55) and `donation_appeal_unconfirmed_payee`
  (30) both scored the same brand-claiming payee. That pushed a single UPI ID
  from P2 to P1. The donation rule now counts only payees attributed to no brand,
  which the payment rule cannot see. `credential_form_brand` plus
  `credential_cross_origin` is kept on purpose: the second rule adds an
  observation, the off-site destination.
- **Still not abuse.** These cases stay `no_action`:
  - an official page with its own login, lures or a confirmed payee;
  - a partner whose login goes through a confirmed SSO domain;
  - a partner whose checkout uses a payee under the partner's own name.
- **Tests added:** a `policy/1` row keeps its provenance through a rescore,
  and a populated v3 store migrates to v4 without changing existing
  rows, and the migrated case can then be scored.
