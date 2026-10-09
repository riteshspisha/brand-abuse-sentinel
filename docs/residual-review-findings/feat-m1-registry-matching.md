# Residual review findings - M1 (U3, U4)

Review: correctness, testing, maintainability, security and adversarial reviewers on
`feat/m1-registry-matching` against the M0 commit. Fixed findings are in the branch;
these were accepted or deferred.

## Deferred

- **Concatenated typos** (`sadhgurrulive.com`): fuzzy matching compares whole labels
  and hyphen tokens, so a typo'd brand glued to another word is missed. Revisit with
  M2 candidate samples (sliding windows at distance 1) before widening, to measure
  false positives first. dnstwist sweeps cover typos of the official domains.
- **ASCII digit lookalikes** (`adiyog1.com`, `1sha-yoga.com`): not normalized.
  Fuzzy keywords catch them; non-fuzzy keywords do not.
- **Confusable table is curated, not complete.** Unmapped lookalikes are caught by
  the `residue` form (inserted characters) and by fuzzy comparison of non-ASCII name
  parts against every high-tier keyword. Generating the table from Unicode
  `confusables.txt` is the next step if M2 samples show misses.
- **Context terms match as substrings of the whole folded name**, TLD included
  (`misha.yoga`, `sevastopol-misha.com`). Weak strength only; refine the term list
  with M2 samples (plan Open Questions).
- **Exclusions match anywhere in the name**, not on token boundaries, per R7. A broad
  maintainer-added exclusion (e.g. `ishan`) silences contexted hits such as
  `ishanyoga.com`; review exclusion additions with `brandsentinel match`.
- **Unicode dot variants**: fullwidth full stop is rejected as an invalid name;
  ideographic full stop makes one `idn_invalid` label.
- **Lab overlay (U11)**: registry validation requires domains under a public suffix,
  so lab hostnames need a real suffix or a lab-only allowance.
- `unicode_host` drops invisible characters for display; `host` (punycode) is the
  identity and must be shown beside it wherever an analyst decides.

## Accepted

- The legacy exclusion `abhishek` is kept for fidelity to the legacy input and
  reported as a validation warning (it can never apply).
- `registry.loader` imports `matching.normalize` for domain canonicalization while
  `matching.matcher` imports `registry.model`; there is no import cycle.
- `dnstwist_targets()`, `confirmed_payees()` and the payee, relationship and
  reference-page models have no production consumer until U6, U14 and U17.
