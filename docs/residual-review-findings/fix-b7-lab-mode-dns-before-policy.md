# Residual findings: lab-mode refusal before DNS (B7, 2026-11-25)

These are the accepted limits of the fix that makes the host fetcher refuse a non-lab destination in lab mode before
any DNS query. A full-depth review on 2026-11-25 covered correctness, security, adversarial spellings, testing,
maintainability and project standards. It found no P0, P1 or actionable finding. Its coverage gaps are fixed by tests
in this change, and the remaining items are recorded below.

## What changed

- `NetGuard.validate(url, lab_only=True)` refuses a hostname that is not in the lab map with `not_lab_host` **before it
  is resolved**. An IP literal needs no query: its address classification runs first (so a redirect to
  `169.254.169.254` still reports `link_local`), and a literal that is not a lab host is then refused as `not_lab_host`.
- The host fetcher passes `lab_only` in lab mode on every hop, the first and each redirect. Its former check after
  validation is removed, because validation now guarantees a lab target.
- Outside lab mode, and for callers that do not pass `lab_only`, nothing changes: the same resolution, pinning and
  address checks run. The lab-only egress proxy already refused other names before DNS (M4) and is unchanged.

**Why.** Before the fix, the fetcher resolved a public name through the host resolver and only then refused it. Nothing
was fetched, but a DNS query left the host. The resolver tripwire (B7 PR-1) turned that query into a `dns_error`, which
failed the SP3 lab test on 2026-11-25 (`test_host_fetcher_refuses_public_urls_in_lab_mode`). This is the host-fetcher
half of the M4 proxy lesson ("Host header checked before DNS", [M4](feat-m4-sandbox-egress-lab.md)).

**Evidence.** Tests that count resolver queries (`StaticResolver.calls`) for direct fetches, redirects to public names
and literals, canonical spellings, numeric and IPv6 literal forms, and ordering against a caller's `host_allowed`
check; plus an offline reproduction of the SP3 failure with the shipped lab configuration under the tripwire. On the old
code 26 of them failed and one errored; all pass on the fix. The live `docker or security` gate passed on 2026-11-25 with this change merged into U14
(`4cf97f9`): 622 passed, 0 failed, 0 errors, 0 skipped, including `test_host_fetcher_refuses_public_urls_in_lab_mode`
and every lab-only refusal test.

## Accepted limits

- **Reason codes in lab mode changed.** A non-lab host now reports `not_lab_host` where it could previously report
  `dns_error` (an unresolvable name) or `host_not_allowed` (a caller's host check). Every case is still refused, and no
  code branches on these kinds.
- **Two exits in `validate`.** The lab-only refusal happens before resolution for hostnames and after classification for
  literals. Both are tested.
- **Lab-map keys are compared verbatim** with canonical hosts. A key with upper case or a trailing dot never matches and
  fails closed. Pre-existing.
- **An IP-shaped lab-map key** (pre-existing, configuration only) would make that literal count as a lab host, with the
  literal itself as its address. `config/lab.yaml` has none. Suggested follow-up for release-security triage: a
  `LabSettings` validator that requires canonical hostnames as keys, and `validate` ignoring the lab map for literals.
- **Other lab-mode network paths are outside this change.** Enrichment is offline in the shipped lab configuration
  (`dns_records` resolves through its own resolver when enabled), and TLS collection refuses lab mode before validation.
- **The NFKC/IDNA folding residual of M3** still holds outside lab mode ([M3](feat-m3-guarded-fetch-enrichment.md)).
