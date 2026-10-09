# BrandSentinel milestone demos

## M1 - Registry and matching (2026-10-09)

```bash
uv run brandsentinel registry validate
uv run brandsentinel match sadhguru.org.verify-login.xyz fakeisha.info shop.ishalife.com ...
```

`registry validate` passes on `registry/brands.yaml`, confirms every legacy input is
present with its `legacy/<file>:<line>` provenance, and warns that the legacy exclusion
`abhishek` can never apply (it does not contain `isha`).

Legacy-style inputs replayed against the committed registry (nothing confirmed yet):

| Name | Legacy script | Candidate | Strength | Hits | Labels / notes |
|---|---|---|---|---|---|
| `sadhguru.org.verify-login.xyz` | dropped (substring whitelist) | yes | strong | keyword:sadhguru, official_lookalike:sadhguru.org | - |
| `login-sadhguru.org.ru` | dropped (substring whitelist) | yes | strong | keyword:sadhguru, official_lookalike:sadhguru.org | - |
| `isha.in.secure-donate.com` | dropped (substring whitelist) | yes | strong | official_lookalike:isha.in, token:isha | - |
| `fakeisha.info` | treated as official | no | - | - | isha_affix_uncontexted |
| `vishal-sadhguru-tickets.com` | dropped (exclusion `vishal`) | yes | strong | keyword:sadhguru | excluded:vishal |
| `odisha-isha.org` | dropped (exclusion `odisha`) | yes | weak | token:isha | excluded:odisha |
| `odisha.gov.in` | no match | no | - | - | excluded:odisha |
| `save-soil.shop` | not matched | yes | strong | keyword:savesoil (folded) | - |
| `inner-engineering.online` | not matched | yes | strong | keyword:innerengineering (folded) | - |
| `xn--sadhgur-t2a.com` (`sadhgurü.com`) | not matched | yes | strong | keyword:sadhguru (homoglyph) | idn |
| `shop.ishalife.com` | dropped (whitelist) | yes | weak | registry_domain:ishalife.com | legacy_whitelist_unverified |
| `manisha-boutique.com` | matched nothing | no | - | - | isha_affix_uncontexted |
| `isha-yoga-donate.in` | matched (`isha` token) | yes | weak | token:isha (context yoga, donate) | - |

With `isha.in` and `sadhguru.org` confirmed by a maintainer (test registry),
`www.sadhguru.org` and `isha.in` are suppressed with `suppressed:official_domain`,
while the lookalikes above stay candidates.
