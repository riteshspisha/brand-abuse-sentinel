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

## M2 - Discovery and durable intake (2026-10-09)

```bash
docker compose -f docker/compose.yaml --profile certstream up -d   # certstream-server-go on 127.0.0.1:8080
uv run brandsentinel sweep isha.in                                 # one dnstwist sweep now
uv run brandsentinel run --no-dnstwist --duration 150              # live CertStream
uv run brandsentinel submit https://suspicious.example/donate      # manual submission
uv run brandsentinel status
uv run brandsentinel replay                                        # idempotent re-ingest
```

Short live smoke run on the development machine (scratch data dir; not the planned
one-hour measurement, which is still to do):

| Measurement | Result |
|---|---|
| dnstwist `isha.in` sweep | 1316 permutations (with brand-word dictionary), 49 registered, 49 strong candidates, 26 s |
| CertStream throughput | ~111k certificates in 90 s (~1,200/s) with no disconnects; matcher alone measured at ~24k names/s |
| CertStream matches | 7 matching certificates in 90 s, 8 weak candidates over 240 s |
| Restart | 10 s `process_restart` coverage gap recorded, ~13,118 CT log entries skipped (from per-log `cert_index` jumps) |
| Raw discovery log | 6.9 KB after both sources (firehose off) |

Observed false positives (weak, matcher tuning for later): `*.anthemishackingfinanceretreat.com`
matches `isha` as an affix contexted by `retreat` (context terms match anywhere in the
name), and each subdomain becomes its own candidate; `makesoil.de` is a distance-2 fuzzy
match of `savesoil`.
