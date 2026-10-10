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

## M3 - Guarded fetch and enrichment (2026-10-09)

```bash
uv run pytest -m security                       # netguard, fetcher, quotas against the local harness
uv run brandsentinel analyze isha.in            # passive: DNS, RDAP, TLS, similarity (no case created)
uv run brandsentinel analyze --fetch <domain>   # plus one static fetch, evidence mode
uv run brandsentinel submit ishayoga.in shopisha.in ishain.com isha9.in
uv run brandsentinel run --no-certstream --no-dnstwist --duration 75
uv run brandsentinel status                     # stage outcomes, deferred work per domain
```

Live run on the development machine (scratch data dir, four registered lookalikes
from the M2 dnstwist sweep):

| Case | Enrichment | Static fetch |
|---|---|---|
| `isha.in` (`analyze`) | A/AAAA on Cloudflare, Google MX; RDAP via the NIXI registry (registered 2005, GoDaddy, redacted); TLS 1.3, Google Trust Services cert verifies; `tls_official_san` for `isha.in` | - |
| `ishayoga.in` | RDAP age 4243 days; TLS on 443 timed out | https timed out, http fallback followed `ishayoga.in` 301 -> `www.ishayoga.org` 301 -> `https://www.ishayoga.org/` 301 -> `isha.sadhguru.org/in/en/yoga-meditation` 200; 292 KB HTML stored as a blob; `page_basics`: canonical, 51 scripts, 16 images |
| `shopisha.in`, `ishain.com`, `isha9.in` | DNS and RDAP ok (`isha9.in` registered 43 days ago); TLS timeout or refused | connect or read timeouts on both schemes, recorded as `http_fetch_attempt` facts and retried after `fetch.retry_delay_seconds` |
| `sadhgurru.com` (`analyze --fetch`) | NXDOMAIN on every record type; RDAP `not_found`; similarity distance 1 to `sadhguru` | `dns_error` / `dns_nxdomain`, not retried |

The several connect timeouts on 443 from this network are not explained yet (the
sites may be down or filtered); each is kept as an error fact with its reason.

Domain age, registrar privacy, the certificate issuer and hosting provider are
recorded as context only. None of them is treated as a maliciousness indicator by
itself; that judgment belongs to the policy scorer (M5).

Subdomain flooding: 30 CertStream events for `sadhguru-N.evil-flood.com` keep 30
candidates and 30 open cases, but only 16 enrichment jobs are queued; the other 14 are
`deferred_jobs` rows (`domain_queue_full`) promoted as the domain's jobs finish
(`tests/integration/test_scheduling.py`).

## M4: sandbox runtime, egress proxy and lab (2026-10-09)

On the development host's rootless Docker (developer account, override set; the
dedicated-account setup is documented but not yet performed):

```sh
scripts/build-sandbox-image.sh
docker compose -f docker/compose.yaml --profile sandbox up -d
docker compose -f docker/lab.compose.yaml up -d
brandsentinel -c <dev config> sandbox check     # account warnings, runtime ok, network ok + probe
uv run pytest -m docker                          # 30 real-container tests
```

- Runner: OOM kill, PID limit, wall-time kill by name, output caps, AE18 orphan
  removal before lease recovery — all on real containers.
- Bypass suite: no direct TCP/UDP/DNS/IPv6/gateway/metadata route out of
  `bs_sandbox`; a positive control on an ordinary network sees the leaks.
- Egress proxy: our own (Squid forwarded Host-mismatched requests); see
  `docs/runbooks/sandbox.md` for the evaluation table and verification record.
- Lab: 16 sites reachable only through the lab proxy; the host fetcher refuses
  public URLs in lab mode.
