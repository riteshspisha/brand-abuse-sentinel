# Offline demo: from submission to an explained case

A five-minute, deterministic walkthrough. It shows a manual URL submission going through
the real pipeline (intake, job queue, enrichment, the hardened fetcher, extractors,
evidence bundle, policy) and then inspected with the real CLI. It runs on one Linux
machine with **no network access and no Docker**, and writes only to a new directory you
choose.

!!! note "What this demo is and is not"
    - **The pages are synthetic.** They are five sites from the controlled lab
      (`labsites/`), built for a fictional brand, *Lumina Foundation*.
    - **The network is simulated.** Each site's hostname resolves, through the test
      suite's local harness, to a loopback web server that serves the committed HTML.
      That harness is test machinery: the `brandsentinel` CLI itself refuses loopback
      addresses.
    - **It shows how a case is built and explained.** It measures nothing about
      real-world detection accuracy. Five fixture pages that were written together with
      the rules are not an evaluation.

## Run it

```sh
uv sync
uv run python docs/demo/offline_demo.py /tmp/bs-demo
```

The script refuses to run if:

- the directory already exists;
- the directory is under `/var/lib/brandsentinel`;
- `BRANDSENTINEL_CONFIG` or `BRANDSENTINEL_DATA_DIR` is set (either would redirect the
  CLI to another store).

Expected output (about 4 s; case numbers, hashes, ports and times vary):

```text
case  site                   priority  category               score  expected (labsites)
   1  donation-fraud         P1        donation_fraud           120  P1/P2 donation_fraud  [ok]
   2  false-association      P2        false_association         70  P2/P3 false_association  [ok]
   3  disguised-credential   P1        credential_phishing       85  P1 credential_phishing  [ok]
   4  news-critical          no_action editorial_or_critical      0  P4/no_action editorial_or_critical  [ok]
   5  official               no_action benign_related             0  no_action benign_related  [ok]
```

The last column compares each outcome with the site's `labsites/<site>/expected.yaml`. The
script exits 1 if a case is not scored within 60 s or any outcome differs. The same run is
a test (`tests/integration/test_offline_demo.py`).

## Inspect the cases

```sh
uv run brandsentinel -c /tmp/bs-demo/demo.yaml cases list
```

```text
  case  priority  category               score  host
     1  P1        donation_fraud           120  donate-luminafoundation.test  [manual]  flag:needs_media
     3  P1        credential_phishing       85  lumina-watch-news.test  [manual]  disclaimer_present, editorial_or_critical, flag:manual_review, flag:needs_media
     2  P2        false_association         70  orin-wellness-partners.test  [manual]  commerce, flag:needs_media
     4  no_action editorial_or_critical      0  dailyledger-news.test  [manual]  editorial_or_critical, flag:needs_media
     5  no_action benign_related             0  luminafoundation.test  [manual]  official_domain
```

```sh
uv run brandsentinel -c /tmp/bs-demo/demo.yaml cases show 1
```

Abridged:

```text
Case #1  donate-luminafoundation.test
  Priority ranks analyst attention from observed evidence; it is not a finding of fraud. BrandSentinel never initiates takedowns.

  priority:              P1  (score 120: abuse 105, supporting 15, relief 0)
  category:              donation_fraud

Why (policy reasons):
    +55  payment_brand_unconfirmed_payee [abuse]
         Payment identifier(s) upi rivers.relief.fund@quickpaybank ('Lumina Relief'); bank_account 000123456789
         are presented under Lumina Foundation (payee name or page) and are not confirmed registry payees.
         evidence: feature:7, fact:21, artifact:1e93002d…, feature:2
    +50  lookalike_domain_brand_content [abuse]
         The domain matches the brand strongly (affix:lumina, keyword:luminafoundation, official_lookalike:luminafoundation.test)
         and the page presents Lumina Foundation in its title, headings or image text.
    +15  domain_similarity_strong [supporting]

Unknowns: enrichment_error_rdap, enrichment_error_tls, media_pending, media analysis is queued: images, QR codes and visual matches are not yet known

HTTP (static fetch, evidence mode):
    hop 200 http://donate-luminafoundation.test:44407/mutable?k=donation-fraud via 127.77.0.1
Payment (facts | attribution | evidence):
  upi rivers.relief.fund@quickpaybank name 'Lumina Relief' amount 1000
      attribution: claims_brand_unconfirmed - payee name 'Lumina Relief' names Lumina Foundation; not a confirmed registry payee
Provenance:
  policy:                policy/5
  bundle:                bundle/4 sha256 0980ebfe…
```

## How to read a case

- **Priority and score.** The score is `abuse + supporting − relief`, floored at 0. It is
  mapped to P1 (≥ 80), P2 (≥ 50), P3 (≥ 25), P4 (≥ 1) or `no_action`. Without at least one
  **abuse** rule a case cannot rise above P3, so a brand mention or a similar name alone
  never becomes urgent. See [Evidence and scoring](../concepts/scoring.md).
- **Reasons cite evidence.** `fact:N`, `feature:N` and `artifact:<sha256>` are records
  in the store. The artifact is the exact page the fetcher received, stored inert.
  `cases show --json 1` prints the whole bundle and policy result.
- **Unknowns are listed, not hidden.** Here the media sandbox did not run (the demo has
  no Docker), so images and QR codes are `media_pending`. The harness serves no RDAP or
  TLS answer for these names, so those enrichment sources report errors. A case with
  missing evidence is never presented as clean.
- **Contrasting cases.**
  - Case 4 (critical journalism) gets the context label `editorial_or_critical`, and
    labels never change a score.
  - Case 5 is on the lab brand's confirmed official domain, so registry relief applies:
    `official_domain`, `no_action`.
  - Case 3 is a credential form disguised as an article with a parody disclaimer. It
    stays P1: page-provided signals such as bylines and disclaimers are never relief.

## More views of the same store

```sh
uv run brandsentinel -c /tmp/bs-demo/demo.yaml cases show --json 1   # bundle + result, machine-readable
uv run brandsentinel -c /tmp/bs-demo/demo.yaml report --index        # HTML under /tmp/bs-demo/data/reports/
uv run brandsentinel -c /tmp/bs-demo/demo.yaml export csv            # CSV on stdout
uv run brandsentinel -c /tmp/bs-demo/demo.yaml status                # jobs: media and render pending (no sandbox)
```

`demo.yaml` enables lab mode only so the CLI loads the same registry (the committed
registry plus the Lumina overlay). Fetching, enrichment, the sandbox, media and the
browser are all off in it, so these commands only read the store.

Delete `/tmp/bs-demo` when you are done. It is yours; nothing else refers to it.

## The full lab demo (Linux, rootless Docker)

The same lab sites, served by nginx on an internal Docker network and fetched through the
lab proxy, also exercise the media sandbox (QR codes, OCR, logo matching) and the isolated
browser (script-built login and payment pages, cloaking). This needs the tier-2
environment from [Reproducibility](reproducibility.md):

- the sandbox image;
- the lab Compose stack;
- a developer config with `runtime.allow_developer_account: true`.

The commands and recorded results per milestone are in the
[milestone demo log](../runbooks/demo.md) and the [browser runbook](../runbooks/browser.md).
The lab tests assert every site's `expected.yaml` (`uv run pytest -m lab`).

## Known gaps

- **No fixture mode in the CLI.** `brandsentinel` cannot analyse a local HTML file or a
  loopback server, by design (netguard). The offline demo therefore drives the pipeline
  from a script that reuses the test harness. Adding an explicit, clearly-labelled
  offline mode is a product decision. It is listed in the [roadmap](../project/roadmap.md).
- **No sandboxes in the offline demo.** Media and browser stages need Docker, so their
  evidence appears only in the full lab demo.
- **No field evidence.** Real-world detection rates have not been measured. Labelled
  evaluation (U21) is not implemented.
