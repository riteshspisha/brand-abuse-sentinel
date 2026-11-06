# BrandSentinel

BrandSentinel finds domains and URLs that may impersonate a protected brand. It collects
evidence about them without trusting them and gives each case a deterministic,
explained priority for an analyst. It runs locally: one Python process, a SQLite store,
and rootless-Docker sandboxes for hostile content.

!!! warning "What a priority means"
    P1–P4 rank analyst attention from observed evidence. They are not findings of fraud.
    BrandSentinel never submits anything to a suspect site and never initiates takedowns.

## Where to start

| You want to… | Read |
|---|---|
| install it and run something safe | [Set up and first commands](guide/getting-started.md) |
| see a case built and explained, offline | [Offline demo](guide/demo.md) |
| know what runs where (laptop, Linux + Docker, production) | [Reproducibility and environments](guide/reproducibility.md) |
| understand the design | [Architecture](concepts/architecture.md), [Pipeline](concepts/pipeline.md) |
| understand a score | [Evidence and scoring](concepts/scoring.md) |
| review the isolation | [Security model](concepts/security.md) |
| look up a command or setting | [CLI](reference/cli.md), [Configuration](reference/configuration.md) |
| contribute | [Testing](development/testing.md), [Documentation system](development/documentation.md), and `AGENTS.md` in the repository |
| know what is finished | [Status and maturity](project/status.md), [Roadmap and limitations](project/roadmap.md) |

## Current status in one paragraph

- **Installed:** version 0.2.0 (milestone M8, commit `e40ffcb`) is the production build,
  and its promotion was accepted on 2026-11-05.
- **Live collection:** no unattended collection has run.
- **Isolated-copy trial (I1):** the first attempt stopped before processing because of a
  launch-script defect. A corrected script is prepared but not yet validated on the host.
- **Not implemented:** advisory decision models, model evaluation, unattended operation
  and the instance lock.

Details: [Status and maturity](project/status.md).
