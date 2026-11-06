# Set up and first commands

This page gets a fresh checkout to a working, tested development environment, using
only safe commands. Nothing here uses Docker, contacts a third-party site, or touches
anything outside the checkout.

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Linux (x86-64 tested) | the test suite's local network harness binds `127.77.0.0/24` on loopback | `uname -s` |
| Python 3.12 (3.13 allowed by `requires-python`) | the application | `.python-version` pins 3.12 |
| [uv](https://docs.astral.sh/uv/) | installs the exact locked dependencies (`uv.lock`) | `uv --version` |
| About 1 GB free | virtual environment and caches | `df -h .` |
| Network access to PyPI, once | installing dependencies | |

Optional, for later tiers only: rootless Docker and the sandbox image
([Reproducibility](reproducibility.md)), and Tesseract on the host for one media unit test
(it is skipped otherwise).

## Install

```sh
git clone https://github.com/riteshspisha/brand-abuse-sentinel.git
cd brand-abuse-sentinel
uv sync            # creates .venv with the runtime dependencies and the dev group
```

`uv sync` installs `brandsentinel` in editable mode. The sandbox-only libraries
(Pillow, Playwright and others: the `sandbox` extra) are **not** installed on the host.
They exist only in the sandbox image.

## First commands

```sh
uv run brandsentinel version
uv run brandsentinel registry validate
uv run brandsentinel match sadhguru.org.verify-login.xyz fakeisha.info odisha.gov.in save-soil.shop
```

Expected:

- `version` prints `0.2.0`.
- `registry validate` prints counts by status and ends with `ok`. It warns once that the
  legacy exclusion `abhishek` can never apply. Note `suppressing domains none`: the
  committed registry has no maintainer-confirmed domains yet, so nothing is suppressed as
  official.
- `match` prints one JSON object per name:
  - `sadhguru.org.verify-login.xyz` is a strong candidate (`keyword:sadhguru`,
    `official_lookalike:sadhguru.org`);
  - `odisha.gov.in` is not a candidate (`notes: ["excluded:odisha"]`);
  - `save-soil.shop` is a strong candidate through the folded keyword `savesoil`.

  These are the defects of the legacy scripts, fixed. The full table is in the
  [milestone demo log](../runbooks/demo.md).

None of these commands opens a store.

## Run the tests

```sh
uv run ruff check
uv run pytest -m "not docker and not lab and not models"
```

From a clean clone (2026-11-06, commit `87c0d16`) the second command reported
**1524 passed, 1 skipped, 118 deselected in 56.3 s**. The skip is the media worker's OCR
test when Tesseract is absent. The deselected tests need Docker, the lab stack or model
servers. See [Testing](../development/testing.md).

## Where data goes

Commands that open a store (`status`, `submit`, `run`, `cases`, `report`, `export`,
`analyze`, `replay`, `registry collect`) use the configured `data_dir`:

1. `-c FILE` if given, else `$BRANDSENTINEL_CONFIG`, else built-in defaults;
2. then `$BRANDSENTINEL_DATA_DIR`, if set, overrides `data_dir`;
3. the default `data_dir` is `./data`, relative to the current directory.

Use a scratch config for anything you try:

```yaml
# scratch.yaml: a throwaway store, no discovery, no network-facing stages
data_dir: /tmp/bs-scratch/data
discovery:
  certstream:
    enabled: false
  dnstwist:
    enabled: false
fetch:
  enabled: false
enrich:
  enabled: false
sandbox:
  enabled: false
```

```sh
uv run brandsentinel -c scratch.yaml submit https://example.invalid/donate
uv run brandsentinel -c scratch.yaml status
uv run brandsentinel -c scratch.yaml cases list
```

`submit` creates a case and queues its first enrichment job, but nothing processes it
because every stage is off: `cases list` shows it unscored. To watch a case be fetched,
scored and explained without any network, run the [offline demo](demo.md).

!!! danger "Never use the production store for experiments"
    Every store-opening command, even `status` and `cases list`, writes. It can:

    - create the data directory and database (without `-c`, `./data` in the current
      directory);
    - switch the database to WAL;
    - apply migrations;
    - delete unreferenced artifact files older than one hour.

    Never point a development command at `/var/lib/brandsentinel/data` or at a copy you
    need to keep byte-identical. Production commands belong to the owner, run as the
    service account ([Deployment](../operations/deployment.md#production-cli-operations)).

## Next

- [Offline demo](demo.md): submission → evidence → explained priority.
- [Reproducibility and environments](reproducibility.md): what needs Docker, the
  network, or the production account.
- [Architecture](../concepts/architecture.md).
