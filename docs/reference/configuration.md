# Configuration

Configuration is one YAML file, validated by the Pydantic model in
[`src/brandsentinel/config.py`](../../src/brandsentinel/config.py).

- Every key is optional and **unknown keys are rejected**, so a typo fails loudly.
- Only two environment variables are read: `BRANDSENTINEL_CONFIG` (the file) and
  `BRANDSENTINEL_DATA_DIR` (overrides `data_dir`). Any other `BRANDSENTINEL_*` variable is
  an error.
- Relative paths are resolved from the current directory, which is why the production
  file uses absolute paths.

## Files in the repository

| File | Purpose |
|---|---|
| `config/brandsentinel.example.yaml` | every key with its default and an explanation (below). A test checks that it lists every field of the model |
| `config/service.yaml` | production: absolute paths, no developer override; installed read-only as `/opt/brandsentinel/etc/service.yaml` |
| `config/lab.yaml` | lab mode: synthetic registry overlay, lab hosts, lab sandbox network, discovery off |
| `config/policy.yaml` | rule points and thresholds ([Evidence and scoring](../concepts/scoring.md)) |
| `config/payment_providers.yaml` | catalog of payment providers and gateways used by the payment extractor |

## Safety-relevant settings

| Setting | Default | Effect |
|---|---|---|
| `data_dir` | `data` | where the store lives; always set it explicitly outside a scratch checkout |
| `discovery.certstream.enabled`, `discovery.dnstwist.enabled` | `true` | live discovery; contacts third parties |
| `fetch.enabled`, `enrich.enabled` | `true` | the static fetch and passive enrichment contact candidate hosts and registries |
| `sandbox.enabled` | `true` | sandbox stages; at startup the runner force-removes containers labelled with `sandbox.instance` (default `main`) |
| `media.enabled`, `browser.enabled` | `true` | image analysis and rendering (only when the sandbox preflight passes) |
| `browser.sample_rate` | `0.1` | share of strong cases rendered without another trigger |
| `browser.analyst_renders_per_day` | `0` | budget for `submit --render`; 0 records and refuses requests |
| `runtime.allow_developer_account` | `false` | lets a developer (code owner, or with rootful Docker access) run sandbox stages. **Development only** |
| `net.lab.enabled` | `false` | lab mode; requires both discovery sources off |

!!! warning "Two settings that surprise people"
    - The analyst budget does **not** control automatic rendering. The browser renders
      triggered and sampled cases whenever it is enabled. To stop all rendering, set
      `browser.enabled: false`.
    - A second instance on the same Docker runtime must use its own `sandbox.instance`.
      Otherwise its startup sweep removes the first instance's running job containers.

## A minimal offline configuration

```yaml
# Validated by tests/unit/test_docs.py.
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
media:
  enabled: false
browser:
  enabled: false
```

## Every key, with defaults

Included verbatim from `config/brandsentinel.example.yaml`:

```yaml
--8<-- "config/brandsentinel.example.yaml"
```
