# Reproducibility and environments

BrandSentinel's work splits into tiers by what each step needs and what it can affect.
Each tier below says what it proves and what it does not. Move to the next tier only when
the previous one is green.

| Tier | Where | Contacts third parties? | Privilege | Proves |
|---|---|---|---|---|
| **0. Offline development** | any Linux machine with Python 3.12 and uv | no | none | the code, scoring, network policy (against a local harness), the demo |
| **1. Network-dependent development** | developer machine with Internet access | **yes** | none | discovery and enrichment against real services |
| **2. Rootless Docker (developer)** | Linux, cgroup v2, rootless Docker, the sandbox image | only through the sandbox proxy, if you choose | your own user's daemon | container isolation, media and browser sandboxes, the lab |
| **3. Production (owner only)** | the dedicated `brandsentinel` account | yes, when collection is authorized | root for installation; the service account for running | the installed build under its real account |

Never use the production data directory as a demonstration or test target, in any tier.

## Tier 0: offline development (any developer machine)

```sh
uv sync
uv run ruff check
uv run pytest -m "not docker and not lab and not models"
uv run python docs/demo/offline_demo.py /tmp/bs-demo
```

| Step | Expected | Common failures |
|---|---|---|
| `uv sync` | `.venv/` created from `uv.lock` | no Python 3.12: `uv python install 3.12` |
| `ruff check` | `All checks passed!` | |
| offline suite | 1524 passed, 1 skipped (2026-11-06, `87c0d16`, clean clone) | `BRANDSENTINEL_*` variables set in your shell: unset them. The configuration refuses unknown `BRANDSENTINEL_*` variables, and `BRANDSENTINEL_DATA_DIR` redirects stores. On macOS the harness addresses `127.77.0.x` are not on loopback |
| demo | five cases, every row `[ok]`, exit 0 | the target directory exists: choose a new one |

What tier 0 does **not** prove: anything about real sites, real DNS, or container
isolation. The security tests here exercise netguard and the fetcher against a local
adversarial DNS/HTTP/TLS server, not the Internet.

## Tier 1: network-dependent commands (developer, Internet)

These contact third parties: certificate-transparency feeds, DNS resolvers, RDAP
registries and the candidate sites themselves. Run them only with a scratch config and
only when contacting those parties is acceptable to you.

```sh
docker compose -f docker/compose.yaml --profile certstream up -d    # local certstream-server-go (optional)
uv run brandsentinel -c scratch.yaml analyze isha.in                 # passive: DNS, RDAP, TLS, similarity; no case
uv run brandsentinel -c scratch.yaml sweep isha.in                   # one dnstwist sweep (many DNS queries)
uv run brandsentinel -c scratch.yaml run --no-dnstwist --duration 150   # live CertStream
```

- `analyze --fetch DOMAIN` also performs one static fetch of the site.
- `submit` followed by `run --no-certstream --no-dnstwist --until-idle --duration 300`
  processes manual submissions with real enrichment and fetching.
- Recorded measurements from these commands, such as CertStream throughput and dnstwist
  sweep sizes, are in the [milestone demo log](../runbooks/demo.md). They were short smoke
  runs, not sustained measurements.

## Tier 2: rootless Docker on a developer machine (Linux)

Requirements, checked by `brandsentinel sandbox check`:

- cgroup v2 with the memory, pids and cpu controllers delegated to your user;
- rootless Docker, with the endpoint at `unix://$XDG_RUNTIME_DIR/docker.sock` and seccomp
  enabled;
- subordinate UID/GID ranges for your user;
- about 3–4 GiB for the sandbox image (`scripts/check-disk-budget.sh`).

On a developer machine you are the owner of the code, so `brandsentinel run` refuses to
start unless a local config sets `runtime.allow_developer_account: true`. Even then its
sandbox stages run only lab content. That override is for development only.

```sh
scripts/build-sandbox-image.sh                               # brandsentinel-sandbox:local; refuses a rootful endpoint
docker compose -f docker/compose.yaml --profile sandbox up -d   # bs_sandbox network + egress proxy
docker compose -f docker/lab.compose.yaml up -d                 # lab sites + lab proxies (internal networks)
uv run brandsentinel -c dev-lab.yaml sandbox check              # account, runtime, network + direct-egress probe
uv run brandsentinel -c dev-lab.yaml sandbox selftest media
uv run brandsentinel -c dev-lab.yaml sandbox selftest browser
uv run pytest -m "docker or security"                           # must pass with zero skipped tests
```

Here `dev-lab.yaml` is a copy of `config/lab.yaml` with
`runtime: {allow_developer_account: true}` added, and its own `data_dir`.

Recorded results (developer runtime):

- M8 branch: `-m "docker or security"` 517 passed, 0 skipped;
- M7: 497 passed, 0 skipped.

See [Testing](../development/testing.md).

| Failure | Meaning |
|---|---|
| `sandbox check` fails "rootless" | the Docker endpoint is rootful, or `docker_host` points at the system socket |
| cgroup controller missing | systemd delegation is not configured for your user (`docs/runbooks/sandbox.md`) |
| image missing | build it; containers run with `--pull never` |
| lab tests fail on `127.0.0.1:3129` | another lab proxy (for example another account's) holds the port |
| docker tests skipped | Docker unreachable. The gate requires zero skips; a skipped run is not a pass |

Setup details: the [sandbox runbook](../runbooks/sandbox.md),
[media runbook](../runbooks/media.md) and [browser runbook](../runbooks/browser.md).

## Tier 3: privileged production operations (owner only)

These change a shared, persistent installation. They are **not** part of reproducing the
project, and coding agents must not run them:

- creating the service account and installing `/opt/brandsentinel`;
- building or loading the image on the account's daemon;
- running `validate.sh` under the account;
- promotions, rollbacks and backups;
- live collection.

They are described in [Deployment and recovery](../operations/deployment.md), and each one
needs its own approval.

## Reproducing a result someone reported

1. Check out the reported commit (`git switch --detach <sha>`) and run `uv sync`.
2. Use the same tier and command, with a fresh scratch `data_dir`.
3. Compare counts (passed, failed, skipped) and, for cases, `cases show --json` output.
   Hashes, ports, case numbers and timestamps vary between runs. Priorities, categories,
   reasons and points do not, given the same registry, policy and pages.
