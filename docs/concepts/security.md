# Security model and isolation

BrandSentinel's job is to look at hostile infrastructure. The design assumes every
candidate host, page, image, certificate, DNS answer and RDAP response is adversarial, and
every such input passes through a control on the way in. This page lists the controls as
implemented and the risks they leave. The requirement IDs (R37–R50) are from the
[implementation plan](../plans/2026-10-08-001-feat-brandsentinel-local-pipeline-plan.md),
"Security Gates by Operation".

## Threats in scope

| Threat | Example | Primary control |
|---|---|---|
| SSRF and internal reachability | a candidate resolving to `127.0.0.1`, `169.254.169.254`, RFC 1918 ranges, IPv4-mapped IPv6 | netguard |
| DNS rebinding | a second resolution returning a private address | pinning: connect only to the validated address |
| Resource exhaustion | gzip bombs, endless headers, slow bodies, huge images, decompression bombs | byte, time and pixel caps in fetcher, proxy and workers |
| Code execution through parsers | malformed images; browser exploits | images decoded only in the media sandbox; pages rendered only in the browser sandbox |
| Exfiltration from a sandbox | a page opening sockets, WebRTC, DNS tunnels | internal network, validating proxy, worker-side refusals |
| Injection into the analyst's tools | terminal escapes, HTML/JS in reports, CSV formulas | escaping at every output |
| Self-compromise of the host | the application with root or rootful Docker | dedicated account, refusal checks |

## Controls

### netguard: who may be contacted (`net/netguard.py`)

- Parses the URL and resolves it once. Every answer must be globally routable unicast.
  Refused:
  - loopback, private, link-local, CGNAT and metadata addresses;
  - multicast and reserved addresses;
  - IPv4-mapped, compatible, NAT64 and 6to4 wrappers of blocked addresses;
  - answer sets that mix public and blocked addresses (`dns_mixed_private`).
- Schemes `http` and `https` only, ports from `net.allowed_ports` (80, 443). No userinfo,
  backslashes, control characters or zone ids.
- IP literals are parsed as browsers parse them (`2130706433`, `0x7f.1`, `127.1`).
- Lab mode adds exactly the pinned lab subnet for listed hostnames. Test ranges are
  accepted only as a constructor argument, never from configuration.

### Hardened static fetcher (`net/fetcher.py`)

- **Requests:** GET and HEAD only; no cookies, credentials or proxy environment variables.
- **Redirects:** a manual redirect walk (at most 5). netguard validates every hop.
- **Connections:** each one goes to a validated address, with the hostname still used for
  SNI and `Host`.
- **Limits:** a whole-fetch wall-clock budget, a cap on bytes from the wire (5 MiB) and a
  cap on decoded bytes (10 MiB). A body is kept only for accepted media types.
- **TLS:** `verified` mode for trusted reference collection; `evidence` mode for
  suspects. Evidence mode retries without verification after a certificate failure, and
  records `tls_verification_failed`. Evidence-mode content can never become reference
  content.

### Egress proxy (`net/proxy.py`)

The only member of the internal sandbox network with a route out.

- Every request is re-decided by netguard. The proxy connects only to the address netguard
  validated, so rebinding between check and connect is impossible.
- `CONNECT` only to port 443, and only when the first bytes look like a TLS ClientHello
  record header. Plain HTTP is forwarded as GET or HEAD.
- Limits on connections (global and per client), header size, timeouts and bytes per
  connection.

### Sandbox containers (`sandbox/runner.py`, `sandbox/preflight.py`)

Each job is a fresh container, created with:

```text
--network <bs_sandbox | none> --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=…
--cap-drop ALL --security-opt no-new-privileges=true [--security-opt seccomp=<profile>]
--memory N --memory-swap N (no swap) --cpus N --pids-limit N --ipc private --shm-size N
--ulimit core=0 --ulimit nofile=1024:1024 --init --log-driver none --pull never
--label brandsentinel.instance=<instance> (plus job, role, attempt labels)
```

- **Lifecycle:** the runner kills the container by name at the wall-time limit, caps
  stdout and stderr, and removes the container afterwards. At startup it removes
  containers left by a crash (labelled with this instance) before job leases are recovered.
- **Preflight before any sandbox stage registers:**
  - the endpoint is rootless;
  - cgroup v2 with the memory, pids and cpu controllers;
  - seccomp is available;
  - the image is present;
  - the account gate passes.
- **Browser stage, in addition:** the network check, including a direct-egress probe that
  must fail.
- **Media worker:** `--network none`.
  - A magic-byte allowlist, with one Pillow plugin per format.
  - Header checks on pixels, dimensions, frames and icon entries before decoding.
  - Output is validated strictly (exact ids, the sha256 of what was sent).
  - The host process never imports an image library, which a test enforces.
- **Browser worker:** Chromium (Playwright 1.63.0) as an unprivileged user.
  - Chromium's own sandbox stays on, with a shipped seccomp profile derived from Docker's
    default.
  - Observe only: non-GET requests are stopped, downloads refused, service workers
    blocked, dialogs dismissed and popups closed.
  - WebSockets are refused, and WebRTC and workers are removed.
  - Output is strictly validated (`render_rejected` otherwise).

### Account (`sandbox/preflight.py`, SP1)

Production runs as a dedicated user. That user:

- is not root;
- is not in the `docker` group;
- cannot open the rootful socket;
- does not own the code;
- has its own rootless Docker daemon.

That is a deployment property, and the application checks it only in a few places.
`check_account` tests three things about the current process:

- `not_root`: the UID is not 0. This always fails for root, even with the developer
  override.
- `not_code_owner`: the UID does not own the application code.
- `no_rootful_docker`: no rootful Docker socket is readable and writable.

The last two pass with a warning under `runtime.allow_developer_account`. The check does
not confirm that the process is the `brandsentinel` account; any account with these
properties passes.

#### Which commands enforce it

| Command | Account check | Opens the store |
|---|---|---|
| `run` | the [production-store checks](#production-store-enforcement) first; then it **refuses to start** (exit 2) before opening the store if any account check fails. Its sandbox stages are additionally withheld, outside lab mode, unless the checks pass with no override (`gate_hostile_content`) | yes, after the checks |
| `registry collect` | the production-store checks; then, outside lab mode, **refuses** (exit 1) unless the account checks pass with no override, because it needs the media sandbox. In lab mode: no further check | yes, after the checks |
| `status` | the production-store checks; then **reports only**: prints the account checks when `sandbox.enabled` is on. It prints the store class | yes |
| `submit`, `replay`, `sweep`, `analyze`, `cases list`, `cases show`, `cases label`, `cases rescore`, `report`, `export csv`, `registry corpus` | the production-store checks: on the production store, only the service account with the approved configuration. On a development store, any non-root account | yes |
| `store check` | the production-store checks, then it stops: exits 0 when a store command would proceed and 2 when it would be refused | no: it reads metadata and the configuration only |
| `sandbox check` | **refuses root** (real or effective UID 0, exit 2); otherwise **reports**, and exits 1 on a failure (`--strict`: also on a warning). A diagnostic, not a gate | no |
| `sandbox selftest`, `sandbox sweep`, `proxy` | **refuse root** (real or effective UID 0, exit 2) before configuration loading or Docker; no other check (`selftest` checks only the runtime) | no |
| `version`, `match`, `registry validate`, `eval` | none | no |

**The CLI guard** (in the repository, not yet installed in production; see
[Status](../project/status.md)). All 14 commands marked *yes* in the last column, and
`store check`, first pass one check. They exit 2, before the configuration is read or
anything is opened or created, when the effective UID is 0, or when none of `-c`, a
non-empty `$BRANDSENTINEL_CONFIG` or a non-empty `$BRANDSENTINEL_DATA_DIR` is given, or
when `$BRANDSENTINEL_DATA_DIR` is only whitespace. There is no override. On a
development store, an explicit source that leaves a relative location (a file with no
`data_dir`, a relative path) still resolves against the current directory.

#### Production-store enforcement

In the repository, not yet installed in production (B3, plan
`docs/plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md`). After the CLI
guard, a store command reads its configuration once and decides, **before anything under
the data directory is created, migrated or swept**, whether the store is the production
store and whether this process may open it. Deciding reads only metadata and the store
marker. Every refusal exits 2 with
`refusing to open a store:` followed by stable check names, and prints no path or value.

- **The anchor.** A root-owned file, `/etc/brandsentinel/production.yaml`, outside the
  install prefix, names the account, the store path, the approved configuration and the
  install prefix. It is believed only if every directory from `/` down and the file
  itself are root-owned and not writable by others, the file is a single regular file
  of at most 64 KiB, and it ends with `complete: true`. Otherwise every store command on
  the host refuses (`anchor_unsafe`). Installed code on a host with no anchor refuses
  every store command (`anchor_missing`); a checkout falls back to the marker.
- **Classification.** A data directory at, under or above the anchor's store path is
  production, decided from the configured path alone, so the account's 0700 home is
  never searched. A path that resolves there (symlinks and `..` resolved as the kernel
  does), the same directory by device and inode (only when this process can reach the
  live store), or a directory holding the store marker is production too. Only the anchor's exact
  store path may be used: a production-class store anywhere else, including a marked
  byte copy, is refused for everyone (`noncanonical_production_store`).
- **The production policy,** at the canonical store only: the effective and real UID
  are the anchor's account, which owns the store; `check_account` passes with no
  warning; `runtime.allow_developer_account` is refused, not ignored; the configuration
  is the approved file, given as an absolute `-c` with no symlink component, root-owned
  and not writable by others; `$BRANDSENTINEL_CONFIG`, `$BRANDSENTINEL_DATA_DIR`,
  `PYTHONPATH`, `PYTHONHOME`, `PYTHONUSERBASE` and `PYTHONSTARTUP` are unset; the running
  package and every `sys.path` entry lie inside the install prefix; the production paths
  are absolute; and the store exists. A production store is never created.
- **Integrity, for every store.** A store is refused (`store_integrity`) when its
  database, WAL, shared-memory or journal file is a symlink or has more than one link,
  or when `raw/`, `artifacts/` and the directories inside them that the store writes
  and sweeps, `cache/` or `reports/` is a symlink. Without this, a scratch store with a
  symlinked `artifacts/` would let the orphan sweep delete another store's evidence.
- **The store layer** repeats the anchor, classification and integrity checks, and
  refuses a production-class store unless it receives the authorization the CLI
  produced for that store's path, device and inode and the effective UID.

**What these checks are.** File permissions are the boundary between accounts: the
account's 0700 home keeps every other non-root account out of the live store. These
checks prevent accidents by the authorized account (a relative `-c`, a store variable,
a symlinked or copied configuration, a checkout on `PYTHONPATH`, the developer
override) and refuse everyone else before anything is touched. They are **not** a
boundary against a deliberate service account or root:

- **The marker is an accidental-misuse signal, not an identity.** Whoever can write a
  store directory can remove it. A copy of the database file alone (`.backup`,
  `VACUUM INTO`, `cp brandsentinel.db`), a copy that skips the marker, and copies made
  before the live store was marked are development stores when opened elsewhere.
  Removing a marker is not an approved procedure.
- **Code without these checks ignores them**: an older checkout, a retained previous
  installation, `legacy/`.
- **The authorization is a value**: it stops accidental callers of `open_store`, not
  hostile Python, which can build one.
- **Not checked:** `DOCKER_HOST`, `XDG_RUNTIME_DIR`, `PATH`, `HOME`, `LD_PRELOAD`; the
  destinations of `report --out` and `export csv -o`; hard links to existing report
  files (a report written over a hard-linked file reaches every name); links created
  after a store is opened, during a long `run`.
- **Tests read the host.** In-process tests never read the real anchor; tests that
  start the CLI as a subprocess (the offline demo, the lab demo) do.
- **One anchor governs the host.** Once it is installed, a malformed or unsafe anchor
  (a wrong mode, a comment after `complete: true`, reordered keys) refuses every store
  command on the host, development included, and installed code with no anchor refuses
  them all too. A deliberate account that can mount over `/etc/brandsentinel` in a
  user namespace can hide the anchor from a checkout; the marker then still classifies
  the live store, unless it was removed too.

The guard and these checks do **not** make a root run safe, and **running a command is
still not evidence that the account is right**. They run inside the command, after the
installed CLI has been imported, so on the current production installation a root
invocation can still write Python bytecode caches into the root-owned code tree, even
when it is refused.
[Bytecode-write prevention](../operations/deployment.md#bytecode-write-prevention) closes
that for console scripts on a new installation. It is implemented and not yet promoted, and
it is not immutability: root can still change the tree. `version`, `match`,
`registry validate` and `eval` still run as root. Until these controls are promoted, the
rule in [Deployment](../operations/deployment.md#production-cli-operations) stays the
only enforcement in production.

`sandbox check --strict` must pass with no warnings under the account.

### Storage and outputs

- **Artifacts** are content-addressed, mode 0600, without extensions, never executed,
  and subject to per-artifact, per-case, per-domain and store-wide quotas.
- **Facts** are sanitized and capped when written (`text.max_fact_chars`,
  `text.max_fact_bytes`).
- **Outputs:**
  - the terminal output is escaped (`textsafe.py`);
  - HTML reports are self-contained, autoescaped, with a strict CSP and no live links;
  - CSV neutralizes formula triggers.
- **Logs** follow an allowlist: no URLs, queries, page data or exception messages.

## How the controls are verified

- `tests/security/` runs every netguard, fetcher, proxy, quota and lease control against a
  local adversarial DNS/HTTP/TLS harness (tier 0).
- The real-container suites (`-m docker`) cover OOM kills, PID limits, wall-time kills,
  output caps and orphan removal. A bypass suite shows no TCP/UDP/DNS/IPv6/gateway/metadata
  route out of `bs_sandbox`, with a positive control on an ordinary network.
- **Standing gate (SP3):** any change under `net/` or `sandbox/` must pass
  `-m "docker or security"` with zero skipped tests.

See [Testing](../development/testing.md).

## Limits and residual risks

These are known and accepted for the current maturity. They are not hidden defects.

- **Containers, not VMs.** Rootless Docker plus seccomp shares the host kernel. VM-level
  isolation (gVisor, Kata) is deferred.
- **Untrusted HTML is parsed on the host.** The static extractors parse fetched HTML in the
  application process (selectolax). Moving parsing into the sandbox is deferred.
- **The TLS check in the proxy is a prefix filter, not TLS enforcement.** A page can still
  make its own GET requests and TLS connections to allowed public destinations from the
  browser sandbox.
- **Egress is attributable.** Fetches and renders come from the host's network. There is no
  VPN or anonymizing egress and no per-destination rate limit.
- **Production-store enforcement is not installed.** The anchor, the account and
  configuration policy, store integrity and the root refusal for Docker and listener
  commands are in the repository on a development branch, not merged or promoted
  ([Production-store enforcement](#production-store-enforcement)). Until they are, the
  installed CLI checks the account only in `run` and `registry collect`, and production
  CLI use is restricted by procedure. Even then they are accident controls: they do not
  stop a deliberate service account, root, or code without them.
- **No instance lock (SP2).** A concurrent `sandbox sweep`, `sandbox check` or a second
  process of the same instance can remove another process's running job containers. This
  blocks unattended operation (M9).
- **Every store open writes.** Inspection commands such as `status` and `cases list`
  can create the data directory and database, enable WAL, run migrations and delete
  unreferenced artifact files older than one hour ([Storage](storage.md)). Never run them
  against a store whose bytes must stay unchanged.
- **Media and browser limits are per container.** Adversarial media can still amplify
  cost within those limits. There is no aggregate cost control across domains.
- **The image is not vulnerability-scanned.**

Per-milestone accepted limits: the review findings pages under
"Project → Review findings by milestone", the [browser runbook](../runbooks/browser.md),
the [media runbook](../runbooks/media.md) and the [sandbox runbook](../runbooks/sandbox.md).
