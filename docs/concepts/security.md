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

### Account (`config.py` runtime gate, SP1)

Production runs as a dedicated user. That user:

- is not root;
- is not in the `docker` group;
- cannot open the rootful socket;
- does not own the code;
- has its own rootless Docker daemon.

`brandsentinel run` refuses to start as root, and as the code owner or with rootful
Docker access unless `runtime.allow_developer_account` is set (development only).
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
- **No instance lock (SP2).** A concurrent `sandbox sweep`, `sandbox check` or a second
  process of the same instance can remove another process's running job containers. This
  blocks unattended operation (M9).
- **Every store open sweeps orphan blobs.** Read-only commands such as `status` delete
  unreferenced artifact files older than one hour. Never run them against a store whose
  bytes must stay unchanged.
- **Media and browser limits are per container.** Adversarial media can still amplify
  cost within those limits. There is no aggregate cost control across domains.
- **The image is not vulnerability-scanned.**

Per-milestone accepted limits: the review findings pages under
"Project → Review findings by milestone", the [browser runbook](../runbooks/browser.md),
the [media runbook](../runbooks/media.md) and the [sandbox runbook](../runbooks/sandbox.md).
