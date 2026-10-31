# Isolated browser rendering (M7: U19)

M7 adds the rendering gate (R41, R43): untrusted pages are rendered only in a
Chromium inside a per-job sandbox container whose network has no route out
except the validating egress proxy, and only after the network check passes. On
top of it: render triggers, static-versus-rendered (cloaking) comparison,
screenshot analysis in the media sandbox, and reference page screenshots.

## Trust boundaries

```text
 brandsentinel process (trusted orchestration; never imports Playwright)
   render decision ── why (fact)         network check before every launch (no probe)
   browser client ── job on stdin        startup: network check with direct-egress probe
          │                                        registry collect: same check first
          ▼
 ┌──────────── browser container (one per job, role `browser`) ───────────────────┐
 │ network: bs_sandbox (lab mode: bs_lab_sandbox) only; internal, no gateway       │
 │ pwuser, cap-drop ALL, no-new-privileges, Chromium seccomp profile, read-only    │
 │ root, noexec /tmp 256 MiB, private IPC + 256 MiB shm, 1536 MiB (no swap),       │
 │ 2 CPUs, 512 PIDs, 60 s wall from outside, stdout 16 MiB, no mounts, no ports    │
 │ Chromium with its own sandbox: renderers in their own user/PID/net namespaces   │
 │ observe only: no click, type, submit, download, permission; non-GET stopped     │
 └──────────────────────────────┬──────────────────────────────────────────────────┘
                                │ CONNECT / GET (Chromium's proxy setting; the
                                ▼ network allows nothing else)
          bs-egress-proxy (production)  /  bs-lab-sandbox-proxy (lab, lab hosts only)
          │ one JSON document back, validated against a strict schema before use
          ▼
 rendered HTML → U12 extractors (rendered features); screenshot → media sandbox
```

### The lab sandbox network (design decision, 2026-10-28)

Lab-mode browsers must reach the lab sites and nothing else, and the production
proxy (Internet, no lab hosts) may not serve them. Decision: a dedicated
network and proxy in the lab project (`docker/lab.compose.yaml`):

| | |
|---|---|
| `bs_lab_sandbox` | internal, `inhibit_ipv4`, IPv6 off, pinned `172.31.254.0/24` (`.1` reserved, held by nothing); lab-mode browser jobs join only this |
| `bs-lab-sandbox-proxy` | the proxy image and command, `lab_only`, reads `config/lab.yaml` read-only; on `bs_lab_sandbox` (`.254.2`) and `bs_lab` (`.250.3`) only; no published port, no network with a route out; listens only on `172.31.254.2:3128` |
| config | lab mode pins `sandbox.network`, `proxy_url` and `proxy_container` to these; outside lab mode they are refused |
| netguard | unchanged: the lab exception is still `172.31.250.0/24` for mapped hostnames only; the `.254` hop is a transport, never a fetch target |

Rejected: joining `bs-lab-proxy` to the new network (smaller, but the proxy the
untrusted browser talks to would also sit on `bs_lab_edge`, which has a route
out, so only the `lab_only` software check would keep the lab offline); putting
the browser on `bs_lab` itself (a page ignoring the proxy reaches `bs-lab-web`
directly, and `bs_lab` has a gateway in the rootless namespace); reusing
`bs_sandbox` (KTD13).

## Controls

| Threat | Control | Where | Proof |
|---|---|---|---|
| A page going direct (IP, IPv6, UDP/STUN, DNS, gateway, rootless host, metadata) | the browser's network is internal with no gateway; Chromium flags are not the boundary | Docker network | `test_docker_isolation.py`, `test_sp1_isolation.py` (each for `bs_sandbox` and `bs_lab_sandbox`, with positive controls); `test_browser_client.py::test_a_browser_that_ignores_the_proxy_has_no_route_anywhere` (Chromium launched with no proxy at all) |
| Proxied requests to private, metadata, loopback, literal lab IPs, other proxies, non-lab names (lab) | netguard in the proxy; the lab proxy refuses non-lab names before DNS | proxy | `test_lab_sites_up.py::test_lab_sandboxes_reach_lab_hostnames_only_through_their_proxy`; `test_browser_client.py::test_every_escape_a_page_tries_...` |
| Redirect (HTTP or script) to metadata | each hop is a new proxied request, validated again; recorded in the network log | proxy, worker | `test_browser_client.py::test_redirects_to_metadata_...` |
| Crossing lab trust boundaries (to `bs-lab-web`, `bs-lab-proxy`, its edge address, the production proxy) | not on those networks | Docker network | `test_lab_sandboxes_reach_lab_hostnames_only_through_their_proxy` (direct TCP fails, the proxy path works) |
| Production sandboxes reaching the lab sandbox proxy | not on `bs_lab_sandbox` | Docker network | `test_production_sandboxes_cannot_reach_the_lab` |
| Browser launched on a weakened network | network check (internal, members, single untrusted container, gateway inhibited, proxy attached and hardened, listeners) before every launch; probe at startup and before `registry collect` | client, `run_service`, CLI | `test_browser_output.py::test_the_network_check_must_pass_...`, `test_render_pipeline.py::test_no_browser_starts_after_a_failed_network_check...` |
| Container escape via configuration | runner-fixed arguments; Chromium profile = Docker default + `clone`, `unshare`, `chroot`; never `--privileged` or an added capability | runner, client | `test_browser_limits.py` (arguments, profile contents), `test_browser_client.py::test_js_login_renders_in_chromiums_own_sandbox...` (CapEff 0, NoNewPrivs 1, Seccomp 2, uid 1001) |
| Renderer exploit reaching the container | Chromium's own namespace sandbox stays on (`chromium_sandbox=True`, never `--no-sandbox`) | worker | live: renderers in their own user namespace, `sandbox selftest browser` |
| Page acting on its own (R39) | worker calls no interaction API; non-GET requests stopped in the browser (a blocked navigation answered locally with 204); downloads refused; service workers blocked; dialogs dismissed; popups closed; no permission granted | worker | `test_browser_limits.py::test_the_worker_never_interacts_with_a_page` (AST, with positive control); `test_browser_client.py::test_page_initiated_actions_are_contained...` (nothing but GET reaches the proxy); lab demo: no action in any lab render |
| Page-opened sockets: WebSocket, WebRTC through a TURN relay, a worker's sockets (outside the HTTP method gate) | proxy: tunnels only to 443 whose first six bytes look like a TLS ClientHello (a prefix filter, not TLS enforcement), so Chromium's plain `ws://` and TURN go nowhere; worker: every WebSocket answered inside the browser and recorded (`websockets`), `RTCPeerConnection`, `Worker`, `SharedWorker` removed from every frame | proxy, worker | `test_browser_sockets.py` (a WebSocket server beside lab-web; raw tunnels from a sandbox and a real render; positive controls; fails on the M7 image); `test_proxy.py` tunnel-policy cases; `test_docker_isolation.py` (`tunnel plain 443` cut, `tunnel tls 443` answered) |
| A page denying rendering by inflating output (control characters) | C0 controls stripped, UTF-8 JSON, worst-case output budget | worker, config | `test_browser_limits.py::test_control_characters_...` |
| A page sending the browser to an error page or the proxy's refusal | no usable page: network log kept, scored on the static view | render stage | `test_render_pipeline.py::test_a_render_without_a_usable_page_...` |
| Brand shown only to the fetcher | the rendered view keeps the static page's brands and claims | bundle | `test_render_pipeline.py::test_a_brand_hidden_from_the_browser_...` |
| Hostile worker output | strict schema, exact requested URL, HTML/text/request caps, screenshot strict base64 of a PNG whose IHDR size matches and fits the viewport; else `render_rejected` and nothing used | client | `test_browser_output.py` (sixteen tampering cases) |
| A page that never settles | settle budget inside; wall time and kill by name outside | worker, runner | `test_browser_client.py::test_a_page_that_never_settles_is_killed...` |
| Orphans (AE18) | labelled one-shot containers; startup sweep before lease recovery; runner removal finishes even when the job is cancelled | runner | `test_browser_cases.py::test_ae18_...`; `test_runner.py::test_a_shutdown_during_removal_still_removes_the_container` |
| Evidence hidden from the browser | when only the static view showed abuse indicators, the static view is scored | cloaking | `test_render_pipeline.py::test_abuse_hidden_from_the_browser_keeps_the_static_evidence` |
| Screenshot self-corroboration | a screenshot shows every page image: its text and QR payees never corroborate a match | policy | `test_render_pipeline.py::test_a_screenshot_never_corroborates...` (fails with the guard removed) |
| Untrusted references | reference screenshots only with verified TLS (`verify_tls`), every navigation and redirect on https on a confirmed official domain | collector, corpus | `test_collector.py` screenshot cases |
| Host running Chromium | Playwright only in the image (`sandbox` extra); the application never imports it | packaging | `test_browser_limits.py::test_the_application_never_imports_the_browser_driver` |

## Chromium's seccomp profile

`src/brandsentinel/sandbox/chromium-seccomp.json` is Docker's default profile
(`moby/profiles` `seccomp/v0.2.4`, the version Docker 29.9.1 vendors; source
sha256 `785b2429…9334`) plus one rule allowing `clone`, `unshare` and `chroot`
unconditionally. With `--cap-drop ALL`, Docker's default withholds namespace
flags on `clone`, `unshare` and `chroot` (they are gated on `CAP_SYS_ADMIN` and
`CAP_SYS_CHROOT`), so Chromium's namespace sandbox cannot start; allowing the
syscalls grants no privilege, because the kernel still checks capabilities in
the caller's own user namespace, which only Chromium's new namespace has.
`clone3` stays ENOSYS (glibc falls back to `clone`). Measured on the dev host:
without `chroot` the zygote fails (`sys_chroot("/proc/self/fdinfo/")`), without
`unshare` it fails too, and `setns` (in Playwright's own profile) is not
needed. To regenerate: append that rule to the vendored default profile of the
Docker version in use, and rerun `test_browser_limits.py` and the browser
self-test.

## Rendering decisions and evidence

- Triggers (`sandbox/triggers.py`, `render_decision/2` since M8): `js_shell` on a
  brand-matching domain (AE10); for strong-strength domains `static_error`,
  `decoy_page` (parked, placeholder or empty without brand content) and
  `script_redirect`; on brand-related pages `form_hints_without_forms` and
  `no_static_images`; `little_text` on brand-matching domains; otherwise a
  stable `sample` of strong-strength cases (`browser.sample_rate`, default
  10%). Never on official domains or without a static response.
- `analyst_request` (M8): see [Analyst-requested renders](#analyst-requested-renders-m8).
- `browser_render` fact: the validated document (requests capped at 300, URLs at
  500 characters), the stored rendered HTML (`rendered_page`) and screenshot
  (`screenshot`) as inert blobs, and the screenshot's media result.
- Rendered extractor features reference the render fact; `cloaking/1`
  compares the views (brands, credential fields, payment, final site, status).
  A script shell completing in the browser is an expected difference.
- `bundle/4` (unchanged by M8, so M7 reads every score M8 writes): the `render` block; content blocks from the rendered page unless
  only the static page showed abuse indicators; screenshot matches, text and
  QR payees in `visual` and `payment` with role `screenshot`.
- `policy/5`: `cloaking_suspected` (abuse, 30 points, needs a brand on the page
  or in the domain) and the `cloaking_suspected` label.
- Reports show the render as text; the screenshot is never embedded (as with
  page images since M6). This deviates from KTD20 (size-capped data URIs) by the
  owner's decision of 2026-10-29: no sandbox-produced image reaches an analyst's
  browser in M7.

## Operating

```sh
brandsentinel sandbox check                    # includes the network and its direct-egress probe
brandsentinel sandbox selftest browser         # Chromium sandbox, unprivileged worker, no direct route
brandsentinel cases list --label cloaking_suspected

docker compose -f docker/lab.compose.yaml up -d   # lab: bs-lab-web, bs-lab-proxy, bs-lab-sandbox-proxy
brandsentinel -c config/lab.yaml sandbox check
brandsentinel -c config/lab.yaml sandbox selftest browser
uv run pytest -m lab tests/lab/test_browser_cases.py
```

The browser stage registers only when the runtime preflight, the account gate,
the orphan sweep and the network check with its probe passed; otherwise the
service logs `browser stage disabled` with the failed checks
(`Orchestrator.browser_disabled`), render jobs wait, and cases show
`render_pending`.

## Analyst-requested renders (M8)

```sh
brandsentinel submit --render https://example.test/login   # prints the round and when it is due
```

- The request is a `render_request` fact for one analysis round: the next
  round, after every decided one, that can still decide (its work is queued:
  a deferred row, or a pending or running enrich or fetch job). A new case:
  round 0. A case already decided (for example a non-brand JS shell that was
  not rendered): the next scheduled recheck, whose time does not move; the
  case renders only then (about a day later by default). A round that can no
  longer decide (its fetch recorded without a decision, as for a case analyzed
  before M7, or its jobs failed for good) is skipped. No round is created. If
  no round is left the request is refused (exit 1). A second request for the same round
  is reported as `already requested` and changes nothing.
- That round's decision consumes it. The request, the budget count and the
  decision are written in one `BEGIN IMMEDIATE` transaction, so a request is
  seen by exactly one decision (`submit` takes the same lock, so it either
  lands before the decision or binds to the next round), a crash leaves
  neither the decision nor the render job, and concurrent deciders (workers or
  processes) cannot overspend. Later rounds do not inherit it.
- **No bypass.** The official-domain and no-static-response skips come first:
  the browser renders only a URL the hardened static fetcher reached through
  netguard. A request for a private, loopback, metadata or off-port target,
  or one redirecting there, gets `no_static_response` and no render job. IP
  literals and URLs with credentials are rejected by `submit`.
- **Budget:** `browser.analyst_renders_per_day`, **default 0** (requests are
  recorded and refused as `analyst_budget_exhausted`). `config/lab.yaml` sets 5.
  Enabling it in production is an explicit configuration decision. It counts
  decisions of the last 24 hours with `analyst_budget_spent`, which is set only
  when the request alone triggers a render with the browser enabled; a request
  beside another reason (for example `js_shell`) is recorded in `reasons` and
  costs nothing. The budget is spent at decision time: a render that later
  fails or is retried does not refund or re-spend it.
- Cases explain a missing render: a `js_shell` case whose round has no render
  (`not_triggered` or `disabled`) gets the `render_not_scheduled` flag and an
  unknown with the reason (`no_trigger`: request one with `submit --render`;
  `analyst_budget_exhausted`: the budget is used up; `no_static_response`;
  `official_domain`; browser disabled). Explanation only: scores and
  priorities do not change (`policy/5`).
- `cases show` lists a request not decided yet as `render requested: round N`
  (`--json`: `render_requests`), read from facts, so it shows at once and
  needs no rescore.

## Verification record (2026-10-28, development host, developer rootless runtime)

Rootless Docker 29.9.1 (UID 1000), sandbox image `brandsentinel-sandbox:local`
built from this branch (Playwright 1.63.0, Chromium headless shell 1243).

| Check | Result |
|---|---|
| `sandbox selftest browser` (lab config) | Chromium sandbox: 3 of 7 Chromium processes in their own user namespace, 0 with `--no-sandbox`; worker uid 1001, CapEff 0, NoNewPrivs 1, Seccomp 2; `http://1.1.1.1/` with no proxy: `ERR_ADDRESS_UNREACHABLE`; container removed |
| Network check on `bs_lab_sandbox` | passes, including `gateway_inhibited`, `rootless_listeners` (the lab's `127.0.0.1:3129` publish is not an exposed namespace listener) and the direct-egress probe |
| `-m "security and docker"` | 51 passed, 0 skipped after the network change; the isolation suites run for both sandbox networks |
| `-m "docker or security"` | 487 passed, 0 skipped (after the review fixes) |
| Full suite (`-m "not models"`) | 1388 passed, 1 skipped (no host Tesseract; covered in the container) |
| Code review | nine reviewers; findings fixed with regression tests or accepted: `docs/residual-review-findings/feat-m7-isolated-browser.md` |
| Lab demo | JS login `credential_phishing` P1 (rendered form); JS payment card fields, the gateway script in the network log, the UPI QR read from the screenshot; image-only, copied-assets and redirects reach their `expected.yaml`; cloaking `donation_fraud` with `cloaking_suspected`; no lab render took any page action |
| AE18 | application SIGKILLed mid-render: the container outlived it, was removed before lease recovery, and the job ran exactly once more |
| Page sockets (2026-10-29, PR review) | before: `ws://` reached the destination through `CONNECT :80`; `ws://host:443` from the page and from a worker exchanged a message and a reply; `wss://` and WebRTC TURN sent TLS and TURN Allocate bytes through `CONNECT :443`; none appeared in the network log. After: the server sees nothing from the page (four WebSockets recorded, worker and WebRTC absent, beacon and keepalive POST blocked; only GET at the proxy); raw plain tunnels are cut, a real ClientHello is relayed. See `docs/solutions/2026-10-29-page-sockets-bypass-the-http-method-gate.md` |

The service-account validation and promotion are separate, gated operations
(see the handoff).

## Residual risks

- Chromium is a large native attack surface; its own sandbox and the container
  (rootless, no capabilities, seccomp, limits, no route out) bound an exploit,
  and the kernel is shared (VM isolation deferred).
- **BrandSentinel does not interact with a page; the page is not prevented from
  every remote side effect.** The worker never clicks, types, submits or
  downloads, and stops what it can see: non-GET HTTP, WebSockets, WebRTC and
  workers. What is enforced without the browser is the proxy's: destinations
  validated by netguard, plain HTTP only as GET or HEAD, tunnels only to 443
  and only when they start like TLS. That last check is a TLS-prefix filter,
  not TLS enforcement: it reads six bytes, which Chromium writes itself and a
  page cannot choose, but which code with raw socket access (a compromised
  renderer, or code running in the container) can forge before plaintext. Such
  code can equally speak real TLS to its own server on 443, so the filter is no
  bound on it; destination validation is. A page's scripts can still send GET requests, with whatever they encode
  in the URL, to any destination the proxy allows, and TLS tunnels are opaque:
  a page's HTTPS POST, a `wss://` WebSocket or a `turns:` relay is stopped only
  by the browser-side layer. A compromised renderer or a page API this layer
  misses could bypass it, still only towards destinations the proxy allows.
  WebSocket-only page content is not rendered (the page sees a socket that
  never answers); the attempted URLs are recorded.
- Rendering is attributable to the host's egress address and loads the page's
  third-party resources through the proxy (pixels, analytics); a page can tell
  it was visited by a headless Chromium.
- A page that detects automation can show the browser a harmless page;
  cloaking toward both the fetcher and the browser is not detected.
- Reference screenshots include third-party content shown on official pages.
- The lab has no `https` reference pages (reference pages are `https`-only with
  verified TLS), so screenshot similarity against a reference screenshot is
  proven with a scripted browser, not end to end in the lab. Accepted by the
  owner (2026-10-29) as a documented test limitation; TLS verification for
  reference pages stays on.
- In evidence mode certificate errors are ignored, not recorded per error
  (Playwright does not report them when ignoring them); the static fetcher
  still records `tls_verification_failed`.
- A container created by a `docker create` that a cancellation interrupted can
  remain in `Created` state until the next startup sweep (it never starts).
