# Sandbox runtime, egress proxy and lab (M4: U23, U18, U11)

This runbook covers the isolation boundary that later browser (M7) and media (M6)
work runs inside, how to set it up on a host, how to verify it, and what it does
not protect against.

## Trust boundaries

```text
 Host, unprivileged account (production: dedicated `brandsentinel`; development: the developer)
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ brandsentinel process (trusted orchestration)                                  │
 │   netguard + static fetcher ── direct to public IPs only (M3 gate)             │
 │   sandbox runner ── docker CLI ──► rootless dockerd socket ($XDG_RUNTIME_DIR)  │
 │   lab mode: fetcher ──► 127.0.0.1:3129 (lab proxy) only                         │
 └───────────────────────────────────────────────────────────────────────────────┘
        rootless dockerd: its own user + network namespace (rootlesskit, slirp4netns)
 ┌─────────────────────────────── rootless network namespace ─────────────────────┐
 │  bs_sandbox (internal, 172.31.251.0/24)        bs_egress (172.31.252.0/24)     │
 │  ┌────────────────────┐   CONNECT / GET   ┌──────────────────────────────┐     │
 │  │ job container      │ ───────────────►  │ bs-egress-proxy  .251.2:3128 │ ──► slirp4netns ──► Internet
 │  │ (untrusted)        │                    │ netguard, pinned connects    │     (public IPs only)
 │  └────────────────────┘                    └──────────────────────────────┘     │
 │  media jobs: --network none                                                     │
 │                                                                                 │
 │  lab project:  bs_lab (internal, 172.31.250.0/24)    bs_lab_edge                │
 │  bs-lab-web .250.10 ◄── bs-lab-proxy (lab_only) ──► 127.0.0.1:3129 on the host  │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

| Zone | Trust | Holds |
|---|---|---|
| Orchestrator process | trusted code, but parses untrusted HTML (accepted residual, plan R&D table) | SQLite store, blobs, rootless Docker socket |
| Job containers | untrusted | stdin job, one JSON document out; nothing else |
| Egress proxy container | semi-trusted (our code, untrusted input) | no credentials, no mounts (lab: read-only lab config) |
| Host session, credentials, other users' files, private network | protected | — |
| Lab sites | synthetic, offline | read-only `labsites/` |

## Threat model: how a workload could try to get out

| Route | Control | Where enforced | Proof |
|---|---|---|---|
| Direct TCP/UDP to a public IP, IPv6, STUN | `bs_sandbox` is `internal: true`: no route out | Docker network (outside the workload) | `test_docker_isolation.py::test_no_direct_route_out_of_the_sandbox_network` + positive control |
| Alternate DNS (public resolver, container default resolver) | no route; embedded DNS does not forward from internal networks | Docker network | same test (`udp dns`, `resolve default`) |
| Docker gateway / rootless host address (10.0.2.2) | internal network, `--disable-host-loopback` | Docker + rootlesskit | same test (`tcp gateway:*`, `tcp rootless host`) |
| Proxy to private, loopback, link-local, metadata, NAT64/6to4/mapped forms | netguard on every request | proxy | `test_proxy.py` (in-process, adversarial DNS), `test_docker_isolation.py` (container) |
| DNS rebinding / validate-then-connect mismatch | resolve once, connect only to the validated IP, peer re-check | proxy | `test_proxy.py::test_a_name_that_rebinds_to_private_is_never_connected_to`, `..._peer_mismatch` |
| Mixed public + private answers | refused as `dns_mixed_private` | proxy (netguard) | `test_proxy.py` |
| Redirect to a private address | browser must re-request through the proxy, which re-validates; host fetcher re-validates every hop | proxy / fetcher | `test_proxy.py`, `test_fetcher.py`, `test_lab_transport.py` |
| Host header / target mismatch, request smuggling, oversized headers | strict parsing, Host must match target, no bodies, no folding, header cap | proxy | `test_proxy.py` |
| Proxy misuse (reverse proxy, ports other than 80/443, POST) | origin-form refused, port allowlist, GET/HEAD only for absolute-form | proxy | `test_proxy.py` |
| Proxy exhaustion | connection cap, header timeout, idle and total timeouts, per-connection byte cap, container memory/CPU/PID limits | proxy + runtime | `test_proxy.py`, `test_docker_isolation.py::test_proxy_container_is_hardened` |
| Resource exhaustion by a job | memory (no swap), CPU, PIDs, wall time from outside, stdout/stderr caps | runtime + runner | `tests/integration/test_runner.py` |
| Container escape via configuration | fixed args: no mounts/devices/caps, `--read-only`, noexec tmpfs, `no-new-privileges`, default seccomp, non-root user, private IPC | runner | `test_runner_security.py`, `test_runner.py::test_container_runs_unprivileged_...` |
| Kernel escape | rootless Docker: container root maps to an unprivileged subordinate UID; no rootful socket for the app | host | preflight `rootless`, `no_rootful_docker` |
| Orphans after a crash | named + labelled containers; startup sweep before lease recovery; retry refuses while an earlier container exists | runner + orchestrator | `test_runner.py::test_restart_removes_the_orphaned_container_before_jobs_are_recovered` (AE18) |
| Lab exceptions leaking into production | lab only via `net.lab` (pinned subnet, hostname map), separate proxy instance (`lab_only`), separate data dir; production proxy has no lab hosts | config + proxy | `test_lab_transport.py`, `tests/lab/test_lab_sites_up.py` |

A browser's proxy setting is not part of the boundary: the network has no route
out, so a page that ignores the proxy simply fails.

## Proxy evaluation: Squid versus our own (KTD10) — decision: our own

Squid 6.14 (`ubuntu/squid:6.6-24.04_edge@sha256:8a3baed4…`) ran on 2026-10-09 in the
same rootless runtime, on `bs_sandbox` + `bs_egress` like the egress proxy, with
an ACL policy mirroring netguard (ports 80/443, GET/HEAD/CONNECT, every netguard
range in `dst` ACLs) and a controlled DNS stub on the sandbox network. A probe
container sent the same requests to Squid and to our proxy:

| Request (from a container on bs_sandbox) | Squid | Ours |
|---|---|---|
| CONNECT metadata, 10/8, 127/8, `[::1]`, `[::ffff:10.0.0.1]`, `[64:ff9b::a00:1]`, `[2002:a00:1::]`, `[::a00:1]`, `2130706433`, `0x7f.1`, port 22 | 403 | 403 |
| CONNECT example.com:443 | 200 | 200 |
| GET http://169.254.169.254/… | 403 | 403 |
| Names answering mixed public+private, private, mapped, NAT64 | 403 | 403 (in-process, `test_proxy.py`) |
| Rebinding name (public, then private on later lookups) | connects to the first answer only; the private listener got no hit | resolves once per request and connects only to the validated IP (`test_proxy.py`) |
| **GET http://example.com/ with `Host: internal.example` / `Host: 169.254.169.254`** | **200, forwarded** (also with `host_verify_strict on`) | 400 `host_mismatch` |
| POST absolute-form | 403 | 405 |
| `GET https://…` absolute-form | Squid itself opens TLS upstream (503 here) | 400 `https_requires_connect` |
| Origin-form (reverse-proxy use) | 400 | 400 |

Other observations:

- Squid silently drops ACL entries that overlap another entry, with only a warning
  in its cache log: listing `::1` together with `::/96` made it ignore `::/96`
  (the IPv4-compatible block). A Squid policy mirroring netguard can lose a range
  without failing, which is exactly the divergence risk the plan names.
- Squid needs writable log and spool paths (it cannot write `/dev/stdout` after
  dropping privileges), and its policy is a second copy of netguard's.

Squid fails the U18 acceptance test "a request whose Host header disagrees with
its target is refused", so under KTD10 the egress proxy is our own
(`src/brandsentinel/net/proxy.py`): it reuses netguard itself, so one test suite
proves the policy for the fetcher and the proxy. No Squid configuration is kept.

## Host setup

### Prerequisites check

```sh
uname -r; stat -fc %T /sys/fs/cgroup                      # cgroup2fs
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers  # cpu memory pids
grep "^$(id -un):" /etc/subuid /etc/subgid                # a subordinate range
sysctl kernel.unprivileged_userns_clone user.max_user_namespaces
scripts/check-disk-budget.sh                              # image (~4 GiB) + build cache + margin
```

On Arch, `user@.service` already delegates `pids memory cpu` (systemd default).

### Development: rootless Docker for the developer account (completed on the dev host, 2026-10-09)

Privileged step (needs sudo):

```sh
sudo pacman -S --needed rootlesskit slirp4netns passt
# rollback: sudo pacman -Rns rootlesskit slirp4netns passt
```

Unprivileged steps. Arch does not ship `dockerd-rootless.sh`; use moby's script
pinned to the installed Docker version and reviewed before use. Do not run
`dockerd-rootless-setuptool.sh install`: it also switches the default Docker
context, which would redirect every other Docker project of the account.

```sh
mkdir -p ~/.local/bin ~/.config/systemd/user
curl -fsSL -o ~/.local/bin/dockerd-rootless.sh \
  https://raw.githubusercontent.com/moby/moby/docker-v29.9.0/contrib/dockerd-rootless.sh
sha256sum ~/.local/bin/dockerd-rootless.sh   # 200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488
chmod 0755 ~/.local/bin/dockerd-rootless.sh
cat > ~/.config/systemd/user/docker-rootless.service <<'EOF'
[Unit]
Description=Rootless Docker for BrandSentinel sandboxes

[Service]
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=%h/.local/bin/dockerd-rootless.sh
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
Type=notify
NotifyAccess=all
KillMode=mixed

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now docker-rootless.service
docker --host unix://$XDG_RUNTIME_DIR/docker.sock info --format '{{.SecurityOptions}}'   # includes name=rootless
```

Rollback: `systemctl --user disable --now docker-rootless.service`, then
`rootlesskit rm -rf ~/.local/share/docker`, then remove the unit and the script.
The rootful daemon and its containers are untouched throughout.

Development config needs `runtime.allow_developer_account: true`; `status` then
warns that the account owns the code and can reach the rootful socket (when the
developer is in the `docker` group). This is not the production boundary.

### Production: dedicated account (R50) — not yet performed

```sh
sudo useradd --create-home --user-group --shell /usr/bin/nologin brandsentinel
grep '^brandsentinel:' /etc/subuid /etc/subgid      # useradd allocates a range; else usermod --add-subuids
sudo loginctl enable-linger brandsentinel           # its user manager (and dockerd) runs without a login
# install the checkout or wheel somewhere brandsentinel can read but not write, e.g. /opt/brandsentinel
sudo machinectl shell brandsentinel@ /bin/bash      # then, as brandsentinel, the "Development" steps
```

The account must not be in the `docker` group, own the code, or hold other
credentials. Its data, cache and model paths live in its home. `brandsentinel run`
refuses to start as root, as the owner of the code, or with access to a rootful
socket (without the developer override).

Rollback: `sudo loginctl disable-linger brandsentinel && sudo userdel -r brandsentinel`.

## Operating

```sh
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock     # the rootless endpoint, for manual commands
scripts/build-sandbox-image.sh                             # refuses a rootful endpoint
docker compose -f docker/compose.yaml --profile sandbox up -d
brandsentinel sandbox check                                # account, runtime, network + direct-egress probe
brandsentinel sandbox sweep                                # manual orphan removal (also automatic at startup)

docker compose -f docker/lab.compose.yaml up -d            # the lab (offline)
brandsentinel -c config/lab.yaml analyze --fetch donate-luminafoundation.test
```

Verification:

```sh
uv run pytest -m "security and docker"     # runner, isolation and proxy suites on rootless Docker
uv run pytest tests/integration/test_runner.py
uv run pytest -m lab                       # needs the image; brings the lab up
```

The Docker suites skip (and say why) when the rootless runtime or the sandbox
image is missing; a skipped run is not a verification.

## Verification record (2026-10-09, development host)

Rootless Docker 29.8 (rootlesskit 3.2.0, slirp4netns 1.3.6), cgroup v2 with
`cpu memory pids` delegated (`io` and `cpuset` are not), seccomp builtin profile.
Sandbox image `brandsentinel-sandbox:local`, 3.97 GB.

| Control | Result on rootless Docker |
|---|---|
| Memory limit | 64 MiB hog killed by the kernel OOM killer (exit 137) in ~0.2 s. Docker's `OOMKilled` flag trails the exit status (seen false once in ~30 runs); the runner re-inspects before classifying |
| PID limit | fork loop stopped by `EAGAIN` after 30 children (limit 32) |
| Wall time | killed by name at 3.1 s (limit 3 s); container removed |
| stdout / stderr caps | overflow kills and removes the container in ~0.2 s |
| In-container identity | uid 1001, CapEff/CapBnd 0, NoNewPrivs 1, Seccomp 2, read-only root, noexec /tmp, only `lo` with `--network none`, no Docker socket |
| AE18 | application SIGKILLed mid-job; restart sweep removed the container before lease recovery; other instances untouched |
| Direct egress from bs_sandbox | TCP 1.1.1.1/8.8.8.8/9.9.9.9, IPv6, STUN, UDP DNS, default resolver, 169.254.169.254, 10.0.2.2: all fail. Positive control on an ordinary network: TCP connects, STUN and DNS answer |
| Gateway 172.31.251.1 | TCP refused on 22/53/80/443/2375/2376/3128/8080 (see residual risks) |
| Proxy | blocked destinations 403, Host mismatch 400, public CONNECT 200, decisions logged with the validated address; container non-root, no capabilities, read-only, limited |
| Lab | all 16 sites answer as `expected.yaml` says; cloaking differs by user agent; POST 405; host reaches the lab only via 127.0.0.1:3129; lab proxy refuses non-lab hosts; production sandboxes and proxy cannot reach the lab |

## After the security review (2026-10-10)

- The orphan sweep runs before stages exist and before lease recovery, and also
  when only non-safety checks fail (image missing); never on a non-rootless or
  unreachable endpoint. `remove()` never reports success while the daemon is down.
- Each job command runs under `timeout --signal=KILL <wall + grace + 1>s` inside the
  container, so a container orphaned by a crash ends on its own even before the
  next restart's sweep. Best effort only (a process in the container can kill it);
  verified at argument level, not by a crash-and-wait test.
- Proxy refusals carry `X-BrandSentinel-Proxy: <reason>`; in lab mode the fetcher
  records them (and refused CONNECTs) as transport outcomes, never as the site's
  response. The lab-only proxy refuses other names before any DNS query.
- One client address may hold at most `proxy.max_connections_per_client` slots.
- Lab mode refuses to use `bs_sandbox` for sandboxes (its proxy reaches the
  Internet, not the lab); `config/lab.yaml` keeps sandboxes off until M7 adds a lab
  sandbox network.

## Residual risks

- The orchestrator parses untrusted HTML with a C-backed parser outside the
  sandbox (accepted in the plan; moving parsing into the sandbox is deferred).
- Containers share the host kernel; rootless mode limits the blast radius of an
  escape to the service account. VM isolation (gVisor/Kata) is deferred.
- The proxy reaches every public address, including the host's own public IP if
  the host has one directly attached. Behind NAT (the normal case) this is moot;
  on a host with a public address add it to a host firewall rule.
- No per-destination rate limiting; egress is attributable to the host's IP.
- The `io` cgroup controller is not delegated on the development host, so there is
  no disk-I/O throttling; the tmpfs size cap and read-only root bound disk use.
- The bridge address of `bs_sandbox` (172.31.251.1, in the rootless network
  namespace) answers TCP with a refusal: it is routable from sandboxes, and
  nothing listens there today (checked with `ss` inside the namespace). Any
  future service bound to all addresses in that namespace would be reachable
  from sandboxes; the isolation suite probes the common ports on every run.
- On the development host the developer account owns the code and is in the
  `docker` group (rootful access). Only the dedicated-account setup meets R50.
- Sandboxes on `bs_sandbox` can reach each other (inter-container traffic is on:
  disabling it would also cut them off from the proxy on the same bridge). The
  browser stage runs one job at a time by default (`stages.render: 1`).
- CONNECT to port 80 is an opaque tunnel (KTD10): the destination is validated,
  the bytes inside are not (as for 443).
- A tunnel whose client half-closed stays open until the idle timeout (30 s);
  its decision is logged when it ends.
- In lab mode a lab site could forge the refusal header on a forwarded response;
  only lab sites are reachable there.
- Any local process can use the lab proxy on 127.0.0.1:3129; it reaches only lab
  hostnames.
- With a hung Docker daemon one `run` can take several minutes beyond its wall time
  (each Docker call has its own timeout); stage leases are renewed meanwhile.
