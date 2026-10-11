# Dedicated service account and sandbox network isolation (SP1)

SP1 closes the M4 prerequisite that blocks M6 and M7 from executing real hostile
content: BrandSentinel's sandboxes run under a dedicated, unprivileged
`brandsentinel` account with its own rootless Docker, and the shared sandbox
network gives sandboxes no gateway into the rootless network namespace and holds
at most one untrusted container at a time.

SP1 is satisfied only when `scripts/service-account/validate.sh` passes under
the account itself (results recorded in the SP1 section of
`docs/runbooks/sandbox.md`). Until then, hostile browser and media execution
stay gated (control M6 below).

## Controls

### Mandatory (enforced and tested)

| # | Control | Enforcement | Proof |
|---|---|---|---|
| M1 | Dedicated account: not root, not owner of the code (`/opt/brandsentinel` root-owned, read-only to it), not in `docker`, cannot open the rootful socket, config without `allow_developer_account` | `check_account`; `brandsentinel sandbox check --strict` fails on any warning | `validate.sh` section 1 and 3; `tests/unit/test_config.py` (no repository config enables the override) |
| M2 | Its own rootless dockerd in its systemd user manager, cgroup v2 `cpu memory pids` delegated | `check_runtime`; `setup-rootless.sh` refuses without the prerequisites | `validate.sh` sections 2-4 |
| M3 | `bs_sandbox` is internal, IPv6 off, `com.docker.network.bridge.inhibit_ipv4=true` with the gateway `172.31.251.1` only *reserved*: the rootless namespace holds no address on that bridge, so sandboxes have no gateway and no route into it, while the proxy (a peer on the bridge) stays reachable | `docker/compose.yaml`; preflight `gateway_inhibited` (option set and the namespace holds no sandbox address) gates the browser stage | `tests/security/test_sp1_isolation.py`: a deliberate wildcard listener in the namespace is unreachable from `bs_sandbox` and reachable from an ordinary internal network (positive control); the proxy answers while direct egress, `10.0.2.2` and `10.0.2.100` do not; no IPv6 on the sandbox interface |
| M4 | At most one untrusted container on `bs_sandbox` | Runner network lease: exclusive `flock` per network in `$XDG_RUNTIME_DIR/brandsentinel/` across all processes and instances of the account (released by the kernel if a process dies); before create, any member other than the egress proxy (another job, an orphan, a manual container) refuses the run; after start, the job is killed if another untrusted container is attached. Preflight `single_untrusted_container` | `tests/security/test_network_lease.py`; `test_sp1_isolation.py` (manual and orphaned containers on the real network) |
| M5 | Media workers have no network | `SandboxSpec(network="none")` takes no lease and joins nothing | `test_sp1_isolation.py::test_media_style_jobs_have_no_network_at_all` |
| M6 | Hostile-content gate: sandbox stages run only when the account checks pass cleanly (no failure, no override); lab mode is exempt (synthetic content) | `_prepare_sandbox` (`dedicated_account`) | `tests/security/test_preflight.py` |
| M7 | Image identity and provenance | Image built from the installed commit; ID and package-file manifest checked after streaming it to the account | `scripts/service-account/image_manifest.py`, `load-image.sh` |

### Defense in depth (not the boundary)

- `rootless_listeners` preflight: anything in the account's rootless namespace
  listening on a non-loopback address fails the network gate. The account reads
  its own `/proc/<rootless child>/net/*`; no privilege needed.
- A full TCP scan (1-65535) of every address the namespace holds, from
  `bs_sandbox` (`test_every_tcp_port_of_every_namespace_address_is_closed_to_sandboxes`).
- The direct-egress probe and the proxy-hardening checks (M4).
- Separate daemons per account: the developer cannot see or launch into the
  service runtime, and vice versa.

### Residual risks (accepted)

- A sandbox can talk to the egress proxy: that is the single intended path; the
  proxy is our hardened code (`docs/runbooks/sandbox.md`).
- The lease cannot stop someone holding the service account's credentials from
  starting a container on `bs_sandbox` *after* a job's post-start check; they
  control that runtime anyway, and the next preflight flags it.
- A future Docker that ignores `inhibit_ipv4`, or `bs_sandbox` recreated without
  it, is detected by `gateway_inhibited`, which then disables the browser stage.
- Validation runs pytest from the production install (`--group dev` in the
  venv); a separate test environment can come later.
- Carried: shared host kernel (rootless limits the blast radius), HTML parsing
  in the orchestrator, egress attributable to the host IP, SP2 (a concurrent
  `sandbox sweep` can remove a running service's containers; the lease is not an
  instance lock).

## Prerequisites

- Linux with cgroup v2 and `user@.service` delegating `cpu memory pids`
  (systemd default on Arch); systemd >= 248 for `systemd-run --user -M user@`.
- `rootlesskit`, `slirp4netns`, `newuidmap`/`newgidmap` (file capabilities or
  setuid), Docker CLI 29.9 with the compose plugin.
- At least 8 GiB free on the filesystem holding `/var/lib` (measured use: image
  ~3.8 GiB in the containerd store, `/opt/brandsentinel` ~0.5 GiB).
- The developer account: the repository at a clean commit, `uv`, its own
  rootless Docker with `brandsentinel-sandbox:local` built from that commit.
- 127.0.0.1:3129 free while `validate.sh` runs (the developer's lab stopped).
- A network with public IPv4 egress while `validate.sh` runs: the proxy tests
  reach public sites through slirp4netns, which is IPv4-only here. On an
  IPv6-only (NAT64) network they time out; `validate.sh` reports this as an
  `environment:` failure first (see the M5 residual findings, 2026-10-10).

## Sequence

`$` lines run as the developer, unprivileged. `#` lines need sudo and are run by
the operator after review. `U` is the service account's UID.

1. Build the image from the commit and record its identity (developer):

   ```sh
   $ scripts/build-sandbox-image.sh
   $ uv run python scripts/service-account/image_manifest.py \
       --docker-host unix://$XDG_RUNTIME_DIR/docker.sock --source .
   ```

   Expect `"package_files_differing": []` and `"verdict": "ok"`; note `image_id`.

2. Create the account (home on the root filesystem, mode 0700, no login shell):

   ```sh
   # useradd --create-home --home-dir /var/lib/brandsentinel --user-group \
       --shell /usr/bin/nologin --comment "BrandSentinel service" brandsentinel
   # id brandsentinel; grep -H '^brandsentinel:' /etc/subuid /etc/subgid
   ```

   Expect a UID >= 1000, groups only `brandsentinel`, and one subordinate range
   per file that does not overlap any other account's (on the development host
   the developer has `100000:65536`; the next range is `165536:65536`).

3. Keep its user manager running without a login, and check its session:

   ```sh
   # loginctl enable-linger brandsentinel
   # U=$(id -u brandsentinel); systemctl is-active user@$U.service; ls -ld /run/user/$U
   # cat /sys/fs/cgroup/user.slice/user-$U.slice/user@$U.service/cgroup.controllers
   ```

   Expect `active`, `drwx------ brandsentinel brandsentinel /run/user/U`, and a
   controller list containing `cpu memory pids`.

4. Install the application root-owned:

   ```sh
   # install -d -o <developer> -g <developer group> -m 0755 /opt/brandsentinel
   $ scripts/service-account/install.sh
   # chown -R root:root /opt/brandsentinel && chmod -R go-w /opt/brandsentinel
   # find /opt/brandsentinel ! -user root | head; cat /opt/brandsentinel/INSTALL
   ```

   `install.sh` refuses a dirty tree or a non-empty target and prints the commit
   it installed. Expect `find` to print nothing.

5. Start the account's rootless dockerd (inside its user manager):

   ```sh
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/src/scripts/service-account/setup-rootless.sh
   ```

   Expect `ok:` lines for the runtime dir, not in `docker`, no rootful socket,
   subordinate ranges, delegated controllers, root-owned read-only install, and
   finally `rootless daemon: Docker 29.9.0, cgroup v2 (systemd) ...`.

6. Stream the image to the account and verify it:

   ```sh
   $ docker --host unix://$XDG_RUNTIME_DIR/docker.sock save brandsentinel-sandbox:local | \
   #   systemd-run --user -M brandsentinel@ --wait --pipe --collect \
         /opt/brandsentinel/src/scripts/service-account/load-image.sh <image_id from step 1>
   ```

   (One pipeline: the left side as the developer, the right side with sudo.)
   Expect the free space before and after, `Loaded image:
   brandsentinel-sandbox:local`, and the manifest with `"id_matches": true` and
   `"verdict": "ok"`.

7. Validate SP1 (stop the developer's lab first, restart it after):

   ```sh
   $ docker --host unix://$XDG_RUNTIME_DIR/docker.sock compose -f docker/lab.compose.yaml stop
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/src/scripts/service-account/validate.sh
   $ docker --host unix://$XDG_RUNTIME_DIR/docker.sock compose -f docker/lab.compose.yaml start
   ```

   Expect only `PASS` lines, `sandbox check --strict` without `WARNING` or
   `FAIL`, `pytest: N tests, 0 failed, 0 errors, 0 skipped`, and
   `SP1 VALIDATION: PASS`.

## Effect on the host

Created: one account and group, its home `/var/lib/brandsentinel`, one
subordinate UID/GID range, a lingering user manager running one rootless dockerd
(about 100 MB RAM plus the egress-proxy container), `/opt/brandsentinel`.
Unchanged: sudoers, the `docker` group, firewall rules, the rootful daemon and
its containers, the developer's rootless runtime and data, other `/opt` entries.
The developer's lab is stopped and started around step 7 (not removed).

## Rollback

Touches only the `brandsentinel` account, `/var/lib/brandsentinel` and
`/opt/brandsentinel`:

```sh
# systemd-run --user -M brandsentinel@ --wait --pipe --collect \
    systemctl --user disable --now docker-rootless.service   # its daemon and containers
# loginctl disable-linger brandsentinel
# loginctl terminate-user brandsentinel                      # that user's processes only
# userdel --remove brandsentinel                              # home, mail spool, subuid/subgid lines
# grep -H '^brandsentinel:' /etc/subuid /etc/subgid || echo "subordinate ranges removed"
# test -d /var/lib/brandsentinel && rm -rf --one-file-system /var/lib/brandsentinel
# rm -rf --one-file-system /opt/brandsentinel
```

`userdel --remove` cannot always delete image layers owned by subordinate UIDs;
the `rm` after it removes what remains. Partial rollback:

- image only: `docker image rm brandsentinel-sandbox:local` in the account's
  daemon (via `systemd-run --user -M brandsentinel@ ...`), then
  `docker image prune --force` there;
- reinstall only: `rm -rf --one-file-system /opt/brandsentinel` and repeat step 4.

The developer's previous image, if replaced in step 1, stays as a dangling image
in the developer's daemon until removed with `docker image prune` there.

## Acceptance history

### Run 1, 2026-10-11: FAILED (namespace resolution defect)

Result directory on the host: `/var/lib/brandsentinel/sp1-validation-20261011T060538Z`.
Account checks and the rootless daemon passed; the environment precheck and
`rootless_listeners` failed (reporting `0.0.0.0:22`, `192.168.122.1:53`); pytest
393 passed, 3 failed.

Root cause: dockerd-rootless.sh starts RootlessKit with `--detach-netns`, which
keeps the bridges in the namespace bind-mounted at `$STATE_DIR/netns`. The SP1
code located the namespace through `child_pid` instead. On the developer's
runtime the child process happened to sit in the bridge namespace; on the
service account it sat in the host namespace (its `/proc/<pid>/net/dev` lists
`wlan0`, `virbr0`, `tailscale0`, the rootful daemon's bridges, and no `tap0`).
So under the service account:

- `rootless_listeners` examined the host's listeners (the reported failure);
- `gateway_inhibited` examined the host's addresses and passed vacuously, without
  examining the bridge namespace;
- the environment precheck and the test listener entered the child's namespace,
  which is the host's and owned by the initial user namespace, so `nsenter`
  was refused before any DNS or TCP attempt (not a network problem).

Correction: the namespace is resolved through the detached netns file (the path
slirp4netns is given), a namespace equal to the host's is refused, tables are
read through `nsenter --net=<file>` when the child is elsewhere (with the entered
namespace's identity checked), and `gateway_inhibited`/`rootless_listeners` fail
unless the examined namespace contains the sandbox network's own bridge. The
egress precheck now measures DNS (through the resolver RootlessKit gives
containers) and IPv4 separately inside that namespace. Regression tests:
`tests/unit/test_netns.py`, `tests/security/test_preflight.py`,
`tests/security/test_sp1_isolation.py` (identity, nsenter/direct agreement,
positive and negative listener controls).

Environment requirement confirmed: the proxy path is DNS through slirp4netns
plus public IPv4; slirp4netns runs without `--ipv6`, so an IPv6-only (NAT64)
network cannot serve it.
