# Deployment and recovery

!!! danger "Owner-operated, privileged"
    Everything on this page changes a shared, persistent installation and needs root or
    the service account. Each step is a separately approved operation. Coding agents and
    contributors do not run these steps. They reproduce the project in tiers 0–2
    ([Reproducibility](../guide/reproducibility.md)).

## Deployment model

| Element | Production form |
|---|---|
| Code | `/opt/brandsentinel`, built from a committed `git archive`; root-owned, nothing group- or world-writable; the service account can read but not modify it |
| Runtime | uv-managed CPython 3.12 and a hash-pinned virtual environment from `uv.lock` (`/opt/brandsentinel/venv`) |
| Configuration | `config/service.yaml`, installed read-only as `/opt/brandsentinel/etc/service.yaml`; no developer override |
| Account | dedicated unprivileged `brandsentinel` user with its own rootless Docker daemon (a systemd user unit) |
| Containers | the sandbox image, `bs_sandbox` and `bs_egress` networks, and the long-running `bs-egress-proxy`, on the account's daemon |
| Data | `/var/lib/brandsentinel/data`, owned by the account |
| Supervision | **none yet**: there is no unit for `brandsentinel run`. Unattended operation is milestone M9 |

## Installing (outline)

The authoritative procedure, with every check, is the service-account runbook
[`docs/runbooks/service-account.md`](../runbooks/service-account.md). That runbook is
kept in the repository but not published on the site, because it contains host-specific
validation records. In outline:

1. **Create the account.** Root creates `brandsentinel` with subordinate UID/GID ranges,
   and enables lingering for its user manager.
2. **Install.** The developer, unprivileged, builds into an empty directory root has
   handed over ([`scripts/service-account/install.sh`](../../scripts/service-account/install.sh)).
   Root then takes ownership.
3. **Start the account's daemon.** Run
   [`setup-rootless.sh`](../../scripts/service-account/setup-rootless.sh) as the account,
   inside its user manager.
4. **Load the image.** Stream it into the account's daemon and verify its id
   ([`load-image.sh`](../../scripts/service-account/load-image.sh)). There is no
   temporary copy, and enough free space is required.
5. **Validate under the account.** [`validate.sh`](../../scripts/service-account/validate.sh)
   checks the account properties, runs `sandbox check --strict` with no warnings, then runs
   the `security or docker` suites. Any skip counts as a failure.

`validate.sh` runs Docker Compose on the account's daemon, including the lab stack. That
itself is a privileged action needing approval.

## Promotion

A new milestone reaches production through a **gated promotion**. Each gate has its own
approval, and its evidence is kept outside the repository. Recent promotions followed this
pattern:

1. a recovery kit and preserved rollback image tags;
2. a fresh installation of the new commit, and a new image;
3. operational acceptance in isolation (image integrity, sandbox isolation with the
   running proxy, self-tests, offline tests, a schema check on a copy of the store);
4. the first open of the live store by the new code.

Because the sandbox image contains the whole wheel, almost every code change needs a new
image. A migration changes the schema irreversibly for older code: an older release
refuses a newer store (`SchemaTooNew`).

## Recovery

- **Code rollback.** The previous installation tree and image tag are kept until a
  promotion is accepted, and rollback swaps them back. Older code cannot open a store that
  a newer schema has migrated, so code rollback must be paired with the matching data.
- **Data recovery points.**
  - A recovery point is a copy of the whole `data_dir`, taken with nothing running. It is
    sealed with content hashes and metadata, and verified without opening it, because
    opening sweeps orphan blobs ([Storage](../concepts/storage.md)).
  - A restore replaces the live directory from a verified recovery point. It is an
    explicitly approved operation.
- **Trials on copies.** Supervised trials can run on a byte copy of a recovery point in
  its own directory, with every network-facing stage and the sandbox off. The live store
  and the recovery point are only read as bytes.

## Failure handling built into the application

| Situation | Behaviour |
|---|---|
| Crash or kill mid-job | the job's lease expires and it returns to pending (or to failed after `jobs.max_attempts`). At startup, labelled orphan containers are removed **before** leases are recovered |
| Transient fetch failure | the attempt is recorded and the job retried after `fetch.retry_delay_seconds`. After the last attempt the failure is the result |
| Netguard refusal | recorded as the fetch result and never retried, including through the browser |
| Sandbox unavailable | media and render stages are not registered. Their jobs wait, and cases show the gap |
| Sandbox limit hit | the container is killed by name and the outcome recorded (`sandbox_killed`, `render_rejected`, `media_rejected`) |
| Quota exceeded | the write is refused and `artifact_quota_exceeded` recorded on the case |
| Low disk | the raw-log firehose pauses below `rawlog.min_free_bytes` |
| SIGINT/SIGTERM | orderly shutdown: running handlers are cancelled (outcome `cancelled`) and the store is closed. Interrupted jobs come back when their leases expire. A shutdown during a job is covered by regression tests (`test_shutdown_*`) |

## Operational lessons recorded

- **Privileged launchers: `sudo` before any session change.** sudo keeps its cached
  credential per terminal and session. A launcher that runs `setsid … sudo -n …` loses the
  credential and fails with "a password is required". The first isolated-copy trial (I1)
  stopped for exactly this reason. Put sudo first and create the new session after it, as
  the target account.
- More lessons: the engineering notes under "Project → Engineering notes", for example
  SQLite's WAL switch under a concurrent writer and Docker attach back-pressure blocking a
  kill.
