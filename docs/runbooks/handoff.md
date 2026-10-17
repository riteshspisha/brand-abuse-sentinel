# Session handoff

The state a new session needs before it touches code or the installation. It is
updated at each milestone close. Facts below were checked on the development
host at the date given; re-check anything marked *reported*.

## Current: M6 closed (2026-10-17)

M6 (U16 media sandbox, U17 reference corpus and visual matching) is merged:
PR #9, merge commit `358bf40` (tree identical to the final feature commit
`e90c92a`). M7 has not started. **The M6 application is staged, not active.**

### Delivered

- **Media sandbox (U16).** `sandbox/media_worker.py` decodes, hashes, QR-decodes
  and OCRs untrusted images only in a `--network none`, read-only, memory, CPU,
  PID and wall-limited container.
  - Magic-byte allowlist; one Pillow plugin per image.
  - Header checks on pixels, dimensions, frames and icon entries before decoding.
  - `media_client.py` validates the output strictly (exact ids, sha256 of what was
    sent) and retries each image alone after a killed batch.
  - The host never imports an image library (security test).
  - `brandsentinel sandbox selftest media`.
- **Reference corpus (U17).**
  - Registry `reference_assets`: a curated file under `registry/assets/` or an
    https URL, pinned by sha256.
  - `registry collect` takes confirmed assets plus confirmed reference pages over
    verified TLS on the brand's confirmed official domains. It is gated by the SP1
    hostile-content gate, which is shared with the pipeline.
  - The corpus loader re-checks every row against the current registry.
  - Third parties seen on official pages become `candidate` observations only.
- **Matching.** `visual/compare.py`, `HashMatcher` behind `VisualMatcher`:
  - an exact sha256 match, or pHash ≤ 10 and dHash ≤ 8 with similar proportions;
  - flat images match only exactly.
- **Pipeline.** A `media_decision` follows each final static fetch: triggered for
  image-only pages, QR candidates or brand-related pages; never for official
  domains.
  - The `media` stage fetches the chosen images through the hardened fetcher and
    stores them under quotas.
- **Evidence.** `bundle/3`: a `visual` block, and payees from QR codes and image
  text with their source image (`image_sha256`).
- **Policy.** `policy/4`:
  - `copied_asset_match` needs corroboration from outside the matched image;
    otherwise it is `visual_match_uncorroborated` plus a review note.
  - Missing visual evidence is always an unknown.
- Schema v5 (migration `0005_media.sql`).
- Lab mode runs media jobs only.
- Details: `docs/runbooks/media.md`.

Decisions worth knowing before M7:
- `config/lab.yaml` uses the placeholder sandbox network `bs_lab_sandbox`, which
  does not exist. M7 must create the lab sandbox network. Config validation still
  refuses `bs_sandbox` in lab mode.
- The worker's thread pools are pinned to one thread (PID limit).
- Exit 137 without a runner kill is reported as `sandbox_killed`.

### Security defects found and fixed in M6

| Defect | Fix | Proof |
|---|---|---|
| A matched image corroborated itself through a payee read from it (OCR lookalike of the confirmed payee, or a QR payee naming the brand); `copied_asset_match` fired with a false "independent" explanation | payees carry `image_sha256`; payees from a matched or unknown image never corroborate; `policy/4` (`c70b3c3`) | `test_payee_read_from_the_matched_image...` (OCR and QR), positive controls in `tests/integration/test_media_pipeline.py`, `tests/unit/test_visual_policy.py` |
| Shutdown hang (pre-existing since M2): a worker cancelled while stopping its lease renewer swallowed its own cancellation; `brandsentinel run` could hang on SIGTERM | `asyncio.wait` instead of suppressing `CancelledError` (`e560ff0`) | `test_shutdown_while_a_job_finishes_is_not_swallowed` (event-coordinated; fails 5/5 on the old code), `test_shutdown_during_a_job_with_the_real_renewer_leaves_no_lease_work` (`e90c92a`) |
| First review round: a favicon role disabled QR/OCR; a 404 on a referenced image read as absent; an OCR lookalike payee neutralised; OCR/QR failure gave `complete`; one image failure retired corpus entries; unhinted images ignored and QR decoys flooding the cap | see `docs/residual-review-findings/feat-m6-media-visual.md` (`316eed2`) | regression tests listed there |
| SQLite `PRAGMA journal_mode = WAL` fails at once under a concurrent writer (concurrent first start) | read mode first, retry a locked switch (`c715e9f`) | `test_wal_switch_waits_for_a_writer...`; `docs/solutions/2026-10-11-sqlite-wal-switch-ignores-busy-timeout.md` |

### Test and acceptance evidence

- Development host, at `e90c92a`:
  - `ruff` clean.
  - Non-docker suite: 1176 passed, 1 skipped (no host Tesseract).
  - 86 docker tests passed on the developer's rootless runtime, at `c70b3c3`:
    - security-and-docker gate;
    - media containers;
    - lab static and media demos.
- UID 1001 (*reported*, PR #9; evidence is account-private):
  - 436 security/Docker tests passed, 0 skipped.
  - `sandbox check --strict` PASS.
  - Media selftest PASS.
  - Image `sha256:aafa3d78aafe…807b`.
  - Evidence directory `/var/lib/brandsentinel/sp1-validation-20261017T100645Z`.
- Checked here (read-only):
  - `/opt/brandsentinel-m6-e90c92a/src` is byte-identical to `git archive e90c92a`.
  - It is root-owned, and nothing in it is group- or world-writable.
  - Its `etc/service.yaml` has no developer override.

### Runtime and installation state (checked 2026-10-17)

| Path / item | State |
|---|---|
| `/opt/brandsentinel` | **active** install, SP1 commit `31318f0` (schema v4 code) |
| `/opt/brandsentinel-m6-e90c92a` | final validated M6 install, commit `e90c92a` |
| `/opt/brandsentinel-m6-stage` | superseded staging install, commit `316eed2` (before the last two fixes); do not promote |
| `/opt/brandsentinel.prev-4280e42` | older SP1 rollback copy |
| `/var/lib/brandsentinel/data` | service data, **schema v5** (migrated during M6 validation; *reported*, account-private) |
| `brandsentinel` (UID 1001) | lingering user manager, its rootless dockerd running |
| Containers under UID 1001 | one: the egress proxy (`brandsentinel proxy --listen 172.31.251.2:3128`) |
| BrandSentinel application | **not running**; no `brandsentinel run` process, no systemd unit (supervision is M9) |
| Images (UID 1001) | `brandsentinel-sandbox:local` = `sha256:aafa3d78…` (*reported*); rollback `brandsentinel-sandbox:sp1-31318f0` (*reported*) |

### Operational hazards

1. **SP1 code cannot open the current data.** The active `/opt/brandsentinel` has
   migrations up to v4, and `store.db.migrate` raises `SchemaTooNew` on the v5
   database (it checks before any write, so nothing is migrated or damaged). Any
   `brandsentinel` command from the active install against
   `/var/lib/brandsentinel/data` fails until the cutover. A rollback to SP1 needs
   a v4 copy of the data or an empty directory, with the v5 data moved aside
   (promotion step 6). Whether a pre-M6 backup exists is **unverified**.
2. **The staged install cannot be renamed into place.** Its venv is bound to its
   path: script shebangs and `pyvenv.cfg` name `/opt/brandsentinel-m6-e90c92a`.
   `mv` to `/opt/brandsentinel` breaks every entry point. A symlink would keep it
   working but would make `validate.sh`'s ownership `find` check the link only.
3. **The staged config reads the active tree.** `etc/service.yaml` (identical to
   SP1's) names `/opt/brandsentinel/src/...` for the registry, dictionary, payment
   catalog and policy. Run from the staged prefix, it loads SP1's `policy/2`,
   which M6 rejects (missing rules). It is consistent only once M6 is installed at
   `/opt/brandsentinel`.
4. **The production corpus is empty.** `registry/brands.yaml` has no confirmed
   `reference_assets` or `reference_pages`, so outside the lab every examined case
   reports `reference_corpus_empty` and visual matching is inert. A maintainer
   must confirm the real reference URLs and assets. This is a plan open question:
   who confirms them.
5. **Media processing starts with the pipeline.** `service.yaml` has no `media:`
   section, so the defaults apply (enabled, 8 images per case, 512 MiB / 1 CPU /
   64 PIDs / 90 s per container). The first `brandsentinel run` under M6 fetches
   images from candidate sites and starts media containers.

### Promoting M6 into the active installation (not done; for an operator)

`$` lines run as the developer; `#` lines need root. Every Docker command runs as
the account against its own socket, `unix:///run/user/1001/docker.sock`; never
run `docker` as root or as the developer for this procedure (that reaches the
rootful or the developer's daemon). This follows `docs/runbooks/service-account.md`
steps 4, 6 and 7. Reinstall rather than move (hazard 2).

1. Preconditions, all checked before anything moves:
   - no `brandsentinel` application process under UID 1001
     (`pgrep -u brandsentinel -af 'brandsentinel (run|registry|cases|analyze|submit)'`
     prints nothing);
   - the developer's lab is stopped (`validate.sh` needs 127.0.0.1:3129);
   - the rollback image exists in the account's daemon:
     ```sh
     # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
         docker --host unix:///run/user/1001/docker.sock image inspect \
         --format '{{.Id}}' brandsentinel-sandbox:sp1-31318f0
     ```
   - room for a full copy of the data: `# du -sh /var/lib/brandsentinel/data`
     against `df -h /var/lib`;
   - the developer's checkout is clean and at the validated commit:
     `$ git switch --detach e90c92a && git status --porcelain` (prints nothing).
     Do not install from `main`: it moves past the validated commit as later PRs
     merge, and `install.sh` records whatever `HEAD` is.
2. Back up the whole data directory (the database references blobs, raw logs,
   cache and reports beside it), with nothing running:
   ```sh
   # STAMP=$(date -u +%Y%m%dT%H%M%SZ)
   # cp -a /var/lib/brandsentinel/data /var/lib/brandsentinel/data.v5-backup-$STAMP
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       sqlite3 -readonly /var/lib/brandsentinel/data.v5-backup-$STAMP/brandsentinel.db 'PRAGMA integrity_check'
   ```
   Expect `ok`. Write down `$STAMP`; the rollback (step 6) reuses it, possibly
   from another shell. This copy protects the M6 data. It is not an SP1 rollback point:
   SP1 cannot read v5 (hazard 1). Record whether a v4 (pre-M6) copy exists
   anywhere.
3. Set SP1 aside and install M6 at the canonical path:
   ```sh
   # mv /opt/brandsentinel /opt/brandsentinel.sp1-31318f0
   # install -d -o <developer> -g <developer group> -m 0755 /opt/brandsentinel
   $ scripts/service-account/install.sh          # at e90c92a; refuses a dirty tree or a non-empty prefix
   # chown -R root:root /opt/brandsentinel && chmod -R go-w /opt/brandsentinel
   # find /opt/brandsentinel ! -user root | head; grep '^commit' /opt/brandsentinel/INSTALL
   # sha256sum /opt/brandsentinel/bin/dockerd-rootless.sh
   ```
   - Expect no output from `find`, `commit: e90c92acbd7a83c83f844ae1dddeece075a9c15d`,
     and `200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488`.
   - Keep this window short. The account's `docker-rootless.service` starts
     `/opt/brandsentinel/bin/dockerd-rootless.sh` (`Restart=always`;
     `setup-rootless.sh`). Between the `mv` and the end of the install that file
     does not exist, so a daemon restart would fail and take down the egress
     proxy. The running daemon is not affected. Do not restart the account's user
     manager or reboot inside the window; if the install fails, move SP1 back
     at once (step 6).
4. The validated image is already in the account's daemon. Confirm it against
   the new source rather than reloading:
   ```sh
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/venv/bin/python /opt/brandsentinel/src/scripts/service-account/image_manifest.py \
       --docker-host unix:///run/user/1001/docker.sock --source /opt/brandsentinel/src \
       --expect-id sha256:aafa3d78aafe8c55b80cb70f65073c4b16c69caed0e9355a2e7230bc8238807b
   ```
   Expect `"verdict": "ok"`. On a mismatch, stop and stream the image as in
   service-account.md step 6.
5. Validate the canonical install:
   ```sh
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/src/scripts/service-account/validate.sh
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/venv/bin/brandsentinel -c /opt/brandsentinel/etc/service.yaml sandbox selftest media
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/venv/bin/brandsentinel -c /opt/brandsentinel/etc/service.yaml status
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       /opt/brandsentinel/venv/bin/python -c "from brandsentinel.config import load_config; \
   from brandsentinel.policy.scorer import Policy; from brandsentinel.analysis.payment import ProviderCatalog; \
   from pathlib import Path; c = load_config(Path('/opt/brandsentinel/etc/service.yaml')); \
   print(Policy.load(c.analysis.policy).version, ProviderCatalog.load(c.analysis.payment_providers).version)"
   ```
   Expect:
   - `SP1 VALIDATION: PASS` (it also runs `compose --profile sandbox up -d` on the
     account's daemon);
   - a passing selftest;
   - `status` reporting schema v5 (the store is already v5; no migration runs);
   - `policy/4` printed by the last command. `status` does not load the policy;
     the last command reads both files through the configured paths, with no side
     effects.
6. Rollback, if needed. Stop any `brandsentinel` process first.
   ```sh
   # mv /opt/brandsentinel /opt/brandsentinel.m6-failed
   # mv /opt/brandsentinel.sp1-31318f0 /opt/brandsentinel
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect \
       docker --host unix:///run/user/1001/docker.sock tag \
       brandsentinel-sandbox:sp1-31318f0 brandsentinel-sandbox:local
   # systemd-run --user -M brandsentinel@ --wait --pipe --collect --working-directory=/opt/brandsentinel/src \
       docker --host unix:///run/user/1001/docker.sock compose -f docker/compose.yaml \
       --profile sandbox up -d --force-recreate
   ```
   - Data: SP1 refuses the v5 directory (`SchemaTooNew`, before any write), so
     SP1 runs only against a v4 copy (if one exists) or an empty directory. Move
     the v5 data aside, never delete it, so M6 can be promoted again:
     `# mv /var/lib/brandsentinel/data /var/lib/brandsentinel/data.v5-$STAMP`.
   - SP1 then starts with an empty store (or the v4 copy restored to
     `/var/lib/brandsentinel/data`). Cases and evidence from the M6 period are not
     visible to SP1.
   - Then run SP1's own `validate.sh` (service-account.md step 7).
7. After acceptance, remove the superseded trees:
   - `/opt/brandsentinel-m6-stage` and `/opt/brandsentinel-m6-e90c92a`;
   - the SP1 copy, `/opt/brandsentinel.prev-4280e42` and the data backup only
     once the rollback window is formally closed.

### Accepted risks and follow-ups

Accepted on PR #9 (2026-10-17), detailed in
`docs/residual-review-findings/feat-m6-media-visual.md`:
- image changes behind unchanged URLs may evade refresh;
- lazy-loaded images (`data-src`, `srcset`, CSS backgrounds) are not collected;
- cropped, mirrored or transformed assets evade whole-image matching;
- adversarial media can amplify processing cost within per-container limits.

Proposed follow-ups:
- re-fetch media candidates on rechecks;
- collect lazy-loaded and CSS images;
- a stronger `VisualMatcher` (and screenshot similarity in M7);
- aggregate media-stage cost controls across domains;
- `--json` for `registry collect` and `registry corpus`;
- split `evidence/bundle.py` and `cli.py` (both over 1000 lines);
- carried as before: SP2 (instance lock) and a separate test environment
  instead of the dev group in the service venv.

### Unresolved decisions

- The cutover window, and whether a pre-M6 (v4) data backup exists.
- Who confirms the production reference assets and pages (hazard 4).
- Cleanup of the superseded `/opt` trees after cutover.
- M7 lab sandbox network design (`bs_lab_sandbox` placeholder in `config/lab.yaml`).

### Developer environment notes

- Commits are SSH-signed; after a reboot run `ssh-add ~/.ssh/id_ed25519_sg_sign`
  before committing.
- The developer's rootless Docker (`docker-rootless.service`) had to be
  restarted once after a reboot.
- About 1.9 GB of dangling images in that daemon can be pruned by the developer.
- The image budget check needs `IMAGE_GIB=3` when the base image is cached.
- The local branch `feat/m6-media-visual` is merged and can be deleted.
