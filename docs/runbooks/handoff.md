# Session handoff

The state a new session needs before it touches code or the installation. It is
updated at each milestone close. Facts below were checked on the development
host at the date given; re-check anything marked *reported*.

## Current: M7 implemented on `feat/m7-isolated-browser` (2026-10-28); M6 deployed

M7 (U19, isolated browser) is implemented, reviewed and verified on the
developer's rootless runtime, on branch `feat/m7-isolated-browser` (PR pending
merge). It is **not deployed**: the canonical installation still runs M6, and
promotion is a separate, gated operation (see "M7 promotion").

### M7 delivered

- **Lab sandbox network (design approved 2026-10-28).** `bs_lab_sandbox`
  (internal, `inhibit_ipv4`, IPv6 off, `172.31.254.0/24`) and the lab-only
  `bs-lab-sandbox-proxy` on `bs_lab_sandbox` and `bs_lab` only, listening only on
  `172.31.254.2:3128`, no published port, no route out. Lab mode pins the
  sandbox network, proxy URL and container; production refuses them. netguard's
  lab exception is unchanged. The Docker isolation and SP1 suites run for both
  sandbox networks.
- **Browser worker and client.** Chromium (Playwright 1.63.0, `sandbox` extra:
  only in the image) in a per-job container: `pwuser`, no capabilities,
  `no-new-privileges`, Docker's default seccomp plus `clone`/`unshare`/`chroot`,
  read-only root, limits; Chromium's own sandbox on. Observe only (R39): non-GET
  stopped, downloads refused, service workers blocked, dialogs dismissed, popups
  closed. Strict output validation (`render_rejected`). Network check before
  every launch; with the direct-egress probe before the stage registers.
- **Triggers, render stage, cloaking.** `render_decision/1` (AE10 `js_shell`,
  `static_error`, `decoy_page`, `script_redirect`, `form_hints_without_forms`,
  `little_text`, `no_static_images`, `sample`); rendered extractor features;
  screenshot through the media sandbox and corpus; `cloaking/1`; `bundle/4`
  (scored on the rendered page unless only the static page showed abuse);
  `policy/5` (`cloaking_suspected`).
- **Reference screenshots** in `registry collect` (verified TLS, official https
  only); `brandsentinel sandbox selftest browser`; reports show the render.
- **Runner fix (affects M6 media jobs too):** a job cancelled during its own
  container removal left the container behind; removal now finishes first.
- Details, controls and the verification record: `docs/runbooks/browser.md`.

### M7 decisions and deviations

- **Screenshots are not embedded in reports: a recorded KTD20 deviation**
  (owner decision, PR #12 review, 2026-10-29). KTD20 says size-capped data
  URIs; M7 keeps M6's stance that no sandbox-produced image reaches the
  analyst's browser, and shows the screenshot's hashes, OCR and QR results as
  text. Embedding is not implemented; revisiting it is a separate decision.
- **Reference screenshots are not demonstrated in the lab: an accepted test
  limitation** (owner decision, 2026-10-29). Reference pages are `https`-only
  with verified TLS and the lab is plain HTTP; TLS verification is not relaxed.
  Proven with a scripted browser (`tests/integration/test_collector.py`).
- **Page-opened sockets (PR #12 review finding).** WebSockets and WebRTC were
  outside the browser's GET-only gate and passed through proxy tunnels. Now the
  proxy tunnels only to 443 and only when the first bytes look like a TLS
  ClientHello, a prefix filter rather than TLS enforcement (this also changes the production egress proxy
  at promotion: `CONNECT` to port 80 and plain tunnels are refused), and the
  worker refuses WebSockets and removes WebRTC and workers. BrandSentinel does
  not interact with pages; a page's own GET requests and TLS traffic remain
  possible towards allowed destinations (`docs/runbooks/browser.md`, residual
  risks).
- **Seccomp profile** shipped in the package (`src/brandsentinel/sandbox/
  chromium-seccomp.json`) rather than `docker/seccomp/chromium.json`, so wheel
  installs carry it; derived from the vendored Docker default, not Playwright's
  older copy (`docs/solutions/2026-10-28-chromium-sandbox-under-cap-drop-all.md`).

### M7 promotion (not authorized; separate gated operation)

Promoting M7 needs, each separately approved: a new image on the service
account's daemon (adds Playwright; the image grows slightly), a fresh install,
the account's lab project recreated (new service and network; residual issues
1 and 2 below apply: a lab `up` recreates `bs-lab-web` and `bs-lab-proxy`),
then under the account: `sandbox check --strict`, `sandbox selftest media`,
`sandbox selftest browser`, and the `security or docker` suites with no skips.
Schema stays v5 (no migration); stored scores keep their `policy/4` and
`bundle/3` labels and rescoring adds rows.

## Earlier: M6 deployed (2026-10-28)

M6 (U16 media sandbox, U17 reference corpus and visual matching) is merged and
now **active** in the canonical installation:
- **Merge:** PR #9, merge commit `358bf40`, whose tree is identical to the final feature commit `e90c92a`.
- **Deployment:** five operator gates on 2026-10-26 to 28. Each was separately approved, and the evidence for all of them is
  outside the repository (see "M6 deployment record").
- **Next:** M7 is implemented on its branch (above); M8 follows.

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

Decisions worth knowing (M6):
- The lab sandbox network `bs_lab_sandbox` was designed and built in M7 (above).
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

### M6 deployment record (2026-10-28)

| Item | State |
|---|---|
| `/opt/brandsentinel` | **active M6**: commit `e90c92acbd7a83c83f844ae1dddeece075a9c15d`, root-owned, nothing group/world-writable, fresh offline install (not a renamed tree). Installation acceptance manifest sha `af78aad3…` |
| `/opt/brandsentinel.sp1-31318f0` | SP1 (`31318f0`), verified identity, kept for code rollback |
| `/opt/brandsentinel-m6-e90c92a` | staged validated install; **still referenced** by the proxy's Compose labels and the lab containers' mounts (see residual issues) |
| `/opt/brandsentinel-m6-stage`, `/opt/brandsentinel.prev-4280e42` | superseded; untouched |
| `/var/lib/brandsentinel/data` | live store, **schema v5** (migrated by the staged M6 install during validation, 2026-10-17). First opened by the canonical install in Gate 5; `brandsentinel.db` unchanged (sha `e51e745d…`, 253,952 bytes); the empty WAL and the SHM were removed on close. 0 artifacts, 0 cases, 0 jobs |
| v5 backup | `/var/backups/brandsentinel/data.v5-backup-20261018T102437Z` (RECORD sha `a4b592ff…`): a recovery point **for M6 only**, `VERIFY: OK` after every gate |
| Images (UID 1001) | `brandsentinel-sandbox:local` = `brandsentinel-sandbox:m6-e90c92a` = `sha256:aafa3d78aafe8c55b80cb70f65073c4b16c69caed0e9355a2e7230bc8238807b`; rollback `brandsentinel-sandbox:sp1-31318f0` = `sha256:5d908b8e2abc55a5fe3ad372f0cf813930af83139b9c2cc63109214a252eba64`; nginx lab image `sha256:15c994d1…` |
| Containers (UID 1001) | `bs-egress-proxy` running the M6 image, never restarted since the 2026-10-26 reboot; `bs-lab-web` and `bs-lab-proxy` exited (manually stopped on 2026-10-17) |
| Account runtime | `docker-rootless.service`: `ExecStart=/opt/brandsentinel/bin/dockerd-rootless.sh`, `Restart=always`, unchanged through the cutover. The socket's group is 166493 (subgid mapping; reviewed) |
| Application | **not running.** No `brandsentinel run` and no unit; supervision is M9 |
| Recovery kit | `/usr/local/lib/brandsentinel-cutover-m6` (r2, `SHA256SUMS` `7b24b4b9…`, root:root 0555); r1 kept beside it as `….r1-2c5f0270` |

**Gates:**
1. root recovery kit;
2. preserve the M6 image as `:m6-e90c92a`;
3. canonical installation (S0 → S6; a 2.6 s window; the daemon was never restarted);
4. operational acceptance in isolation (image integrity; sandbox isolation with the running proxy; media OCR/QR self-test;
   248 offline tests; schema v5 on a copy of the store);
5. the first M6 open of the live store.

All of them passed with the runtime snapshot unchanged.

**Evidence and procedures** are outside the repository:
- `~/brandsentinel-cutover-m6-work/`: start at `M6-CLOSEOUT.md`. It also holds `CUTOVER-DECISION.md`, the `GATE*.md` files, the
  `manifests/` and the `evidence/` directories.
- The kit's run evidence is in `~/brandsentinel-cutover-m6-evidence/{tag,install}`.

### Not authorized (each needs its own reviewed decision and operator approval)

- **Live collection:** `brandsentinel run`, `submit`, `registry collect`, CertStream and dnstwist. The first supervised run starts
  media containers and fetches images from candidate sites (`service.yaml` has no `media:` section, so the defaults apply).
- **Any Docker Compose on the account's daemon**, including `scripts/service-account/validate.sh`. It runs
  `compose --profile sandbox up -d` and, through the `security or docker` pytest selection, `compose lab.compose.yaml up/stop`.
- **Recreating, restarting or retagging** `bs-egress-proxy`, the images, the networks or `docker-rootless.service`.
- **Retiring the lab containers**, or removing staging, superseded trees, the SP1 copy, the Gate 4 store copy
  (`/var/lib/brandsentinel/gate4-20261028T073350Z`) or the backup.
- **Unattended operation** (M9).
- **Store-opening commands on the live data beyond Gate 5:** `status`, `cases`, `report`, `export`, `analyze` and
  `registry corpus` all call `open_store`. It is benign at v5 with an empty blob store, but it sweeps orphan blobs older than 1 h.

### Residual operational issues

1. **The proxy's Compose metadata names staging.** `bs-egress-proxy` carries project `brandsentinel`, working dir
   `/opt/brandsentinel-m6-e90c92a/src/docker` and config file `…/compose.yaml`.
   - A `compose -f docker/compose.yaml` run from the canonical tree belongs to the same project (`name: brandsentinel`), so it
     may adopt or recreate the proxy.
   - Removing staging leaves the labels pointing at a missing file.
   - It needs a decision: leave it as is, or recreate the proxy once from the canonical path in a separately approved window.
2. **The lab containers mount staging.** `bs-lab-web` and `bs-lab-proxy` (project `brandsentinel-lab`, `unless-stopped`,
   manually stopped) bind-mount files from `/opt/brandsentinel-m6-e90c92a/src/`. Retire them, or decide what to do with them,
   before staging is removed. Any lab Compose `up` from the canonical tree recreates them.
3. **SP1 cannot open the v5 store.** SP1 raises `SchemaTooNew` inside `connect()`, before any migration or orphan sweep. Before
   that it has already run `chmod 0700` on the data directory and opened the database in WAL mode (creating `-wal`/`-shm`), so
   it is not entirely side-effect free. Never start SP1 against
   `/var/lib/brandsentinel/data`.
   - **Code rollback:** two renames under `/opt` (`restore-sp1.sh` refuses S6, so this is a manual, approved operation).
   - **Data rollback for SP1:** move the v5 directory aside and give SP1 an empty directory. Never restore the v5 backup for SP1.
4. **The production reference corpus is empty** (`registry/brands.yaml`: `reference_assets: []`, `reference_pages: []`).
   Visual matching is inert outside the lab, and every case reports `reference_corpus_empty`. Who confirms the real assets is
   still open.
5. **Deployment-specific items:**
   - the offline install inputs in `/var/tmp/bs-*` age out after about 2026-11-17 (only needed for a reinstall);
   - SP2 (instance lock) is not done and blocks M9;
   - `bs_lab_sandbox` exists only in this branch's lab project (M7); the account's lab project gains it on promotion;
   - CertStream reports STALE because no source runs.

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

- Whether a pre-M6 (v4) data backup exists. This is unverified; the only recorded backup is the v5 one, which is not an SP1
  rollback point.
- Who confirms the production reference assets and pages (residual issue 4).
- The proxy's Compose ownership and lab-container retirement (residual issues 1 and 2), and cleanup of staging, the
  superseded `/opt` trees and the Gate 4 store copy.
- When the first supervised `brandsentinel run` happens (live collection; not authorized).

### Next: M8 (U20 providers, U21 evaluation)

U21 depends on M7 (merged first). Lab sites now carry rendered evidence; U21's
evaluation reads each site's `expected.yaml` as before.

### Developer environment notes

- Commits are SSH-signed; after a reboot run `ssh-add ~/.ssh/id_ed25519_sg_sign`
  before committing.
- The developer's rootless Docker (`docker-rootless.service`) had to be
  restarted once after a reboot.
- About 1.9 GB of dangling images in that daemon can be pruned by the developer.
- The image budget check needs `IMAGE_GIB=3` when the base image is cached.
- The local branch `feat/m6-media-visual` is merged and can be deleted. Pull `main` before branching for M7 (the local `main` has lagged `origin/main` before).
