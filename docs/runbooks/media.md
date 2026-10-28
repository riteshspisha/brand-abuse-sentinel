# Media sandbox, reference corpus and visual matching (M6: U16, U17)

M6 adds the image-processing gate (R42, R43): untrusted images are decoded,
hashed, QR-decoded and read by OCR only in a network-less, limited sandbox
container; the application never decodes an image. On top of it, a trusted
reference corpus built only from confirmed official assets and pages, and
visual matching of candidate images against it.

## Trust boundaries

```text
 brandsentinel process (trusted orchestration; never imports an image library)
   media decision ── which images, why (fact)          registry collect ── confirmed assets/pages only
   hardened fetcher ── evidence mode, raster types      hardened fetcher ── verified TLS, official hosts only
   blob store ── inert, quotas                           corpus rows ── re-checked against the registry on load
          │ one JSON job on stdin (base64 images)                     │
          ▼                                                           ▼
 ┌──────────── media container (per batch) ──────────────────────────────────────────┐
 │ --network none, read-only root, noexec /tmp 64 MiB, cap-drop ALL, no-new-privs,    │
 │ non-root user, memory 512 MiB (no swap), 1 CPU, 64 PIDs, 90 s wall, stdout 2 MiB   │
 │ magic-byte allowlist → header checks → Pillow (one plugin) → hashes, zxing, OCR   │
 └────────────────────────────────────────────────────────────────────────────────────┘
          │ one JSON document, validated against a strict schema before use
```

## Controls

| Threat | Control | Where | Proof |
|---|---|---|---|
| Decoder exploit reaching the host | images decoded only in the media container; the application imports no image library | `sandbox/media_worker.py`, `media_client.py` | `tests/security/test_media_limits.py::test_the_application_never_imports_an_image_decoder` |
| Media job reaching a network | `--network none` fixed in `media_spec`; no network lease, no network inspected | `media_client.media_spec`, runner | `test_media_limits.py` (arguments, fake runtime), `test_media_sandbox.py::test_media_container_has_no_network...`, selftest `no_network_inside` |
| Decompression bomb, lying header | explicit `MAX_IMAGE_PIXELS`, bomb warnings as errors, pixel and dimension caps from the header before decoding; hard cap 100 MP whatever the config | worker | `test_media_worker.py::test_ae12_...`, `::test_a_lying_header...` |
| Bomb within the pixel cap | memory limit (no swap); the image is retried alone and recorded `sandbox_oom`/`sandbox_killed` | runtime + client | `test_media_sandbox.py::test_ae12_bomb_that_passes_the_header_check...` |
| Animation or icon floods | frame cap (seeks at most cap + 1), icon entry cap | worker | `test_media_worker.py` |
| Format confusion (HTML named `.png`, SVG, PDF) | magic-byte allowlist PNG, JPEG, GIF, WebP, ICO; Pillow opens with that one plugin | worker | `test_media_worker.py`, `test_media_pipeline.py::test_html_served_as_an_image...` |
| Slow OCR, CPU and fork pressure | OCR timeout, OCR downscaling, 1 CPU, 64 PIDs, BLAS/OpenMP pools pinned to one thread, wall time enforced from outside | worker + runtime | `test_media_sandbox.py::test_wall_time_limit_ends_a_slow_job`; `docs/solutions/2026-10-11-blas-threads-exhaust-the-pid-limit.md` |
| Hostile worker output | strict schema (no unknown keys, bounded strings and lists, hex digests), exact ids, sha256 of what was sent; else `invalid_output` | client | `test_media_client.py` (ten tampering cases) |
| One bad image hiding others | per-image results; a killed batch is retried one image at a time | worker + client | `test_media_client.py::test_ae12_a_killed_batch...` |
| Unguarded image fetching | every image through the hardened fetcher (netguard, pinned connects, per-hop validation, caps); lab mode only via the lab proxy | `pipeline/media.py`, `visual/collector.py` | `test_media_pipeline.py::test_image_at_a_private_address_is_never_fetched`, `test_collector.py` |
| Real content under the developer account | SP1 hostile-content gate, shared by the pipeline and `registry collect` (lab mode exempt: synthetic content) | `sandbox/preflight.gate_hostile_content` | `tests/security/test_preflight.py`; `registry collect` refuses with `dedicated_account` |
| Untrusted references in the corpus | only confirmed registry assets whose bytes match their pin, and images from confirmed reference pages fetched with verified TLS on confirmed official domains of the brand; every row re-checked on load; evidence-mode artifacts refused | `visual/corpus.py`, `visual/collector.py` | `test_corpus.py`, `test_collector.py` |
| Third parties on official pages | recorded as `candidate` observations (R14), never corpus, never suppressing | collector | `test_collector.py::test_r14_...` |

## How matching becomes evidence (policy/4)

- `HashMatcher` (`visual/compare.py`): exact sha256, or pHash ≤ 10 **and** dHash ≤ 8
  (of 64 bits) with proportions within 1.35×; images with luminance standard
  deviation under 12 match only exactly. Calibrated on the lab logo: resized and
  recompressed, recoloured, watermarked, bordered, alpha, GIF and ICO copies
  match (pHash ≤ 8, dHash ≤ 4); unrelated suns (closest pHash 12 / dHash 15),
  discs, flats, gradients and a payment screenshot do not. Mirrored and cropped
  copies do not match either; that is a known limit of the initial method.
- `copied_asset_match` (abuse, 40 points) fires only with corroboration for the
  matched brand from outside the matched image: the domain name, the page
  presenting the brand (title, headings, alt text), an association claim, a
  brand-tied credential or payment request, or brand text read from another
  image. Alone it stays at P3 or below; with a lookalike domain it reaches P1.
- Otherwise `visual_match_uncorroborated` (supporting, 10 points) and a
  manual-review note. A visual match or OCR text alone is never proof.
- Image text counts as presentation and donation language; QR payees and OCR
  payees join the payment block with `source` `qr_code` or `image_text`. An OCR
  identifier within two edits of a confirmed payee is a
  `possible_ocr_misread_of_registry_payee`: it may be a misreading or a
  deliberate lookalike, so it is never relief, counts as an unconfirmed payee of
  that payee's brand, and adds a manual-review note.
- Payee and credential ties count as corroboration only when they do not rest
  on the matched image's own text (a payee name naming the brand, or the brand
  presented by the page or by another image). A payee read from a matched image
  itself (its QR code or its text) never corroborates; each media payee records
  the image it was read from (`image_sha256`), and one whose image is unknown is
  not treated as independent.
- Media status `pending`, `failed`, `partial` or `disabled`, and rejected
  images, are listed as incomplete (`partial` also covers an image whose
  requested OCR or QR decoding was unavailable, timed out or failed) with the `needs_media` flag, a
  `media_rejected` label and review notes. Missing visual evidence never makes a
  case benign; an image-only page stays at least P4 `insufficient_evidence`
  unless abuse evidence lifts it.

## Which images are examined

After each final static fetch the pipeline records a `media_decision`:

- never on a confirmed official domain or without a fetched HTML page;
- triggered by an image-only page, QR-code candidates, or a brand-related page;
- at most `media.max_images_per_case` (8): QR candidates (at most half the
  slots), logo candidates (file name, alt text, class or id, brand in alt text,
  in the header), up to two icons (else the guessed `/favicon.ico`), og:image,
  the page images of an image-only page, inline `data:` images, then any other
  page image in document order. Wanted images left out are counted
  (`images_not_selected`) and reported as not examined.
- every image gets QR decoding; OCR when any reference to it asks for it.

Only the guessed `/favicon.ico` may be `absent` (404/410 or not an image). A
404 or failure for an image the page itself references is unknown, since a site
can hide an image from the scanner. An unchanged recheck carries the earlier
media result only when that result was complete (or not needed); a pending,
failed, partial or disabled result is decided again.

## Operating

```sh
brandsentinel sandbox selftest media     # real container: hashes, OCR, QR, rejections, no network
brandsentinel registry validate          # reference assets: pins, official hosts
brandsentinel registry collect [--brand ID]   # dedicated account only (lab mode exempt)
brandsentinel registry corpus            # entries matching uses, and any no longer vouched for
brandsentinel cases list --label media_rejected
```

Corpus entries are used from the moment they are collected. Matches are stored
with the case (with the corpus version) so a bundle rebuilds identically; a
later corpus change applies to a case's next media run.

Lab: `config/lab.yaml` enables sandboxes (media jobs without a network; since
M7 browser jobs on `bs_lab_sandbox`, see `docs/runbooks/browser.md`); the lab
corpus is the pinned synthetic logo `registry/assets/lab/lumina-logo.png`.

```sh
brandsentinel -c <lab dev config> registry collect
brandsentinel -c <lab dev config> run --duration 30
uv run pytest -m lab tests/lab/test_media_demo.py
```

## Verification record (2026-10-11, development host, developer rootless runtime)

Sandbox image `brandsentinel-sandbox:local` `sha256:75854f79…` built from the
tree (`image_manifest.py`: no package file differs).

| Check | Result |
|---|---|
| `sandbox selftest media` | all checks pass: valid image hashed; OCR reads "Donate to Lumina Foundation"; UPI QR decoded; bomb, HTML-as-PNG, 40-frame GIF and 20-entry ICO rejected; inside the container TCP 1.1.1.1:443 `OSError`, DNS `gaierror`; container removed |
| Bomb with the pixel cap raised (81 MP, 160 MiB) | killed by the kernel (exit 137); recorded `sandbox_killed`; the other image analyzed alone; nothing left running |
| Wall time 1 s on dense-text OCR | killed by name at ~1 s, `sandbox_timeout`, container removed |
| In-process vs container | identical sha256, pHash, dHash, favicon hash and dimensions for the lab images |
| `-m "security and docker"` | 41 passed, 0 skipped (SP1 isolation, Docker isolation, media selftest) |
| `-m "docker and not security"` | 45 passed, 0 skipped (runner, media sandbox, lab static and media demos) |
| `registry collect` with the production config as the developer | refused: `dedicated_account` (not_code_owner, no_rootful_docker) |

The service-account validation (SP1 `validate.sh` from an install of this
branch) is still to be run by an operator; see "Service-account re-validation".

## Service-account re-validation

The SP1 procedure (`docs/runbooks/service-account.md`, steps 1, 4, 6 and 7)
re-run from this branch's commit, then, as the account:

```sh
# systemd-run --user -M brandsentinel@ --wait --pipe --collect \
    /opt/brandsentinel/venv/bin/brandsentinel -c /opt/brandsentinel/etc/service.yaml sandbox selftest media
# systemd-run --user -M brandsentinel@ --wait --pipe --collect \
    /opt/brandsentinel/venv/bin/brandsentinel -c /opt/brandsentinel/etc/service.yaml registry collect
```

`validate.sh` runs `-m "security or docker"`, which now includes the media
suites. Expect `SP1 VALIDATION: PASS` and a passing selftest; `registry collect`
with an empty production registry reports nothing to collect.

## Residual risks

- Pillow, libwebp, zxing-cpp and Tesseract are native code parsing hostile
  bytes; the container (rootless, no network, no mounts, limits) bounds an
  exploit, the shared kernel remains (VM isolation deferred, as in M4).
- OCR is basic: stylized or small text is missed, and characters are misread
  (hence the misread guard). An image whose text OCR misses stays unknown, not
  benign, only when its page is image-only; elsewhere the static text decides.
- The initial matcher misses mirrored, cropped and heavily edited copies.
  Screenshot similarity (M7) uses the same hashes against reference page
  screenshots (`docs/runbooks/browser.md`).
- An image served with a non-image content type (other than the guessed
  favicon) is not fetched and stays unknown; browsers may still show it.
- Docker's OOMKilled flag is not set when the kernel kills the worker under
  `--init`; such kills are reported as `sandbox_killed`
  (`docs/solutions/2026-10-11-oomkilled-not-set-for-child-of-init.md`).
- The service install carries the dev group (for `validate.sh`), so Pillow and
  the other media libraries are present on the host. The application never
  imports them (`test_the_application_never_imports_an_image_decoder` fails
  if any host module does); a separate test environment remains the SP1 follow-up.
- Rejected images are stored as inert blobs (0600, never opened) as evidence;
  they count toward the artifact quotas.
- Matches are computed when a case's media runs; a corpus change does not
  re-match earlier cases until their next media run.
