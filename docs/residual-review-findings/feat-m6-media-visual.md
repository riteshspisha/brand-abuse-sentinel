# Residual review findings - M6 (U16, U17)

Review run `20261017-103557-956e6eb2` on branch `feat/m6-media-visual` against
`f943177`. Ten reviewers: correctness, security, adversarial, reliability,
testing, maintainability, performance, data-migration, learnings and
agent-native. Project-standards did not run (no CLAUDE.md or AGENTS.md), and no
peer CLI was installed, so there was no cross-model pass. Instead of a separate
validator wave, the implementer checked each finding against the code and fixed
it with a regression test that exercises the reported scenario. A simplify pass
(reuse, quality, efficiency) ran before the review.

## Fixed before commit

- **P1, a favicon role switched off QR decoding** (adversarial). An icon that
  pointed at a page image, or identical bytes under a favicon, dropped QR
  decoding and OCR for a payment image. Every image is now QR-decoded, OCR
  requests merge across duplicates, and the byte budget charges only new bytes.
  Tests: `test_icon_pointing_at_a_page_image_keeps_its_qr_and_ocr`,
  `test_every_candidate_gets_qr_decoding_and_duplicates_merge`.
- **P1, a 404 on a referenced image read as absent** (adversarial). A site could
  404 its own QR image to the scanner and get `complete` media. Only the guessed
  `/favicon.ico` may be absent now; anything else is unknown.
  Test: `test_referenced_image_returning_404_is_unknown_not_absent`.
- **P1, a lookalike payee in image text was neutralised** (adversarial). An OCR
  identifier within two characters of the confirmed payee now counts as an
  unconfirmed payee of that brand (never relief), with the review note.
  Tests: `test_lookalike_of_the_registry_payee_in_image_text_is_an_unconfirmed_payee`,
  `tests/unit/test_media_text.py`.
- **P1, OCR or QR failure still gave `complete`** (reliability). Requested OCR
  that is unavailable, times out or fails, or a QR error, is now a per-image gap,
  and the media status becomes `partial` (`media_partial`, `needs_media`).
  Test: `test_ocr_that_cannot_run_leaves_media_partial`.
- **P1, one transient image failure retired corpus entries** (reliability). A
  page counts as examined only when every in-scope image was fetched and hashed.
  Test: `test_a_transient_image_failure_keeps_the_pages_entries`.
- **P2, a matched image's own OCR could corroborate its own match**
  (correctness, adversarial). Payee and credential ties corroborate
  `copied_asset_match` only when they rest on a payee name or on brands presented
  outside the matched images.
  Test: `test_payee_resting_on_the_matched_images_own_text_is_not_corroboration`.
- **P2, unhinted images were never examined, and QR decoys could take every
  slot** (adversarial). Remaining slots now go to the other page images; QR
  candidates take at most half; wanted images left out are reported as not
  examined. Tests: `tests/unit/test_media_decision.py`,
  `test_unexamined_images_are_reported`.
- **P2, a redelivered media job did not rescore** (reliability).
  Test: `test_redelivered_media_job_rescores`.
- **P3, worker `ok` items could omit fields the host indexes** (security,
  adversarial, correctness). Width, height and luminance statistics are now
  required; anything else is invalid output.
- **P3, an unchanged recheck carried a pending, failed, partial or disabled
  result** (correctness). Only a complete (or untriggered) result is carried.
  Tests: `test_decide_media_does_not_carry_an_incomplete_result`,
  `test_decide_media_is_a_no_op_for_a_superseded_round`.
- **P3, smaller fixes** (correctness):
  - Matching runs once per unique image.
  - Inline image indices now match what the media stage can read.
  - Corpus rows are keyed by their owner, so the same image on two pages is two
    entries (migration 0005 is unreleased, so it was edited in place).
  - A media fact whose image list was dropped by the fact-size cap reads as
    `failed`.
- **Testing gaps closed**:
  - the WAL-switch retry (waits for a writer, re-raises other errors);
  - a populated bundle/3 round trip through stored scores;
  - the OCR near-miss producer;
  - the `decide_media` branches.

Verification after the fixes:
- `ruff check` is clean.
- 1158 non-docker tests pass.
- All 86 docker tests pass on an image rebuilt from the tree: the `security and docker` gate, the media containers, and the lab static and media demos.

Two time-bounded integration tests (`test_html_served_as_an_image...` and M3's
`test_retry_policy_by_outcome[/slow...]`) each failed once, in runs that took
about twice the usual time, and passed on rerun. Host load is suspected, not
the change.

## Accepted, not fixed (for the reviewer's decision)

- **Maintainability, file size** (P1 by the 1000-line heuristic).
  `evidence/bundle.py` (now ~1150 lines) and `cli.py` (~1070) cross 1000 lines.
  Moving the visual block to `evidence/visual.py` and the registry media
  commands to a CLI submodule is mechanical, but it would churn a
  security-reviewed diff. Suggested as a follow-up refactor.
- **Maintainability, P2.**
  - `MediaStage._record` takes many positional arguments and does several jobs.
  - `pipeline/media.py` and `pipeline/stages.py` import each other (one import
    is lazy, so there is no import-time cycle).
  - Batching for the sandbox lives in the collector, not the media client.
- **Agent-native, P2.**
  - `registry collect` and `registry corpus` have no `--json`.
  - Candidate observations are reviewed by editing the registry YAML (no accept
    or reject command).
  - `sandbox selftest` prints details only for passing checks.
- **Adversarial, P2 (advisory): an image swapped behind a stable URL on a
  recheck.** A complete result is carried while the page HTML is unchanged, so
  a later swap of the image bytes alone is not seen until the content changes.
  Re-fetching candidates on rechecks is the follow-up.
- **Adversarial, residual.**
  - Lazy-loaded (`data-src`, `srcset`, `<picture>`), CSS background and SVG
    `<image>` images are not candidates.
  - Whole-image hashing misses logos embedded in banners, padded beyond the
    aspect factor, mirrored or faded (documented limits of the initial
    `HashMatcher`).
  - Many attacker domains can fill the media stage's concurrency.
- **Security, residual.**
  - A compromised worker controls the results of its own batch (per case only).
  - `sandbox selftest` is not account-gated; acceptable while it processes only
    synthetic fixtures.
  - Lab mode's gate exemption relies on the fetcher's lab-host restriction.
- **Performance, residual.**
  - An OCR-heavy batch that hits the 90 s wall time is retried image by image
    (up to 8 more containers).
  - Hashing and JSON for up to 12 MiB run on the event loop.
  - The bundle is built up to three times per media round.
  - The corpus is reloaded per job.
- **Data migration, residual.** bundle/3 fields are pinned by `extra=forbid`,
  so future changes must be additive or bump to bundle/4. Older code cannot read
  bundle/3 rows; `migrate()` refuses older code anyway.
