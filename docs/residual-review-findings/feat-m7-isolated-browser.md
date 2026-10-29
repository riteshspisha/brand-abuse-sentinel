# Residual review findings - M7 (U19)

Review run `20261028-150934-6837e240` on branch `feat/m7-isolated-browser`
against `e0f9a56`. Nine reviewers: correctness, security, adversarial,
reliability, testing, maintainability, project-standards, learnings and
agent-native. No peer CLI was installed, so there was no cross-model pass.
Instead of a separate validator wave, the implementer checked each finding
against the code and fixed it with a regression test that fails on the reviewed
code (`1ff9cf5`).

## Fixed before merge

- **P1, a failed navigation was scored as the rendered page** (adversarial,
  correctness). A page that sent the browser to an error page, or whose final
  document was the proxy's refusal, replaced the static evidence with an empty
  view and could trigger a false cloaking difference. Such a render is now "no
  usable page": its network log is kept, scoring stays static, with a review note.
  Test: `test_render_pipeline.py::test_a_render_without_a_usable_page_keeps_the_static_evidence`
  (two cases).
- **P1, hiding the brand from the browser lowered the score** (adversarial,
  security). Static brand plus form, rendered form without the brand: the
  rendered view lost the brand tie. The rendered view now keeps the static
  page's brands and claims; the cloaking rule counts static brands.
  Test: `test_a_brand_hidden_from_the_browser_still_ties_the_rendered_form`.
- **P2, control characters inflated the worker's output** (adversarial). JSON
  escapes each C0 control as six bytes, so a page could overflow stdout and get
  every render killed. The worker strips them and writes UTF-8; the output budget
  counts the worst case. Test: `test_browser_limits.py::test_control_characters_...`.
- **P2, the render fact could exceed the fact cap** (correctness). A page with
  many long URLs made the store drop `requests`, reading as a failed render. Lists
  and URLs are capped so the fact always fits.
  Test: `test_a_render_record_inflated_by_the_page_still_fits_the_fact`.
- **P2, wall-time budget undercounted the worker's steps** (reliability,
  correctness). The budget now includes text, screenshot, reading and launch
  (`POST_SETTLE_SECONDS`); defaults navigation 15 s, settle 5 s, wall 60 s.
- **P2, concurrent renders would burn retries on the network lease**
  (reliability). `stages.render` is limited to 1.
- **P2/P3, render-stage error paths** (reliability). A transient media-sandbox
  failure on the screenshot is retried; an unexpected processing error on the
  last attempt is recorded as `processing_error` instead of leaving no outcome.
- **Residual from security, symmetric self-corroboration**: a matched screenshot
  is no longer corroborated by OCR of page images it shows.
  Test: `test_a_matched_screenshot_is_not_corroborated_by_page_images_it_shows`
  (fails with the guard removed).
- **P2, duplicated client wiring** (maintainability): `build_browser_client`
  serves the service and `registry collect`.
- **Tests** (testing): the proxy-less browser test gained a positive control
  (it reaches its network's one peer); the proxy-log check requires `GET` and is
  scoped to its test.

## PR #12 review (2026-10-29)

- **Page-opened sockets bypassed the HTTP method gate** (owner's security
  review). `context.route` sees HTTP only: a page's WebSocket (also from a
  worker) exchanged messages through a proxy tunnel, and WebRTC sent TURN
  traffic through one. Fixed in the proxy (tunnels only TLS to 443) and the
  worker (WebSockets refused and recorded; WebRTC and workers removed).
  Test: `tests/lab/test_browser_sockets.py` (fails on the M7 image).
  Residual: GET requests and TLS-tunnelled traffic a page itself sends towards
  allowed destinations (`docs/runbooks/browser.md`).
- **KTD20 screenshot embedding**: not implemented, recorded as a deviation.
- **Lab reference screenshots**: accepted as a documented test limitation.

## Accepted residuals

- **Reference screenshots are not demonstrated in the lab** (testing, P2):
  reference pages are https-only with verified TLS and the lab is plain HTTP.
  Covered by `tests/integration/test_collector.py` with a scripted browser.
  Accepted by the owner as a test limitation (2026-10-29).
- **`bundle.py` grew past 1300 lines** (maintainability, P2): splitting the
  render and visual blocks into their own module is a follow-up, as for `cli.py`.
- **Cloaking explanation text built in both the rule and the label**
  (maintainability, P3).
- **A page that busy-loops its main thread** ends every render at the wall time
  (adversarial): the case keeps its static evidence and shows the failed render.
- **A second cancellation during shutdown** can still leave a container until the
  next startup sweep (reliability, adversarial).
- **Reference screenshots include third-party subresources and iframes**, and
  are taken without requiring network idle or a 2xx status (security,
  adversarial, correctness). They come only from confirmed official https pages;
  a maintainer reviews the corpus (`registry corpus`).
- **`check_network` does not confirm that `proxy_url` is the attached proxy's
  address, or that the lab sandbox proxy runs `lab_only`** (security): config
  validation pins both, and the networks are internal.
- **Headless Chromium is easy to fingerprint** (security, adversarial): cloaking
  aimed at both the fetcher and the browser is not detected.
- **`decide_render` records nothing when the bundle cannot be built**
  (reliability, adversarial), the same as `decide_media`.
- **Docker suites skip without the rootless runtime** (testing): SP3 is checked by
  running the gates with `-rs` and requiring no skips, as since M4.
- **The no-interaction test is an AST name check** (testing): the lab demo's
  `attempt_counts` and the proxy-log `GET`-only check back it at runtime.
