# Residual findings: runtime image identity (B7 U14, 2026-11-23)

These are the accepted limits of the U14 runtime step in the
[B7 plan](../plans/2026-11-10-002-chore-b7-production-promotion-plan.md) (KTD12, option C,
OB8). It closes failure path F5: the runner no longer creates containers by a tag that can
move between the preflight and the creation. It builds on the
[approval reader](feat-b7-image-approval-reader.md) and the
[selection rule](feat-b7-image-selection-rule.md), and changes neither.

**Status:** development-tested. The first SP3 run (`docker or security`, 0 skipped) on this
change, on 2026-11-25, failed on a pre-existing lab-mode DNS lookup outside U14
([fix](fix-b7-lab-mode-dns-before-policy.md)). With the fix merged in (`4cf97f9`), SP3 passed:
622 passed, 0 failed, 0 errors, 0 skipped. Not merged, not released, not promoted.

## What it does

- **`check_runtime(docker, config)`** selects once (`image_selection.select`), before any
  Docker call. When enforcing it reads the record once (`approval.load_approval`). It then
  resolves `sandbox.image` to a full ID once (`image inspect`), and requires that ID to be
  the record's when enforcing. The `Report` carries the ID only when every runtime check
  passed.
- **`prepare_runtime`** builds the only runner that can create containers, bound to that ID.
  Every caller goes through it: `run` (`_prepare_sandbox`), `sandbox check`,
  `sandbox selftest`, `registry collect` and `status`.
- **The runner** takes `image_id` (a full `sha256:` ID, checked) and `image_enforced`, both
  read-only. Every `docker create` names the ID after `--`. A spec's `image` must be
  absent or equal to that ID, in every mode. A runner without an ID (the sweeps in
  `sandbox sweep` and the orchestrator fallback) cannot validate or create a job.
- **`check_network`** adds `proxy_image` when the runner enforces: the proxy container's
  `.Image`, read by `container inspect`, must equal the runner's ID. The browser client
  runs this before every launch.
- **Named failures**, each disabling sandbox stages (or, for `proxy_image`, the browser
  gate), with `needs_media` and `needs_render` visible:

| Check | Detail | When |
|---|---|---|
| `image_selection` | `anchor_unsafe`, `anchor_missing`, `anchor_account_unknown`, `unclassifiable`, `selection_error (<type>)` | the selection was refused or raised |
| `image_approval` | `approval_missing`, `approval_unsafe`, `approval_malformed`, `approval_error (<type>)` | enforcing, and the record is not usable |
| `image_approved` | shortened resolved and approved IDs | enforcing, and the tag names another ID |
| `sandbox_image` | not found; not a full ID; not resolved | any mode |
| `proxy_image` | the proxy's name | enforcing, and the proxy runs another image |

- `status` and `sandbox check` print an `image:` line: enforced or not, the selection's
  reason and a 12-digit ID. Details carry stable check names only: no path, account,
  record content or exception text.

## Residual limits

- **No mid-run revocation** (plan residual). A run keeps the ID it resolved and approved at
  start. A record or tag changed during a run is seen only at the next preflight. The
  browser client's per-launch network check re-reads the proxy's image, but not the record.
- **Compose is U13's (F6).** `docker/compose.yaml` and `docker/lab.compose.yaml` still start
  the proxies by `brandsentinel-sandbox:local`. U14 detects a proxy on another image when
  enforcing (`proxy_image`); it does not prevent the start.
- **Development hosts do not compare the proxy.** When not enforcing, the proxy's image is
  not compared with the resolved ID. The plan requires the comparison only when enforcing,
  and on a developer host the lab proxies may legitimately run an older build.
- **The account controls its own daemon.** A manual `docker tag`, `load`, `run` or
  `compose` outside BrandSentinel is not prevented. The runner's own creates are by ID;
  other starts are only contained (the proxy check, the identity checks and the event log
  of the plan).
- **Docker semantics are taken from U15**, not re-verified here: `create --pull never <ID>`
  is bound to the ID (DV5), and a container's `.Image` is its full image ID. SP3 exercises
  creation by ID on the developer daemon; the enforcing path is first exercised at G8.
- **Unexpected errors** in the selection or the record read are caught broadly and named
  (`selection_error`, `approval_error`, with the exception's type name only). This keeps
  the rest of `run` alive with sandbox stages disabled. The error text is not kept, so
  diagnosing one needs a reproduction.
- **Root** is refused by the CLI and by the account checks, not by this step.
- **Selection and reader limits carry over**, including the two open anchor-parser
  findings (duplicate keys; a trailing newline in the account). They stay open for triage
  before U3/U4 release acceptance.

## Verification (development only, 2026-11-23)

- **Failing first:** the new and adapted runner, preflight and harness tests were run
  against the unchanged source (`main` `986c7c4`): 135 failed, 94 passed.
- **Offline suite** (`-m "not docker and not lab and not models"`), after the review fixes:
  3217 passed, 1 skipped (tesseract not installed, pre-existing), 0 failed. `ruff check`
  is clean. The strict MkDocs build was not run offline; CI runs it.
- **Review** (full depth: security, adversarial, correctness, testing, reliability,
  project standards): no P0 or P1, and the security reviewer found no bypass. Fixed:
  - the Docker-test harness ran its preflight in module-scoped fixtures, before the
    test suite's anchor isolation, so it could read the host's anchor and record. It now
    isolates them itself, and fails rather than skips on an image-identity refusal;
  - the `image:` line said `REFUSED` when an unrelated runtime check had failed;
  - the configured tag is passed to `image inspect` after `--`;
  - unexpected errors now name their exception type;
  - tests added for a production-class store with a valid record, a proxy on another
    image through `sandbox check`, a refused runtime starting no probe, and the `image:`
    line states; documentation wording corrected.
- **Added for SP3** (passed in the 2026-11-25 run on `4cf97f9`): a Docker test that a container created by the runner
  reports the resolved ID as its `.Image`, and that the tag resolves to the same ID.
