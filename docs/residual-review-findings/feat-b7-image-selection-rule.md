# Residual findings: image-identity selection rule (B7 U14, 2026-11-23)

These are the accepted limits of `src/brandsentinel/store/image_selection.py`, after one focused independent security review on 2026-11-23. The review covered missing-anchor, user-ID and production-classification bypasses, and found no P0 or P1. Its P3 notes are fixed or recorded below.

This step of U14 in the [B7 plan](../plans/2026-11-10-002-chore-b7-production-promotion-plan.md) (option C, OB8, decisions D1-D4) **decides only whether image identity is enforced.** Nothing calls it yet:
- no preflight or runner check;
- no container is created by ID;
- no Compose change.

Nothing in this step enforces image identity.

## What the rule decides

| Anchor | Other facts | Result |
|---|---|---|
| unsafe or malformed | (any) | refused: `anchor_unsafe` |
| (any) | `data_dir` cannot be classified, including a lost working directory for a relative path | refused: `unclassifiable` |
| absent | the code runs from an installation, or `data_dir` holds a valid store marker (the only production signal without an anchor) | refused: `anchor_missing` (D1) |
| absent | neither | not enforced: development |
| present | its account does not exist on the host, or the lookup fails | refused: `anchor_account_unknown` (D2) |
| present | the effective **or** the real user ID is the account's | enforced, whatever the store (D3) |
| present | neither ID is the account's, and `data_dir` is production (anchor path, resolved path, device and inode, or marker) | enforced |
| present | neither ID is the account's, and `data_dir` is development | not enforced: development |

**Design.**
- `decide` is a pure function over `Facts`. `gather` reads only what `identity.load_anchor`, `identity.running_from_installation`, `identity.classify` and `policy.account_uid` already read. There is no second production detector.
- A refusal carries its check name only, with no path, account or chained error. Callers disable sandbox stages on a refusal.
- Error mapping:
  - an `OSError` reading the anchor is `anchor_unsafe`;
  - errors from installation detection or classification are `unclassifiable`, including a NUL byte in the path and a symlink loop;
  - an account lookup that raises is `anchor_account_unknown`.
- Selecting enforcement authorizes nothing. Opening the production store still requires both user IDs to be the account's (`policy.authorize`).
- Nothing creates or changes a file, opens a store, reads the approval record or runs Docker.
- No environment variable selects the anchor or the approval record. The test suite redirects both for every in-process test (`tests/conftest.py`).

## Residual limits

- **`data_dir` comes from the resolved configuration.** That may come from `-c`, `$BRANDSENTINEL_CONFIG` or `$BRANDSENTINEL_DATA_DIR`, as for every store command. A different `data_dir` can change only the store classification. For the anchor's account, enforcement does not depend on it (D3).
- **A relative `data_dir`** is classified against the working directory, exactly as the store guard does. D4 forbids that inference for U13's production Compose creates; the CLI path keeps the existing behaviour.
- **One call is one answer.** Preflight and the runner must select once per run and pass the result on. A host change mid-run (an anchor installed or removed) is not seen.
- **The account lookup uses the password database** (`pwd`, through `policy.account_uid`). With a network name service, a lookup that fails transiently reads as an unknown account and is refused, which fails closed.
- **Without an anchor, production is recognized only by the code's installation or by the marker in `data_dir` itself.** This is inherent in reusing `identity` (D1), and `policy.authorize` behaves the same way. These are all development on such a host:
  - an unmarked store;
  - a subdirectory of a marked store;
  - a symlink alias of the store;
  - a checkout run with `-c` pointing at a copy of the service configuration.

  Installation detection is `identity.running_from_installation`: a root-owned `INSTALL` record beside the interpreter or above the package.
- **Saved set-user-ID.** Only the real and effective user IDs are compared (D3). A process whose saved user ID alone is the account selects "not enforced". Selection happens once per run, so switching afterwards is not seen. This is theoretical, because the CLI is never set-user-ID.
- **Root is not refused here.** The CLI and preflight already refuse effective UID 0 for every sandbox and store command. Root with an anchor and a development store selects "not enforced".
- **The anchor parser's open findings** (pre-existing, unchanged; see the [approval reader page](feat-b7-image-approval-reader.md#pre-existing-anchor-findings-unresolved-not-changed-here)) carry over: duplicate keys keep the last value, and the account pattern accepts a trailing newline. The rule's account comparison inherits both. They stay open for scoped triage before U3/U4 release acceptance.

## Verification (development only, 2026-11-23)

- **Failing first:**
  - on `main` `859f458`, the new test file fails at collection, because the module does not exist;
  - against a scratch copy implementing the plan's pre-D1-D3 wording (no anchor always means development, only the effective user ID counts, an unknown account reads as "not the account"), 56 tests fail. Every D1, D2 and D3 test fails, as does the conftest isolation test.
- **Independent review:** no P0 or P1, and every mutation of the rule's branches was killed, including dropping the real-UID comparison, `or` changed to `and`, and dropping installation or marker detection. Its P3 findings were fixed: unnamed exceptions now map to named refusals, the anchor `OSError` branch is pinned by a test, and the wording here and in the plan is corrected.
- The pure matrix covers all 64 combinations of anchor, installation, effective user, real user, known account and production, against an independently written expectation.
- Nothing ran as root. Nothing read `/etc` or used Docker.
