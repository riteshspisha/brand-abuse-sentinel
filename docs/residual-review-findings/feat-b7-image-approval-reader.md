# Residual findings: image approval record reader (B7 U14, first step, 2026-11-22)

These are the accepted limits of `src/brandsentinel/store/approval.py`, after one focused security review. The review covered filesystem trust, parsing ambiguity, TOCTOU limits and failure handling.

It is the first step of U14 in the [B7 plan](../plans/2026-11-10-002-chore-b7-production-promotion-plan.md) (option C, OB8). **Nothing calls the reader yet:**
- no preflight or runner check;
- no image selection;
- no Docker or Compose use;
- no writer.

Nothing in this step enforces image identity. The record `/etc/brandsentinel/image-approval.yaml` does not exist on any host.

## What the reader guarantees

- **Location.**
  - The path is a module constant beside the production anchor. The environment never selects it; tests replace module attributes.
  - The path must be absolute, normalized and under the chain root. Otherwise it is refused.
- **Directory chain.** Every directory from `/` down to `/etc/brandsentinel` must be:
  - root-owned;
  - not writable by group or others;
  - traversable by others.

  It is opened without following symlinks, relative to the descriptor of the directory above it, and checked on that descriptor. A directory renamed or replaced by a symlink after its parent was checked cannot redirect the walk. The anchor's reader checks the chain by path, then opens the full path.
- **File.** The record must be:
  - opened without following symlinks, non-blocking and without a controlling terminal;
  - a regular file;
  - root-owned;
  - not writable by group or others, and readable by others (the service account reads it);
  - one link only;
  - at most 4096 bytes, refused on its size before any read, with the read itself also capped.

  These are checked on the open descriptor. A rename over the record after it is opened does not change what is parsed.
- **Content.** The record is exactly `image_id: sha256:<64 lowercase hex>\ncomplete: true\n`, matched on raw bytes. There is no YAML parser, so these are all refused:
  - duplicate, missing, unexpected or reordered keys;
  - comments and quoting;
  - YAML document markers, flow mappings, anchors and tags;
  - `True` or `yes`;
  - CRLF, a byte-order mark, stray spaces and blank lines;
  - non-ASCII digits;
  - a missing final newline, so a write cut short is refused.

  The form is still valid YAML, so a YAML reader agrees on what it says.
- **Outcomes.**
  - A missing record, or a missing `/etc/brandsentinel` or `/etc`, returns `None`. What that means is the caller's decision: when enforcing, U14's preflight must disable sandbox stages.
  - Anything else raises `ApprovalRefused` with one stable check: `approval_unsafe` (location, type, ownership, mode, links, size, read errors) or `approval_malformed` (content).
  - The error carries no path or content, and the OS error is not chained.

## Residual limits

- **Root is trusted.** The record proves only that root wrote it. It is not signed, and it is not bound to the G5a report or the owner's approval; G5b's procedure provides that binding. Root, or anyone who can write the chain, can approve any ID.
- **One read is one answer.** The reader returns what the record says at that moment. Preflight and the runner must resolve once per run and pass the ID on, as U14's contract requires. A later change of the record is not seen mid-run ("No mid-run revocation" in the plan).
- **No lock.** G5b and G5r serialize record changes with U13's image lock. This reader takes no lock. A writer that renames a complete file into place is atomic for this reader; a writer that edits in place could be read part-way and refused as malformed, which fails closed.
- **Group ownership and ACLs.** The file's group is not checked; group write is refused instead. With POSIX ACLs, the mode's group bits carry the ACL mask, so a named entry granting write shows as group write and is refused.
- **A missing record is not an error here.** A host with the anchor but no record yields `None`. Enforcement must treat that as a failure (U14's next steps). The tests cover the reader only.
- **Linux descriptors.** The walk uses `O_PATH` where the platform has it. Without it, a directory that others can traverse but not read is refused (EACCES), which fails closed.
- **`close` errors.** A failure of `close` on a descriptor would surface as an `OSError` carrying no path. It is not wrapped.

## Pre-existing finding (not changed here)

**The anchor's parser keeps the last of duplicate keys.** `identity._parse_anchor` reads the anchor with `yaml.safe_load`. PyYAML keeps the last value of a duplicate key, and the key-order check still passes. So an anchor with two `account:` lines is read with the second one.
- **Severity:** low. The anchor is root-owned and written by the owner's procedure.
- **Status:** not changed in this step, and recorded for an owner decision. The approval record does not inherit the problem, because it is matched on its fixed form.

## Verification (development only, 2026-11-22)

- `tests/unit/test_image_approval.py` failed first at collection on `main` `5422511`, because the module did not exist.
- A test fails when each guard is removed: the link count, the "others may read" bit, `O_NOFOLLOW` on the file and on the directories, the size check, directory modes, the exact match, and missing-versus-unsafe.
- Nothing ran as root. Nothing read `/etc` or used Docker.
