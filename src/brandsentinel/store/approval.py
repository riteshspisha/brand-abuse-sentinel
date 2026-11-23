"""The image approval record: which sandbox image ID root has approved (B7 U14, KTD12).

Plan: docs/plans/2026-11-10-002-chore-b7-production-promotion-plan.md (U14, option C).

The record lives beside the production anchor and names exactly one image ID. Root
writes it at G5b, only for an ID with a passing load-profile report and the owner's
recorded approval. It is believed only for its ownership and location, never its
content alone. This module only reads it; nothing here writes, selects an image or
talks to Docker. The callers (preflight, the runner, U13's scripts) decide what a
missing record means.

Format: exactly two lines, each ending in a newline, in this order:

    image_id: sha256:<64 lowercase hex digits>
    complete: true

The form is fixed rather than parsed as YAML, so duplicate keys, comments, quoting,
aliases, tags and alternative spellings of `true` cannot be accepted silently. It is
still a subset of YAML, so a YAML reader agrees on what it says. The sentinel comes
last, so a write cut short is refused.

Tests replace the module attributes `APPROVAL_PATH`, `CHAIN_ROOT` and `TRUSTED_UID`;
the environment never selects them.
"""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

APPROVAL_PATH = Path("/etc/brandsentinel/image-approval.yaml")
CHAIN_ROOT = Path("/")
TRUSTED_UID = 0
MAX_APPROVAL_BYTES = 4096

# Bytes, not text: no decoding step, and `[0-9a-f]` cannot match non-ASCII digits.
_RECORD = re.compile(rb"image_id: (sha256:[0-9a-f]{64})\ncomplete: true\n")
_O_PATH = getattr(os, "O_PATH", 0)
_DIR_FLAGS = _O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


class ApprovalRefused(Exception):
    """The record exists but may not be believed. `check` is a stable name; no path or
    content is kept, and the underlying OS error is not chained."""

    UNSAFE = "approval_unsafe"  # location, type, ownership, mode, links, size or I/O
    MALFORMED = "approval_malformed"  # the content is not exactly the fixed form

    def __init__(self, check: str) -> None:
        super().__init__(check)
        self.check = check


@dataclass(frozen=True)
class ImageApproval:
    image_id: str  # "sha256:" + 64 lowercase hex: the image's manifest digest (U15, DV1)


def _unsafe() -> ApprovalRefused:
    return ApprovalRefused(ApprovalRefused.UNSAFE)


def _close(fd: int) -> None:
    """Close `fd` once. Linux releases a descriptor even when close reports an error, so
    it is never retried; the error is refused as unsafe instead of escaping unnamed."""
    try:
        os.close(fd)
    except OSError:
        raise _unsafe() from None


def _safe_directory(st: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == TRUSTED_UID
        and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and bool(st.st_mode & stat.S_IXOTH)
    )


def _components() -> tuple[str, list[str], str] | None:
    """(chain root, directory names below it, record file name), or None if the record
    path is not absolute, not normalized, or not under the chain root."""
    path = os.fspath(APPROVAL_PATH)
    root = os.fspath(CHAIN_ROOT)
    if not path.startswith("/") or os.path.normpath(path) != path or "//" in path:
        return None
    try:
        rel = Path(path).relative_to(root)
    except ValueError:
        return None
    parts = list(rel.parts)
    if not parts or any(p in ("", ".", "..") for p in parts):
        return None
    return root, parts[:-1], parts[-1]


def load_approval() -> ImageApproval | None:
    """The approved image ID, or None when the record (or its directory) is missing.

    Raises ApprovalRefused when it exists but is unsafe or malformed. Every directory
    from the chain root down is opened relative to the descriptor of the one above it,
    without following symlinks, and checked on that descriptor; the record is opened
    the same way and checked after opening, so no path is resolved twice."""
    parts = _components()
    if parts is None:
        raise _unsafe()
    root, directories, name = parts
    try:
        fd = _open_directory(root, None)
    except FileNotFoundError:
        raise _unsafe() from None  # the chain root itself must exist
    if fd is None:
        raise _unsafe()
    try:
        for directory in directories:
            try:
                next_fd = _open_directory(directory, fd)
            except FileNotFoundError:
                return None  # every existing ancestor passed: no record on this host
            if next_fd is None:
                raise _unsafe()
            # Hand over before closing: if the close fails, `fd` already names the
            # successor, so the `finally` closes that one and nothing is closed twice.
            previous, fd = fd, next_fd
            _close(previous)
        data = _read_record(name, fd)
    finally:
        _close(fd)
    if data is None:
        return None
    match = _RECORD.fullmatch(data)
    if match is None:
        raise ApprovalRefused(ApprovalRefused.MALFORMED)
    return ImageApproval(image_id=match.group(1).decode("ascii"))


def _open_directory(name: str, dir_fd: int | None) -> int | None:
    """A descriptor for a safe directory, None if it is unsafe; FileNotFoundError if it
    does not exist. Any other OS error is unsafe."""
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError:  # ENOTDIR (a file or symlink), ELOOP, EACCES, ...
        return None
    try:
        if _safe_directory(os.fstat(fd)):
            return fd
    except OSError:
        pass
    _close(fd)
    return None


def _read_record(name: str, dir_fd: int) -> bytes | None:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError:  # ELOOP for a symlink, EACCES, ...
        raise _unsafe() from None
    try:
        st = os.fstat(fd)
        if not (
            stat.S_ISREG(st.st_mode)
            and st.st_uid == TRUSTED_UID
            and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and st.st_mode & stat.S_IROTH
            and st.st_nlink == 1
            and st.st_size <= MAX_APPROVAL_BYTES
        ):
            raise _unsafe()
        data = _read_capped(fd, MAX_APPROVAL_BYTES)
    except OSError:
        raise _unsafe() from None
    finally:
        _close(fd)
    if data is None:
        raise _unsafe()
    return data


def _read_capped(fd: int, cap: int) -> bytes | None:
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 8192)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > cap:
            return None
        chunks.append(chunk)
