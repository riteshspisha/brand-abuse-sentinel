"""Small filesystem helpers for private, crash-durable storage."""

import contextlib
import os
from pathlib import Path


def ensure_private_dir(path: Path) -> None:
    """Create `path` and any missing parents with mode 0700. pathlib's mkdir
    applies `mode` only to the final component, so parents are made one by one."""
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        with contextlib.suppress(FileExistsError):
            d.mkdir(mode=0o700)


def fsync_dir(path: Path) -> None:
    """Persist directory entries (new or renamed files) across a crash."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
