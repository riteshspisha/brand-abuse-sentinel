"""Bounded raw-log storage and the free-disk guard.

Segments are removed oldest first: by age (last write) for every log, and for the
optional firehose also until the log fits its byte cap. The segment a writer has
open is never removed. Discovery event rows in SQLite are pruned on the same age
as the discovery log; candidates, cases and per-source summaries are kept.
"""

import logging
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from brandsentinel.store.db import transaction
from brandsentinel.store.rawlog import RawLog

log = logging.getLogger(__name__)

DAY = 86400.0


@dataclass(frozen=True)
class PruneResult:
    removed: int
    removed_bytes: int
    remaining_bytes: int


def prune_rawlog(
    rawlog: RawLog, *, now: float, max_age_days: float, max_bytes: int | None = None
) -> PruneResult:
    keep = rawlog.current_segment
    entries = []
    for path in rawlog.segments():
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        entries.append((st.st_mtime, path, st.st_size))
    entries.sort()
    total = sum(size for _, _, size in entries)
    removed = removed_bytes = 0
    cutoff = now - max_age_days * DAY
    for mtime, path, size in entries:
        too_old = mtime < cutoff
        too_big = max_bytes is not None and total > max_bytes
        if not (too_old or too_big) or path == keep:
            continue
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            log.error(
                "cannot remove raw segment", extra={"fields": {"path": str(path), "error": str(e)}}
            )
            continue
        total -= size
        removed += 1
        removed_bytes += size
    return PruneResult(removed, removed_bytes, total)


def prune_discovery_events(conn: sqlite3.Connection, *, now: float, max_age_days: float) -> int:
    with transaction(conn):
        cur = conn.execute(
            "DELETE FROM discovery_events WHERE observed_at < ?", (now - max_age_days * DAY,)
        )
        return cur.rowcount


def free_bytes(path: Path) -> int:
    """Free space on the filesystem holding `path` (or its nearest existing parent)."""
    while not path.exists() and path != path.parent:
        path = path.parent
    return shutil.disk_usage(path).free
