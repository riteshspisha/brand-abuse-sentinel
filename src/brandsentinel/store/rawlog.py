"""Append-only, gzip-compressed JSON-lines logs, segmented by time.

Each process opens fresh segment files and never appends to an existing one, so
a segment left unterminated by a crash is never extended. `flush()` performs a
zlib sync flush plus fsync: every record written before it stays readable even
if the process dies before closing the segment. `read_segment` tolerates such a
truncated tail.

If a write or flush fails (for example, disk full), the compressor state no
longer matches the file, so the segment is abandoned and the next write opens a
new one. Records not yet flushed when the error occurred are lost; durable
writes report the failure to the caller.
"""

import contextlib
import gzip
import json
import os
import re
import time
import zlib
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from brandsentinel.store.fsutil import ensure_private_dir, fsync_dir

_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_READ_CHUNK = 64 * 1024


def valid_source(name: str) -> bool:
    return bool(_SOURCE_RE.match(name))


class RawLog:
    def __init__(
        self,
        root: Path,
        source: str,
        *,
        rotation: Literal["hour", "day"] = "day",
        flush_every: int = 100,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not _SOURCE_RE.match(source):
            raise ValueError(f"invalid raw log source name: {source!r}")
        self.dir = root / source
        self.source = source
        self._rotation = rotation
        self._flush_every = flush_every
        self._clock = clock
        self._period: str | None = None
        self._raw = None
        self._gz: gzip.GzipFile | None = None
        self._unflushed = 0

    def _period_of(self, ts: float) -> str:
        fmt = "%Y%m%dT%H" if self._rotation == "hour" else "%Y%m%d"
        return datetime.fromtimestamp(ts, UTC).strftime(fmt)

    def _open_segment(self, ts: float) -> None:
        self.close()
        ensure_private_dir(self.dir)
        period = self._period_of(ts)
        path = self.dir / f"{period}-{time.time_ns()}-{os.getpid()}.jsonl.gz"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._raw = os.fdopen(fd, "wb")
        self._gz = gzip.GzipFile(fileobj=self._raw, mode="wb", mtime=0)
        self._period = period
        fsync_dir(self.dir)  # the new file itself must survive a crash

    def _abandon_segment(self) -> None:
        """Drop a segment whose compressor state may no longer match the file.
        No gzip trailer is written; readers stop at the last decodable record."""
        raw = self._raw
        self._gz = self._raw = None
        self._period = None
        self._unflushed = 0
        if raw is not None:
            with contextlib.suppress(OSError):
                raw.close()

    def write(self, record: dict, *, durable: bool = False) -> None:
        """Append one record. With durable=True it is on disk before this returns."""
        now = self._clock()
        line = json.dumps(
            {"logged_at": datetime.fromtimestamp(now, UTC).isoformat(), "record": record},
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        if self._gz is None or self._period_of(now) != self._period:
            self._open_segment(now)
        try:
            self._gz.write(line.encode("ascii") + b"\n")
            self._unflushed += 1
            if durable or self._unflushed >= self._flush_every:
                self._flush_segment()
        except BaseException:
            self._abandon_segment()
            raise

    def _flush_segment(self) -> None:
        self._gz.flush()  # zlib Z_SYNC_FLUSH: data so far is decodable
        self._raw.flush()
        os.fsync(self._raw.fileno())
        self._unflushed = 0

    def flush(self) -> None:
        if self._gz is None:
            return
        try:
            self._flush_segment()
        except BaseException:
            self._abandon_segment()
            raise

    def close(self) -> None:
        if self._gz is None:
            return
        try:
            self._gz.close()  # writes the gzip trailer
            self._raw.flush()
            os.fsync(self._raw.fileno())
            self._raw.close()
        except BaseException:
            self._abandon_segment()
            raise
        self._gz = self._raw = None
        self._period = None
        self._unflushed = 0

    def segments(self) -> list[Path]:
        if not self.dir.exists():
            return []
        return sorted(self.dir.glob("*.jsonl.gz"))

    def total_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.segments())

    def __enter__(self) -> "RawLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _decompress_until_error(decomp, chunk: bytes) -> tuple[bytes, bool]:
    """Decompress `chunk`; on corruption, recover the output preceding the bad byte.
    Returns (output, corrupt)."""
    backup = decomp.copy()
    try:
        return decomp.decompress(chunk), False
    except zlib.error:
        pass
    out = b""
    for i in range(len(chunk)):
        try:
            out += backup.decompress(chunk[i : i + 1])
        except zlib.error:
            break
    return out, True


def read_segment(path: Path) -> Iterator[dict]:
    """Yield records from a segment, stopping cleanly at a truncated or corrupt tail."""
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    pending = b""
    corrupt = False
    with path.open("rb") as f:
        while not corrupt and (chunk := f.read(_READ_CHUNK)):
            while chunk and not corrupt:
                data, corrupt = _decompress_until_error(decomp, chunk)
                pending += data
                if not corrupt and decomp.eof:  # concatenated gzip members
                    chunk = decomp.unused_data
                    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    chunk = b""
            *lines, pending = pending.split(b"\n")
            for line in lines:
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:  # undetected corruption: stop at the damage
                    return
