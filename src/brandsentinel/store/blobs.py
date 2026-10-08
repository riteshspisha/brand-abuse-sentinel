"""Content-addressed artifact store with quotas.

Artifacts are inert: stored under their sha256 with no extension and mode 0600,
never executed or opened by the host. Every write is checked against quotas per
artifact, per case (count and bytes), per registrable domain, and for the whole
store. Near the store-wide cap a reserved share stays available for privileged
(strong-strength or manual) cases. A rejected write raises QuotaExceeded and is
recorded on the case as an `artifact_quota_exceeded` fact. A file is placed in
the store only inside the committing transaction and removed if the commit
fails; `sweep_orphans` cleans up after a crash at that point.
"""

import hashlib
import os
import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from brandsentinel.config import ArtifactQuotas
from brandsentinel.store.db import transaction
from brandsentinel.store.fsutil import ensure_private_dir, fsync_dir
from brandsentinel.store.records import add_fact

COLLECTOR_VERSION = "blobstore/1"


class QuotaExceeded(Exception):
    def __init__(self, quota: str, limit: int, attempted: int) -> None:
        super().__init__(f"artifact quota exceeded: {quota} (limit {limit}, attempted {attempted})")
        self.quota = quota
        self.limit = limit
        self.attempted = attempted


class BlobStore:
    def __init__(
        self,
        root: Path,
        conn: sqlite3.Connection,
        quotas: ArtifactQuotas,
        *,
        max_fact_chars: int = 4096,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.root = root
        self._conn = conn
        self._q = quotas
        self._max_fact_chars = max_fact_chars
        self._clock = clock

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("not a sha256 hex digest")
        return self.root / "sha256" / sha256[:2] / sha256

    def put(
        self,
        data: bytes | Iterable[bytes],
        *,
        case_id: int,
        registrable_domain: str,
        content_type: str | None = None,
        role: str | None = None,
        privileged: bool = False,
    ) -> str:
        """Store bytes (or a stream of chunks) for a case. Returns the sha256.

        `registrable_domain` is required so every artifact counts toward a domain
        quota; for hosts without one, callers pass the host or IP literal."""
        if not registrable_domain:
            raise ValueError("registrable_domain is required")
        chunks = [data] if isinstance(data, bytes) else data
        try:
            return self._put(chunks, case_id, registrable_domain, content_type, role, privileged)
        except QuotaExceeded as e:
            add_fact(
                self._conn,
                case_id,
                source="blobstore",
                name="artifact_quota_exceeded",
                value={"quota": e.quota, "limit": e.limit, "attempted": e.attempted, "role": role},
                collector_version=COLLECTOR_VERSION,
                max_chars=self._max_fact_chars,
                now=self._clock(),
            )
            raise

    def _put(self, chunks, case_id, domain, content_type, role, privileged) -> str:
        tmp_dir = self.root / "tmp"
        ensure_private_dir(tmp_dir)
        fd, tmp_name = tempfile.mkstemp(dir=tmp_dir)  # created with mode 0600
        tmp = Path(tmp_name)
        try:
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "wb") as f:
                for chunk in chunks:
                    size += len(chunk)
                    if size > self._q.max_blob_bytes:
                        raise QuotaExceeded("blob_bytes", self._q.max_blob_bytes, size)
                    digest.update(chunk)
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
            sha = digest.hexdigest()
            self._commit(tmp, sha, size, case_id, domain, content_type, role, privileged)
            return sha
        finally:
            tmp.unlink(missing_ok=True)

    def _commit(self, tmp, sha, size, case_id, domain, content_type, role, privileged) -> None:
        final = self.path_for(sha)
        placed = False  # whether this call moved the file into the store
        try:
            with transaction(self._conn):
                now = self._clock()
                c = self._conn
                if c.execute(
                    "SELECT 1 FROM case_artifacts WHERE case_id = ? AND sha256 = ?",
                    (case_id, sha),
                ).fetchone():
                    return
                case_n, case_bytes = c.execute(
                    "SELECT COUNT(*), COALESCE(SUM(a.size), 0) FROM case_artifacts ca"
                    " JOIN artifacts a USING (sha256) WHERE ca.case_id = ?",
                    (case_id,),
                ).fetchone()
                if case_n + 1 > self._q.max_case_count:
                    raise QuotaExceeded("case_count", self._q.max_case_count, case_n + 1)
                if case_bytes + size > self._q.max_case_bytes:
                    raise QuotaExceeded("case_bytes", self._q.max_case_bytes, case_bytes + size)
                in_domain = c.execute(
                    "SELECT 1 FROM case_artifacts WHERE registrable_domain = ? AND sha256 = ?",
                    (domain, sha),
                ).fetchone()
                if not in_domain:
                    (domain_bytes,) = c.execute(
                        "SELECT COALESCE(SUM(a.size), 0) FROM (SELECT DISTINCT sha256"
                        " FROM case_artifacts WHERE registrable_domain = ?)"
                        " JOIN artifacts a USING (sha256)",
                        (domain,),
                    ).fetchone()
                    if domain_bytes + size > self._q.max_domain_bytes:
                        raise QuotaExceeded(
                            "domain_bytes", self._q.max_domain_bytes, domain_bytes + size
                        )
                is_new = (
                    c.execute("SELECT 1 FROM artifacts WHERE sha256 = ?", (sha,)).fetchone() is None
                )
                if is_new:
                    (store_bytes,) = c.execute(
                        "SELECT COALESCE(SUM(size), 0) FROM artifacts"
                    ).fetchone()
                    limit = self._q.max_store_bytes
                    if not privileged:
                        limit = int(limit * (1 - self._q.reserve_fraction))
                    if store_bytes + size > limit:
                        raise QuotaExceeded("store_bytes", limit, store_bytes + size)
                    c.execute(
                        "INSERT INTO artifacts (sha256, size, content_type, created_at)"
                        " VALUES (?, ?, ?, ?)",
                        (sha, size, content_type, now),
                    )
                c.execute(
                    "INSERT INTO case_artifacts"
                    " (case_id, sha256, registrable_domain, role, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (case_id, sha, domain, role, now),
                )
                # Place the file last, just before COMMIT, so a failed check or
                # insert never leaves an untracked file behind.
                if not final.exists():
                    ensure_private_dir(final.parent)
                    os.replace(tmp, final)
                    placed = True
                    os.chmod(final, 0o600)
                    fsync_dir(final.parent)
        except BaseException:
            if placed:
                final.unlink(missing_ok=True)
            raise

    def sweep_orphans(self, min_age_seconds: float = 3600.0) -> int:
        """Remove stale temp files and stored files with no artifacts row (left by
        a crash between placing a file and committing). Files younger than
        `min_age_seconds` are kept so an in-flight write is never disturbed."""
        cutoff = self._clock() - min_age_seconds
        removed = 0
        tmp_dir = self.root / "tmp"
        if tmp_dir.exists():
            for p in tmp_dir.iterdir():
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink(missing_ok=True)
                    removed += 1
        store_dir = self.root / "sha256"
        if store_dir.exists():
            for p in store_dir.glob("*/*"):
                if not p.is_file() or p.stat().st_mtime >= cutoff:
                    continue
                known = self._conn.execute(
                    "SELECT 1 FROM artifacts WHERE sha256 = ?", (p.name,)
                ).fetchone()
                if not known:
                    p.unlink(missing_ok=True)
                    removed += 1
        return removed

    def read(self, sha256: str, max_bytes: int | None = None) -> bytes:
        limit = self._q.max_blob_bytes if max_bytes is None else max_bytes
        with self.path_for(sha256).open("rb") as f:
            return f.read(limit)

    def stats(self) -> tuple[int, int]:
        n, total = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM artifacts"
        ).fetchone()
        return n, total
