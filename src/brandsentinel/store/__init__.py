"""Persistent state: SQLite store, job queue, raw logs and artifacts."""

import sqlite3
from dataclasses import dataclass, field

from brandsentinel.config import Config
from brandsentinel.store.blobs import BlobStore
from brandsentinel.store.db import connect
from brandsentinel.store.fsutil import ensure_private_dir
from brandsentinel.store.jobs import JobQueue
from brandsentinel.store.rawlog import RawLog, valid_source

FIREHOSE_SOURCE = "certstream-firehose"


@dataclass
class Store:
    config: Config
    conn: sqlite3.Connection
    jobs: JobQueue = field(init=False)
    blobs: BlobStore = field(init=False)
    _rawlogs: dict[str, RawLog] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.jobs = JobQueue(self.conn, default_max_attempts=self.config.jobs.max_attempts)
        self.blobs = BlobStore(
            self.config.artifacts_dir,
            self.conn,
            self.config.artifacts,
            max_fact_chars=self.config.text.max_fact_chars,
        )

    def rawlog(self, source: str) -> RawLog:
        """The shared writer for `source`; closed by Store.close()."""
        if source not in self._rawlogs:
            rotation = (
                "hour" if source == FIREHOSE_SOURCE else self.config.rawlog.discovery_rotation
            )
            self._rawlogs[source] = RawLog(
                self.config.raw_dir,
                source,
                rotation=rotation,
                flush_every=self.config.rawlog.flush_every_records,
            )
        return self._rawlogs[source]

    def raw_sources(self) -> list[str]:
        root = self.config.raw_dir
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir() if p.is_dir() and valid_source(p.name))

    def raw_bytes(self, source: str) -> int:
        return RawLog(self.config.raw_dir, source).total_bytes()

    def close(self) -> None:
        try:
            for log in self._rawlogs.values():
                log.close()
        finally:
            self._rawlogs.clear()
            self.conn.close()


def open_store(config: Config) -> Store:
    ensure_private_dir(config.data_dir)
    config.data_dir.chmod(0o700)
    store = Store(config=config, conn=connect(config.db_path))
    store.blobs.sweep_orphans()
    return store
