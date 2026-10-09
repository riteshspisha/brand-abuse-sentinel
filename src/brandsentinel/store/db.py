"""SQLite connection, transactions, and numbered migrations."""

import contextlib
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from brandsentinel.store.fsutil import ensure_private_dir

_MIGRATIONS = "brandsentinel.store.migrations"


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE so concurrent writers serialize instead of failing on upgrade.

    Nested use joins the enclosing transaction, so store helpers compose into one
    atomic write; an exception anywhere rolls back the whole outer transaction.
    The connection is in autocommit mode, so only an explicit outer BEGIN can
    leave it in a transaction."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        # SQLite may already have rolled back (e.g. on SQLITE_FULL); a second
        # ROLLBACK would raise and mask the original error.
        if conn.in_transaction:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
        raise


def _migration_files() -> list[tuple[int, str]]:
    found = []
    for entry in resources.files(_MIGRATIONS).iterdir():
        name = entry.name
        if name.endswith(".sql") and name[:4].isdigit():
            found.append((int(name[:4]), entry.read_text(encoding="utf-8")))
    return sorted(found)


class SchemaTooNew(Exception):
    """The database was migrated by a newer BrandSentinel than this one."""


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Apply pending numbered migrations; returns the versions applied by this call."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)"
    )
    files = _migration_files()
    known = files[-1][0] if files else 0
    current = schema_version(conn)
    if current > known:
        raise SchemaTooNew(f"database schema v{current} is newer than this code (v{known})")
    applied_now = []
    for version, sql in files:
        done = conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
        ).fetchone()
        if done:
            continue
        # The INSERT runs first, so a concurrent process that already applied this
        # version makes the script fail before any DDL, and the rollback is clean.
        # Only an int parsed from a packaged filename and a float clock are interpolated.
        record = f"INSERT INTO schema_migrations VALUES ({int(version)}, {time.time()});"  # noqa: S608
        script = f"BEGIN IMMEDIATE;\n{record}\n{sql}\nCOMMIT;"
        try:
            conn.executescript(script)
        except sqlite3.Error:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            if conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
            ).fetchone():
                continue
            raise
        applied_now.append(version)
    return applied_now


def schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return row[0] or 0


def connect(path: Path) -> sqlite3.Connection:
    ensure_private_dir(path.parent)
    # Create the file 0600 up front; SQLite gives the -wal and -shm files the
    # same permissions as the database.
    os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
    # Autocommit mode: every transaction is explicit via transaction().
    conn = sqlite3.connect(path, isolation_level=None, timeout=30.0)
    try:
        conn.row_factory = sqlite3.Row
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if mode != "wal":
            raise sqlite3.OperationalError(f"could not enable WAL mode (got {mode!r})")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn
