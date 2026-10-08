import stat
import threading

import pytest

from brandsentinel.store import open_store
from brandsentinel.store.db import SchemaTooNew, connect, migrate, schema_version


def test_restart_applies_no_duplicate_migrations(config):
    first = open_store(config)
    assert schema_version(first.conn) == 1
    first.jobs.enqueue("fetch", {"keep": True})
    first.close()

    second = open_store(config)
    assert migrate(second.conn) == []
    assert second.conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1
    assert second.conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    second.close()


def test_concurrent_first_start_migrates_exactly_once(tmp_path):
    db = tmp_path / "fresh.db"
    barrier = threading.Barrier(4)
    counts, errors = [], []

    def worker():
        barrier.wait()
        try:
            conn = connect(db)  # SQLite connections stay on their own thread
            counts.append(conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0])
            conn.close()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert counts == [1, 1, 1, 1]


def test_newer_schema_is_refused(config):
    store = open_store(config)
    store.conn.execute("INSERT INTO schema_migrations VALUES (999, 0)")
    store.close()
    with pytest.raises(SchemaTooNew):
        connect(config.db_path)


def test_wal_mode_and_private_files(config):
    store = open_store(config)
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert stat.S_IMODE(config.data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(config.db_path.stat().st_mode) == 0o600
    store.close()


def test_existing_data_dir_is_tightened(config):
    config.data_dir.mkdir(parents=True, mode=0o755)
    config.data_dir.chmod(0o755)
    open_store(config).close()
    assert stat.S_IMODE(config.data_dir.stat().st_mode) == 0o700


def test_failed_transaction_does_not_wedge_connection(store):
    from brandsentinel.store.db import transaction

    with pytest.raises(RuntimeError), transaction(store.conn):
        store.conn.execute("INSERT INTO health_samples (sampled_at, data_json) VALUES (1, '{}')")
        raise RuntimeError("boom")
    assert not store.conn.in_transaction
    assert store.conn.execute("SELECT COUNT(*) FROM health_samples").fetchone()[0] == 0
    with transaction(store.conn):  # connection still usable
        store.conn.execute("INSERT INTO health_samples (sampled_at, data_json) VALUES (2, '{}')")
