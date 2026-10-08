import hashlib
import os
import sqlite3
import stat

import pytest

from brandsentinel.store.records import create_case, upsert_candidate

DOMAIN = "sadhguru-donate.test"


@pytest.fixture
def case_id(store):
    cand, _ = upsert_candidate(store.conn, DOMAIN, match_strength="strong")
    return create_case(store.conn, cand)


def test_same_bytes_twice_yields_one_blob_and_one_row(store, case_id):
    data = b"<html>fake donation page</html>"
    a = store.blobs.put(data, case_id=case_id, registrable_domain=DOMAIN)
    b = store.blobs.put(data, case_id=case_id, registrable_domain=DOMAIN)
    assert a == b == hashlib.sha256(data).hexdigest()
    assert store.blobs.stats() == (1, len(data))
    assert store.conn.execute("SELECT COUNT(*) FROM case_artifacts").fetchone()[0] == 1
    assert store.blobs.read(a) == data


def test_blob_is_private_with_no_extension(store, case_id):
    sha = store.blobs.put(
        b"x", case_id=case_id, registrable_domain=DOMAIN, content_type="text/html"
    )
    path = store.blobs.path_for(sha)
    assert path.name == sha and path.suffix == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for d in (path.parent, path.parent.parent, store.blobs.root):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_streamed_chunks_hash_like_bytes(store, case_id):
    sha = store.blobs.put(iter([b"ab", b"cd"]), case_id=case_id, registrable_domain=DOMAIN)
    assert sha == hashlib.sha256(b"abcd").hexdigest()


def test_registrable_domain_is_required(store, case_id):
    for missing in (None, ""):
        with pytest.raises(ValueError):
            store.blobs.put(b"x", case_id=case_id, registrable_domain=missing)


def test_shared_blob_counts_once_toward_store(store, case_id):
    cand, _ = upsert_candidate(store.conn, "other.test", match_strength="weak")
    other = create_case(store.conn, cand)
    store.blobs.put(b"same", case_id=case_id, registrable_domain="a.test")
    store.blobs.put(b"same", case_id=other, registrable_domain="b.test")
    assert store.blobs.stats() == (1, 4)
    assert store.conn.execute("SELECT COUNT(*) FROM case_artifacts").fetchone()[0] == 2


def test_no_temp_files_left_behind(store, case_id):
    store.blobs.put(b"data", case_id=case_id, registrable_domain=DOMAIN)
    assert list((store.blobs.root / "tmp").iterdir()) == []


def test_failed_commit_leaves_no_stored_file(store):
    # A missing case violates the foreign key, so the transaction rolls back.
    with pytest.raises(sqlite3.IntegrityError):
        store.blobs.put(b"orphan?", case_id=9999, registrable_domain=DOMAIN)
    sha = hashlib.sha256(b"orphan?").hexdigest()
    assert not store.blobs.path_for(sha).exists()
    assert store.blobs.stats() == (0, 0)
    assert list((store.blobs.root / "tmp").iterdir()) == []


def test_sweep_removes_old_orphans_only(store, case_id, clock):
    store.blobs._clock = clock
    kept = store.blobs.put(b"tracked", case_id=case_id, registrable_domain=DOMAIN)
    orphan = store.blobs.path_for("a" * 64)
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"crash leftover")
    stale_tmp = store.blobs.root / "tmp" / "tmpabc"
    stale_tmp.write_bytes(b"partial")
    fresh_orphan = store.blobs.path_for("b" * 64)
    fresh_orphan.parent.mkdir(parents=True, exist_ok=True)
    fresh_orphan.write_bytes(b"in flight")
    old = clock() - 7200
    for p in (orphan, stale_tmp, store.blobs.path_for(kept)):
        os.utime(p, (old, old))
    os.utime(fresh_orphan, (clock(), clock()))

    assert store.blobs.sweep_orphans(min_age_seconds=3600) == 2
    assert not orphan.exists() and not stale_tmp.exists()
    assert fresh_orphan.exists()
    assert store.blobs.path_for(kept).exists()


@pytest.mark.parametrize("bad", ["../../etc/passwd", "ABC", "a" * 63])
def test_path_for_rejects_non_digest(store, bad):
    with pytest.raises(ValueError):
        store.blobs.path_for(bad)
