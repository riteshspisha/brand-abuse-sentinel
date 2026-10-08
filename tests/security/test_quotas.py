import json

import pytest

from brandsentinel.config import ArtifactQuotas, Config
from brandsentinel.store import open_store
from brandsentinel.store.blobs import QuotaExceeded
from brandsentinel.store.records import create_case, upsert_candidate

pytestmark = pytest.mark.security


def _store(tmp_path, **quotas):
    defaults = dict(
        max_blob_bytes=100,
        max_case_count=3,
        max_case_bytes=150,
        max_domain_bytes=250,
        max_store_bytes=1000,
        reserve_fraction=0.2,
    )
    defaults.update(quotas)
    return open_store(Config(data_dir=tmp_path / "data", artifacts=ArtifactQuotas(**defaults)))


def _case(store, name, strength="strong"):
    cand, _ = upsert_candidate(store.conn, name, match_strength=strength)
    return create_case(store.conn, cand)


def _quota_facts(store, case_id):
    rows = store.conn.execute(
        "SELECT value_json FROM facts WHERE case_id = ? AND name = 'artifact_quota_exceeded'",
        (case_id,),
    ).fetchall()
    return [json.loads(r[0])["quota"] for r in rows]


def _assert_rejected(store, case, quota, data, domain):
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(data, case_id=case, registrable_domain=domain)
    assert e.value.quota == quota
    assert _quota_facts(store, case)[-1] == quota


def _blob(i, size):
    return f"{i:04d}".encode() + b"x" * (size - 4)


def test_oversized_blob_rejected_and_recorded(tmp_path):
    store = _store(tmp_path)
    case = _case(store, "a.test")
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(_blob(0, 101), case_id=case, registrable_domain="a.test")
    assert e.value.quota == "blob_bytes"
    assert _quota_facts(store, case) == ["blob_bytes"]
    assert store.blobs.stats() == (0, 0)
    assert list((store.blobs.root / "tmp").iterdir()) == []


def test_streamed_blob_stops_at_cap(tmp_path):
    store = _store(tmp_path)
    case = _case(store, "a.test")

    def endless():
        while True:
            yield b"y" * 64

    with pytest.raises(QuotaExceeded):
        store.blobs.put(endless(), case_id=case, registrable_domain="a.test")


def test_case_count_cap(tmp_path):
    store = _store(tmp_path, max_case_bytes=10_000, max_domain_bytes=10_000)
    case = _case(store, "a.test")
    for i in range(3):
        store.blobs.put(_blob(i, 10), case_id=case, registrable_domain="a.test")
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(_blob(3, 10), case_id=case, registrable_domain="a.test")
    assert e.value.quota == "case_count"
    assert _quota_facts(store, case) == ["case_count"]


def test_case_bytes_cap(tmp_path):
    store = _store(tmp_path)
    case = _case(store, "a.test")
    store.blobs.put(_blob(0, 100), case_id=case, registrable_domain="a.test")
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(_blob(1, 60), case_id=case, registrable_domain="a.test")
    assert e.value.quota == "case_bytes"


def test_domain_bytes_cap_spans_cases(tmp_path):
    store = _store(tmp_path)
    for i in range(2):
        case = _case(store, f"c{i}.evil.test")
        store.blobs.put(_blob(i, 100), case_id=case, registrable_domain="evil.test")
    case = _case(store, "c2.evil.test")
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(_blob(2, 60), case_id=case, registrable_domain="evil.test")
    assert e.value.quota == "domain_bytes"


def test_store_total_cap_and_reserve(tmp_path):
    # 1000-byte store, 20% reserved: unprivileged writes stop at 800 bytes.
    store = _store(tmp_path, max_case_bytes=1000, max_case_count=50, max_domain_bytes=1000)
    for i in range(8):
        case = _case(store, f"d{i}.test")
        store.blobs.put(_blob(i, 100), case_id=case, registrable_domain=f"d{i}.test")
    weak = _case(store, "weak.test", "weak")
    with pytest.raises(QuotaExceeded) as e:
        store.blobs.put(_blob(100, 100), case_id=weak, registrable_domain="weak.test")
    assert e.value.quota == "store_bytes"
    manual = _case(store, "manual.test")
    store.blobs.put(
        _blob(101, 100), case_id=manual, registrable_domain="manual.test", privileged=True
    )
    store.blobs.put(
        _blob(102, 100), case_id=manual, registrable_domain="manual.test", privileged=True
    )
    with pytest.raises(QuotaExceeded):
        store.blobs.put(
            _blob(103, 10), case_id=manual, registrable_domain="m2.test", privileged=True
        )
    assert store.blobs.stats() == (10, 1000)


def test_relinking_existing_blob_does_not_count_against_store_cap(tmp_path):
    store = _store(tmp_path, max_store_bytes=100, reserve_fraction=0.0)
    first = _case(store, "a.test")
    store.blobs.put(_blob(0, 100), case_id=first, registrable_domain="a.test")
    second = _case(store, "b.test")
    store.blobs.put(_blob(0, 100), case_id=second, registrable_domain="b.test")
    assert store.blobs.stats() == (1, 100)


def test_every_quota_rejection_is_recorded_and_leaves_no_file(tmp_path):
    import hashlib

    store = _store(tmp_path, max_store_bytes=300, reserve_fraction=0.0)
    a = _case(store, "a.test")
    store.blobs.put(_blob(0, 100), case_id=a, registrable_domain="a.test")
    _assert_rejected(store, a, "case_bytes", _blob(1, 60), "a.test")
    b = _case(store, "b.test")
    store.blobs.put(_blob(2, 100), case_id=b, registrable_domain="b.test")
    store.blobs.put(_blob(3, 100), case_id=_case(store, "c.test"), registrable_domain="c.test")
    rejected = _blob(4, 50)
    _assert_rejected(store, _case(store, "d.test"), "store_bytes", rejected, "d.test")
    assert not store.blobs.path_for(hashlib.sha256(rejected).hexdigest()).exists()
    assert store.blobs.stats() == (3, 300)


def test_relinking_blob_already_counted_for_domain_is_allowed(tmp_path):
    store = _store(tmp_path, max_domain_bytes=100, max_case_bytes=1000)
    first = _case(store, "x.evil.test")
    store.blobs.put(_blob(0, 100), case_id=first, registrable_domain="evil.test")
    second = _case(store, "y.evil.test")
    # Same bytes on the same domain: the domain already pays for this blob.
    store.blobs.put(_blob(0, 100), case_id=second, registrable_domain="evil.test")
    _assert_rejected(store, second, "domain_bytes", _blob(1, 1), "evil.test")
