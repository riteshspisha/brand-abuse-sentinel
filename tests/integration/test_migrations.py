import hashlib
import json
import stat
import threading

import pytest
from tests.detection_support import context, lab_registry, lab_site, policy

from brandsentinel.analysis import run_extractors
from brandsentinel.policy.scorer import CaseScorer, evaluate, latest_score
from brandsentinel.store import db as store_db
from brandsentinel.store import open_store
from brandsentinel.store.db import (
    SchemaTooNew,
    _migration_files,
    connect,
    migrate,
    schema_version,
)
from brandsentinel.triage import load_case

LATEST = _migration_files()[-1][0]


def test_restart_applies_no_duplicate_migrations(config):
    first = open_store(config)
    assert schema_version(first.conn) == LATEST
    first.jobs.enqueue("fetch", {"keep": True})
    first.close()

    second = open_store(config)
    assert migrate(second.conn) == []
    assert second.conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == LATEST
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
    assert counts == [LATEST] * 4


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


def _seed_donation_case(conn):
    """Case 7: the donation-fraud lab page, fetched and extracted (pre-M5 records)."""
    expected, html = lab_site("donation-fraud")
    url, sha = expected["url"], hashlib.sha256(html).hexdigest()
    host = "donate-luminafoundation.test"
    conn.execute(
        "INSERT INTO candidates (id, name, registrable_domain, match_strength, first_seen,"
        " last_seen) VALUES (1, ?, ?, 'strong', 1.0, 1.0)",
        (host, host),
    )
    conn.execute(
        "INSERT INTO cases (id, candidate_id, subject_url, status, created_at, updated_at,"
        " escalated) VALUES (7, 1, ?, 'open', 1.0, 2.0, 1)",
        (url,),
    )
    fetch = {
        "requested_url": url,
        "final_url": url,
        "status": 200,
        "outcome": "ok",
        "final": True,
        "analysis_round": 0,
        "hops": [{"url": url, "status": 200, "address": "192.0.2.1"}],
        "body": {"content_type": "text/html", "sha256": sha, "decoded_bytes": len(html)},
        "body_stored": True,
    }
    conn.execute(
        "INSERT INTO facts (id, case_id, source, name, value_json, artifact_refs,"
        " collector_version, observed_at) VALUES (100, 7, 'fetcher', 'http_fetch', ?, ?,"
        " 'fetcher/1', 3.0)",
        (json.dumps(fetch), json.dumps([sha])),
    )
    for r in run_extractors(html, "text/html", "utf-8", url, context()):
        conn.execute(
            "INSERT INTO features (case_id, name, value_json, extractor_version, fact_refs,"
            " computed_at) VALUES (7, ?, ?, ?, '[100]', 4.0)",
            (r.extractor.name, json.dumps({**r.value, "analysis_round": 0}), r.extractor.version),
        )


def test_populated_v3_store_migrates_to_v4_and_scores(tmp_path, monkeypatch):
    # A store holding M3/M4 analysis (candidate, case, fetch fact, features, a
    # finished stage) gains the M5 scores table without losing or altering rows,
    # and the migrated case can then be scored.
    files = store_db._migration_files()
    assert [v for v, _ in files][:4] == [1, 2, 3, 4]
    monkeypatch.setattr(store_db, "_migration_files", lambda: [f for f in files if f[0] <= 3])
    path = tmp_path / "v3.db"
    conn = connect(path)
    assert schema_version(conn) == 3

    _seed_donation_case(conn)
    conn.execute("INSERT INTO stage_runs VALUES (7, 'fetch', 0, 'ok', 3.0)")
    tables = ("candidates", "cases", "facts", "features", "stage_runs")
    before = {t: conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall() for t in tables}  # noqa: S608

    monkeypatch.undo()
    assert migrate(conn) == [4]
    assert schema_version(conn) == LATEST
    for t in ("candidates", "facts", "features", "stage_runs"):
        assert conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall() == before[t], t  # noqa: S608
    (case,) = conn.execute("SELECT * FROM cases").fetchall()
    assert tuple(case)[: len(before["cases"][0])] == tuple(before["cases"][0])
    assert case["score_id"] is None and case["priority"] is None
    assert conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 0

    outcome = CaseScorer(conn, lab_registry(), policy(), clock=lambda: 5.0).score(7)
    assert outcome.changed and outcome.result.category == "donation_fraud"
    assert outcome.result.priority in ("P1", "P2")
    row = conn.execute("SELECT priority, category, score_id FROM cases WHERE id = 7").fetchone()
    assert tuple(row) == (outcome.result.priority, "donation_fraud", outcome.score_id)
    conn.close()


def test_scores_from_an_earlier_policy_keep_their_provenance(tmp_path):
    # A row scored under policy/1 with a bundle/1 bundle (before the M5 review
    # corrections) still loads with its own labels. Rescoring under the current
    # policy adds a row and leaves the old one untouched.
    conn = connect(tmp_path / "s.db")
    _seed_donation_case(conn)
    scorer = CaseScorer(conn, lab_registry(), policy(), clock=lambda: 5.0)
    current = scorer.bundle(7)
    old_bundle = current.model_dump(mode="json")
    old_bundle["schema_version"] = "bundle/1"
    for key in ("vouching_brands", "credential_destinations"):
        del old_bundle["registry"][key]
    old_result = evaluate(current, policy()).model_copy(
        update={"policy_version": "policy/1", "bundle_schema": "bundle/1", "score": 150}
    )
    conn.execute(
        "INSERT INTO scores (case_id, analysis_round, policy_version, bundle_schema,"
        " bundle_sha256, bundle_json, result_json, priority, category, score, created_at)"
        " VALUES (7, 0, 'policy/1', 'bundle/1', 'x', ?, ?, 'P1', 'donation_fraud', 150, 1.0)",
        (json.dumps(old_bundle), old_result.model_dump_json()),
    )
    old_row = conn.execute("SELECT * FROM scores").fetchone()
    bundle, result, _ = latest_score(conn, 7)
    assert bundle.schema_version == "bundle/1" and bundle.registry.credential_destinations == []
    assert result.policy_version == "policy/1" and result.score == 150

    outcome = scorer.score(7)
    assert outcome.changed
    assert (outcome.result.policy_version, outcome.result.bundle_schema) == (
        policy().version,
        "bundle/2",
    )
    rows = conn.execute("SELECT * FROM scores ORDER BY id").fetchall()
    assert len(rows) == 2 and tuple(rows[0]) == tuple(old_row)
    assert [r["policy_version"] for r in rows] == ["policy/1", "policy/2"]
    assert [h["policy_version"] for h in load_case(conn, 7).history] == ["policy/1", "policy/2"]
    conn.close()
