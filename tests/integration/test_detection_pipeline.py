"""End to end through the queue and the guarded fetcher: intake -> enrich -> fetch ->
extract -> score -> report and CSV, against the local adversarial harness."""

import csv
import io

import pytest
from tests.detection_support import lab_registry, lab_site
from tests.integration.test_orchestrator import drain
from tests.security.harness import harness_stages

from brandsentinel.config import Config
from brandsentinel.discovery.submit import submit
from brandsentinel.matching.matcher import Matcher
from brandsentinel.pipeline.orchestrator import Orchestrator
from brandsentinel.store import open_store
from brandsentinel.triage import load_case
from brandsentinel.triage.export import COLUMNS, to_csv
from brandsentinel.triage.report import render_case_html


def make_env(tmp_path, harness, clock, **config_kw):
    config = Config(data_dir=tmp_path / "data", fetch={"retry_delay_seconds": 0}, **config_kw)
    store = open_store(config)
    store.jobs._clock = clock
    registry = lab_registry()
    stages = harness_stages(harness, store, registry, clock=clock)
    return store, stages, Matcher(registry)


def run_until(store, stages, until, *, enrich=True, timeout=15):
    orch = Orchestrator(store)
    stages.register(orch, enrich=enrich, fetch=True)
    for s in orch.stages.values():
        s.poll_seconds = 0.01
    drain(orch, until, timeout)


def scored(store, case_id):
    return store.conn.execute("SELECT priority FROM cases WHERE id = ?", (case_id,)).fetchone()[0]


@pytest.fixture
def env(tmp_path, harness, clock):
    store, stages, matcher = make_env(tmp_path, harness, clock)
    yield store, stages, matcher
    store.close()


def test_donation_page_goes_from_intake_to_report_and_csv(env, harness):
    store, stages, matcher = env
    _, html = lab_site("donation-fraud")
    harness.recorder.pages["m5-donation"] = html
    url = f"http://site.harness.test:{harness.http.port}/mutable?k=m5-donation"
    case_id = submit(store, matcher, url).case_id
    run_until(store, stages, lambda: scored(store, case_id))

    report = load_case(store.conn, case_id)
    b, p = report.bundle, report.result
    assert p.priority in ("P1", "P2") and p.category == "donation_fraud"
    assert b.http.redirect_chain[0].address == "127.77.0.1"  # the validated, pinned address
    assert b.infrastructure.enrichment in ("ok", "partial") and b.infrastructure.dns
    (upi,) = [o for o in b.payment.observations if o.kind == "upi"]
    assert upi.attribution == "claims_brand_unconfirmed"
    artifact = next(r for r in upi.refs if r.startswith("artifact:"))
    assert store.blobs.read(artifact.split(":", 1)[1]) == html  # evidence is the stored page
    assert "rivers.relief.fund@quickpaybank" in render_case_html(report)
    rows = list(csv.reader(io.StringIO(to_csv([report]))))
    assert tuple(rows[0]) == COLUMNS and rows[1][1] == p.priority


def test_blocked_redirect_is_scored_without_following_it(env, harness):
    store, stages, matcher = env
    url = f"http://site.harness.test:{harness.http.port}/redirect?to=http://127.0.0.1/admin"
    case_id = submit(store, matcher, url).case_id
    run_until(store, stages, lambda: scored(store, case_id))
    b, p = load_case(store.conn, case_id).bundle, load_case(store.conn, case_id).result
    assert b.http.outcome == "blocked_redirect"
    assert "blocked_redirect" in {r.rule for r in p.reasons}
    assert p.category == "insufficient_evidence" and "manual_review" in p.flags
    # The redirect target is recorded as evidence and was never connected to.
    assert b.http.redirect_chain[0].location == "http://127.0.0.1/admin"
    assert all(hop.address != "127.0.0.1" for hop in b.http.redirect_chain)


def test_recheck_with_new_content_rescores_the_case(env, harness, clock):
    # AE19 with re-scoring: a parked page later serves a donation appeal.
    from brandsentinel.pipeline import scheduling

    store, stages, matcher = env
    harness.recorder.pages["m5-recheck"] = b"<title>Coming soon</title><p>Under construction</p>"
    url = f"http://site.harness.test:{harness.http.port}/mutable?k=m5-recheck"
    case_id = submit(store, matcher, url).case_id
    run_until(store, stages, lambda: scored(store, case_id))
    first = scored(store, case_id)
    harness.recorder.pages["m5-recheck"] = lab_site("donation-fraud")[1]
    clock.advance(86400 + 1)
    scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
    run_until(
        store,
        stages,
        lambda: (
            store.conn.execute(
                "SELECT COUNT(*) FROM scores WHERE case_id = ?", (case_id,)
            ).fetchone()[0]
            >= 2
        ),
    )
    history = load_case(store.conn, case_id).history
    assert first in ("P4", "no_action", "P3") and history[-1]["priority"] in ("P1", "P2")


def test_with_enrichment_disabled_cases_still_reach_the_fetch(tmp_path, harness, clock):
    store, stages, matcher = make_env(tmp_path, harness, clock, enrich={"enabled": False})
    try:
        url = f"http://site.harness.test:{harness.http.port}/ok"
        case_id = submit(store, matcher, url).case_id
        run_until(store, stages, lambda: scored(store, case_id), enrich=False)
        runs = dict(store.conn.execute("SELECT stage, outcome FROM stage_runs").fetchall())
        assert runs == {"enrich": "offline", "fetch": "ok"}
        names = {r[0] for r in store.conn.execute("SELECT name FROM facts")}
        assert "similarity" in names and not names & {"dns_records", "rdap_registration"}
    finally:
        store.close()


def test_a_redelivered_fetch_scores_a_case_left_unscored(env, harness):
    # A crash (or scoring error) between the fetch commit and scoring leaves the
    # case unscored; the redelivered job must score it without fetching again.
    import asyncio

    from brandsentinel.store.jobs import Job

    store, stages, matcher = env
    url = f"http://site.harness.test:{harness.http.port}/ok"
    case_id = submit(store, matcher, url).case_id
    run_until(store, stages, lambda: scored(store, case_id))
    store.conn.execute("UPDATE cases SET score_id = NULL, priority = NULL WHERE id = ?", (case_id,))
    store.conn.execute("DELETE FROM scores WHERE case_id = ?", (case_id,))
    store.conn.commit()
    before = len(harness.recorder.requests)
    job = Job(
        id=0,
        stage="fetch",
        queue_class="strong",
        payload={"case_id": case_id, "round": 0},
        attempts=1,
        max_attempts=3,
        lease_owner="t",
        lease_token="t",  # noqa: S106 - a test lease, not a secret
        lease_expires_at=0.0,
    )
    asyncio.run(stages.fetch(job))
    assert scored(store, case_id) is not None
    assert len(harness.recorder.requests) == before  # nothing fetched again
