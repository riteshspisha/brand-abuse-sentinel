"""End to end through the queue: submit -> enrich -> fetch -> facts, blobs, rechecks."""

import asyncio
import json

import pytest
from tests.conftest import build_matcher
from tests.integration.test_orchestrator import drain
from tests.security.harness import harness_stages

from brandsentinel.config import Config
from brandsentinel.discovery.submit import submit
from brandsentinel.pipeline import scheduling
from brandsentinel.pipeline.orchestrator import Orchestrator
from brandsentinel.registry.model import Registry
from brandsentinel.store import open_store
from brandsentinel.store.jobs import Job


@pytest.fixture
def env(tmp_path, harness, registry_data, clock):
    config = Config(data_dir=tmp_path / "data", fetch={"retry_delay_seconds": 0})
    store = open_store(config)
    store.jobs._clock = clock
    registry = Registry.model_validate(registry_data)
    stages = harness_stages(harness, store, registry, clock=clock)
    yield store, stages, build_matcher(registry_data), clock
    store.close()


def run_until(store, stages, until, timeout=15):
    orch = Orchestrator(store)
    stages.register(orch)
    for s in orch.stages.values():
        s.poll_seconds = 0.01
    drain(orch, until, timeout)


def runs(store, stage=None):
    sql = "SELECT stage, round, outcome FROM stage_runs"
    rows = store.conn.execute(sql).fetchall()
    return [tuple(r) for r in rows if stage is None or r[0] == stage]


def facts(store, name):
    return [
        (json.loads(r[0]), json.loads(r[1]))
        for r in store.conn.execute(
            "SELECT value_json, artifact_refs FROM facts WHERE name = ? ORDER BY id", (name,)
        )
    ]


def url(h, path):
    return f"http://site.harness.test:{h.http.port}{path}"


def test_submitted_url_is_enriched_fetched_and_stored(env, harness):
    store, stages, matcher, clock = env
    submit(store, matcher, url(harness, "/ok"))
    run_until(store, stages, lambda: runs(store, "fetch"))
    assert runs(store) == [("enrich", 0, "partial"), ("fetch", 0, "ok")]  # TLS :443 refused
    ((fetch, refs),) = facts(store, "http_fetch")
    assert fetch["outcome"] == "ok" and fetch["final_url"] == url(harness, "/ok")
    assert fetch["hops"][0]["address"] == "127.77.0.1" and fetch["body_stored"]
    assert refs == [fetch["body"]["sha256"]]
    assert store.blobs.read(refs[0]).startswith(b"<!doctype html>")
    role = store.conn.execute("SELECT role FROM case_artifacts").fetchone()[0]
    assert role == "page"
    page = json.loads(
        store.conn.execute("SELECT value_json FROM features WHERE name = 'page_basics'").fetchone()[
            0
        ]
    )
    assert page["title"] == "Lumina Foundation Donate"
    ((fp, _),) = facts(store, "analysis_fingerprint")
    assert fp["addresses"] == ["127.77.0.1"] and fp["status"] == 200
    assert fp["body_sha256"] == fetch["body"]["sha256"]
    # Two rechecks wait in deferred_jobs, 1 and 7 days out.
    due = [
        r[0] - clock()
        for r in store.conn.execute(
            "SELECT not_before FROM deferred_jobs WHERE reason = 'recheck' ORDER BY not_before"
        )
    ]
    assert [round(d / 86400) for d in due] == [1, 7]
    tls_err = facts(store, "tls_error")[0][0]
    assert tls_err["kind"] == "connect_error"  # incomplete evidence is kept with its reason


def test_recheck_detects_changed_content_at_same_ip_and_status(env, harness):
    # Covers AE19.
    store, stages, matcher, clock = env
    harness.recorder.pages["ae19"] = b"<title>Parked</title>for sale"
    submit(store, matcher, url(harness, "/mutable?k=ae19"))
    run_until(store, stages, lambda: runs(store, "fetch"))

    harness.recorder.pages["ae19"] = b"<title>Parked</title>Donate now via UPI"
    clock.advance(86400 + 1)
    scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
    run_until(store, stages, lambda: ("fetch", 1, "ok") in runs(store))
    change = next(v for v, _ in facts(store, "material_change") if v["analysis_round"] == 1)
    assert change["changed"] and change["fields"] == ["body_sha256"]

    clock.advance(6 * 86400)  # second recheck, nothing changed
    scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
    run_until(store, stages, lambda: ("fetch", 2, "ok") in runs(store))
    change2 = next(v for v, _ in facts(store, "material_change") if v["analysis_round"] == 2)
    assert change2 == {
        "previous_round": 1,
        "changed": False,
        "fields": [],
        "unknown_fields": [],
        "analysis_round": 2,
    }


def test_intermittent_site_is_retried_and_every_attempt_kept(env, harness):
    store, stages, matcher, _ = env
    submit(store, matcher, url(harness, "/flaky?fail=1&k=pipeline"))
    run_until(store, stages, lambda: runs(store, "fetch"))
    attempts = facts(store, "http_fetch_attempt")
    assert [a["outcome"] for a, _ in attempts] == ["protocol_error"]
    ((final, _),) = facts(store, "http_fetch")
    assert final["outcome"] == "ok" and final["attempt"] == 2


def test_unreachable_site_records_failure_after_last_attempt(env, harness):
    store, stages, matcher, _ = env
    submit(store, matcher, f"http://dead.harness.test:{harness.dead_port}/")
    run_until(store, stages, lambda: runs(store, "fetch"))
    assert runs(store, "fetch") == [("fetch", 0, "connect_error")]
    assert len(facts(store, "http_fetch_attempt")) == 2
    ((final, refs),) = facts(store, "http_fetch")
    assert final["error"]["kind"] == "connect_error" and refs == []
    job = store.conn.execute("SELECT status FROM jobs WHERE stage = 'fetch'").fetchone()[0]
    assert job == "done"  # the failure is the observation; the case moves on


def test_blocked_subject_is_recorded_and_not_retried(env, harness):
    store, stages, matcher, _ = env
    submit(store, matcher, "http://metadata.harness.test/latest/meta-data/")
    run_until(store, stages, lambda: runs(store, "fetch"))
    ((final, _),) = facts(store, "http_fetch")
    assert final["outcome"] == "blocked" and final["error"]["class"] == "link_local"
    assert facts(store, "http_fetch_attempt") == []
    assert store.blobs.stats() == (0, 0)


def test_subject_url_on_another_host_is_not_fetched(env, harness):
    store, stages, matcher, _ = env
    submit(store, matcher, url(harness, "/ok"))
    store.conn.execute("UPDATE cases SET subject_url = 'http://evil.example/x'")
    case = stages._case(1)
    assert stages.urls_for(case) == ["https://site.harness.test/", "http://site.harness.test/"]


def test_redelivered_jobs_write_nothing_twice(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, url(harness, "/ok"))
    job = Job(r.job_id, "enrich", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0)
    asyncio.run(stages.enrich(job))
    n_facts = store.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    asyncio.run(stages.enrich(job))  # e.g. the lease was lost after the work committed
    assert store.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == n_facts
    fetch_jobs = store.conn.execute("SELECT COUNT(*) FROM jobs WHERE stage = 'fetch'").fetchone()
    assert fetch_jobs[0] == 1
    rechecks = store.conn.execute("SELECT COUNT(*) FROM deferred_jobs").fetchone()[0]
    assert rechecks == 2


def test_closed_cases_are_not_analyzed(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, url(harness, "/ok"))
    store.conn.execute("UPDATE cases SET status = 'closed'")
    job = Job(r.job_id, "enrich", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0)
    asyncio.run(stages.enrich(job))
    assert store.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 0


def test_quota_rejection_keeps_the_fetch_fact(env, harness, tmp_path, registry_data, clock):
    _, _, matcher, _ = env
    artifacts = {"max_blob_bytes": 1000, "max_case_bytes": 100}  # page is over the case cap
    small = Config(data_dir=tmp_path / "small", artifacts=artifacts)
    s2 = open_store(small)
    try:
        stages = harness_stages(harness, s2, Registry.model_validate(registry_data), clock=clock)
        submit(s2, matcher, url(harness, "/ok"))
        run_until(s2, stages, lambda: runs(s2, "fetch"))
        ((final, refs),) = facts(s2, "http_fetch")
        assert final["outcome"] == "ok" and not final["body_stored"] and refs == []
        assert facts(s2, "artifact_quota_exceeded")
    finally:
        s2.close()


@pytest.mark.parametrize(
    ("path", "outcome", "attempts"),
    [
        ("/slow-timeout", "timeout", 3),  # transient: retried until the last attempt
        ("/status/500", "ok", 1),  # an HTTP error status is an observation
    ],
)
def test_retry_policy_by_outcome(env, harness, path, outcome, attempts):
    store, stages, matcher, _ = env
    if path == "/slow-timeout":
        target = f"http://blackhole.harness.test:{harness.blackhole.port}/"
        stages.fetcher.settings = stages.fetcher.settings.model_copy(
            update={"read_timeout_seconds": 0.3}
        )
    else:
        target = url(harness, path)
    submit(store, matcher, target)
    run_until(store, stages, lambda: runs(store, "fetch"), timeout=30)
    ((final, _),) = facts(store, "http_fetch")
    assert final["outcome"] == outcome and final["attempt"] == attempts
    assert len(facts(store, "http_fetch_attempt")) == attempts - 1


def test_dns_never_resolving_is_not_retried(env, harness):
    store, stages, matcher, _ = env
    submit(store, matcher, "http://gone.harness.test/")
    run_until(store, stages, lambda: runs(store, "fetch"))
    ((final, _),) = facts(store, "http_fetch")
    assert final["error"]["kind"] == "dns_nxdomain" and final["attempt"] == 1


def test_rebinding_between_enrich_and_fetch_is_blocked(env, harness):
    store, stages, matcher, _ = env
    harness.dns.set("flip.harness.test", A=["127.77.0.1"])
    r = submit(store, matcher, f"http://flip.harness.test:{harness.http.port}/ok")
    enrich = Job(
        r.job_id, "enrich", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0
    )
    asyncio.run(stages.enrich(enrich))
    ((dns, _),) = facts(store, "dns_records")
    assert dns["records"]["A"]["values"] == ["127.77.0.1"]
    harness.dns.set("flip.harness.test", A=["169.254.169.254"])  # rebind before the fetch
    fetch = Job(98, "fetch", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0)
    asyncio.run(stages.fetch(fetch))
    ((final, _),) = facts(store, "http_fetch")
    assert final["outcome"] == "blocked" and final["error"]["class"] == "link_local"


def test_redelivered_fetch_writes_one_result_and_one_artifact(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, url(harness, "/ok"))
    job = Job(99, "fetch", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0)
    asyncio.run(stages.fetch(job))
    asyncio.run(stages.fetch(job))
    assert len(facts(store, "http_fetch")) == 1
    assert store.conn.execute("SELECT COUNT(*) FROM case_artifacts").fetchone()[0] == 1


def test_manual_case_fetch_bypasses_a_flooded_domain(env, harness):
    store, stages, matcher, clock = env
    cfg = store.config.scheduling
    for i in range(cfg.max_queued_per_domain_strong):  # fill the fetch allowance
        scheduling.schedule(
            store.conn,
            store.jobs,
            cfg,
            stage="fetch",
            payload={},
            group_key="site.harness.test",
            queue_class="strong",
            dedupe_key=f"filler{i}",
            now=clock(),
        )
    r = submit(store, matcher, url(harness, "/ok"))
    job = Job(r.job_id, "enrich", "strong", {"case_id": r.case_id, "round": 0}, 1, 3, "o", "t", 0)
    asyncio.run(stages.enrich(job))
    key = f"fetch:case:{r.case_id}:r0"
    assert store.conn.execute("SELECT 1 FROM jobs WHERE dedupe_key = ?", (key,)).fetchone()
