"""Subdomain flooding control: per-domain allowances, deferral, fairness, escalation."""

import asyncio

from tests.integration.test_orchestrator import drain
from tests.unit.test_events import cert_event

from brandsentinel.config import Config, SchedulingSettings
from brandsentinel.discovery.events import ingest
from brandsentinel.discovery.submit import submit
from brandsentinel.pipeline import scheduling
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage
from brandsentinel.store import open_store
from brandsentinel.store.records import create_case, upsert_candidate

SETTINGS = SchedulingSettings(max_queued_per_domain_strong=3, max_queued_per_domain_weak=2)


def sched(store, n, group, *, cls="weak", stage="enrich", start=0, **kw):
    settings = kw.pop("settings", SETTINGS)
    out = []
    for i in range(start, start + n):
        out.append(
            scheduling.schedule(
                store.conn,
                store.jobs,
                settings,
                stage=stage,
                payload={"i": i, "g": group},
                group_key=group,
                queue_class=cls,
                dedupe_key=f"{stage}:{group}:{i}",
                now=store.jobs._clock(),
                **kw,
            ).decision
        )
    return out


def count(store, sql, *args):
    return store.conn.execute(sql, args).fetchone()[0]


def test_work_beyond_the_domain_allowance_is_deferred_not_dropped(store):
    decisions = sched(store, 10, "flood.com")
    assert decisions.count("enqueued") == 2 and decisions.count("deferred") == 8
    assert (
        count(store, "SELECT COUNT(*) FROM deferred_jobs WHERE reason = 'domain_queue_full'") == 8
    )
    # Another domain is unaffected by the flood.
    assert sched(store, 1, "other.com") == ["enqueued"]


def test_strong_work_has_a_larger_allowance(store):
    assert sched(store, 5, "a.com", cls="strong").count("enqueued") == 3


def test_scheduling_is_idempotent_on_the_dedupe_key(store):
    sched(store, 3, "a.com")  # 2 enqueued, 1 deferred
    assert sched(store, 3, "a.com") == ["exists"] * 3
    assert count(store, "SELECT COUNT(*) FROM jobs") == 2
    assert count(store, "SELECT COUNT(*) FROM deferred_jobs") == 1


def test_flood_of_matching_subdomains_keeps_every_candidate(store, matcher):
    events = [cert_event(f"sadhguru-{i}.evil-flood.com") for i in range(30)]
    for e in events:
        ingest(store, matcher, e)
    cfg = store.config.scheduling
    assert count(store, "SELECT COUNT(*) FROM candidates") == 30
    assert count(store, "SELECT COUNT(*) FROM cases WHERE status = 'open'") == 30
    assert count(store, "SELECT COUNT(*) FROM discovery_events") == 30
    assert count(store, "SELECT COUNT(*) FROM jobs") == cfg.max_queued_per_domain_strong
    assert (
        count(store, "SELECT COUNT(*) FROM deferred_jobs") == 30 - cfg.max_queued_per_domain_strong
    )
    assert {r[0] for r in store.conn.execute("SELECT group_key FROM deferred_jobs")} == {
        "evil-flood.com"
    }


def test_least_recently_served_domain_is_claimed_first(store):
    sched(store, 2, "flood.com")  # queued first
    sched(store, 1, "quiet.com")
    first = store.jobs.claim("enrich", "w", 60)
    second = store.jobs.claim("enrich", "w", 60)
    assert (first.group_key, second.group_key) == ("flood.com", "quiet.com")


def test_running_jobs_per_domain_are_capped_at_claim(store):
    settings = SchedulingSettings(max_queued_per_domain_weak=10)
    sched(store, 5, "flood.com", settings=settings)
    claimed = [store.jobs.claim("enrich", "w", 60, per_group_limit=2) for _ in range(3)]
    assert [c is not None for c in claimed] == [True, True, False]
    sched(store, 1, "quiet.com")
    assert store.jobs.claim("enrich", "w", 60, per_group_limit=2).group_key == "quiet.com"


def test_promotion_fills_freed_allowance_in_order(store):
    sched(store, 6, "flood.com")
    assert scheduling.promote(store.conn, store.jobs, SETTINGS, now=store.jobs._clock()) == 0
    job = store.jobs.claim("enrich", "w", 60)
    store.jobs.complete(job)
    assert scheduling.promote(store.conn, store.jobs, SETTINGS, now=store.jobs._clock()) == 1
    payloads = [r[0] for r in store.conn.execute("SELECT payload_json FROM jobs ORDER BY id")]
    assert '"i": 2' in payloads[-1]  # the oldest deferred item went first


def test_manual_submission_bypasses_the_allowance(store, matcher, config):
    for i in range(20):
        ingest(store, matcher, cert_event(f"sadhguru-{i}.evil-flood.com"))
    queued = count(store, "SELECT COUNT(*) FROM jobs")
    r = submit(store, matcher, "https://login.evil-flood.com/")
    assert r.new_case and count(store, "SELECT COUNT(*) FROM jobs") == queued + 1


def test_manual_resubmission_escalates_deferred_work(store, matcher):
    for i in range(20):
        ingest(store, matcher, cert_event(f"sadhguru-{i}.evil-flood.com"))
    deferred = store.conn.execute(
        "SELECT d.case_id, k.name FROM deferred_jobs d JOIN cases c ON c.id = d.case_id"
        " JOIN candidates k ON k.id = c.candidate_id ORDER BY d.not_before DESC LIMIT 1"
    ).fetchone()
    submit(store, matcher, f"https://{deferred['name']}/")
    moved = scheduling.promote(
        store.conn, store.jobs, store.config.scheduling, now=store.jobs._clock()
    )
    assert moved == 1
    assert (
        count(store, "SELECT COUNT(*) FROM deferred_jobs WHERE case_id = ?", deferred["case_id"])
        == 0
    )


def test_strong_sighting_upgrades_deferred_weak_work(store):
    cand, _ = upsert_candidate(store.conn, "x.a.com", match_strength="weak")
    case_id = create_case(store.conn, cand)
    sched(store, 3, "a.com", case_id=case_id)  # third is deferred (weak allowance 2)
    scheduling.escalate_case(store.conn, case_id, manual=False)
    row = store.conn.execute("SELECT queue_class, escalated FROM deferred_jobs").fetchone()
    assert tuple(row) == ("strong", 0)
    # The strong allowance (3) now admits it.
    assert scheduling.promote(store.conn, store.jobs, SETTINGS, now=store.jobs._clock()) == 1


def test_recheck_waits_until_due(store, clock):
    store.jobs._clock = clock
    sched(store, 1, "a.com", not_before=clock() + 86400)
    assert count(store, "SELECT reason FROM deferred_jobs") == "recheck"
    assert scheduling.promote(store.conn, store.jobs, SETTINGS, now=clock()) == 0
    clock.advance(86401)
    assert scheduling.promote(store.conn, store.jobs, SETTINGS, now=clock()) == 1


def test_deferred_work_survives_a_restart(config, clock):
    s1 = open_store(config)
    s1.jobs._clock = clock
    sched(s1, 6, "flood.com")
    running = s1.jobs.claim("enrich", "dead-worker", 30)  # the process then dies
    s1.close()

    clock.advance(31)
    s2 = open_store(config)
    s2.jobs._clock = clock
    try:
        assert count(s2, "SELECT COUNT(*) FROM deferred_jobs") == 4
        assert s2.jobs.recover_expired() == 1
        again = s2.jobs.claim("enrich", "w", 30)
        assert again.id == running.id and again.attempts == 2  # same job, next attempt
        # Draining everything processes all six items exactly once.
        seen = []

        async def handler(job):
            seen.append(job.payload["i"])

        orch = Orchestrator(s2)
        s2.jobs.complete(again)
        seen.append(again.payload["i"])
        orch.register_stage(
            Stage("enrich", handler, concurrency=2, per_group_limit=1, poll_seconds=0.01)
        )

        async def promote():
            while True:
                scheduling.promote(s2.conn, s2.jobs, SETTINGS, now=clock())
                await asyncio.sleep(0.01)

        orch.add_task("promote", promote)
        drain(orch, lambda: len(seen) == 6)
        assert sorted(seen) == list(range(6))
    finally:
        s2.close()


def test_one_flooding_domain_cannot_starve_others_end_to_end(tmp_path):
    config = Config(
        data_dir=tmp_path / "d",
        # A generous allowance, so fairness must come from the claim order, not the cap.
        scheduling={"max_queued_per_domain_weak": 500, "promote_interval_seconds": 0.01},
    )
    store = open_store(config)
    try:
        sched(store, 200, "flood.com", settings=config.scheduling)
        sched(store, 3, "victim.org", settings=config.scheduling)
        order: list[str] = []
        running: dict[str, int] = {}
        peak: dict[str, int] = {}

        async def handler(job):
            g = job.group_key
            running[g] = running.get(g, 0) + 1
            peak[g] = max(peak.get(g, 0), running[g])
            await asyncio.sleep(0.005)
            running[g] -= 1
            order.append(g)

        orch = Orchestrator(store)
        orch.register_stage(
            Stage("enrich", handler, concurrency=4, per_group_limit=2, poll_seconds=0.002)
        )

        async def promote():
            while True:
                scheduling.promote(
                    store.conn, store.jobs, config.scheduling, now=store.jobs._clock()
                )
                await asyncio.sleep(0.01)

        orch.add_task("promote", promote)
        drain(orch, lambda: len(order) == 203, timeout=30)
        assert peak["flood.com"] <= 2
        # Every victim job finished within the first handful of completions.
        last_victim = max(i for i, g in enumerate(order) if g == "victim.org")
        assert last_victim < 10
        assert count(store, "SELECT COUNT(*) FROM deferred_jobs") == 0
    finally:
        store.close()


def test_saturated_domains_do_not_starve_other_due_work(store):
    settings = SchedulingSettings(max_queued_per_domain_weak=1, promote_batch=5)
    for g in range(20):  # 20 domains, each at its allowance with deferred work
        sched(store, 2, f"busy{g}.com", settings=settings)
    sched(store, 1, "idle.com", settings=settings, not_before=store.jobs._clock() + 10)
    now = store.jobs._clock() + 11
    assert scheduling.promote(store.conn, store.jobs, settings, now=now) == 1
    assert count(store, "SELECT COUNT(*) FROM jobs WHERE group_key = 'idle.com'") == 1


def test_pre_m3_jobs_are_backfilled_with_a_group(tmp_path):
    import sqlite3

    from brandsentinel.store.db import _migration_files

    (tmp_path / "d").mkdir()
    conn = sqlite3.connect(tmp_path / "d" / "brandsentinel.db")
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at REAL)")
    for version, sql in _migration_files()[:2]:
        conn.executescript(sql)
        conn.execute("INSERT INTO schema_migrations VALUES (?, 0)", (version,))
    conn.execute(
        "INSERT INTO jobs (stage, queue_class, payload_json, status, max_attempts, available_at,"
        " created_at, updated_at) VALUES ('enrich', 'weak',"
        ' \'{"name": "a.flood.com", "registrable_domain": "flood.com"}\','
        " 'pending', 3, 0, 0, 0)"
    )
    conn.commit()
    conn.close()
    store = open_store(Config(data_dir=tmp_path / "d"))  # applies 0003
    try:
        assert count(store, "SELECT group_key FROM jobs") == "flood.com"
        job = store.jobs.claim("enrich", "w", 30, per_group_limit=1)
        assert job.group_key == "flood.com" and job.payload.get("round") is None
    finally:
        store.close()
