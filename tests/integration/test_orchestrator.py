"""Orchestrator: bounded stages, per-domain exclusion, lease recovery, run service."""

import asyncio

from tests.unit.test_events import cert_event

from brandsentinel.config import DiscoverySettings
from brandsentinel.discovery.events import DISCOVERY_LOG, write_events
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage, maintenance, run_service
from brandsentinel.registry.model import Registry
from brandsentinel.store import open_store


def drain(orch: Orchestrator, until, timeout: float = 5.0) -> None:
    async def main():
        stop = asyncio.Event()

        async def watch():
            while not until():
                await asyncio.sleep(0.01)
            stop.set()

        watcher = asyncio.create_task(watch())
        await asyncio.wait_for(orch.run(stop), timeout)
        await watcher

    asyncio.run(main())


def done_count(store, stage="work"):
    return store.conn.execute(
        "SELECT COUNT(*) FROM jobs WHERE stage = ? AND status = 'done'", (stage,)
    ).fetchone()[0]


def test_stage_concurrency_limit_is_respected(store):
    active = peak = 0

    async def slow(job):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.03)
        active -= 1

    for i in range(10):
        store.jobs.enqueue("work", {"i": i})
    orch = Orchestrator(store)
    orch.register_stage(Stage("work", slow, concurrency=2, poll_seconds=0.01))
    drain(orch, lambda: done_count(store) == 10)
    assert peak == 2


def test_same_registrable_domain_never_runs_concurrently(store):
    running: dict[str, int] = {}
    overlap = []

    async def fetch(job):
        d = job.payload["registrable_domain"]
        running[d] = running.get(d, 0) + 1
        overlap.append(running[d])
        await asyncio.sleep(0.02)
        running[d] -= 1

    for i in range(6):
        store.jobs.enqueue("work", {"registrable_domain": "same.com", "i": i})
    orch = Orchestrator(store)
    orch.register_stage(Stage("work", fetch, concurrency=4, per_domain=True, poll_seconds=0.01))
    drain(orch, lambda: done_count(store) == 6)
    assert max(overlap) == 1
    assert orch._domain_locks == {}  # lock map does not grow without bound


def test_job_interrupted_by_a_crash_completes_exactly_once_after_restart(config, clock):
    s1 = open_store(config)
    s1.jobs._clock = clock
    s1.jobs.enqueue("work", {"k": 1})
    s1.jobs.claim("work", "dead-worker", lease_seconds=60)  # then the process dies
    s1.close()

    clock.advance(61)
    s2 = open_store(config)
    s2.jobs._clock = clock
    seen = []

    async def handler(job):
        seen.append(job.payload["k"])

    orch = Orchestrator(s2)
    orch.register_stage(Stage("work", handler, concurrency=1, poll_seconds=0.01))
    try:
        assert orch.startup() == 1
        drain(orch, lambda: done_count(s2) == 1)
        assert seen == [1]
    finally:
        s2.close()


def test_failing_handler_is_retried_then_failed_with_error(store):
    async def boom(job):
        raise RuntimeError("upstream down")

    store.jobs.enqueue("work", {}, max_attempts=2)
    orch = Orchestrator(store)
    orch.register_stage(
        Stage("work", boom, concurrency=1, poll_seconds=0.01, retry_delay_seconds=0)
    )
    drain(
        orch,
        lambda: store.conn.execute("SELECT status FROM jobs").fetchone()[0] == "failed",
    )
    row = store.conn.execute("SELECT attempts, last_error FROM jobs").fetchone()
    assert row["attempts"] == 2 and "upstream down" in row["last_error"]


def test_crashing_background_task_does_not_stop_stage_workers(store):
    async def bad_task():
        raise RuntimeError("source broke")

    async def ok(job):
        pass

    store.jobs.enqueue("work", {})
    orch = Orchestrator(store)
    orch.add_task("bad", bad_task)
    orch.register_stage(Stage("work", ok, concurrency=1, poll_seconds=0.01))
    drain(orch, lambda: done_count(store) == 1)


def test_run_service_replays_the_discovery_log_on_startup(store, registry_data, matcher):
    # Events logged by a process that died before ingesting them.
    write_events(store.rawlog(DISCOVERY_LOG), [cert_event("sadhguru-crash.com")])
    store.rawlog(DISCOVERY_LOG).close()
    registry = Registry.model_validate(registry_data)

    async def main():
        stop = asyncio.Event()
        stop.set()  # start, recover, stop
        await run_service(
            store, registry, certstream_enabled=False, dnstwist_enabled=False, stop=stop
        )

    asyncio.run(main())
    asyncio.run(main())  # a second restart duplicates nothing
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 1
    assert store.conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


def test_discovery_disabled_config_is_valid(config):
    d = DiscoverySettings()
    assert d.certstream.url.startswith("ws://localhost")
    assert d.dnstwist.interval_hours == 24


def test_maintenance_keeps_raw_storage_bounded(config, clock):
    from brandsentinel.config import FirehoseSettings, RawLogSettings
    from brandsentinel.store import FIREHOSE_SOURCE

    raw = config.rawlog.model_dump()
    raw["firehose"] = FirehoseSettings(enabled=True, max_total_bytes=20_000, max_age_days=7)
    cfg = config.model_copy(update={"rawlog": RawLogSettings(**raw)})
    store = open_store(cfg)
    try:
        import os
        import random

        rnd = random.Random(0)  # noqa: S311 - test padding, not crypto
        fh = store.rawlog(FIREHOSE_SOURCE)
        for hour in range(48):  # two days of hourly segments
            fh._clock = lambda h=hour: clock() + h * 3600
            for _ in range(20):
                fh.write({"junk": rnd.randbytes(200).hex()})
            fh.flush()
        maintenance(store, clock() + 48 * 3600)
        assert store.raw_bytes(FIREHOSE_SOURCE) <= 20_000 + os.path.getsize(fh.current_segment)
        assert fh.current_segment.exists()  # never deletes the open segment
    finally:
        store.close()


def test_worker_survives_store_errors(store, monkeypatch):
    import sqlite3

    real = store.jobs.claim
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise sqlite3.OperationalError("database is locked")
        return real(*a, **k)

    monkeypatch.setattr(store.jobs, "claim", flaky)

    async def ok(job):
        pass

    store.jobs.enqueue("work", {})
    orch = Orchestrator(store)
    orch.register_stage(Stage("work", ok, concurrency=1, poll_seconds=0.001))
    drain(orch, lambda: done_count(store) == 1)


def test_lease_is_renewed_while_waiting_for_the_domain_lock(store):
    finished = []

    async def slow(job):
        await asyncio.sleep(0.3)
        finished.append(job.id)

    for i in range(2):
        store.jobs.enqueue("work", {"registrable_domain": "same.com", "i": i})
    orch = Orchestrator(store)
    # Second job waits ~0.3s for the lock; its 0.15s lease must be renewed meanwhile.
    orch.register_stage(
        Stage("work", slow, concurrency=2, per_domain=True, lease_seconds=0.15, poll_seconds=0.01)
    )
    drain(orch, lambda: done_count(store) == 2)
    attempts = [r[0] for r in store.conn.execute("SELECT attempts FROM jobs")]
    assert attempts == [1, 1] and len(finished) == 2
