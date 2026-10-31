"""`run --until-idle` (M8): a bounded run stops once no work is left, never
early. Future rechecks stay as they are, jobs of stages this run does not serve
never hold it open, and `--duration` still ends a run that never goes idle."""

import asyncio
import io
import json
import logging
import time

import pytest
from typer.testing import CliRunner

from brandsentinel.config import Config, SandboxSettings
from brandsentinel.logging import configure_logging
from brandsentinel.pipeline import scheduling
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage, _stop_when_idle, run_service
from brandsentinel.registry.model import Registry
from brandsentinel.store import open_store

FAST = {"promote_interval_seconds": 0.05}


@pytest.fixture
def store(tmp_path):
    s = open_store(
        Config(data_dir=tmp_path / "data", sandbox=SandboxSettings(enabled=False), scheduling=FAST)
    )
    yield s
    s.close()


@pytest.fixture
def logbuf():
    root = logging.getLogger("brandsentinel")
    saved = (root.handlers[:], root.level, root.propagate)
    buf = io.StringIO()
    configure_logging("INFO", stream=buf)
    yield buf
    root.handlers[:], root.level, root.propagate = saved


def defer(store, key, *, stage="enrich", not_before, reason="recheck"):
    store.conn.execute(
        "INSERT INTO deferred_jobs (dedupe_key, stage, group_key, queue_class, escalated,"
        " payload_json, case_id, reason, not_before, deferred_at)"
        " VALUES (?, ?, 'x.test', 'strong', 0, '{}', NULL, ?, ?, ?)",
        (key, stage, reason, not_before, time.time()),
    )


def deferred_rows(store):
    return [tuple(r) for r in store.conn.execute("SELECT * FROM deferred_jobs ORDER BY 1")]


def statuses(store):
    return [r[0] for r in store.conn.execute("SELECT status FROM jobs ORDER BY id")]


def run_idle(store, stages, *, timeout=10.0, duration=None, clock=time.time) -> float:
    """Run an orchestrator with the stages, promotion and the idle task, as
    run_service wires them. Returns the seconds it ran."""
    orch = Orchestrator(store)
    for s in stages:
        orch.register_stage(s)

    async def promote():
        while True:
            scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
            await asyncio.sleep(store.config.scheduling.promote_interval_seconds)

    async def main():
        stop = asyncio.Event()
        orch.add_task("promote", promote)
        orch.add_task("idle", lambda: _stop_when_idle(orch, stop, clock))
        if duration is not None:
            asyncio.get_running_loop().call_later(duration, stop.set)
        await asyncio.wait_for(orch.run(stop), timeout)

    start = time.monotonic()
    asyncio.run(main())
    return time.monotonic() - start


def stage(name, handler, **kw):
    return Stage(name, handler, concurrency=kw.pop("concurrency", 2), poll_seconds=0.01, **kw)


# --- the snapshot ------------------------------------------------------------------


def test_the_snapshot_counts_only_work_this_run_can_do_now(store):
    now = time.time()
    snap = scheduling.idle_snapshot(store.conn, ["enrich"], now)
    assert snap.idle and snap == scheduling.IdleSnapshot(0, 0, 0, {})
    defer(store, "enrich:case:1:r1", not_before=now + 86400)
    store.jobs.enqueue("media", {"case_id": 1})
    snap = scheduling.idle_snapshot(store.conn, ["enrich"], now)
    assert snap.idle and snap.not_due_deferred == 1 and snap.unserved == {"media": 1}
    defer(store, "enrich:case:2:r0", not_before=now - 1, reason="domain_queue_full")
    assert not scheduling.idle_snapshot(store.conn, ["enrich"], now).idle
    store.conn.execute("DELETE FROM deferred_jobs WHERE reason = 'domain_queue_full'")
    job_id, _ = store.jobs.enqueue("enrich", {"case_id": 3}, delay=3600)  # a waiting retry
    assert scheduling.idle_snapshot(store.conn, ["enrich"], now).outstanding == 1
    store.conn.execute("UPDATE jobs SET status = 'running' WHERE id = ?", (job_id,))
    assert not scheduling.idle_snapshot(store.conn, ["enrich"], now).idle  # running counts


# --- the run ----------------------------------------------------------------------


def test_a_chain_whose_handlers_queue_their_successor_late_never_stops_early(store):
    """Each handler sleeps, then queues the next step: while it sleeps its own job
    is running, so the run is never idle before the last step is done."""
    steps = []

    async def step(job):
        n = job.payload["n"]
        await asyncio.sleep(0.15)
        steps.append(n)
        if n < 4:
            store.jobs.enqueue("work", {"n": n + 1})

    store.jobs.enqueue("work", {"n": 0})
    run_idle(store, [stage("work", step)])
    assert steps == [0, 1, 2, 3, 4] and statuses(store) == ["done"] * 5


def test_deferred_work_coming_due_during_the_settle_window_prevents_the_stop(store):
    done = []

    async def work(job):
        done.append(job.payload)

    # Not due at the first look; due (and promoted) before the second.
    soon = time.time() + 0.03
    store.conn.execute(
        "INSERT INTO deferred_jobs (dedupe_key, stage, group_key, queue_class, escalated,"
        " payload_json, case_id, reason, not_before, deferred_at)"
        " VALUES ('work:k', 'work', 'x.test', 'strong', 0, '{\"k\": 1}', NULL, 'recheck', ?, ?)",
        (soon, time.time()),
    )
    run_idle(store, [stage("work", work)])
    assert done == [{"k": 1}] and deferred_rows(store) == []


def test_a_queued_retry_holds_the_run_until_it_is_done(store):
    attempts = []

    async def flaky(job):
        attempts.append(job.attempts)
        if job.attempts == 1:
            raise RuntimeError("try later")

    store.jobs.enqueue("work", {})
    ran = run_idle(store, [stage("work", flaky, retry_delay_seconds=0.6)])
    assert attempts == [1, 2] and statuses(store) == ["done"] and ran >= 0.6


def test_an_idle_stop_leaves_rechecks_and_unserved_jobs_and_reports_them(store, logbuf):
    later = time.time() + 86400
    for r in (1, 2):
        defer(store, f"enrich:case:7:r{r}", not_before=later + r)
    store.jobs.enqueue("media", {"case_id": 7})  # no media stage in this run
    store.jobs.enqueue("work", {})
    before = deferred_rows(store)

    async def ok(job):
        pass

    ran = run_idle(store, [stage("work", ok)])
    assert ran < 5
    assert deferred_rows(store) == before  # byte-identical: keys, not_before, payload
    assert statuses(store) == ["pending", "done"]  # media waits for a run that serves it
    assert not store.conn.execute("SELECT 1 FROM jobs WHERE status = 'running'").fetchone()
    (rec,) = [json.loads(x) for x in logbuf.getvalue().splitlines() if "run idle" in x]
    assert rec["level"] == "INFO" and rec["deferred_not_due"] == 2
    assert rec["unserved_jobs"] == {"media": 1}


def test_duration_still_ends_a_run_that_never_goes_idle(store):
    async def ok(job):
        pass

    store.jobs.enqueue("work", {}, delay=3600)  # a retry not due within the run
    ran = run_idle(store, [stage("work", ok)], duration=0.8)
    assert 0.7 < ran < 5 and statuses(store) == ["pending"]


def test_run_service_until_idle_stops_and_refuses_discovery(store, registry_data):
    registry = Registry.model_validate(registry_data)

    async def main(**kw):
        stop = asyncio.Event()
        await asyncio.wait_for(
            run_service(store, registry, stop=stop, until_idle=True, enrich_enabled=False,
                        fetch_enabled=False, sandbox_enabled=False, **kw),
            15,
        )  # fmt: skip

    asyncio.run(main(certstream_enabled=False, dnstwist_enabled=False))
    for kw in ({"certstream_enabled": True, "dnstwist_enabled": False},
               {"certstream_enabled": False, "dnstwist_enabled": True}):  # fmt: skip
        with pytest.raises(ValueError, match="until_idle"):
            asyncio.run(main(**kw))


@pytest.mark.parametrize("flags", [[], ["--certstream"], ["--no-certstream", "--dnstwist"]])
def test_the_cli_refuses_until_idle_with_discovery_on_before_opening_the_store(
    tmp_path, monkeypatch, flags
):
    from tests.unit.test_cli import REPO

    from brandsentinel.cli import app

    monkeypatch.chdir(REPO)
    cfg = tmp_path / "c.yaml"
    discovery = "{certstream: {enabled: true}, dnstwist: {enabled: false}}"
    cfg.write_text(f"data_dir: {tmp_path / 'data'}\ndiscovery: {discovery}\n")
    result = CliRunner().invoke(app, ["--config", str(cfg), "run", "--until-idle", *flags])
    assert result.exit_code == 2 and "refusing --until-idle" in result.output
    assert not (tmp_path / "data").exists()
