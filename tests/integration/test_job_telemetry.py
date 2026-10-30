"""Job lifecycle telemetry (M8): one `job started` and one `job finished` per
claimed job, from an allowlist, and no URL, query, credential, page text or
exception message in any record, whatever fails. The full error stays in
`jobs.last_error`."""

import asyncio
import io
import json
import logging
from datetime import UTC, datetime

import pytest
from tests.detection_support import lab_registry
from tests.integration.test_orchestrator import done_count, drain

from brandsentinel.config import Config
from brandsentinel.logging import configure_logging
from brandsentinel.net.fetcher import FetchResult
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage, job_fields
from brandsentinel.pipeline.stages import AnalysisStages, build_network
from brandsentinel.store import open_store
from brandsentinel.store.jobs import Job

SECRET_URL = "https://x.test/path?session=SECRET123#frag"  # noqa: S105 - a planted marker
FORBIDDEN = ("SECRET123", "session=", "/path", "hunter2", "PAGE-TEXT-MARKER", "#frag")
LIFECYCLE_KEYS = {"job", "stage", "case_id", "round", "attempt", "domain"}
FINISHED_KEYS = LIFECYCLE_KEYS | {"outcome", "duration_ms"}
COMMON = {"ts", "level", "logger", "msg"}


@pytest.fixture
def logbuf():
    root = logging.getLogger("brandsentinel")
    saved = (root.handlers[:], root.level, root.propagate)
    buf = io.StringIO()
    configure_logging("DEBUG", stream=buf)
    yield buf
    root.handlers[:], root.level, root.propagate = saved


def records(buf) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def lifecycle(buf, msg) -> list[dict]:
    return [r for r in records(buf) if r["msg"] == msg]


def assert_clean(buf, *extra):
    text = buf.getvalue()
    for needle in FORBIDDEN + extra:
        assert needle not in text, needle


def one_start_and_finish_per_job(buf) -> dict[int, dict]:
    started = lifecycle(buf, "job started")
    finished = lifecycle(buf, "job finished")
    keys = [(r["job"], r["attempt"]) for r in started]
    assert sorted(keys) == sorted((r["job"], r["attempt"]) for r in finished)
    assert len(set(keys)) == len(keys)
    for r in started:
        assert set(r) - COMMON <= LIFECYCLE_KEYS, r
    for r in finished:
        assert set(r) - COMMON <= FINISHED_KEYS, r
        assert isinstance(r["duration_ms"], int) and r["duration_ms"] >= 0
    return {(r["job"], r["attempt"]): r for r in finished}


class LeakyFetcher:
    """A fetcher whose results carry the URL (as netguard refusals do) in the
    error, and time out on the first attempt."""

    def __init__(self) -> None:
        self.calls = 0

    async def fetch(self, url, *, mode, max_bytes):
        self.calls += 1
        return FetchResult(
            requested_url=url,
            mode="evidence",
            purpose="evidence",
            started_at=datetime.now(UTC).isoformat(),
            outcome="timeout",
            error={"url": url, "message": f"timed out reading {url} password=hunter2"},
        )


def test_no_record_leaks_the_url_query_or_error_text_and_the_store_keeps_it(
    tmp_path, logbuf, monkeypatch
):
    from brandsentinel.discovery.submit import submit
    from brandsentinel.matching.matcher import Matcher

    config = Config(data_dir=tmp_path / "data", jobs={"max_attempts": 2})
    store = open_store(config)
    try:
        registry = lab_registry()
        guard, _ = build_network(config)
        stages = AnalysisStages(store, registry, guard=guard, fetcher=LeakyFetcher())

        def bad_score(case_id):
            raise ValueError(f"cannot score {SECRET_URL}: PAGE-TEXT-MARKER")

        monkeypatch.setattr(stages.scorer, "score", bad_score)
        case_id = submit(store, Matcher(registry), SECRET_URL).case_id

        async def leaky(job):
            raise RuntimeError(f"upstream refused {SECRET_URL} with password=hunter2")

        store.jobs.enqueue("other", {"case_id": case_id, "name": "x.test", "round": 0,
                                     "registrable_domain": "x.test"},
                           group_key="x.test", max_attempts=1)  # fmt: skip
        orch = Orchestrator(store)
        stages.register(orch)
        orch.register_stage(Stage("other", leaky, concurrency=1, poll_seconds=0.01))
        for s in orch.stages.values():
            s.poll_seconds = 0.01
            s.retry_delay_seconds = 0.0
        drain(
            orch,
            lambda: (
                store.conn.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'running')"
                ).fetchone()[0]
                == 0
            ),
            timeout=20,
        )
    finally:
        rows = store.conn.execute("SELECT stage, status, last_error FROM jobs").fetchall()
        store.close()

    assert_clean(logbuf, "lease_token")
    finished = one_start_and_finish_per_job(logbuf)
    assert {(r["stage"], r["outcome"]) for r in finished.values()} == {
        ("enrich", "completed"),
        ("fetch", "retry"),  # attempt 1 timed out
        ("fetch", "completed"),  # attempt 2 recorded the timeout as the result
        ("other", "failed"),
    }
    assert all(r["domain"] == "x.test" and r["case_id"] == case_id for r in finished.values())
    failed = lifecycle(logbuf, "job failed")
    assert {r["error_type"] for r in failed} == {"TransientFetchFailure", "RuntimeError"}
    fetch_fail = next(r for r in failed if r["error_type"] == "TransientFetchFailure")
    assert fetch_fail["fetch_outcome"] == "timeout" and "error" not in fetch_fail
    assert all(isinstance(r["error_at"], list) for r in failed)
    scoring = lifecycle(logbuf, "scoring failed")
    assert scoring and scoring[0]["error_type"] == "ValueError" and "exc" not in scoring[0]
    errors = {stage: e for stage, _, e in rows if e}
    assert "SECRET123" in errors["fetch"] and "hunter2" in errors["fetch"]
    assert "SECRET123" in errors["other"]


def test_a_failure_that_cannot_be_recorded_logs_no_chained_message(store, logbuf, monkeypatch):
    import sqlite3

    async def leaky(job):
        raise RuntimeError(f"refused {SECRET_URL}")

    def broken_fail(*a, **k):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store.jobs, "fail", broken_fail)
    store.jobs.enqueue("work", {"case_id": 1}, max_attempts=1)
    orch = Orchestrator(store)
    orch.register_stage(Stage("work", leaky, concurrency=1, poll_seconds=0.01))
    drain(orch, lambda: lifecycle(logbuf, "job finished"))
    assert_clean(logbuf)
    (rec,) = lifecycle(logbuf, "could not record job failure")
    assert rec["error_type"] == "OperationalError" and "exc" not in rec
    assert lifecycle(logbuf, "job finished")[0]["outcome"] == "unrecorded"


def test_lease_loss_and_cancellation_each_end_with_one_finished_record(store, logbuf):
    started = asyncio.Event()

    async def slow(job):
        started.set()
        await asyncio.sleep(30)

    store.jobs.enqueue("steal", {"case_id": 1, "round": 0})
    orch = Orchestrator(store)
    orch.register_stage(Stage("steal", slow, concurrency=1, poll_seconds=0.01, lease_seconds=0.09))

    def stolen():
        # Another claimer took the job: renewal fails and the handler is cancelled.
        store.conn.execute("UPDATE jobs SET lease_token = 'other' WHERE stage = 'steal'")
        return bool(lifecycle(logbuf, "job finished"))

    drain(orch, lambda: started.is_set() and stolen())
    (fin,) = lifecycle(logbuf, "job finished")
    assert fin["outcome"] == "lease_lost" and fin["stage"] == "steal"

    store.jobs.enqueue("long", {"case_id": 2, "round": 1})
    orch = Orchestrator(store)
    begun = []

    async def long(job):
        begun.append(job.id)
        await asyncio.sleep(30)

    orch.register_stage(Stage("long", long, concurrency=1, poll_seconds=0.01))
    drain(orch, lambda: bool(begun))  # shutdown while the handler runs
    fins = [r for r in lifecycle(logbuf, "job finished") if r["stage"] == "long"]
    assert [r["outcome"] for r in fins] == ["cancelled"]
    one_start_and_finish_per_job(logbuf)


def test_completed_jobs_log_started_then_finished(store, logbuf):
    async def ok(job):
        pass

    for i in range(3):
        store.jobs.enqueue("work", {"case_id": i, "round": 0, "registrable_domain": "a.test"},
                           group_key="a.test")  # fmt: skip
    orch = Orchestrator(store)
    orch.register_stage(Stage("work", ok, concurrency=2, poll_seconds=0.01))
    drain(orch, lambda: done_count(store) == 3)
    finished = one_start_and_finish_per_job(logbuf)
    assert sorted(r["outcome"] for r in finished.values()) == ["completed"] * 3
    msgs = [r["msg"] for r in records(logbuf) if r["msg"].startswith("job ")]
    first = {}
    for i, m in enumerate(msgs):
        first.setdefault(m, i)
    assert first["job started"] < first["job finished"]


def job(payload, group_key=None) -> Job:
    return Job(1, "fetch", "strong", payload, 1, 3, "w", "TOKEN-SECRET", 0.0, group_key)


@pytest.mark.parametrize(
    "payload, group_key, expected",
    [
        ({"case_id": 3, "round": 1, "registrable_domain": "x.test", "name": "a.x.test",
          "subject_url": SECRET_URL}, "x.test",
         {"job": 1, "stage": "fetch", "attempt": 1, "case_id": 3, "round": 1, "domain": "x.test"}),
        # Values that are not what they claim to be are dropped, never logged.
        ({"case_id": "3; drop", "round": True, "registrable_domain": "x.test/path?q=1"}, None,
         {"job": 1, "stage": "fetch", "attempt": 1}),
        ({"registrable_domain": None}, "Evil Domain\n", {"job": 1, "stage": "fetch", "attempt": 1}),
        ({}, "group.test", {"job": 1, "stage": "fetch", "attempt": 1, "domain": "group.test"}),
    ],
)  # fmt: skip
def test_job_fields_are_an_allowlist(payload, group_key, expected):
    assert job_fields("fetch", job(payload, group_key)) == expected
