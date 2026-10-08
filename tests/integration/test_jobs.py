import pytest

from brandsentinel.store.db import connect
from brandsentinel.store.jobs import JobQueue, LeaseLost


@pytest.fixture
def two_queues(config, clock):
    """Two workers with separate connections to the same database file."""
    a = connect(config.db_path)
    b = connect(config.db_path)
    yield JobQueue(a, clock=clock), JobQueue(b, clock=clock)
    a.close()
    b.close()


def _rows(q):
    return [tuple(r) for r in q._conn.execute("SELECT status, attempts FROM jobs ORDER BY id")]


def test_claim_takes_a_lease_that_blocks_other_workers(two_queues, clock):
    qa, qb = two_queues
    qa.enqueue("fetch", {"url": "https://example.test"})
    job = qa.claim("fetch", "worker-a", lease_seconds=60)
    assert job is not None and job.attempts == 1
    assert qb.claim("fetch", "worker-b", 60) is None
    clock.advance(61)
    stolen = qb.claim("fetch", "worker-b", 60)
    assert stolen is not None and stolen.id == job.id and stolen.attempts == 2


def test_renewed_lease_is_not_reclaimed(two_queues, clock):
    qa, qb = two_queues
    qa.enqueue("render", {})
    job = qa.claim("render", "a", 60)
    clock.advance(50)
    qa.renew(job, 60)
    clock.advance(50)  # past the original expiry, within the renewed one
    assert qb.claim("render", "b", 60) is None
    qa.complete(job)
    assert _rows(qa) == [("done", 1)]


def test_crash_recovery_completes_exactly_once(two_queues, clock):
    qa, qb = two_queues
    qa.enqueue("fetch", {"n": 1})
    job = qa.claim("fetch", "a", 60)
    # worker a "crashes"; the restarted process recovers expired leases
    clock.advance(120)
    assert qb.recover_expired() == 1
    retry = qb.claim("fetch", "b", 60)
    qb.complete(retry)
    with pytest.raises(LeaseLost):
        qa.complete(job)  # the stale worker cannot complete it again
    assert _rows(qb) == [("done", 2)]


def test_stale_claim_with_same_owner_name_is_rejected(store, clock):
    q = JobQueue(store.conn, clock=clock)
    q.enqueue("fetch", {})
    first = q.claim("fetch", "worker-1", 30)
    clock.advance(31)
    second = q.claim("fetch", "worker-1", 30)  # same owner string, new claim
    with pytest.raises(LeaseLost):
        q.complete(first)
    with pytest.raises(LeaseLost):
        q.renew(first, 30)
    q.complete(second)
    assert _rows(q) == [("done", 2)]


def test_expired_holder_cannot_renew_or_fail(two_queues, clock):
    qa, _ = two_queues
    qa.enqueue("fetch", {})
    job = qa.claim("fetch", "a", 10)
    clock.advance(11)
    with pytest.raises(LeaseLost):
        qa.renew(job, 10)
    with pytest.raises(LeaseLost):
        qa.fail(job, "late")
    with pytest.raises(LeaseLost):
        qa.complete(job)


def test_job_exceeding_attempt_limit_ends_failed_with_last_error(store, clock):
    q = JobQueue(store.conn, clock=clock, default_max_attempts=2)
    q.enqueue("fetch", {})
    assert q.fail(q.claim("fetch", "w", 60), "timeout one") == "pending"
    assert q.fail(q.claim("fetch", "w", 60), "timeout two") == "failed"
    assert q.claim("fetch", "w", 60) is None
    row = store.conn.execute("SELECT status, attempts, last_error FROM jobs").fetchone()
    assert tuple(row) == ("failed", 2, "timeout two")


def test_lease_expiry_on_final_attempt_fails_the_job_at_claim(store, clock):
    q = JobQueue(store.conn, clock=clock, default_max_attempts=1)
    q.enqueue("render", {})
    q.claim("render", "w", 30)
    clock.advance(31)
    assert q.claim("render", "w2", 30) is None
    assert _rows(q) == [("failed", 1)]


def test_recover_expired_fails_jobs_out_of_attempts(store, clock):
    q = JobQueue(store.conn, clock=clock, default_max_attempts=1)
    q.enqueue("render", {})
    q.claim("render", "w", 30)
    clock.advance(31)
    assert q.recover_expired() == 1
    row = store.conn.execute("SELECT status, last_error FROM jobs").fetchone()
    assert tuple(row) == ("failed", "lease expired")


def test_recover_expired_leaves_live_leases_alone(store, clock):
    q = JobQueue(store.conn, clock=clock)
    q.enqueue("fetch", {})
    job = q.claim("fetch", "w", 60)
    clock.advance(30)
    assert q.recover_expired() == 0
    q.complete(job)


def test_retry_delay_defers_the_job(store, clock):
    q = JobQueue(store.conn, clock=clock)
    q.enqueue("fetch", {})
    q.fail(q.claim("fetch", "w", 60), "429", retry_delay=30)
    assert q.claim("fetch", "w", 60) is None
    clock.advance(30)
    assert q.claim("fetch", "w", 60) is not None


def test_strong_jobs_are_claimed_before_weak(store, clock):
    q = JobQueue(store.conn, clock=clock)
    weak, _ = q.enqueue("enrich", {"n": "weak"}, queue_class="weak")
    clock.advance(1)
    strong, _ = q.enqueue("enrich", {"n": "strong"}, queue_class="strong")
    assert q.claim("enrich", "w", 60).id == strong
    assert q.claim("enrich", "w", 60).id == weak


def test_claim_is_scoped_to_stage(store, clock):
    q = JobQueue(store.conn, clock=clock)
    q.enqueue("fetch", {})
    assert q.claim("render", "w", 60) is None


def test_dedupe_key_returns_live_job(store, clock):
    q = JobQueue(store.conn, clock=clock)
    first = q.enqueue("enrich", {"a": 1}, dedupe_key="enrich:example.test")
    second = q.enqueue("enrich", {"a": 2}, dedupe_key="enrich:example.test")
    assert first == (first[0], True)
    assert second == (first[0], False)
    job = q.claim("enrich", "w", 60)  # still deduplicated while running
    assert q.enqueue("enrich", {}, dedupe_key="enrich:example.test") == (first[0], False)
    q.complete(job)


def test_dedupe_key_can_be_reused_after_job_finishes(store, clock):
    q = JobQueue(store.conn, clock=clock, default_max_attempts=1)
    first, _ = q.enqueue("enrich", {}, dedupe_key="recheck:x.test")
    q.complete(q.claim("enrich", "w", 60))
    second, created = q.enqueue("enrich", {}, dedupe_key="recheck:x.test")
    assert created and second != first
    q.fail(q.claim("enrich", "w", 60), "boom")
    third, created = q.enqueue("enrich", {}, dedupe_key="recheck:x.test")
    assert created and third not in (first, second)


def test_jobs_without_dedupe_key_never_conflict(store, clock):
    q = JobQueue(store.conn, clock=clock)
    assert q.enqueue("fetch", {})[1] and q.enqueue("fetch", {})[1]


def test_error_text_is_sanitized(store, clock):
    q = JobQueue(store.conn, clock=clock)
    q.enqueue("fetch", {})
    q.fail(q.claim("fetch", "w", 60), "bad title \x1b]0;x\x07\u202e")
    err = store.conn.execute("SELECT last_error FROM jobs").fetchone()[0]
    assert "\x1b" not in err and "\u202e" not in err
