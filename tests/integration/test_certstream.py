"""CertStream consumer: per-SAN events, idempotency, gaps, backoff, bounded state."""

import asyncio
import json

import pytest
import websockets
from tests.conftest import FakeClock, cert_message

from brandsentinel.config import Config, FirehoseSettings, RawLogSettings
from brandsentinel.discovery.certstream import CertStreamConsumer
from brandsentinel.discovery.events import DISCOVERY_LOG, replay
from brandsentinel.pipeline import health
from brandsentinel.store import FIREHOSE_SOURCE, open_store
from brandsentinel.store.rawlog import read_segment

THREE_SANS = ["sadhguru-donate.com", "www.isha-yoga-seva.org", "innerengineering-online.net"]


def consumer(store, matcher, clock, **kw):
    return CertStreamConsumer(store, matcher, store.config, clock=clock, **kw)


def count(store, table):
    return store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def discovery_records(store):
    store.rawlog(DISCOVERY_LOG).flush()
    return [r for seg in store.rawlog(DISCOVERY_LOG).segments() for r in read_segment(seg)]


def test_three_matching_sans_create_three_candidates_and_jobs(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message([*THREE_SANS, "unrelated.example.com"]))
    assert count(store, "candidates") == 3
    assert count(store, "jobs") == 3
    records = discovery_records(store)
    assert sorted(r["record"]["name"] for r in records) == sorted(
        ["sadhguru-donate.com", "www.isha-yoga-seva.org", "innerengineering-online.net"]
    )
    ctx = records[0]["record"]["context"]
    assert ctx["fingerprint"] == "AA:BB:CC"
    assert ctx["issuer"]["O"] == "Let's Encrypt"
    assert ctx["not_before"] == 1760000000 and ctx["not_after"] == 1767776000
    assert len(ctx["all_domains"]) == 4  # every SAN is kept as provenance


def test_non_matching_certificate_is_written_nowhere(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["example.com", "www.example.com"]))
    assert count(store, "candidates") == 0
    assert count(store, "discovery_events") == 0
    assert store.raw_sources() == []


def test_duplicate_sans_and_wildcards_on_one_certificate_collapse(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["*.sadhguru-x.com", "sadhguru-x.com", "SADHGURU-X.COM"]))
    assert count(store, "discovery_events") == 1
    assert count(store, "candidates") == 1


def test_same_certificate_twice_creates_nothing_new(store, matcher, clock):
    c = consumer(store, matcher, clock)
    msg = cert_message(THREE_SANS)
    c.handle_message(msg)
    c.handle_message(msg)
    assert c.counters.duplicate_certificates == 1
    assert (count(store, "candidates"), count(store, "jobs")) == (3, 3)


def test_certificate_seen_again_after_restart_creates_no_new_jobs(config, matcher, clock):
    s1 = open_store(config)
    consumer(s1, matcher, clock).handle_message(cert_message(THREE_SANS))
    s1.close()
    s2 = open_store(config)
    try:
        c2 = consumer(s2, matcher, clock)  # fresh in-memory dedupe cache
        c2.handle_message(cert_message(THREE_SANS))
        assert (count(s2, "candidates"), count(s2, "jobs"), count(s2, "cases")) == (3, 3, 3)
        assert count(s2, "discovery_events") == 3
    finally:
        s2.close()


def test_kill_after_log_flush_before_ingest_recovers_exactly_once(
    store, matcher, clock, monkeypatch
):
    import brandsentinel.discovery.certstream as cs

    def crash(*a, **k):
        raise KeyboardInterrupt("killed")

    monkeypatch.setattr(cs, "ingest", crash)
    with pytest.raises(KeyboardInterrupt):
        consumer(store, matcher, clock).handle_message(cert_message(THREE_SANS))
    monkeypatch.undo()
    assert count(store, "candidates") == 0
    assert len(discovery_records(store)) == 3  # flushed before processing

    replay(store, matcher)
    replay(store, matcher)
    consumer(store, matcher, clock).handle_message(cert_message(THREE_SANS))  # redelivered
    assert (count(store, "candidates"), count(store, "jobs"), count(store, "cases")) == (3, 3, 3)


def test_malformed_messages_are_logged_and_do_not_stop_the_consumer(store, matcher, clock, caplog):
    c = consumer(store, matcher, clock)
    bad_messages = [
        b"\xff\xfe",
        "not json",
        "[]",
        '{"message_type": "certificate_update"}',
        '{"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": 5}}}',
    ]
    for bad in bad_messages:
        c.handle_message(bad)
    c.handle_message(cert_message(["sadhguru-ok.com"]))
    assert c.counters.malformed == 5
    assert count(store, "candidates") == 1
    assert any("malformed" in r.message for r in caplog.records)


def test_heartbeat_keeps_feed_alive_without_side_effects(store, matcher, clock):
    c = consumer(store, matcher, clock)
    assert c.handle_message('{"message_type": "heartbeat", "timestamp": 1}')
    assert count(store, "discovery_events") == 0


def test_rawlog_failure_still_persists_the_finding(store, matcher, clock, monkeypatch, caplog):
    import brandsentinel.discovery.certstream as cs

    def disk_full(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cs, "write_events", disk_full)
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["sadhguru-full.com"]))
    assert count(store, "candidates") == 1
    assert c.counters.rawlog_errors == 1
    assert any("discovery log write failed" in r.message for r in caplog.records)


# --- coverage gaps -------------------------------------------------------------


def test_disconnect_is_recorded_as_gap_with_cert_index_jump(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["a.example"], fingerprint="1", cert_index=100))
    c.handle_message(cert_message(["b.example"], fingerprint="2", cert_index=101, log_url="L2"))
    clock.advance(1)
    c.disconnected("ConnectionClosedError")
    clock.advance(90)
    c.handle_message(cert_message(["c.example"], fingerprint="3", cert_index=150))
    c.handle_message(cert_message(["d.example"], fingerprint="4", cert_index=102, log_url="L2"))
    gap = store.conn.execute("SELECT * FROM coverage_gaps").fetchone()
    assert gap["ended_at"] - gap["started_at"] == pytest.approx(91)
    assert gap["reason"] == "ConnectionClosedError"
    jumps = json.loads(gap["detail_json"])["cert_index_jumps"]
    assert jumps == {
        "https://ct.example/log1/": {"last_seen": 100, "resumed_at": 150, "missed": 49}
    }

    h = health.collect(store, store.config, clock())
    assert h.recent_gaps and h.open_gaps_seconds_24h == pytest.approx(91)


def test_process_restart_is_recorded_as_gap(config, matcher, clock):
    s1 = open_store(config)
    c1 = consumer(s1, matcher, clock)
    c1.handle_message(cert_message(["a.example"], cert_index=10))
    c1.save_state(force=True)
    s1.close()
    clock.advance(600)
    s2 = open_store(config)
    try:
        c2 = consumer(s2, matcher, clock)
        c2.handle_message(cert_message(["b.example"], fingerprint="2", cert_index=500))
        gap = s2.conn.execute("SELECT * FROM coverage_gaps").fetchone()
        assert gap["reason"] == "process_restart"
        assert gap["ended_at"] - gap["started_at"] == pytest.approx(600)
        assert (
            json.loads(gap["detail_json"])["cert_index_jumps"]["https://ct.example/log1/"]["missed"]
            == 489
        )
    finally:
        s2.close()


def test_status_reports_stale_feed(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["a.example"]))
    c.save_state(force=True)
    assert not health.collect(store, store.config, clock()).certstream_stale
    clock.advance(store.config.discovery.certstream.stale_after_seconds + 1)
    assert health.collect(store, store.config, clock()).certstream_stale


# --- reconnect and backoff -----------------------------------------------------


def test_backoff_grows_to_cap_and_resets_after_a_message(store, matcher, clock):
    c = consumer(store, matcher, clock)
    delays = []
    for _ in range(10):
        delays.append(c.backoff())
        c.failures += 1
    assert delays[:4] == [1, 2, 4, 8]
    assert max(delays) == 60 and delays == sorted(delays)


def test_run_reconnects_and_resets_backoff_against_a_stub_server(config, matcher):
    """A real websocket server drops the client twice; the consumer reconnects,
    records gaps, and every certificate sent is processed exactly once."""
    sleeps = []

    async def scenario():
        connections = 0

        async def handler(ws):
            nonlocal connections
            connections += 1
            if connections == 1:
                await ws.close()  # drop before sending anything
                return
            await ws.send(cert_message(["sadhguru-a.com"], fingerprint=f"c{connections}"))
            await ws.send(cert_message(["sadhguru-a.com"], fingerprint=f"c{connections}"))
            if connections == 2:
                await ws.close(code=1011)
                return
            await ws.wait_closed()

        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            cfg = config.model_copy(
                update={
                    "discovery": config.discovery.model_copy(
                        update={
                            "certstream": config.discovery.certstream.model_copy(
                                update={"url": f"ws://127.0.0.1:{port}/full-stream"}
                            )
                        }
                    )
                }
            )
            store = open_store(cfg)

            async def fast_sleep(d):
                sleeps.append(d)
                await asyncio.sleep(0)

            c = CertStreamConsumer(store, matcher, cfg, sleep=fast_sleep)
            task = asyncio.create_task(c.run())
            for _ in range(200):
                await asyncio.sleep(0.02)
                if (
                    store.conn.execute("SELECT COUNT(*) FROM candidate_sources").fetchone()
                    and c.counters.certificates >= 2
                    and connections >= 3
                ):
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return store, c, connections

    store, _, connections = asyncio.run(scenario())
    try:
        assert connections >= 3
        assert sleeps[:2] == [1, 1]  # second failure came after a message: reset
        obs = store.conn.execute("SELECT observations FROM candidate_sources").fetchone()[0]
        assert obs == 2  # c2 and c3 certificates; duplicates within each skipped
        assert count(store, "cases") == 1
        assert count(store, "coverage_gaps") >= 1
        assert store.conn.execute(
            "SELECT state_json FROM source_state WHERE source='certstream'"
        ).fetchone()
    finally:
        store.close()


# --- firehose and bounds ---------------------------------------------------------


def _with_firehose(config: Config, **fh) -> Config:
    raw = config.rawlog.model_dump()
    raw["firehose"] = FirehoseSettings(enabled=True, **fh)
    return config.model_copy(update={"rawlog": RawLogSettings(**raw)})


def test_firehose_paused_by_disk_guard_still_logs_matches(config, matcher, clock, monkeypatch):
    import brandsentinel.discovery.certstream as cs

    cfg = _with_firehose(config)
    monkeypatch.setattr(cs, "free_bytes", lambda p: 0)  # disk "full"
    store = open_store(cfg)
    try:
        c = CertStreamConsumer(store, matcher, cfg, clock=clock)
        c.handle_message(cert_message(["sadhguru-a.com"]))
        assert c.counters.firehose_records == 0
        assert FIREHOSE_SOURCE not in store.raw_sources()
        assert len(discovery_records(store)) == 1
    finally:
        store.close()


def test_firehose_records_every_certificate_when_enabled(config, matcher, clock):
    store = open_store(_with_firehose(config))
    try:
        c = CertStreamConsumer(store, matcher, store.config, clock=clock)
        c.handle_message(cert_message(["example.com"], fingerprint="1"))
        c.handle_message(cert_message(["sadhguru-a.com"], fingerprint="2"))
        assert c.counters.firehose_records == 2
    finally:
        store.close()


def test_memory_stays_bounded_under_sustained_unique_traffic(store, matcher, clock):
    cfg = store.config.model_copy(
        update={
            "discovery": store.config.discovery.model_copy(
                update={
                    "certstream": store.config.discovery.certstream.model_copy(
                        update={"dedupe_cache_size": 500}
                    )
                }
            )
        }
    )
    c = CertStreamConsumer(store, matcher, cfg, clock=clock)
    for i in range(5000):
        c.handle_message(
            cert_message(
                [f"host{i}.example.com"], fingerprint=f"f{i}", log_url=f"log{i}", cert_index=i
            )
        )
        clock.advance(0.01)
    assert len(c._dedupe) == 500
    assert len(c._last_index) <= 512
    assert c.counters.certificates == 5000


def test_hourly_counters_are_sampled(store, matcher, clock):
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["sadhguru-a.com"]))
    clock.advance(3600)
    c.handle_message(cert_message(["example.com"], fingerprint="2"))
    sample = json.loads(store.conn.execute("SELECT data_json FROM health_samples").fetchone()[0])
    assert sample["certificates"] == 1 and sample["new_candidates"] == 1


def test_fake_clock_fixture_is_shared():
    assert FakeClock()() > 0


def test_database_error_on_one_event_keeps_consumer_running(store, matcher, clock, monkeypatch):
    import sqlite3

    import brandsentinel.discovery.certstream as cs

    real = cs.ingest

    def flaky(store_, matcher_, ev, **kw):
        if ev.name == "sadhguru-donate.com":
            raise sqlite3.OperationalError("database or disk is full")
        return real(store_, matcher_, ev, **kw)

    monkeypatch.setattr(cs, "ingest", flaky)
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(THREE_SANS))
    assert c.counters.ingest_errors == 1
    assert count(store, "candidates") == 2
    monkeypatch.undo()
    replay(store, matcher)  # startup replay recovers the failed event
    assert count(store, "candidates") == 3


def test_many_matching_sans_store_the_san_list_once(store, matcher, clock):
    names = [f"sadhguru-{i}.com" for i in range(200)]
    consumer(store, matcher, clock).handle_message(cert_message(names))
    lists = [
        len(json.loads(r[0])["all_domains"])
        for r in store.conn.execute("SELECT context_json FROM discovery_events")
    ]
    assert len(lists) == 200
    assert sorted(lists)[-1] == 200 and sum(lists) == 200
    counts = {
        json.loads(r[0])["san_count"]
        for r in store.conn.execute("SELECT context_json FROM discovery_events")
    }
    assert counts == {200}


def test_failed_certificate_is_retried_on_redelivery(store, matcher, clock, monkeypatch):
    import sqlite3

    import brandsentinel.discovery.certstream as cs

    real = cs.ingest
    monkeypatch.setattr(
        cs, "ingest", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("full"))
    )
    c = consumer(store, matcher, clock)
    c.handle_message(cert_message(["sadhguru-retry.com"]))
    monkeypatch.setattr(cs, "ingest", real)
    c.handle_message(cert_message(["sadhguru-retry.com"]))  # same fingerprint again
    assert count(store, "candidates") == 1


def test_unexpected_error_in_session_records_a_gap_and_reconnects(store, matcher, clock):
    attempts = []

    class Boom:
        def __init__(self, *a, **k):
            attempts.append(1)

        async def __aenter__(self):
            if len(attempts) == 1:
                raise RuntimeError("unexpected")
            raise asyncio.CancelledError

        async def __aexit__(self, *a):
            return False

    async def no_sleep(d):
        pass

    c = CertStreamConsumer(store, matcher, store.config, clock=clock, connect=Boom, sleep=no_sleep)
    c.handle_message(cert_message(["a.example"]))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(c.run())
    assert len(attempts) == 2  # reconnected after the error
    clock.advance(5)
    c.handle_message(cert_message(["b.example"], fingerprint="2"))
    gap = store.conn.execute("SELECT reason FROM coverage_gaps").fetchone()
    assert gap["reason"] == "RuntimeError"
