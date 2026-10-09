"""Raw-log and discovery-event retention."""

import os

from tests.unit.test_events import T0, cert_event

from brandsentinel.discovery.events import DISCOVERY_LOG, ingest
from brandsentinel.store.retention import DAY, prune_discovery_events, prune_rawlog


def test_discovery_segments_are_pruned_by_age_only(store, clock):
    log = store.rawlog(DISCOVERY_LOG)
    log.write({"n": 1}, durable=True)
    old = log.current_segment
    log.close()
    log.write({"n": 2}, durable=True)
    young = log.current_segment
    log.close()
    os.utime(old, (clock() - 400 * DAY, clock() - 400 * DAY))
    os.utime(young, (clock() - 300 * DAY, clock() - 300 * DAY))
    r = prune_rawlog(log, now=clock(), max_age_days=365)
    assert r.removed == 1
    assert not old.exists() and young.exists()


def test_size_cap_removes_oldest_first_but_never_the_open_segment(store, clock):
    log = store.rawlog("certstream-firehose")
    paths = []
    for i in range(3):
        log.write({"pad": "x" * 5000, "i": i}, durable=True)
        paths.append(log.current_segment)
        if i < 2:
            log.close()
        os.utime(paths[-1], (clock() + i, clock() + i))
    r = prune_rawlog(log, now=clock(), max_age_days=7, max_bytes=1)
    assert r.removed == 2
    assert paths[2].exists() and not paths[0].exists()


def test_discovery_event_rows_are_pruned_by_age_but_candidates_kept(store, matcher):
    ingest(store, matcher, cert_event("sadhguru-old.com"))
    removed = prune_discovery_events(store.conn, now=T0.timestamp() + 400 * DAY, max_age_days=365)
    assert removed == 1
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 1
    assert store.conn.execute("SELECT COUNT(*) FROM candidate_sources").fetchone()[0] == 1
