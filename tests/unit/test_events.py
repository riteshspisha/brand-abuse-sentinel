"""Common candidate events: validation, idempotent ingest, cross-source identity, replay."""

import gzip
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from tests.conftest import build_matcher, confirm_domain

from brandsentinel.discovery.events import (
    DISCOVERY_LOG,
    CandidateEvent,
    CertContext,
    DnstwistContext,
    event_id,
    ingest,
    replay,
    replay_since_marker,
    write_events,
)

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def cert_event(name, fingerprint="fp1", observed=T0):
    return CandidateEvent(
        event_id=event_id("certstream", fingerprint, name),
        source="certstream",
        name=name,
        observed_at=observed,
        context=CertContext(fingerprint=fingerprint, all_domains=[name]),
    )


def twist_event(name, target="sadhguru.org", run_id=1, fuzzer="addition", observed=T0):
    return CandidateEvent(
        event_id=event_id("dnstwist", target, str(run_id), name),
        source="dnstwist",
        name=name,
        observed_at=observed,
        context=DnstwistContext(target=target, fuzzer=fuzzer, run_id=run_id),
    )


def count(store, table, where="1"):
    return store.conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()[0]  # noqa: S608


# --- schema -------------------------------------------------------------------


def test_event_requires_timezone_aware_time_and_normalizes_to_utc():
    ev = cert_event(
        "x.com",
        observed=datetime(2026, 10, 9, 17, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
    )
    assert ev.observed_at == T0
    assert ev.observed_at.tzinfo == UTC
    with pytest.raises(ValidationError):
        cert_event("x.com", observed=datetime(2026, 10, 9, 12, 0))


def test_event_context_must_match_source():
    with pytest.raises(ValidationError):
        CandidateEvent(
            event_id="0" * 64,
            source="dnstwist",
            name="x.com",
            observed_at=T0,
            context=CertContext(fingerprint="f"),
        )


def test_event_rejects_unknown_fields_and_bad_ids():
    record = cert_event("x.com").to_record()
    with pytest.raises(ValidationError):
        CandidateEvent.model_validate({**record, "extra": 1})
    with pytest.raises(ValidationError):
        CandidateEvent.model_validate({**record, "event_id": "not-hex"})


def test_event_round_trips_through_its_record():
    ev = twist_event("sadhgurux.org")
    assert CandidateEvent.model_validate(json.loads(json.dumps(ev.to_record()))) == ev


# --- ingest -------------------------------------------------------------------


def test_matching_certstream_event_creates_candidate_case_and_job(store, matcher):
    r = ingest(store, matcher, cert_event("sadhguru-donate.xyz"))
    assert r.outcome == "candidate" and r.new_candidate and r.new_case and r.job_id
    row = store.conn.execute("SELECT * FROM candidates").fetchone()
    assert row["name"] == "sadhguru-donate.xyz"
    assert row["match_strength"] == "strong"
    job = store.conn.execute("SELECT * FROM jobs").fetchone()
    assert job["stage"] == "enrich" and job["queue_class"] == "strong"
    assert json.loads(job["payload_json"])["case_id"] == r.case_id
    ev = store.conn.execute("SELECT * FROM discovery_events").fetchone()
    assert json.loads(ev["match_json"])["matcher_version"]
    assert json.loads(ev["context_json"])["fingerprint"] == "fp1"


def test_same_event_twice_is_a_no_op(store, matcher):
    ev = cert_event("sadhguru-donate.xyz")
    first = ingest(store, matcher, ev)
    second = ingest(store, matcher, ev)
    assert second.outcome == "duplicate"
    assert second.candidate_id == first.candidate_id
    assert count(store, "discovery_events") == 1
    assert count(store, "cases") == 1
    assert count(store, "jobs") == 1
    assert store.conn.execute("SELECT observations FROM candidate_sources").fetchone()[0] == 1


def test_new_certificate_for_known_host_is_a_repeat_observation_not_a_new_case(store, matcher):
    ingest(store, matcher, cert_event("sadhguru-donate.xyz", "fp1"))
    later = ingest(
        store, matcher, cert_event("sadhguru-donate.xyz", "fp2", observed=T0 + timedelta(days=1))
    )
    assert later.outcome == "candidate" and not later.new_case and later.job_id is None
    assert count(store, "cases") == 1 and count(store, "jobs") == 1
    src = store.conn.execute("SELECT * FROM candidate_sources").fetchone()
    assert src["observations"] == 2
    assert src["last_seen"] - src["first_seen"] == 86400


def test_domain_from_both_sources_is_one_candidate_with_both_provenances(store, matcher):
    a = ingest(store, matcher, twist_event("sadhgurux.org"))
    b = ingest(store, matcher, cert_event("SADHGURUX.ORG"))
    assert a.candidate_id == b.candidate_id
    assert count(store, "candidates") == 1
    assert count(store, "cases") == 1
    assert count(store, "jobs") == 1
    sources = dict(store.conn.execute("SELECT source, observations FROM candidate_sources"))
    assert sources == {"dnstwist": 1, "certstream": 1}


def test_wildcard_and_idn_forms_share_identity(store, matcher):
    a = ingest(store, matcher, cert_event("*.sadhguru-login.com", "fp1"))
    b = ingest(store, matcher, cert_event("sadhguru-login.com", "fp2"))
    assert a.candidate_id == b.candidate_id


def test_dnstwist_lookalike_is_strong_even_without_keyword_hit(store, matcher):
    # `lsha.in` (bitsquat of isha.in) carries no brand keyword; dnstwist found it
    # as a permutation of an official domain, which is the evidence.
    r = ingest(store, matcher, twist_event("lsha.in", target="isha.in", fuzzer="bitsquatting"))
    assert r.outcome == "candidate"
    assert store.conn.execute("SELECT match_strength FROM candidates").fetchone()[0] == "strong"
    ctx = json.loads(store.conn.execute("SELECT context_json FROM discovery_events").fetchone()[0])
    assert ctx["fuzzer"] == "bitsquatting" and ctx["target"] == "isha.in"


def test_non_matching_certstream_name_creates_no_candidate(store, matcher):
    r = ingest(store, matcher, cert_event("example.com"))
    assert r.outcome == "no_match"
    assert count(store, "candidates") == 0 and count(store, "jobs") == 0


def test_invalid_name_is_reported_not_raised(store, matcher):
    r = ingest(store, matcher, cert_event("bad..name"))
    assert r.outcome == "invalid"
    assert count(store, "discovery_events") == 0


# --- suppression and legacy-unverified entries (R6, AE1, AE20) ---------------


def test_legacy_unverified_whitelist_entry_does_not_hide_a_domain(store, matcher):
    r = ingest(store, matcher, cert_event("shop.ishalife.com"))
    assert r.outcome == "candidate"
    match = json.loads(store.conn.execute("SELECT match_json FROM discovery_events").fetchone()[0])
    assert "legacy_whitelist_unverified" in match["labels"]


def test_legacy_unverified_official_domain_is_still_a_dnstwist_candidate(store, matcher):
    # sadhguru.org is legacy-unverified, so its own subdomains are reported too.
    r = ingest(store, matcher, twist_event("www.sadhguru.org"))
    assert r.outcome == "candidate"


def test_only_confirmed_domains_suppress_and_never_by_substring(store, registry_data):
    confirm_domain(registry_data, "sadhguru.org")
    m = build_matcher(registry_data)
    assert ingest(store, m, cert_event("www.sadhguru.org", "f1")).outcome == "suppressed"
    assert ingest(store, m, twist_event("www.sadhguru.org", run_id=2)).outcome == "suppressed"
    for i, name in enumerate(["sadhguru.org.verify-login.xyz", "login-sadhguru.org.ru"]):
        assert ingest(store, m, cert_event(name, f"g{i}")).outcome == "candidate", name
    assert count(store, "candidates") == 2


def test_exclusion_does_not_suppress_an_independent_strong_hit(store, matcher):
    r = ingest(store, matcher, cert_event("vishal-sadhguru-tickets.com"))
    assert r.outcome == "candidate"
    assert store.conn.execute("SELECT match_strength FROM candidates").fetchone()[0] == "strong"


def test_weak_candidate_upgrades_to_strong_on_strong_sighting(store, matcher):
    ingest(store, matcher, cert_event("isha-yoga-donate.in"))
    assert store.conn.execute("SELECT match_strength FROM candidates").fetchone()[0] == "weak"
    ingest(store, matcher, twist_event("isha-yoga-donate.in", target="isha.in"))
    assert store.conn.execute("SELECT match_strength FROM candidates").fetchone()[0] == "strong"


def test_untrusted_context_strings_are_sanitized(store, matcher):
    ev = CandidateEvent(
        event_id=event_id("certstream", "fpx", "sadhguru-x.com"),
        source="certstream",
        name="sadhguru-x.com",
        observed_at=T0,
        context=CertContext(fingerprint="fpx", issuer={"O": "Evil\x1b]0;pwn\x07\u202eCorp"}),
    )
    ingest(store, matcher, ev)
    ctx = json.loads(store.conn.execute("SELECT context_json FROM discovery_events").fetchone()[0])
    assert "\x1b" not in ctx["issuer"]["O"] and "\u202e" not in ctx["issuer"]["O"]


# --- replay -------------------------------------------------------------------


def test_replay_after_crash_completes_work_exactly_once(store, matcher):
    events = [cert_event(f"sadhguru-{i}.com", f"fp{i}") for i in range(3)]
    write_events(store.rawlog(DISCOVERY_LOG), events)
    ingest(store, matcher, events[0])  # crash after ingesting only the first
    store.rawlog(DISCOVERY_LOG).close()

    stats = replay(store, matcher)
    assert (stats.records, stats.ingested, stats.duplicates) == (3, 2, 1)
    again = replay(store, matcher)
    assert (again.ingested, again.duplicates) == (0, 3)
    assert count(store, "candidates") == 3
    assert count(store, "cases") == 3
    assert count(store, "jobs") == 3
    assert store.conn.execute("SELECT SUM(observations) FROM candidate_sources").fetchone()[0] == 3


def test_replay_reads_a_segment_truncated_by_a_crash(store, matcher):
    log = store.rawlog(DISCOVERY_LOG)
    write_events(log, [cert_event("sadhguru-a.com", "a")])
    write_events(log, [cert_event("sadhguru-b.com", "b")])
    path = log.current_segment
    log._abandon_segment()  # simulate a kill: no gzip trailer
    with path.open("ab") as f:
        f.write(b"\x00garbage")
    assert replay(store, matcher).ingested == 2


def test_replay_skips_unreadable_records_and_keeps_going(store, matcher):
    log = store.rawlog(DISCOVERY_LOG)
    log.write({"not": "an event"}, durable=True)
    write_events(log, [cert_event("sadhguru-ok.com")])
    log.close()
    stats = replay(store, matcher)
    assert stats.invalid == 1 and stats.ingested == 1


def test_replay_since_marker_only_reads_recent_segments(store, matcher, config):
    old_dir = config.raw_dir / DISCOVERY_LOG
    old_dir.mkdir(parents=True, exist_ok=True)
    with gzip.open(old_dir / "20261001-1-1.jsonl.gz", "wt") as f:
        record = cert_event("sadhguru-old.com").to_record()
        f.write(json.dumps({"logged_at": "2026-10-01T00:00:00+00:00", "record": record}) + "\n")
    from brandsentinel.discovery.events import put_state

    put_state(store.conn, "discovery-replay", {"checkpoint": T0.timestamp()}, T0.timestamp())
    assert replay_since_marker(store, matcher, now=T0.timestamp()).records == 0
    assert replay(store, matcher).ingested == 1  # a full replay still sees it


def test_failed_ingest_holds_the_checkpoint_until_replayed(store, matcher):
    import time

    from brandsentinel.discovery.events import checkpoint, hold_replay

    now = time.time()  # the raw log stamps records with the real clock
    write_events(store.rawlog(DISCOVERY_LOG), [cert_event("sadhguru-held.com")])
    hold_replay(store, now)  # its ingest failed
    checkpoint(store, now + 3600)  # maintenance runs later
    store.rawlog(DISCOVERY_LOG).close()
    stats = replay_since_marker(store, matcher, now=now + 7200)
    assert stats.ingested == 1
    assert count(store, "candidates") == 1
    # The hold is cleared once replayed.
    from brandsentinel.discovery.events import REPLAY_STATE, get_state

    assert "hold" not in get_state(store.conn, REPLAY_STATE)


def test_full_replay_skips_records_older_than_event_retention(store, matcher):
    from brandsentinel.store.retention import prune_discovery_events

    old = cert_event("sadhguru-ancient.com", observed=T0)
    write_events(store.rawlog(DISCOVERY_LOG), [old])
    store.rawlog(DISCOVERY_LOG).close()
    ingest(store, matcher, old)
    later = T0.timestamp() + 400 * 86400
    prune_discovery_events(store.conn, now=later, max_age_days=365)
    stats = replay(store, matcher, now=later)
    assert stats.ingested == 0
    assert store.conn.execute("SELECT observations FROM candidate_sources").fetchone()[0] == 1
