"""The common discovery event, its persistence, and raw-log replay.

Every source (CertStream, dnstwist, manual submission) turns what it saw into
`CandidateEvent`s: one per observed host, with a deterministic `event_id` and the
source's own metadata as a typed `context`. The event is written durably to the
`discovery` raw log first, then `ingest` records it in SQLite.

`ingest` is idempotent on `event_id`: the event row, candidate upsert, per-source
summary, case and enrich job are written in one transaction, and a second ingest
of the same event changes nothing. Replaying the raw log after a crash therefore
completes interrupted work without duplicating it.

Identity is the canonical ASCII host (`MatchResult.host`), shared by every
source, so a name found by both dnstwist and CertStream is one candidate with
two `candidate_sources` rows.

Suppression is decided by the matcher alone: only a confirmed official domain
suppresses. dnstwist results are official-domain lookalikes by construction and
become strong candidates unless suppressed; manual submissions are never
suppressed but record the official domain they fall under.
"""

import hashlib
import json
import logging
import sqlite3
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from brandsentinel.matching.matcher import Matcher, MatchResult
from brandsentinel.matching.normalize import InvalidName
from brandsentinel.store import Store
from brandsentinel.store.db import transaction
from brandsentinel.store.rawlog import RawLog, read_segment
from brandsentinel.store.records import sanitize_value, upsert_candidate

log = logging.getLogger(__name__)

DISCOVERY_LOG = "discovery"
EVENT_SCHEMA_VERSION = 1
ENRICH_STAGE = "enrich"
MAX_NAME_CHARS = 1024
MAX_LIST_ITEMS = 1000

Source = Literal["certstream", "dnstwist", "manual"]
Outcome = Literal["candidate", "suppressed", "no_match", "duplicate", "invalid"]


class _Context(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CertContext(_Context):
    """Certificate provenance. Strings come from the CT log, so they are untrusted."""

    kind: Literal["certstream"] = "certstream"
    fingerprint: str = Field(max_length=200)
    issuer: dict[str, str | None] = {}
    not_before: float | None = None
    not_after: float | None = None
    serial_number: str | None = Field(None, max_length=200)
    # Every SAN, on the certificate's first matching event only; later events
    # from the same certificate carry san_count and an empty list.
    all_domains: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    san_count: int | None = None
    cert_index: int | None = None
    log_url: str | None = Field(None, max_length=500)
    log_name: str | None = Field(None, max_length=500)
    seen: float | None = None  # server's timestamp, when it sent one


class DnstwistContext(_Context):
    kind: Literal["dnstwist"] = "dnstwist"
    target: str = Field(max_length=253)  # the official domain that was permuted
    fuzzer: str = Field(max_length=64)
    run_id: int
    dns: dict[str, list[str]] = {}  # dns_a, dns_aaaa, dns_mx, dns_ns as reported


class ManualContext(_Context):
    kind: Literal["manual"] = "manual"
    submitted: str = Field(max_length=2048)  # the URL or domain as entered
    url: str | None = Field(None, max_length=2048)


Context = Annotated[CertContext | DnstwistContext | ManualContext, Field(discriminator="kind")]


class CandidateEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = EVENT_SCHEMA_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: Source
    name: str = Field(min_length=1, max_length=MAX_NAME_CHARS)  # host as observed
    observed_at: datetime
    context: Context

    @field_validator("observed_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def _context_matches_source(self):
        if self.context.kind != self.source:
            raise ValueError(f"context kind {self.context.kind!r} != source {self.source!r}")
        return self

    def to_record(self) -> dict:
        return self.model_dump(mode="json")


def event_id(source: Source, *parts: str) -> str:
    """Deterministic id over a source's identity for one observation."""
    material = "\x1f".join((source, *parts))
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


@dataclass(frozen=True)
class IngestResult:
    outcome: Outcome
    host: str | None = None
    candidate_id: int | None = None
    case_id: int | None = None
    new_candidate: bool = False
    new_case: bool = False
    job_id: int | None = None


def _decide(event: CandidateEvent, m: MatchResult) -> tuple[str, str | None]:
    """(outcome, strength) for a matched event."""
    if event.source == "manual":
        return "candidate", "strong"
    if m.suppressed_by:
        return "suppressed", None
    if event.source == "dnstwist":
        return "candidate", "strong"
    if m.candidate:
        return "candidate", m.strength
    return "no_match", None


def ingest(
    store: Store,
    matcher: Matcher,
    event: CandidateEvent,
    *,
    match: MatchResult | None = None,
    now: float | None = None,
) -> IngestResult:
    """Persist one event idempotently. Never raises for a bad name."""
    try:
        m = match or matcher.match(event.name)
    except InvalidName:
        return IngestResult("invalid")
    outcome, strength = _decide(event, m)
    now = time.time() if now is None else now
    observed = event.observed_at.timestamp()
    max_chars = store.config.text.max_fact_chars
    match_json = m.to_json()
    context_json = json.dumps(
        sanitize_value(event.context.model_dump(mode="json"), max_chars),
        sort_keys=True,
        ensure_ascii=True,
    )
    conn = store.conn
    with transaction(conn):
        inserted = conn.execute(
            "INSERT INTO discovery_events (event_id, source, name, observed_at, outcome,"
            " match_json, context_json, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (event_id) DO NOTHING",
            (
                event.event_id,
                event.source,
                m.host,
                observed,
                outcome,
                match_json,
                context_json,
                now,
            ),
        ).rowcount
        if not inserted:
            row = conn.execute(
                "SELECT candidate_id FROM discovery_events WHERE event_id = ?", (event.event_id,)
            ).fetchone()
            return IngestResult("duplicate", m.host, candidate_id=row[0] if row else None)
        if outcome != "candidate":
            return IngestResult(outcome, m.host)

        candidate_id, new_candidate = upsert_candidate(
            conn,
            m.host,
            match_strength=strength,
            registrable_domain=m.registrable_domain or None,
            now=observed,
        )
        conn.execute(
            "UPDATE discovery_events SET candidate_id = ? WHERE event_id = ?",
            (candidate_id, event.event_id),
        )
        conn.execute(
            "INSERT INTO candidate_sources (candidate_id, source, first_seen, last_seen,"
            " observations) VALUES (?, ?, ?, ?, 1) ON CONFLICT (candidate_id, source) DO UPDATE"
            " SET first_seen = MIN(first_seen, excluded.first_seen),"
            " last_seen = MAX(last_seen, excluded.last_seen), observations = observations + 1",
            (candidate_id, event.source, observed, observed),
        )
        case_id, new_case = _open_case(conn, candidate_id, event, now)
        job_id = None
        if new_case:
            job_id, _ = store.jobs.enqueue(
                ENRICH_STAGE,
                {
                    "case_id": case_id,
                    "candidate_id": candidate_id,
                    "name": m.host,
                    "registrable_domain": m.registrable_domain,
                },
                queue_class=strength,
                dedupe_key=f"{ENRICH_STAGE}:case:{case_id}",
            )
    return IngestResult("candidate", m.host, candidate_id, case_id, new_candidate, new_case, job_id)


def _open_case(
    conn: sqlite3.Connection, candidate_id: int, event: CandidateEvent, now: float
) -> tuple[int, bool]:
    row = conn.execute(
        "SELECT id FROM cases WHERE candidate_id = ? AND status = 'open'", (candidate_id,)
    ).fetchone()
    if row:
        return row[0], False
    url = event.context.url if isinstance(event.context, ManualContext) else None
    cur = conn.execute(
        "INSERT INTO cases (candidate_id, subject_url, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (candidate_id, url, now, now),
    )
    return cur.lastrowid, True


def write_events(rawlog: RawLog, events: Iterable[CandidateEvent]) -> int:
    """Append events to the discovery log; the last write is fsynced.

    Raises OSError if the log cannot be written; callers log it and still
    ingest, because a finding in SQLite is better than none."""
    events = list(events)
    for i, ev in enumerate(events):
        rawlog.write(ev.to_record(), durable=i == len(events) - 1)
    return len(events)


# --- Replay -----------------------------------------------------------------

REPLAY_STATE = "discovery-replay"
REPLAY_SLACK_SECONDS = 300.0


@dataclass
class ReplayStats:
    segments: int = 0
    records: int = 0
    ingested: int = 0
    duplicates: int = 0
    invalid: int = 0


def _iter_records(root: Path, since: float | None) -> Iterator[tuple[Path, dict]]:
    log_dir = root / DISCOVERY_LOG
    if not log_dir.exists():
        return
    since_day = utc(since).strftime("%Y%m%d") if since is not None else None
    for seg in sorted(log_dir.glob("*.jsonl.gz")):
        if since_day is not None and seg.name[:8] < since_day:
            continue
        for rec in read_segment(seg):
            yield seg, rec


def replay(
    store: Store, matcher: Matcher, *, since: float | None = None, now: float | None = None
) -> ReplayStats:
    """Re-ingest discovery-log records logged at or after `since` (all retained
    records if None)."""
    stats = ReplayStats()
    seen_segments = set()
    # Event rows older than the retention age are pruned (store.retention), so
    # replaying such records would count them again as new observations.
    oldest = (time.time() if now is None else now) - (
        store.config.rawlog.discovery_max_age_days * 86400
    )
    since = oldest if since is None else max(since, oldest)
    for seg, rec in _iter_records(store.config.raw_dir, since):
        seen_segments.add(seg)
        stats.records += 1
        try:
            logged_at = datetime.fromisoformat(rec["logged_at"]).timestamp()
            if since is not None and logged_at < since:
                continue
            event = CandidateEvent.model_validate(rec["record"])
        except (KeyError, TypeError, ValueError, ValidationError) as e:
            stats.invalid += 1
            log.warning(
                "skipping unreadable discovery record",
                extra={"fields": {"segment": seg.name, "error": str(e)[:300]}},
            )
            continue
        result = ingest(store, matcher, event, now=now)
        if result.outcome == "duplicate":
            stats.duplicates += 1
        elif result.outcome == "invalid":
            stats.invalid += 1
        else:
            stats.ingested += 1
    stats.segments = len(seen_segments)
    return stats


def get_state(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    row = conn.execute("SELECT state_json FROM source_state WHERE source = ?", (source,)).fetchone()
    return json.loads(row[0]) if row else {}


def put_state(conn: sqlite3.Connection, source: str, state: dict[str, Any], now: float) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO source_state (source, state_json, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT (source) DO UPDATE SET state_json = excluded.state_json,"
            " updated_at = excluded.updated_at",
            (source, json.dumps(state, sort_keys=True), now),
        )


def replay_since_marker(store: Store, matcher: Matcher, *, now: float) -> ReplayStats:
    """Startup recovery: replay from the last checkpoint (or the oldest event whose
    ingest failed, if earlier), minus slack; everything retained when there is no
    checkpoint. Safe to over-replay: ingest is idempotent."""
    state = get_state(store.conn, REPLAY_STATE)
    marks = [t for t in (state.get("checkpoint"), state.get("hold")) if t is not None]
    since = min(marks) - REPLAY_SLACK_SECONDS if marks else None
    stats = replay(store, matcher, since=since, now=now)
    put_state(store.conn, REPLAY_STATE, {"checkpoint": now}, now)  # clears any hold
    return stats


def checkpoint(store: Store, now: float) -> None:
    """Record that every discovery event logged before `now` has been ingested.
    Valid because sources ingest each event right after logging it, on one thread;
    an event whose ingest failed holds the checkpoint back (see hold_replay)."""
    state = get_state(store.conn, REPLAY_STATE)
    hold = state.get("hold")
    state["checkpoint"] = now if hold is None else min(now, hold)
    put_state(store.conn, REPLAY_STATE, state, now)


def hold_replay(store: Store, logged_at: float) -> None:
    """Keep the replay checkpoint at or before an event that is logged but not
    ingested, so the next startup replay picks it up."""
    state = get_state(store.conn, REPLAY_STATE)
    state["hold"] = min(state.get("hold", logged_at), logged_at)
    put_state(store.conn, REPLAY_STATE, state, logged_at)
