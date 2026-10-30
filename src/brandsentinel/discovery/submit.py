"""Manual submission of a URL or domain into the discovery pipeline.

A submission is always a strong candidate: an analyst asked for it. It is never
suppressed, but when the host falls under a confirmed official domain the match
result records `suppressed_by`, so the case shows it is official. Resubmitting
the same host reuses the open case.

`render=True` (`submit --render`, M8) also records a `render_request` fact for
one analysis round: the next round that can still decide (`request_render`).
That is round 0 for a new case, and for a case already decided the next
scheduled recheck, whose time is unchanged; no round is created. The request is read by
that round's render decision only (`AnalysisStages.decide_render`), which
applies the skips and the analyst budget. Ingest and request commit together.
"""

import time
import uuid
from dataclasses import dataclass, replace
from typing import Literal
from urllib.parse import urlsplit

from brandsentinel.discovery.events import (
    DISCOVERY_LOG,
    CandidateEvent,
    IngestResult,
    ManualContext,
    event_id,
    ingest,
    utc,
    write_events,
)
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import InvalidName, canonical_host
from brandsentinel.store import Store
from brandsentinel.store.db import transaction
from brandsentinel.store.records import add_fact

SOURCE = "manual"
MAX_INPUT_CHARS = 2048
BIDI = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F))


REQUEST_VERSION = "render_request/1"
ENRICH_STAGE = "enrich"


class SubmissionError(ValueError):
    pass


@dataclass(frozen=True)
class RenderRequest:
    status: Literal["requested", "already_requested", "refused"]
    round: int | None = None
    # When the round's analysis starts: a recheck's `not_before`; None when the
    # round is under way or about to start.
    due: float | None = None
    reason: str | None = None


def parse_submission(text: str) -> tuple[str, str | None]:
    """Return (host, url or None). Raises SubmissionError."""
    text = text.strip()
    if not text or len(text) > MAX_INPUT_CHARS:
        raise SubmissionError("empty or too long")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 or c in BIDI for c in text):
        raise SubmissionError("contains control or bidirectional-override characters")
    url = None
    if "://" in text:
        try:
            parts = urlsplit(text)
            host = parts.hostname
            parts.port  # noqa: B018 - raises ValueError for an invalid or out-of-range port
        except ValueError as e:
            raise SubmissionError(f"invalid URL: {e}") from e
        if parts.scheme.lower() not in ("http", "https"):
            raise SubmissionError(f"unsupported scheme {parts.scheme!r}; use http or https")
        if parts.username or parts.password:
            raise SubmissionError("URLs with credentials are not accepted")
        if not host:
            raise SubmissionError("URL has no host")
        url = text
    else:
        if any(c in text for c in "/?#@: "):
            raise SubmissionError("not a domain; give a full http(s) URL instead")
        host = text
    try:
        canonical, wildcard = canonical_host(host)
    except InvalidName as e:
        raise SubmissionError(f"invalid host: {e}") from e
    if wildcard:
        raise SubmissionError("wildcards are not accepted")
    return canonical, url


def submit(
    store: Store, matcher: Matcher, text: str, *, now: float | None = None, render: bool = False
) -> IngestResult:
    """Submit one target. With `render`, `IngestResult.render_request` says
    whether and for which round a render was requested."""
    host, url = parse_submission(text)
    now = time.time() if now is None else now
    event = CandidateEvent(
        event_id=event_id(SOURCE, uuid.uuid4().hex, host),
        source=SOURCE,
        name=host,
        observed_at=utc(now),
        context=ManualContext(submitted=text.strip(), url=url),
    )
    write_events(store.rawlog(DISCOVERY_LOG), [event])  # durable before ingest
    if not render:
        return ingest(store, matcher, event, now=now)
    # One transaction: the request binds to a round against the render
    # decisions as they are at commit (decide_render takes the same lock).
    with transaction(store.conn):
        result = ingest(store, matcher, event, now=now)
        if result.case_id is None:
            request = RenderRequest("refused", reason="no case was opened")
        else:
            rounds = len(store.config.scheduling.recheck_after_days)
            request = request_render(store, result.case_id, rounds=rounds, now=now)
    return replace(result, render_request=request)


def request_render(store: Store, case_id: int, *, rounds: int, now: float) -> RenderRequest:
    """Record a render request for the case's next round (0..`rounds`) that can
    still decide: above every decided round, and with its work queued (a
    deferred row, or a pending or running enrich or fetch job; once its static
    fetch is recorded, only its fetch job counts). A round that can no longer
    decide (its fetch recorded without a decision, as for a case analyzed before
    M7, or its jobs failed for good) is skipped, so no request is stranded on it.
    Idempotent per round. Call inside a transaction."""
    conn = store.conn
    decided = {
        r[0]
        for r in conn.execute(
            "SELECT json_extract(value_json, '$.analysis_round') FROM facts"
            " WHERE case_id = ? AND name = 'render_decision'",
            (case_id,),
        )
    }
    fetched = {
        r[0]
        for r in conn.execute(
            "SELECT round FROM stage_runs WHERE case_id = ? AND stage = 'fetch'", (case_id,)
        )
    }
    first = max((r for r in decided if isinstance(r, int)), default=-1) + 1
    target = due = None
    for rnd in range(first, rounds + 1):
        keys = [f"{stage}:case:{case_id}:r{rnd}" for stage in (ENRICH_STAGE, "fetch")]
        if rnd in fetched:
            # Recorded: it decides only if its fetch job is still running (the
            # handler decides next, or its redelivery does).
            keys = [keys[1], keys[1]]
        deferred = conn.execute(
            "SELECT MIN(not_before) FROM deferred_jobs WHERE dedupe_key IN (?, ?)", keys
        ).fetchone()[0]
        live = conn.execute(
            "SELECT 1 FROM jobs WHERE dedupe_key IN (?, ?) AND status IN ('pending', 'running')",
            keys,
        ).fetchone()
        if deferred is not None or live:
            target, due = rnd, deferred
            break
    if target is None:
        why = (
            "every analysis round already has a render decision"
            if first > rounds
            else "no remaining analysis round is scheduled"
        )
        return RenderRequest("refused", reason=why)
    if conn.execute(
        "SELECT 1 FROM facts WHERE case_id = ? AND name = 'render_request'"
        " AND json_extract(value_json, '$.analysis_round') = ?",
        (case_id, target),
    ).fetchone():
        return RenderRequest("already_requested", target, due)
    add_fact(
        conn,
        case_id,
        source="analyst",
        name="render_request",
        value={"round": target, "requested_at": now, "via": "cli", "analysis_round": target},
        collector_version=REQUEST_VERSION,
        untrusted=False,
        now=now,
    )
    return RenderRequest("requested", target, due)
