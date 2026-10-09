"""Manual submission of a URL or domain into the discovery pipeline.

A submission is always a strong candidate: an analyst asked for it. It is never
suppressed, but when the host falls under a confirmed official domain the match
result records `suppressed_by`, so the case shows it is official. Resubmitting
the same host reuses the open case.
"""

import time
import uuid
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

SOURCE = "manual"
MAX_INPUT_CHARS = 2048
BIDI = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F))


class SubmissionError(ValueError):
    pass


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


def submit(store: Store, matcher: Matcher, text: str, *, now: float | None = None) -> IngestResult:
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
    return ingest(store, matcher, event, now=now)
