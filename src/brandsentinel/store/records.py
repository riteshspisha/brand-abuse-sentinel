"""Writers for candidates, cases and facts.

Every string in a fact value comes from an untrusted source unless the caller
says otherwise, so the fact writer sanitizes it before storing. Fact values are
also bounded in nesting depth, collection size and serialized bytes; a value over
the byte cap is replaced by a truncation marker rather than stored partially.
"""

import json
import sqlite3
import time
from collections.abc import Iterable
from typing import Literal

from brandsentinel.store.db import transaction
from brandsentinel.textsafe import sanitize_fact

MatchStrength = Literal["strong", "weak"]

MAX_FACT_DEPTH = 16
MAX_FACT_ITEMS = 1000
_TRUNCATED = "[truncated]"


def sanitize_value(value: object, max_chars: int, depth: int = 0) -> object:
    """Sanitize every string in a JSON-like value and bound its shape."""
    if isinstance(value, str):
        return sanitize_fact(value, max_chars)
    if isinstance(value, (dict, list, tuple)) and depth >= MAX_FACT_DEPTH:
        return _TRUNCATED
    if isinstance(value, dict):
        items = list(value.items())[:MAX_FACT_ITEMS]
        return {
            sanitize_fact(str(k), max_chars): sanitize_value(v, max_chars, depth + 1)
            for k, v in items
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_value(v, max_chars, depth + 1) for v in value[:MAX_FACT_ITEMS]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_fact(str(value), max_chars)


def upsert_candidate(
    conn: sqlite3.Connection,
    name: str,
    *,
    match_strength: MatchStrength,
    registrable_domain: str | None = None,
    now: float | None = None,
) -> tuple[int, bool]:
    """Insert a candidate, or refresh last_seen if it exists. A strong sighting
    upgrades a weak candidate; nothing downgrades one. Returns (id, created)."""
    now = time.time() if now is None else now
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO candidates (name, registrable_domain, match_strength, first_seen,"
            " last_seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT (name) DO NOTHING",
            (name, registrable_domain, match_strength, now, now),
        )
        if cur.rowcount == 1:
            return cur.lastrowid, True
        # MIN/MAX keep first/last seen right when older events are replayed late.
        conn.execute(
            "UPDATE candidates SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?),"
            " match_strength = CASE WHEN ? = 'strong' THEN 'strong' ELSE match_strength END"
            " WHERE name = ?",
            (now, now, match_strength, name),
        )
        row = conn.execute("SELECT id FROM candidates WHERE name = ?", (name,)).fetchone()
        return row[0], False


def create_case(
    conn: sqlite3.Connection,
    candidate_id: int,
    *,
    subject_url: str | None = None,
    now: float | None = None,
) -> int:
    now = time.time() if now is None else now
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO cases (candidate_id, subject_url, created_at, updated_at)"
            " VALUES (?, ?, ?, ?)",
            (candidate_id, subject_url, now, now),
        )
        return cur.lastrowid


def add_fact(
    conn: sqlite3.Connection,
    case_id: int,
    *,
    source: str,
    name: str,
    value: object,
    collector_version: str,
    artifact_refs: Iterable[str] = (),
    untrusted: bool = True,
    max_chars: int = 4096,
    max_bytes: int = 256 * 1024,
    now: float | None = None,
) -> int:
    now = time.time() if now is None else now
    stored = sanitize_value(value, max_chars) if untrusted else value
    encoded = json.dumps(stored, sort_keys=True, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > max_bytes:
        encoded = json.dumps({"truncated": True, "original_bytes": len(encoded.encode("utf-8"))})
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO facts (case_id, source, name, value_json, artifact_refs,"
            " collector_version, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                source,
                name,
                encoded,
                json.dumps(sorted(set(artifact_refs))),
                collector_version,
                now,
            ),
        )
        return cur.lastrowid
