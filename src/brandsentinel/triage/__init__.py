"""Analyst triage: case queries, analyst labels and the report model (U15, R32).

Everything shown to an analyst comes from the stored score: the EvidenceBundle
that was evaluated and the policy result, so a report always matches the
decision it explains. Untrusted strings stay raw here; each sink (terminal,
HTML, CSV) applies its own neutralization.
"""

import json
import sqlite3
import time
from dataclasses import dataclass, field

from brandsentinel.evidence.bundle import EvidenceBundle
from brandsentinel.evidence.bundle import iso as bundle_iso
from brandsentinel.policy.scorer import PRIORITIES, PolicyResult, latest_score
from brandsentinel.store.db import transaction

# The decision questions (R25) plus the overall verdict, as analysts label them.
QUESTIONS = (
    "brand_related",
    "brand_impersonation",
    "false_association",
    "credential_harvesting",
    "payment_or_donation_abuse",
    "unauthorized_commerce",
)
ANSWERS = ("yes", "no", "unsure")
VERDICTS = ("abusive", "suspicious", "benign", "unrelated", "unsure")
OVERALL = "overall"

_PRIORITY_ORDER = (
    "CASE c.priority "
    + " ".join(f"WHEN '{p}' THEN {i}" for i, p in enumerate(PRIORITIES))
    + f" WHEN 'no_action' THEN {len(PRIORITIES)} ELSE {len(PRIORITIES) + 1} END"
)


def iso(ts: float | None) -> str:
    """UTC ISO 8601 for display ("" when unknown)."""
    return bundle_iso(ts) or ""


@dataclass
class CaseSummary:
    case_id: int
    host: str
    registrable_domain: str | None
    status: str
    priority: str | None
    category: str | None
    score: int | None
    match_strength: str
    sources: list[str]
    first_seen: float
    last_seen: float
    created_at: float
    scored_at: float | None
    labels: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    summary: str | None = None
    verdict: str | None = None


@dataclass(frozen=True)
class CaseFilter:
    priority: tuple[str, ...] = ()
    category: tuple[str, ...] = ()
    label: str | None = None
    source: str | None = None
    strength: str | None = None
    status: str | None = None
    since: float | None = None
    limit: int | None = None
    case_id: int | None = None


def list_cases(conn: sqlite3.Connection, f: CaseFilter | None = None) -> list[CaseSummary]:
    f = f or CaseFilter()
    where, args = [], []
    if f.case_id is not None:
        where.append("c.id = ?")
        args.append(f.case_id)
    if f.priority:
        where.append(f"c.priority IN ({','.join('?' * len(f.priority))})")
        args += list(f.priority)
    if f.category:
        where.append(f"c.category IN ({','.join('?' * len(f.category))})")
        args += list(f.category)
    if f.label:
        where.append("EXISTS (SELECT 1 FROM json_each(s.result_json, '$.labels') WHERE value = ?)")
        args.append(f.label)
    if f.source:
        where.append(
            "EXISTS (SELECT 1 FROM candidate_sources cs WHERE cs.candidate_id = k.id"
            " AND cs.source = ?)"
        )
        args.append(f.source)
    if f.strength:
        where.append("k.match_strength = ?")
        args.append(f.strength)
    if f.status:
        where.append("c.status = ?")
        args.append(f.status)
    if f.since is not None:
        where.append("c.created_at >= ?")
        args.append(f.since)
    # Only fixed SQL fragments are joined; every value is a bound parameter.
    sql = (
        "SELECT c.id, k.name, k.registrable_domain, c.status, c.priority, c.category, s.score,"  # noqa: S608
        " k.match_strength, k.first_seen, k.last_seen, c.created_at, s.created_at,"
        " s.result_json, (SELECT group_concat(source, ',') FROM (SELECT source FROM"
        " candidate_sources WHERE candidate_id = k.id ORDER BY source)),"
        " (SELECT value FROM labels l WHERE l.case_id = c.id AND l.question = 'overall')"
        " FROM cases c JOIN candidates k ON k.id = c.candidate_id"
        " LEFT JOIN scores s ON s.id = c.score_id"
        + (" WHERE " + " AND ".join(where) if where else "")
        + f" ORDER BY {_PRIORITY_ORDER}, s.score DESC, c.id"
        + (" LIMIT ?" if f.limit else "")
    )
    if f.limit:
        args.append(f.limit)
    out = []
    for r in conn.execute(sql, args):
        result = json.loads(r[12]) if r[12] else {}
        out.append(
            CaseSummary(
                case_id=r[0],
                host=r[1],
                registrable_domain=r[2],
                status=r[3],
                priority=r[4],
                category=r[5],
                score=r[6],
                match_strength=r[7],
                first_seen=r[8],
                last_seen=r[9],
                created_at=r[10],
                scored_at=r[11],
                labels=result.get("labels", []),
                flags=result.get("flags", []),
                summary=result.get("summary"),
                sources=(r[13] or "").split(",") if r[13] else [],
                verdict=r[14],
            )
        )
    return out


@dataclass
class CaseReport:
    summary: CaseSummary
    bundle: EvidenceBundle | None
    result: PolicyResult | None
    analyst_labels: dict[str, dict]
    history: list[dict]


def load_case(conn: sqlite3.Connection, case_id: int) -> CaseReport | None:
    rows = list_cases(conn, CaseFilter(case_id=case_id))
    if not rows:
        return None
    scored = latest_score(conn, case_id)
    bundle, result = (scored[0], scored[1]) if scored else (None, None)
    history = [
        {"at": r[0], "priority": r[1], "category": r[2], "score": r[3], "policy_version": r[4]}
        for r in conn.execute(
            "SELECT created_at, priority, category, score, policy_version FROM scores"
            " WHERE case_id = ? ORDER BY id",
            (case_id,),
        )
    ]
    return CaseReport(rows[0], bundle, result, case_labels(conn, case_id), history)


# --- analyst labels ---------------------------------------------------------------


class LabelError(ValueError):
    pass


def record_label(
    conn: sqlite3.Connection,
    case_id: int,
    question: str,
    value: str,
    *,
    labelled_by: str | None = None,
    now: float | None = None,
) -> None:
    """Store (or replace) an analyst label. `question` is a decision question or
    `overall` for the verdict. Labels never change the policy decision."""
    if question == OVERALL:
        if value not in VERDICTS:
            raise LabelError(f"verdict must be one of {', '.join(VERDICTS)}")
    elif question in QUESTIONS:
        if value not in ANSWERS:
            raise LabelError(f"answer must be one of {', '.join(ANSWERS)}")
    else:
        raise LabelError(f"question must be one of {', '.join((*QUESTIONS, OVERALL))}")
    if conn.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone() is None:
        raise LabelError(f"no case #{case_id}")
    with transaction(conn):
        conn.execute(
            "INSERT INTO labels (case_id, question, value, labelled_by, created_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT (case_id, question) DO UPDATE SET"
            " value = excluded.value, labelled_by = excluded.labelled_by,"
            " created_at = excluded.created_at",
            (case_id, question, value, labelled_by, time.time() if now is None else now),
        )


def case_labels(conn: sqlite3.Connection, case_id: int) -> dict[str, dict]:
    return {
        r[0]: {"value": r[1], "by": r[2], "at": r[3]}
        for r in conn.execute(
            "SELECT question, value, labelled_by, created_at FROM labels WHERE case_id = ?"
            " ORDER BY question",
            (case_id,),
        )
    }


def load_labelled_cases(conn: sqlite3.Connection) -> dict[int, dict[str, str]]:
    """Every labelled case's answers, for the evaluation dataset loader (U21)."""
    out: dict[int, dict[str, str]] = {}
    for case_id, question, value in conn.execute(
        "SELECT case_id, question, value FROM labels ORDER BY case_id, question"
    ):
        out.setdefault(case_id, {})[question] = value
    return out
