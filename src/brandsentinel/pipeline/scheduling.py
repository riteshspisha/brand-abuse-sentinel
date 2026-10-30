"""Fair, bounded scheduling per registrable domain (subdomain flooding control).

Candidates stay per host, and every discovery event, candidate and case is kept.
What is bounded is the *work* one registrable domain can put in front of the
pipeline:

- Concurrency: a claim skips a domain already running its per-stage limit of
  jobs (`stages.per_domain_enrich`, `stages.per_domain_fetch`), and among
  runnable jobs serves the least recently served domain first (store.jobs).
- Backlog: a domain may have `max_queued_per_domain_{strong,weak}` live jobs per
  stage. Work beyond that is written to `deferred_jobs` with the reason, never
  dropped, and promoted as the domain's jobs finish.
- Escalation: manual submissions bypass the allowance; strong-strength work has a
  larger allowance and is promoted first; a later strong sighting of a deferred
  weak candidate upgrades its deferred work.

Rechecks are deferred rows with a future `not_before`, so they obey the same
limits when they come due. Everything lives in SQLite; restarts lose nothing.

`idle_snapshot` (M8, `run --until-idle`) says whether a run has work left: a
pending or running job of a stage this run serves (a retry waiting for its
`available_at` included), or deferred work already due. Work that is not due
yet (rechecks) is left as it is, and jobs of stages this run does not serve
(for example media while the sandbox is unavailable) are reported, not waited
for.
"""

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from brandsentinel.config import SchedulingSettings
from brandsentinel.store.db import transaction
from brandsentinel.store.jobs import JobQueue

Decision = Literal["enqueued", "deferred", "exists"]


@dataclass(frozen=True)
class ScheduleResult:
    decision: Decision
    job_id: int | None = None


def group_key_for(registrable_domain: str | None, host: str) -> str:
    return registrable_domain or host


def live_jobs(conn: sqlite3.Connection, stage: str, group_key: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM jobs WHERE stage = ? AND group_key = ?"
        " AND status IN ('pending', 'running')",
        (stage, group_key),
    ).fetchone()[0]


def _allowance(settings: SchedulingSettings, queue_class: str) -> int:
    if queue_class == "strong":
        return settings.max_queued_per_domain_strong
    return settings.max_queued_per_domain_weak


def schedule(
    conn: sqlite3.Connection,
    jobs: JobQueue,
    settings: SchedulingSettings,
    *,
    stage: str,
    payload: dict,
    group_key: str,
    queue_class: str,
    dedupe_key: str,
    now: float,
    escalated: bool = False,
    not_before: float | None = None,
    case_id: int | None = None,
) -> ScheduleResult:
    """Enqueue one unit of work, or defer it. Idempotent on `dedupe_key`: work
    that was ever queued or is already deferred is not scheduled again."""
    with transaction(conn):
        prior = conn.execute(
            "SELECT id FROM jobs WHERE dedupe_key = ? ORDER BY id DESC LIMIT 1", (dedupe_key,)
        ).fetchone()
        if prior:
            return ScheduleResult("exists", prior[0])
        if conn.execute(
            "SELECT 1 FROM deferred_jobs WHERE dedupe_key = ?", (dedupe_key,)
        ).fetchone():
            if escalated:
                _mark_escalated(conn, dedupe_key=dedupe_key)
            return ScheduleResult("exists")
        due = not_before is None or not_before <= now
        if due and (
            escalated or live_jobs(conn, stage, group_key) < _allowance(settings, queue_class)
        ):
            job_id, _ = jobs.enqueue(
                stage,
                payload,
                queue_class=queue_class,
                dedupe_key=dedupe_key,
                group_key=group_key,
                once=True,
            )
            return ScheduleResult("enqueued", job_id)
        conn.execute(
            "INSERT INTO deferred_jobs (dedupe_key, stage, group_key, queue_class, escalated,"
            " payload_json, case_id, reason, not_before, deferred_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dedupe_key,
                stage,
                group_key,
                queue_class,
                int(escalated),
                json.dumps(payload, sort_keys=True),
                case_id,
                "recheck" if not due else "domain_queue_full",
                not_before if not_before is not None else now,
                now,
            ),
        )
        return ScheduleResult("deferred")


def _mark_escalated(conn: sqlite3.Connection, *, dedupe_key: str) -> None:
    conn.execute(
        "UPDATE deferred_jobs SET escalated = 1, queue_class = 'strong' WHERE dedupe_key = ?",
        (dedupe_key,),
    )


def escalate_case(conn: sqlite3.Connection, case_id: int, *, manual: bool) -> int:
    """Raise the case's deferred, due work: a manual submission bypasses the
    domain allowance, a strong sighting makes it strong-class. Future rechecks
    keep their schedule. Returns rows changed."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE deferred_jobs SET queue_class = 'strong',"
            " escalated = CASE WHEN ? THEN 1 ELSE escalated END"
            " WHERE case_id = ? AND reason = 'domain_queue_full'",
            (int(manual), case_id),
        )
        return cur.rowcount


def promote(
    conn: sqlite3.Connection,
    jobs: JobQueue,
    settings: SchedulingSettings,
    *,
    now: float,
) -> int:
    """Move due deferred work into the queue, domain by domain, up to each
    domain's allowance. Escalated rows always move. Returns jobs enqueued."""
    moved = 0
    with transaction(conn):
        # Only groups that can move: those with escalated work, or with fewer live
        # jobs than the allowance of their best class. Groups still at their
        # allowance never use up the batch, so due work elsewhere is not starved.
        groups = conn.execute(
            "SELECT d.stage, d.group_key FROM deferred_jobs d WHERE d.not_before <= :now"
            " GROUP BY d.stage, d.group_key"
            " HAVING MAX(d.escalated) = 1 OR ("
            "  SELECT COUNT(*) FROM jobs j WHERE j.stage = d.stage AND j.group_key = d.group_key"
            "  AND j.status IN ('pending', 'running')) < CASE"
            "  WHEN MIN(CASE d.queue_class WHEN 'strong' THEN 0 ELSE 1 END) = 0 THEN :strong"
            "  ELSE :weak END"
            " ORDER BY MAX(d.escalated) DESC, MIN(d.not_before) LIMIT :batch",
            {
                "now": now,
                "strong": settings.max_queued_per_domain_strong,
                "weak": settings.max_queued_per_domain_weak,
                "batch": settings.promote_batch,
            },
        ).fetchall()
        for stage, group in groups:
            live = live_jobs(conn, stage, group)
            rows = conn.execute(
                "SELECT * FROM deferred_jobs WHERE stage = ? AND group_key = ? AND not_before <= ?"
                " ORDER BY escalated DESC, CASE queue_class WHEN 'strong' THEN 0 ELSE 1 END,"
                " not_before, deferred_at LIMIT ?",
                (stage, group, now, settings.promote_batch),
            ).fetchall()
            for row in rows:
                if not row["escalated"] and live >= _allowance(settings, row["queue_class"]):
                    break
                jobs.enqueue(
                    stage,
                    json.loads(row["payload_json"]),
                    queue_class=row["queue_class"],
                    dedupe_key=row["dedupe_key"],
                    group_key=group,
                    once=True,
                )
                conn.execute("DELETE FROM deferred_jobs WHERE dedupe_key = ?", (row["dedupe_key"],))
                live += 1
                moved += 1
                if moved >= settings.promote_batch:
                    return moved
    return moved


@dataclass(frozen=True)
class IdleSnapshot:
    outstanding: int  # pending or running jobs of served stages
    due_deferred: int  # deferred work of served stages that is due
    not_due_deferred: int  # deferred work not due yet (rechecks), any stage
    unserved: dict[str, int]  # pending or running jobs of stages not served

    @property
    def idle(self) -> bool:
        return not self.outstanding and not self.due_deferred


def idle_snapshot(conn: sqlite3.Connection, stages: Iterable[str], now: float) -> IdleSnapshot:
    """Outstanding work for `stages`, read in one statement (one snapshot)."""
    served = json.dumps(sorted(stages))
    row = conn.execute(
        "SELECT"
        " (SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'running')"
        "  AND stage IN (SELECT value FROM json_each(:served))),"
        " (SELECT COUNT(*) FROM deferred_jobs WHERE not_before <= :now"
        "  AND stage IN (SELECT value FROM json_each(:served))),"
        " (SELECT COUNT(*) FROM deferred_jobs WHERE not_before > :now),"
        " (SELECT json_group_object(stage, n) FROM (SELECT stage, COUNT(*) AS n FROM jobs"
        "  WHERE status IN ('pending', 'running')"
        "  AND stage NOT IN (SELECT value FROM json_each(:served)) GROUP BY stage))",
        {"served": served, "now": now},
    ).fetchone()
    return IdleSnapshot(row[0], row[1], row[2], json.loads(row[3] or "{}"))


def deferred_summary(conn: sqlite3.Connection, now: float, limit: int = 5) -> dict:
    total, due = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(not_before <= ?), 0) FROM deferred_jobs", (now,)
    ).fetchone()
    top = conn.execute(
        "SELECT group_key, COUNT(*) AS n FROM deferred_jobs WHERE reason = 'domain_queue_full'"
        " GROUP BY group_key ORDER BY n DESC, group_key LIMIT ?",
        (limit,),
    ).fetchall()
    return {"total": total, "due": due, "top_domains": [(r[0], r[1]) for r in top]}
