"""Durable, lease-based job queue on SQLite.

A worker claims a job by taking a time-limited lease identified by a token that
is unique to that claim. Renewal, completion and failure are accepted only with
the current token on an unexpired lease, so a worker whose lease lapsed (after a
crash, a long pause or a clock jump) cannot finish a job that has since been
reclaimed, even under the same worker name. Delivery is therefore at-least-once:
stage handlers must be idempotent. Expired leases return jobs to pending, or to
failed once their attempts are exhausted.
"""

import json
import secrets
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from brandsentinel.store.db import transaction
from brandsentinel.textsafe import sanitize_fact

QueueClass = Literal["strong", "weak"]

# Next runnable job for a stage. Strong-strength work is claimed before weak;
# within a class the least recently served registrable domain (group) goes
# first, so one domain with many jobs cannot starve the others. A group already
# running `per_group_limit` jobs in this stage is skipped (NULL: no limit).
_NEXT_JOB_SQL = (
    "SELECT j.* FROM jobs j LEFT JOIN job_groups g"
    " ON g.stage = j.stage AND g.group_key = j.group_key"
    " WHERE j.stage = :stage AND ("
    " (j.status = 'pending' AND j.available_at <= :now)"
    " OR (j.status = 'running' AND j.lease_expires_at <= :now))"
    " AND (:limit IS NULL OR j.group_key IS NULL OR ("
    "  SELECT COUNT(*) FROM jobs r WHERE r.stage = j.stage AND r.group_key = j.group_key"
    "  AND r.status = 'running' AND r.lease_expires_at > :now) < :limit)"
    " ORDER BY CASE j.queue_class WHEN 'strong' THEN 0 ELSE 1 END,"
    " COALESCE(g.last_claimed_at, 0), j.available_at, j.id LIMIT 1"
)
_INSERT_SQL = (
    "INSERT INTO jobs (stage, queue_class, dedupe_key, group_key, payload_json, status,"
    " max_attempts, available_at, created_at, updated_at)"
    " VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)"
    " ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL"
    " AND status IN ('pending', 'running') DO NOTHING RETURNING id"
)
_LIVE_BY_KEY_SQL = "SELECT id FROM jobs WHERE dedupe_key = ? AND status IN ('pending', 'running')"
# Statements below are guarded by the caller still holding an unexpired lease
# with its token: WHERE id = ? AND status = 'running' AND lease_token = ? AND
# lease_expires_at > ?
_RENEW_SQL = (
    "UPDATE jobs SET lease_expires_at = ?, updated_at = ?"
    " WHERE id = ? AND status = 'running' AND lease_token = ? AND lease_expires_at > ?"
)
_COMPLETE_SQL = (
    "UPDATE jobs SET status = 'done', lease_owner = NULL, lease_token = NULL,"
    " lease_expires_at = NULL, updated_at = ?"
    " WHERE id = ? AND status = 'running' AND lease_token = ? AND lease_expires_at > ?"
)
_HELD_ATTEMPTS_SQL = (
    "SELECT attempts, max_attempts FROM jobs"
    " WHERE id = ? AND status = 'running' AND lease_token = ? AND lease_expires_at > ?"
)
_MAX_ERROR_CHARS = 2000


class LeaseLost(Exception):
    """The caller no longer holds the lease on this job."""


@dataclass(frozen=True)
class Job:
    id: int
    stage: str
    queue_class: QueueClass
    payload: dict
    attempts: int
    max_attempts: int
    lease_owner: str
    lease_token: str
    lease_expires_at: float
    group_key: str | None = None


class JobQueue:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        default_max_attempts: int = 3,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._conn = conn
        self._default_max_attempts = default_max_attempts
        self._clock = clock

    def enqueue(
        self,
        stage: str,
        payload: dict,
        *,
        queue_class: QueueClass = "strong",
        dedupe_key: str | None = None,
        group_key: str | None = None,
        max_attempts: int | None = None,
        delay: float = 0.0,
        once: bool = False,
    ) -> tuple[int, bool]:
        """Add a job. While a job with the same dedupe_key is pending or running,
        that job is returned instead of a new one; with `once`, any earlier job
        with the key (whatever its status) is. Returns (job_id, created)."""
        with transaction(self._conn):
            now = self._clock()
            if once and dedupe_key is not None:
                prior = self._conn.execute(
                    "SELECT id FROM jobs WHERE dedupe_key = ? ORDER BY id DESC LIMIT 1",
                    (dedupe_key,),
                ).fetchone()
                if prior:
                    return prior[0], False
            row = self._conn.execute(
                _INSERT_SQL,
                (
                    stage,
                    queue_class,
                    dedupe_key,
                    group_key,
                    json.dumps(payload, sort_keys=True),
                    max_attempts or self._default_max_attempts,
                    now + delay,
                    now,
                    now,
                ),
            ).fetchone()
            if row:
                return row[0], True
            existing = self._conn.execute(_LIVE_BY_KEY_SQL, (dedupe_key,)).fetchone()
            return existing[0], False

    def claim(
        self,
        stage: str,
        owner: str,
        lease_seconds: float,
        *,
        per_group_limit: int | None = None,
    ) -> Job | None:
        """Lease the next runnable job for `stage`, or return None."""
        with transaction(self._conn):
            # Read the clock after acquiring the write lock, so time spent waiting
            # on a busy database does not shorten the lease.
            now = self._clock()
            while True:
                row = self._conn.execute(
                    _NEXT_JOB_SQL, {"stage": stage, "now": now, "limit": per_group_limit}
                ).fetchone()
                if row is None:
                    return None
                if row["attempts"] >= row["max_attempts"]:
                    # Expired lease on its final attempt: give up rather than retry.
                    self._conn.execute(
                        "UPDATE jobs SET status = 'failed', lease_owner = NULL, lease_token = NULL,"
                        " lease_expires_at = NULL, updated_at = ?,"
                        " last_error = COALESCE(last_error, 'lease expired on final attempt')"
                        " WHERE id = ?",
                        (now, row["id"]),
                    )
                    continue
                token = secrets.token_hex(16)
                expires = now + lease_seconds
                self._conn.execute(
                    "UPDATE jobs SET status = 'running', lease_owner = ?, lease_token = ?,"
                    " lease_expires_at = ?, attempts = attempts + 1, updated_at = ? WHERE id = ?",
                    (owner, token, expires, now, row["id"]),
                )
                if row["group_key"] is not None:
                    self._conn.execute(
                        "INSERT INTO job_groups (stage, group_key, last_claimed_at)"
                        " VALUES (?, ?, ?)"
                        " ON CONFLICT (stage, group_key) DO UPDATE"
                        " SET last_claimed_at = excluded.last_claimed_at",
                        (stage, row["group_key"], now),
                    )
                return Job(
                    id=row["id"],
                    stage=row["stage"],
                    group_key=row["group_key"],
                    queue_class=row["queue_class"],
                    payload=json.loads(row["payload_json"]),
                    attempts=row["attempts"] + 1,
                    max_attempts=row["max_attempts"],
                    lease_owner=owner,
                    lease_token=token,
                    lease_expires_at=expires,
                )

    def renew(self, job: Job, lease_seconds: float) -> float:
        """Extend a held lease; returns the new expiry. Raises LeaseLost if expired."""
        with transaction(self._conn):
            now = self._clock()
            expires = now + lease_seconds
            cur = self._conn.execute(_RENEW_SQL, (expires, now, job.id, job.lease_token, now))
            if cur.rowcount != 1:
                raise LeaseLost(job.id)
        return expires

    def complete(self, job: Job) -> None:
        with transaction(self._conn):
            now = self._clock()
            cur = self._conn.execute(_COMPLETE_SQL, (now, job.id, job.lease_token, now))
            if cur.rowcount != 1:
                raise LeaseLost(job.id)

    def fail(self, job: Job, error: str, *, retry_delay: float = 0.0) -> str:
        """Record a failed attempt. Returns the job's new status: pending or failed."""
        message = sanitize_fact(error, _MAX_ERROR_CHARS)
        with transaction(self._conn):
            now = self._clock()
            row = self._conn.execute(_HELD_ATTEMPTS_SQL, (job.id, job.lease_token, now)).fetchone()
            if row is None:
                raise LeaseLost(job.id)
            status = "failed" if row["attempts"] >= row["max_attempts"] else "pending"
            self._conn.execute(
                "UPDATE jobs SET status = ?, last_error = ?, lease_owner = NULL,"
                " lease_token = NULL, lease_expires_at = NULL, available_at = ?,"
                " updated_at = ? WHERE id = ?",
                (status, message, now + retry_delay, now, job.id),
            )
        return status

    def recover_expired(self) -> int:
        """Return jobs with expired leases to pending (or failed if out of attempts)."""
        with transaction(self._conn):
            now = self._clock()
            cur = self._conn.execute(
                "UPDATE jobs SET"
                " status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,"
                " last_error = COALESCE(last_error, 'lease expired'),"
                " lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, updated_at = ?"
                " WHERE status = 'running' AND lease_expires_at <= ?",
                (now, now),
            )
            return cur.rowcount

    def depths(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT stage, status, queue_class, COUNT(*) AS n FROM jobs"
            " GROUP BY stage, status, queue_class ORDER BY stage, status, queue_class"
        ).fetchall()

    def recent_failures(self, limit: int = 10) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT id, stage, attempts, last_error FROM jobs WHERE status = 'failed'"
            " ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
