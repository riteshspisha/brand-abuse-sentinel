"""Scheduled dnstwist sweeps of the registry's official domains.

dnstwist itself generates and resolves the permutations; this module only runs
its CLI safely and records what it found:

- Targets are every confirmed or legacy-unverified official domain in the
  registry, never a hardcoded list.
- The CLI runs as an argv list (no shell) in its own session, with stdin closed,
  a minimal environment, `--` before the domain, and a timeout sized from a
  preliminary `--format list` count (which does no DNS). On timeout the whole
  process group is killed. `--lsh`, `--phash`, `--screenshots`, `--banners`,
  `--whois` and `--geoip` are never passed: they fetch untrusted pages or call
  third parties outside the network guard.
- Each sweep is a `discovery_runs` row. One target's failure is recorded on its
  own row and never affects other targets or already persisted records; each
  result is ingested in its own transaction.
- The last run per target lives in SQLite, so a restart neither skips nor
  repeats a sweep. A run left `running` by a crash is marked `abandoned` and
  retried after `retry_hours`.
"""

import asyncio
import contextlib
import json
import logging
import os
import shutil
import signal
import sqlite3
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from brandsentinel.config import Config
from brandsentinel.discovery.events import (
    DISCOVERY_LOG,
    CandidateEvent,
    DnstwistContext,
    event_id,
    hold_replay,
    ingest,
    utc,
    write_events,
)
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import InvalidName, canonical_host
from brandsentinel.registry.model import Registry
from brandsentinel.store import Store
from brandsentinel.store.db import transaction
from brandsentinel.textsafe import sanitize_fact

log = logging.getLogger(__name__)

SOURCE = "dnstwist"
FORBIDDEN_FLAGS = frozenset(
    {
        "--lsh",
        "--lsh-url",
        "--phash",
        "--phash-url",
        "--screenshots",
        "-p",
        "-b",
        "--banners",
        "-w",
        "--whois",
        "-g",
        "--geoip",
        "-m",
        "--mxcheck",
    }
)
DNS_KEYS = ("dns_a", "dns_aaaa", "dns_mx", "dns_ns")
MAX_NEW_LISTED = 500
MAX_STDERR_CHARS = 2000
# Statuses after which the next sweep waits a full interval.
# "partial" is settled too: its records are logged, and failed ones are replayed at
# startup, so re-sweeping hourly would not help.
SETTLED = ("ok", "partial", "timeout", "too_large")


class SweepError(Exception):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class SweepResult:
    target: str
    run_id: int
    status: str
    permutations: int = 0
    registered: int = 0
    candidates: int = 0
    new: tuple[str, ...] = ()
    error: str | None = None


def resolve_binary(name: str) -> str | None:
    if "/" in name:
        return name if os.access(name, os.X_OK) else None
    beside = Path(sys.executable).parent / name  # the project venv's console script
    if beside.is_file() and os.access(beside, os.X_OK):
        return str(beside)
    return shutil.which(name)


def _clean_env() -> dict[str, str]:
    env = {"PATH": os.defpath, "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    return env


async def run_capped(
    argv: list[str], *, timeout: float, max_bytes: int
) -> tuple[int, bytes, bytes]:
    """Run argv; return (returncode, stdout, stderr). Kills the process group and
    raises SweepError on timeout or when stdout exceeds max_bytes."""
    bad = FORBIDDEN_FLAGS.intersection(argv)
    if bad:
        raise ValueError(f"refusing dnstwist flags {sorted(bad)}")
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_clean_env(),
        start_new_session=True,
    )

    async def read(stream: asyncio.StreamReader, cap: int) -> bytes:
        buf = bytearray()
        while chunk := await stream.read(65536):
            buf += chunk
            if len(buf) > cap:
                raise SweepError("error", f"output exceeded {cap} bytes")
        return bytes(buf)

    try:
        async with asyncio.timeout(timeout):
            out, err = await asyncio.gather(
                read(proc.stdout, max_bytes), read(proc.stderr, 1024 * 1024)
            )
            code = await proc.wait()
    except TimeoutError:
        _kill(proc)
        await proc.wait()
        raise SweepError("timeout", f"timed out after {timeout:.0f}s") from None
    except BaseException:
        _kill(proc)
        with contextlib.suppress(Exception):
            await asyncio.shield(proc.wait())
        raise
    return code, out, err


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


class DnstwistRunner:
    def __init__(
        self,
        store: Store,
        matcher: Matcher,
        registry: Registry,
        config: Config,
        *,
        clock: Callable[[], float] = time.time,
        runner: Callable = run_capped,
    ) -> None:
        self.store = store
        self.matcher = matcher
        self.registry = registry
        self.settings = config.discovery.dnstwist
        self._clock = clock
        self._run = runner

    # --- schedule ------------------------------------------------------------

    def targets(self) -> list[str]:
        return sorted(d.name for d in self.registry.dnstwist_targets())

    def max_wall_seconds(self) -> float:
        """Longest a live sweep can run; a `running` row older than this is dead."""
        s = self.settings
        return s.count_timeout_seconds + s.timeout_max_seconds + 60.0

    def recover_abandoned(self) -> int:
        """Mark sweeps left running by a crash as abandoned (startup hook). A sweep
        younger than the maximum wall time may belong to a live `sweep` command,
        so it is left alone."""
        now = self._clock()
        with transaction(self.store.conn):
            return self.store.conn.execute(
                "UPDATE discovery_runs SET status = 'abandoned', finished_at = ?"
                " WHERE source = ? AND status = 'running' AND started_at < ?",
                (now, SOURCE, now - self.max_wall_seconds()),
            ).rowcount

    def next_due(self, target: str) -> float:
        """Epoch time the next sweep of `target` is due (<= now means due)."""
        row = self.store.conn.execute(
            "SELECT started_at, status FROM discovery_runs WHERE source = ? AND target = ?"
            " ORDER BY started_at DESC, id DESC LIMIT 1",
            (SOURCE, target),
        ).fetchone()
        if row is None:
            return 0.0
        s = self.settings
        if row["status"] == "running":  # possibly another process's live sweep
            return row["started_at"] + self.max_wall_seconds()
        wait = (
            s.interval_hours if row["status"] in SETTLED else min(s.retry_hours, s.interval_hours)
        )
        return row["started_at"] + wait * 3600

    async def run(self, *, poll_seconds: float = 300.0) -> None:
        """Sweep due targets one at a time, forever (until cancelled)."""
        self.recover_abandoned()
        while True:
            now = self._clock()
            due = [t for t in self.targets() if self.next_due(t) <= now]
            for target in due:
                await self.sweep(target)
            upcoming = [self.next_due(t) for t in self.targets()]
            wait = min(upcoming, default=now + poll_seconds) - self._clock()
            await asyncio.sleep(max(1.0, min(poll_seconds, wait)))

    # --- one sweep -----------------------------------------------------------

    def _argv(self, binary: str, target: str, *, count: bool) -> list[str]:
        argv = [binary]
        if count:
            argv += ["--format", "list"]
        else:
            argv += ["--registered", "--format", "json", "--threads", str(self.settings.threads)]
        dictionary = self.settings.dictionary
        if dictionary is not None and dictionary.is_file():
            argv += ["--dictionary", str(dictionary)]
        return [*argv, "--", target]

    def _start_run(self, target: str) -> int:
        with transaction(self.store.conn):
            return self.store.conn.execute(
                "INSERT INTO discovery_runs (source, target, started_at, status)"
                " VALUES (?, ?, ?, 'running')",
                (SOURCE, target, self._clock()),
            ).lastrowid

    def _finish_run(self, run_id: int, status: str, detail: dict) -> None:
        with transaction(self.store.conn):
            self.store.conn.execute(
                "UPDATE discovery_runs SET status = ?, finished_at = ?, detail_json = ?"
                " WHERE id = ?",
                (status, self._clock(), json.dumps(detail, sort_keys=True), run_id),
            )

    def _previous_registered(self, target: str, run_id: int) -> set[str] | None:
        row = self.store.conn.execute(
            "SELECT detail_json FROM discovery_runs WHERE source = ? AND target = ?"
            " AND status = 'ok' AND id < ? ORDER BY id DESC LIMIT 1",
            (SOURCE, target, run_id),
        ).fetchone()
        return None if row is None else set(json.loads(row[0]).get("registered_domains", []))

    async def sweep(self, target: str) -> SweepResult:
        run_id = self._start_run(target)
        detail: dict = {}
        try:
            host, wildcard = canonical_host(target)
            if host != target or wildcard or target.startswith("-"):
                raise SweepError("error", f"target {target!r} is not a canonical domain")
            binary = resolve_binary(self.settings.binary)
            if binary is None:
                raise SweepError(
                    "unavailable", f"dnstwist binary {self.settings.binary!r} not found"
                )
            permutations = await self._count(binary, target)
            detail["permutations"] = permutations
            if permutations > self.settings.max_permutations:
                raise SweepError(
                    "too_large", f"{permutations} permutations > {self.settings.max_permutations}"
                )
            timeout = self.timeout_for(permutations)
            detail["timeout_seconds"] = timeout
            records = await self._scan(binary, target, timeout)
        except (SweepError, InvalidName, OSError) as e:
            status = e.status if isinstance(e, SweepError) else "error"
            detail["error"] = sanitize_fact(str(e), MAX_STDERR_CHARS)
            self._finish_run(run_id, status, detail)
            log.error(
                "dnstwist sweep failed",
                extra={"fields": {"target": target, "status": status, "error": detail["error"]}},
            )
            return SweepResult(
                target, run_id, status, detail.get("permutations", 0), error=detail["error"]
            )
        return self._record(target, run_id, records, detail)

    def timeout_for(self, permutations: int) -> float:
        s = self.settings
        return min(
            s.timeout_max_seconds,
            s.timeout_floor_seconds + permutations / s.resolution_rate_per_second,
        )

    async def _count(self, binary: str, target: str) -> int:
        code, out, err = await self._run(
            self._argv(binary, target, count=True),
            timeout=self.settings.count_timeout_seconds,
            max_bytes=self.settings.max_output_bytes,
        )
        if code != 0:
            raise SweepError(
                "error", f"permutation count exited {code}: {err.decode(errors='replace')[-500:]}"
            )
        lines = [ln for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
        return max(0, len(lines) - 1)  # the list includes the original domain

    async def _scan(self, binary: str, target: str, timeout: float) -> list[dict]:
        code, out, err = await self._run(
            self._argv(binary, target, count=False),
            timeout=timeout,
            max_bytes=self.settings.max_output_bytes,
        )
        if code != 0:
            raise SweepError(
                "error", f"dnstwist exited {code}: {err.decode(errors='replace')[-500:]}"
            )
        try:
            records = json.loads(out)
        except ValueError as e:
            raise SweepError("error", f"unparseable dnstwist output: {e}") from e
        if not isinstance(records, list):
            raise SweepError("error", "dnstwist output is not a JSON list")
        return records

    def _events(self, target: str, run_id: int, records: list) -> list[CandidateEvent]:
        now = self._clock()
        events, skipped = {}, 0
        for item in records:
            if not isinstance(item, dict) or not isinstance(item.get("domain"), str):
                skipped += 1
                continue
            fuzzer = str(item.get("fuzzer", ""))[:64]
            if fuzzer == "*original":
                continue
            try:
                host, _ = canonical_host(item["domain"])
            except InvalidName:
                skipped += 1
                continue
            dns = {
                k: [str(v)[:300] for v in item[k][:50]]
                for k in DNS_KEYS
                if isinstance(item.get(k), list)
            }
            events[host] = CandidateEvent(
                event_id=event_id(SOURCE, target, str(run_id), host),
                source=SOURCE,
                name=host,
                observed_at=utc(now),
                context=DnstwistContext(target=target, fuzzer=fuzzer, run_id=run_id, dns=dns),
            )
        if skipped:
            log.warning(
                "skipped malformed dnstwist records",
                extra={"fields": {"target": target, "count": skipped}},
            )
        return list(events.values())

    def _record(self, target: str, run_id: int, records: list, detail: dict) -> SweepResult:
        # No await from here on: the batch is logged and ingested without
        # interleaving, so the replay checkpoint stays valid.
        events = self._events(target, run_id, records)
        try:
            write_events(self.store.rawlog(DISCOVERY_LOG), events)
        except OSError as e:
            detail["rawlog_error"] = str(e)
            log.error(
                "discovery log write failed; ingesting without raw records",
                extra={"fields": {"target": target, "error": str(e)}},
            )
        candidates = failed = 0
        for ev in events:
            try:
                result = ingest(self.store, self.matcher, ev)
            except Exception:  # one bad record must not lose the rest of the batch
                failed += 1
                log.exception("ingest failed", extra={"fields": {"host": ev.name}})
                with contextlib.suppress(sqlite3.Error):
                    hold_replay(self.store, self._clock())
                continue
            candidates += (
                result.outcome in ("candidate", "duplicate") and result.candidate_id is not None
            )
        registered = sorted(ev.name for ev in events)
        previous = self._previous_registered(target, run_id)
        new = sorted(set(registered) - previous) if previous is not None else []
        detail.update(
            registered=len(registered),
            registered_domains=registered,
            candidates=candidates,
            ingest_failures=failed,
            new_count=len(new),
            new=new[:MAX_NEW_LISTED],
            first_run=previous is None,
        )
        status = "ok" if not failed else "partial"
        self._finish_run(run_id, status, detail)
        log.info(
            "dnstwist sweep done",
            extra={
                "fields": {
                    "target": target,
                    "registered": len(registered),
                    "candidates": candidates,
                    "new": len(new),
                    "status": status,
                }
            },
        )
        return SweepResult(
            target,
            run_id,
            status,
            detail.get("permutations", 0),
            len(registered),
            candidates,
            tuple(new),
        )
