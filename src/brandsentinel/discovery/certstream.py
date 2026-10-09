"""CertStream consumer (certstream-server-go full stream) over plain websockets.

Guarantees are limited to certificates actually received:

- Every name on a certificate is matched; each matching name becomes its own
  `CandidateEvent` (one certificate with three matching SANs yields three).
- Matching events are flushed to the discovery log before they are ingested, and
  ingest is idempotent on (certificate fingerprint, host), so a duplicate
  delivery, a reconnect or a crash-and-replay never duplicates a candidate, case
  or job. A host seen again on a new certificate is a new observation of the same
  candidate (counted in `candidate_sources`), not a new case.
- Time the feed was not delivering (disconnects, and the downtime of this process
  since its last message) is recorded in `coverage_gaps`, with per-log
  `cert_index` jumps where the next message shows them. Certificates logged
  during a gap are not recovered: the feed has no replay.

Memory is bounded: a fixed-size fingerprint LRU, a capped per-log index map, and
the websocket's own message-size and queue limits.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

import websockets

from brandsentinel.config import Config
from brandsentinel.discovery.events import (
    DISCOVERY_LOG,
    CandidateEvent,
    CertContext,
    event_id,
    get_state,
    hold_replay,
    ingest,
    put_state,
    utc,
    write_events,
)
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import InvalidName
from brandsentinel.store import FIREHOSE_SOURCE, Store
from brandsentinel.store.db import transaction
from brandsentinel.store.retention import free_bytes

log = logging.getLogger(__name__)

SOURCE = "certstream"
STATE_SAVE_SECONDS = 10.0
MAX_TRACKED_LOGS = 512
# After a reconnect, the first message from each CT log within this window is
# compared with that log's last index to measure what the gap skipped.
GAP_INDEX_WINDOW_SECONDS = 120.0
DISK_CHECK_SECONDS = 30.0


class _LRU:
    def __init__(self, size: int) -> None:
        self._size = size
        self._d: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key in self._d:
            self._d.move_to_end(key)
            return True
        return False

    def add(self, key: str) -> None:
        self._d[key] = None
        self._d.move_to_end(key)
        if len(self._d) > self._size:
            self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)


@dataclass
class Counters:
    hour: str = ""
    certificates: int = 0
    duplicate_certificates: int = 0
    malformed: int = 0
    matched_certificates: int = 0
    events: int = 0
    new_candidates: int = 0
    affix_uncontexted: int = 0
    rawlog_errors: int = 0
    ingest_errors: int = 0
    firehose_records: int = 0


@dataclass
class _Gap:
    id: int
    ended_at: float
    checked_logs: set[str] = field(default_factory=set)


def _str(v: object, limit: int = 500) -> str | None:
    return v[:limit] if isinstance(v, str) else None


def _num(v: object) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


class CertStreamConsumer:
    def __init__(
        self,
        store: Store,
        matcher: Matcher,
        config: Config,
        *,
        clock: Callable[[], float] = time.time,
        connect: Callable = websockets.connect,
        sleep: Callable = asyncio.sleep,
    ) -> None:
        self.store = store
        self.matcher = matcher
        self.settings = config.discovery.certstream
        self.config = config
        self._clock = clock
        self._connect = connect
        self._sleep = sleep
        self._dedupe = _LRU(self.settings.dedupe_cache_size)
        self.counters = Counters()
        state = get_state(store.conn, SOURCE)
        self._last_message_at: float | None = state.get("last_message_at")
        self._last_index: dict[str, int] = dict(state.get("last_index", {}))
        # A previous run's last message opens a gap that the first message closes.
        self._down_since: float | None = self._last_message_at
        self._down_reason = "process_restart"
        self._gap: _Gap | None = None
        self._state_saved_at = 0.0
        self._disk_ok = True
        self._disk_checked_at = -DISK_CHECK_SECONDS
        self.failures = 0

    # --- connection loop ---------------------------------------------------

    def backoff(self) -> float:
        s = self.settings
        return min(s.backoff_max_seconds, s.backoff_initial_seconds * 2 ** min(self.failures, 30))

    async def run(self) -> None:
        """Consume until cancelled, reconnecting with capped exponential backoff."""
        s = self.settings
        try:
            while True:
                try:
                    async with self._connect(
                        s.url,
                        ping_interval=s.ping_interval_seconds,
                        ping_timeout=s.ping_interval_seconds,
                        open_timeout=s.open_timeout_seconds,
                        max_size=s.max_message_bytes,
                        max_queue=64,
                    ) as ws:
                        log.info("certstream connected", extra={"fields": {"url": s.url}})
                        async for raw in ws:
                            if self.handle_message(raw):
                                self.failures = 0
                    reason = "closed"
                except (OSError, TimeoutError, websockets.WebSocketException) as e:
                    reason = type(e).__name__
                    log.warning(
                        "certstream connection lost",
                        extra={"fields": {"url": s.url, "error": str(e)[:300]}},
                    )
                except Exception as e:  # never let one bad state kill the consumer
                    reason = type(e).__name__
                    log.exception("certstream consumer error; reconnecting")
                self.disconnected(reason)
                delay = self.backoff()
                self.failures += 1
                await self._sleep(delay)
        finally:
            try:
                self.save_state(force=True)
            except sqlite3.Error:
                log.exception("could not save certstream state")

    def disconnected(self, reason: str) -> None:
        if self._down_since is None:
            self._down_since = self._last_message_at or self._clock()
            self._down_reason = reason

    # --- message handling --------------------------------------------------

    def handle_message(self, raw: str | bytes) -> bool:
        """Process one websocket message. Returns True if it was a well-formed
        message from the feed (so the connection is healthy). Never raises for
        bad input."""
        now = self._clock()
        self._roll_hour(now)
        try:
            msg = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            msg = None
        if not isinstance(msg, dict) or not isinstance(msg.get("message_type"), str):
            self.counters.malformed += 1
            log.error("malformed certstream message", extra={"fields": {"bytes": len(raw)}})
            return False
        try:
            self._feed_alive(now)
            if msg["message_type"] == "certificate_update":
                self._handle_certificate(msg.get("data"), now)
            self.save_state()
        except _Malformed as e:
            self.counters.malformed += 1
            log.error("malformed certificate update", extra={"fields": {"error": str(e)}})
        except sqlite3.Error as e:
            log.error(
                "store error handling certstream message", extra={"fields": {"error": str(e)}}
            )
        return True

    def _feed_alive(self, now: float) -> None:
        if self._down_since is not None:
            with transaction(self.store.conn):
                cur = self.store.conn.execute(
                    "INSERT INTO coverage_gaps (source, started_at, ended_at, reason)"
                    " VALUES (?, ?, ?, ?)",
                    (SOURCE, self._down_since, now, self._down_reason),
                )
            log.warning(
                "certstream coverage gap",
                extra={
                    "fields": {
                        "seconds": round(now - self._down_since, 1),
                        "reason": self._down_reason,
                    }
                },
            )
            self._gap = _Gap(cur.lastrowid, now)
            self._down_since = None
        self._last_message_at = now

    def _handle_certificate(self, data: object, now: float) -> None:
        if not isinstance(data, dict) or not isinstance(data.get("leaf_cert"), dict):
            raise _Malformed("missing data.leaf_cert")
        leaf = data["leaf_cert"]
        names = leaf.get("all_domains")
        if not isinstance(names, list):
            raise _Malformed("leaf_cert.all_domains is not a list")
        names = [n for n in names[: self.settings.max_names_per_cert] if isinstance(n, str)]
        source = data.get("source") if isinstance(data.get("source"), dict) else {}
        log_url = _str(source.get("url"))
        cert_index = data.get("cert_index")
        cert_index = cert_index if isinstance(cert_index, int) else None
        self.counters.certificates += 1
        self._track_index(log_url, cert_index)

        fingerprint = _str(leaf.get("fingerprint"), 200) or _str(leaf.get("sha256"), 200)
        if not fingerprint:  # fall back to identity fields so dedupe still works
            ident = json.dumps([leaf.get("serial_number"), leaf.get("not_before"), names])
            fingerprint = "derived:" + hashlib.sha256(ident.encode()).hexdigest()
        if fingerprint in self._dedupe:
            self.counters.duplicate_certificates += 1
            return

        issuer = leaf.get("issuer") if isinstance(leaf.get("issuer"), dict) else {}
        context = CertContext(
            fingerprint=fingerprint,
            issuer={k: _str(issuer.get(k), 300) for k in ("O", "CN", "C") if k in issuer},
            not_before=_num(leaf.get("not_before")),
            not_after=_num(leaf.get("not_after")),
            serial_number=_str(leaf.get("serial_number"), 200),
            all_domains=[n[:300] for n in names],
            san_count=len(names),
            cert_index=cert_index,
            log_url=log_url,
            log_name=_str(source.get("name")),
            seen=_num(data.get("seen")),
        )
        self._firehose(context, now)
        brief = context.model_copy(update={"all_domains": []})

        matched, seen_hosts = [], set()
        for name in names:
            try:
                m = self.matcher.match(name)
            except InvalidName:
                continue
            if m.host in seen_hosts:  # *.x.com and x.com on one certificate
                continue
            seen_hosts.add(m.host)
            if "isha_affix_uncontexted" in m.notes:
                self.counters.affix_uncontexted += 1
            if m.candidate:
                # The full SAN list is kept once per certificate (on its first
                # event), so many matching SANs cannot multiply storage.
                ctx = context if not matched else brief
                ev = CandidateEvent(
                    event_id=event_id(SOURCE, fingerprint, m.host),
                    source=SOURCE,
                    name=m.host,
                    observed_at=utc(now),
                    context=ctx,
                )
                matched.append((ev, m))
        if not matched:
            self._dedupe.add(fingerprint)
            return
        self.counters.matched_certificates += 1
        try:
            write_events(self.store.rawlog(DISCOVERY_LOG), (ev for ev, _ in matched))
        except OSError as e:
            self.counters.rawlog_errors += 1
            log.error(
                "discovery log write failed; ingesting without raw record",
                extra={"fields": {"error": str(e), "fingerprint": fingerprint}},
            )
        failed = False
        for ev, m in matched:
            try:
                result = ingest(self.store, self.matcher, ev, match=m, now=now)
            except sqlite3.Error as e:
                # The raw record is on disk: hold the replay checkpoint so the
                # next startup ingests it, and let a redelivery retry it now.
                failed = True
                self.counters.ingest_errors += 1
                log.error(
                    "ingest failed; event kept in discovery log for replay",
                    extra={"fields": {"host": ev.name, "error": str(e)}},
                )
                with contextlib.suppress(sqlite3.Error):
                    hold_replay(self.store, now)
                continue
            self.counters.events += 1
            if result.new_candidate:
                self.counters.new_candidates += 1
                log.info(
                    "new candidate",
                    extra={
                        "fields": {
                            "source": SOURCE,
                            "host": result.host,
                            "strength": m.strength,
                            "case_id": result.case_id,
                        }
                    },
                )
        if not failed:
            self._dedupe.add(fingerprint)

    def _track_index(self, log_url: str | None, index: int | None) -> None:
        if log_url is None or index is None:
            return
        last = self._last_index.get(log_url)
        gap = self._gap
        if gap is not None:
            if self._clock() - gap.ended_at > GAP_INDEX_WINDOW_SECONDS:
                self._gap = None
            elif log_url not in gap.checked_logs:
                gap.checked_logs.add(log_url)
                if last is not None and index > last + 1:
                    self._record_jump(gap.id, log_url, last, index)
        if last is None and len(self._last_index) >= MAX_TRACKED_LOGS:
            return
        if last is None or index > last:
            self._last_index[log_url] = index

    def _record_jump(self, gap_id: int, log_url: str, last: int, index: int) -> None:
        conn = self.store.conn
        with transaction(conn):
            row = conn.execute(
                "SELECT detail_json FROM coverage_gaps WHERE id = ?", (gap_id,)
            ).fetchone()
            detail = json.loads(row[0]) if row else {}
            jumps = detail.setdefault("cert_index_jumps", {})
            jumps[log_url] = {"last_seen": last, "resumed_at": index, "missed": index - last - 1}
            conn.execute(
                "UPDATE coverage_gaps SET detail_json = ? WHERE id = ?",
                (json.dumps(detail, sort_keys=True), gap_id),
            )

    # --- firehose and state ------------------------------------------------

    def _firehose(self, context: CertContext, now: float) -> None:
        fh = self.config.rawlog.firehose
        if not fh.enabled:
            return
        if now - self._disk_checked_at >= DISK_CHECK_SECONDS:
            self._disk_checked_at = now
            ok = free_bytes(self.config.data_dir) >= self.config.rawlog.min_free_bytes
            ok = ok and self.store.raw_bytes(FIREHOSE_SOURCE) < fh.max_total_bytes
            if ok != self._disk_ok:
                log.log(
                    logging.INFO if ok else logging.ERROR,
                    "firehose resumed" if ok else "firehose paused: disk or size limit",
                )
            self._disk_ok = ok
        if not self._disk_ok:
            return
        try:
            self.store.rawlog(FIREHOSE_SOURCE).write(context.model_dump(mode="json"))
            self.counters.firehose_records += 1
        except OSError as e:
            self._disk_ok = False
            log.error("firehose write failed; paused", extra={"fields": {"error": str(e)}})

    def _roll_hour(self, now: float) -> None:
        """Keep one sample per hour (certificates, matches, candidates, firehose)
        in health_samples, for the per-hour throughput and storage measurements."""
        hour = utc(now).strftime("%Y-%m-%dT%H")
        if hour == self.counters.hour:
            return
        if self.counters.hour:
            sample = {"source": SOURCE, **self.counters.__dict__}
            with transaction(self.store.conn):
                self.store.conn.execute(
                    "INSERT INTO health_samples (sampled_at, data_json) VALUES (?, ?)",
                    (now, json.dumps(sample, sort_keys=True)),
                )
        self.counters = Counters(hour=hour)

    def save_state(self, *, force: bool = False) -> None:
        now = self._clock()
        if not force and now - self._state_saved_at < STATE_SAVE_SECONDS:
            return
        self._state_saved_at = now
        state = {
            "last_message_at": self._last_message_at,
            "last_index": self._last_index,
            "connected": self._down_since is None and self._last_message_at is not None,
            "counters": self.counters.__dict__,
        }
        put_state(self.store.conn, SOURCE, state, now)


class _Malformed(Exception):
    pass
