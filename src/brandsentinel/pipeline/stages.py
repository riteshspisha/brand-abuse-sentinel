"""Analysis stages: passive enrichment and the hardened static fetch (M3).

`enrich` runs every registered enrichment source for a case's host, writes the
observations as facts, then schedules the case's static fetch. `fetch` retrieves
the case's page through the hardened fetcher in evidence mode, stores an
accepted body in the blob store, writes the fetch and extractor results, and
records an analysis fingerprint. On a recheck round the fingerprint is compared
with the previous round's and a `material_change` fact says which of DNS
answers, HTTP status, final URL, title or body hash changed (AE19); re-scoring
on change belongs to the policy stage (M5).

Each (case, stage, round) finishes exactly once: its facts and a `stage_runs`
marker are written in one transaction, so a redelivered job is a no-op. A fetch
whose outcome is transient (connection refused, timeout, protocol error) records
the attempt and is retried by the queue; after the last attempt the failure is
recorded as the result. Facts carry `analysis_round` (0 first analysis, then 1
and 2 for the rechecks).
"""

import json
import logging
import sqlite3
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from brandsentinel.analysis import run_extractors
from brandsentinel.config import Config
from brandsentinel.enrich import Cache, EnrichContext, Observation, run_sources
from brandsentinel.enrich.rdap import RdapClient
from brandsentinel.matching.normalize import InvalidName, canonical_host
from brandsentinel.net.fetcher import COLLECTOR_VERSION as FETCH_VERSION
from brandsentinel.net.fetcher import Fetcher, FetchResult
from brandsentinel.net.netguard import DnsResolver, NetGuard, make_dns_resolver
from brandsentinel.pipeline import scheduling
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage
from brandsentinel.registry.model import Registry
from brandsentinel.store import Store
from brandsentinel.store.blobs import QuotaExceeded
from brandsentinel.store.db import transaction
from brandsentinel.store.jobs import Job
from brandsentinel.store.records import add_fact, add_feature, sanitize_value

log = logging.getLogger(__name__)

ENRICH = "enrich"
FETCH = "fetch"
FINGERPRINT_FIELDS = ("addresses", "status", "final_url", "title", "body_sha256")
# A failed https attempt for these reasons is followed by a plain-http attempt.
HTTP_FALLBACK = frozenset({"connect_error", "tls_error", "timeout", "protocol_error"})


class TransientFetchFailure(Exception):
    """Raised to let the job queue retry a fetch that may succeed later."""


@dataclass
class CaseRow:
    case_id: int
    status: str
    subject_url: str | None
    host: str
    registrable_domain: str | None
    match_strength: str
    escalated: int = 0

    @property
    def group_key(self) -> str:
        return scheduling.group_key_for(self.registrable_domain, self.host)


class StoreCache(Cache):
    def __init__(self, conn: sqlite3.Connection, clock: Callable[[], float]) -> None:
        self._conn = conn
        self._clock = clock

    def get(self, source: str, key: str, max_age: float) -> tuple[dict, float] | None:
        row = self._conn.execute(
            "SELECT value_json, observed_at FROM enrichment_cache WHERE source = ? AND key = ?",
            (source, key),
        ).fetchone()
        if row is None or self._clock() - row[1] > max_age:
            return None
        return json.loads(row[0]), row[1]

    def put(self, source: str, key: str, value: dict) -> None:
        with transaction(self._conn):
            self._conn.execute(
                "INSERT INTO enrichment_cache (source, key, value_json, observed_at)"
                " VALUES (?, ?, ?, ?) ON CONFLICT (source, key) DO UPDATE"
                " SET value_json = excluded.value_json, observed_at = excluded.observed_at",
                (source, key, json.dumps(value, sort_keys=True), self._clock()),
            )


def build_network(
    config: Config,
    *,
    guard: NetGuard | None = None,
    verify_context: ssl.SSLContext | None = None,
) -> tuple[NetGuard, Fetcher]:
    guard = guard or NetGuard(config.net, DnsResolver(make_dns_resolver(config.net.dns)))
    return guard, Fetcher(config.fetch, guard, verify_context=verify_context)


class AnalysisStages:
    def __init__(
        self,
        store: Store,
        registry: Registry,
        *,
        guard: NetGuard,
        fetcher: Fetcher,
        resolver=None,
        rdap: RdapClient | None = None,
        verify_context: ssl.SSLContext | None = None,
        tls_port: int = 443,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """`verify_context` and `tls_port` are for tests against the local harness."""
        self.store = store
        self.config = store.config
        self.registry = registry
        self.guard = guard
        self.fetcher = fetcher
        self.resolver = resolver or make_dns_resolver(self.config.net.dns)
        self.rdap = rdap or RdapClient(
            fetcher, self.config.enrich, self.config.cache_dir, clock=clock
        )
        self.verify_context = verify_context
        self.tls_port = tls_port
        self.clock = clock
        self.cache = StoreCache(store.conn, clock)

    def register(self, orch: Orchestrator, *, enrich: bool = True, fetch: bool = True) -> None:
        c = self.config
        if enrich:
            orch.register_stage(
                Stage(
                    ENRICH,
                    self.enrich,
                    concurrency=c.stages.enrich,
                    per_group_limit=c.stages.per_domain_enrich,
                    lease_seconds=c.jobs.lease_for(ENRICH),
                )
            )
        if fetch:
            orch.register_stage(
                Stage(
                    FETCH,
                    self.fetch,
                    concurrency=c.stages.fetch,
                    per_domain=True,
                    per_group_limit=c.stages.per_domain_fetch,
                    lease_seconds=c.jobs.lease_for(FETCH),
                    retry_delay_seconds=c.fetch.retry_delay_seconds,
                )
            )

    # --- helpers -------------------------------------------------------------------

    def _case(self, case_id: int) -> CaseRow | None:
        row = self.store.conn.execute(
            "SELECT c.id, c.status, c.subject_url, k.name, k.registrable_domain,"
            " k.match_strength, c.escalated FROM cases c JOIN candidates k ON k.id = c.candidate_id"
            " WHERE c.id = ?",
            (case_id,),
        ).fetchone()
        return CaseRow(*row) if row else None

    def _done(self, case_id: int, stage: str, rnd: int) -> bool:
        return (
            self.store.conn.execute(
                "SELECT 1 FROM stage_runs WHERE case_id = ? AND stage = ? AND round = ?",
                (case_id, stage, rnd),
            ).fetchone()
            is not None
        )

    def _fact(
        self, case_id: int, source: str, name: str, value: dict, version: str, rnd: int, refs=()
    ) -> int:
        t = self.config.text
        return add_fact(
            self.store.conn,
            case_id,
            source=source,
            name=name,
            value={**value, "analysis_round": rnd},
            collector_version=version,
            artifact_refs=refs,
            max_chars=t.max_fact_chars,
            max_bytes=t.max_fact_bytes,
            now=self.clock(),
        )

    def _schedule(self, case: CaseRow, stage: str, rnd: int, *, not_before: float | None = None):
        return scheduling.schedule(
            self.store.conn,
            self.store.jobs,
            self.config.scheduling,
            stage=stage,
            payload={
                "case_id": case.case_id,
                "name": case.host,
                "registrable_domain": case.registrable_domain,
                "round": rnd,
            },
            group_key=case.group_key,
            queue_class=case.match_strength,
            dedupe_key=f"{stage}:case:{case.case_id}:r{rnd}",
            now=self.clock(),
            not_before=not_before,
            case_id=case.case_id,
            escalated=bool(case.escalated),  # manual cases bypass domain allowances
        )

    def _finish(self, case_id: int, stage: str, rnd: int, outcome: str) -> None:
        now = self.clock()
        self.store.conn.execute(
            "INSERT INTO stage_runs (case_id, stage, round, outcome, finished_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (case_id, stage, rnd, outcome, now),
        )
        self.store.conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))

    # --- enrich ----------------------------------------------------------------------

    def context(self, host: str, registrable_domain: str) -> EnrichContext:
        return EnrichContext(
            host=host,
            registrable_domain=registrable_domain,
            guard=self.guard,
            resolver=self.resolver,
            rdap=self.rdap,
            registry=self.registry,
            settings=self.config.enrich,
            cache=self.cache,
            verify_context=self.verify_context,
            clock=self.clock,
            tls_port=self.tls_port,
        )

    async def enrich(self, job: Job) -> None:
        case_id, rnd = int(job.payload["case_id"]), int(job.payload.get("round", 0))
        case = self._case(case_id)
        if case is None or case.status != "open" or self._done(case_id, ENRICH, rnd):
            return
        observations = await run_sources(self.context(case.host, case.registrable_domain or ""))
        errors = sorted(o.source for o in observations if o.name.endswith("_error"))
        with transaction(self.store.conn):
            if self._done(case_id, ENRICH, rnd):  # a redelivery finished first
                return
            ids = {o.name: self._write(case_id, o, rnd) for o in observations}
            self._derive_age(case_id, observations, ids)
            self._finish(case_id, ENRICH, rnd, "partial" if errors else "ok")
            self._schedule(case, FETCH, rnd)
            if rnd == 0:
                now = self.clock()
                for i, days in enumerate(self.config.scheduling.recheck_after_days, start=1):
                    self._schedule(case, ENRICH, i, not_before=now + days * 86400)

    def _write(self, case_id: int, o: Observation, rnd: int) -> int:
        return self._fact(case_id, o.source, o.name, o.value, o.collector_version, rnd)

    def _derive_age(self, case_id: int, observations: list[Observation], ids: dict) -> None:
        for o in observations:
            if o.name == "rdap_registration" and o.value.get("domain_age_days") is not None:
                # Context for the policy layer, not a maliciousness indicator alone.
                add_feature(
                    self.store.conn,
                    case_id,
                    name="domain_age_days",
                    value=o.value["domain_age_days"],
                    extractor_version="domain_age/1",
                    fact_refs=[ids[o.name]],
                    now=self.clock(),
                )

    # --- fetch -----------------------------------------------------------------------

    def urls_for(self, case: CaseRow) -> list[str]:
        """The manual submission's URL when its host is the candidate host,
        otherwise the site root over https, then http."""
        if case.subject_url:
            try:
                parts = urlsplit(case.subject_url)
                host, _ = canonical_host(parts.hostname or "")
            except (ValueError, InvalidName):
                host = None
            if host == case.host and parts.scheme in ("http", "https"):
                return [case.subject_url]
        return [f"https://{case.host}/", f"http://{case.host}/"]

    async def fetch(self, job: Job) -> None:
        case_id, rnd = int(job.payload["case_id"]), int(job.payload.get("round", 0))
        case = self._case(case_id)
        if case is None or case.status != "open" or self._done(case_id, FETCH, rnd):
            return
        results: list[FetchResult] = []
        for url in self.urls_for(case):
            # Never read more than the blob store would accept for one artifact.
            r = await self.fetcher.fetch(
                url, mode="evidence", max_bytes=self.config.artifacts.max_blob_bytes
            )
            results.append(r)
            if r.outcome not in HTTP_FALLBACK:
                break
        final = results[-1]
        last_attempt = job.attempts >= job.max_attempts
        if final.transient and not last_attempt:
            with transaction(self.store.conn):
                for r in results:
                    self._fact(
                        case_id,
                        "fetcher",
                        "http_fetch_attempt",
                        {**r.to_fact(), "attempt": job.attempts},
                        FETCH_VERSION,
                        rnd,
                    )
            raise TransientFetchFailure(f"{final.outcome}: {final.error}")

        # One transaction for the blob reference, facts, features and the marker:
        # a crash leaves either all of them or none (an orphan file is swept).
        with transaction(self.store.conn):
            if self._done(case_id, FETCH, rnd):  # a redelivery finished first
                return
            blob = self._store_body(case, final)
            fact_ids = []
            for r in results:
                refs = [blob] if r is final and blob else []
                value = {**r.to_fact(), "attempt": job.attempts, "final": r is final}
                fact_ids.append(
                    self._fact(case_id, "fetcher", "http_fetch", value, FETCH_VERSION, rnd, refs)
                )
            title = self._extract(case_id, final, fact_ids[-1], rnd)
            self._fingerprint(case_id, final, title, fact_ids[-1], rnd)
            self._finish(case_id, FETCH, rnd, final.outcome)

    def _store_body(self, case: CaseRow, r: FetchResult) -> str | None:
        if r.body is None or not r.body.data:
            return None
        try:
            sha = self.store.blobs.put(
                r.body.data,
                case_id=case.case_id,
                registrable_domain=case.group_key,
                content_type=r.body.content_type,
                role="page",
                privileged=case.match_strength == "strong",
            )
        except QuotaExceeded:
            return None  # recorded as an artifact_quota_exceeded fact by the store
        r.body_stored = True
        return sha

    def _extract(self, case_id: int, r: FetchResult, fact_id: int, rnd: int) -> str | None:
        if r.body is None or not r.body.data or r.final_url is None:
            return None
        title = None
        for res in run_extractors(r.body.data, r.body.content_type, r.body.charset, r.final_url):
            value = res.value if res.value is not None else {"error": res.error}
            add_feature(
                self.store.conn,
                case_id,
                name=res.extractor.name,
                value={**value, "analysis_round": rnd},
                extractor_version=res.extractor.version,
                fact_refs=[fact_id],
                now=self.clock(),
            )
            if res.extractor.name == "page_basics" and res.value:
                title = res.value.get("title")
        return title

    def _round_fact(self, case_id: int, name: str, rnd: int) -> dict | None:
        row = self.store.conn.execute(
            "SELECT value_json FROM facts WHERE case_id = ? AND name = ?"
            " AND json_extract(value_json, '$.analysis_round') = ? ORDER BY id DESC LIMIT 1",
            (case_id, name, rnd),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _fingerprint(self, case_id: int, r: FetchResult, title, fact_id: int, rnd: int) -> None:
        dns_fact = self._round_fact(case_id, "dns_records", rnd) or {}
        records = dns_fact.get("records", {})
        addresses = None  # unknown unless both address lookups gave a definite answer
        if all(records.get(t, {}).get("status") in ("ok", "no_answer") for t in ("A", "AAAA")):
            addresses = sorted(records["A"]["values"] + records["AAAA"]["values"])
        # Sanitized now, as the stored copy will be, so comparisons are like for like.
        fp = sanitize_value(
            {
                "addresses": addresses,
                "status": r.status,
                "final_url": r.final_url,
                "title": title,
                "body_sha256": r.body.sha256 if r.body else None,
                "fetch_outcome": r.outcome,
            },
            self.config.text.max_fact_chars,
        )
        self._fact(case_id, "pipeline", "analysis_fingerprint", fp, "fingerprint/1", rnd, ())
        if rnd == 0:
            return
        previous = None
        for prev in range(rnd - 1, -1, -1):
            previous = self._round_fact(case_id, "analysis_fingerprint", prev)
            if previous:
                break
        if previous is None:
            return
        # A field missing on either side (failed lookup or fetch) is "unknown", not
        # a change, so an outage does not look like new content.
        unknown = [f for f in FINGERPRINT_FIELDS if previous.get(f) is None or fp.get(f) is None]
        changed = [
            f for f in FINGERPRINT_FIELDS if f not in unknown and previous.get(f) != fp.get(f)
        ]
        self._fact(
            case_id,
            "pipeline",
            "material_change",
            {
                "previous_round": previous["analysis_round"],
                "changed": bool(changed),
                "fields": changed,
                "unknown_fields": unknown,
            },
            "fingerprint/1",
            rnd,
        )
