"""The single-process pipeline: discovery tasks plus one bounded worker pool per stage.

Stages register by name, so later units add enrichment, fetching and so on
without editing this module. Each stage runs `concurrency` workers that claim
jobs from the SQLite queue; a job's lease is renewed while its handler runs, and
a lost lease cancels the handler. Delivery is at-least-once (see store.jobs), so
handlers must be idempotent. Stages that set `per_domain` never run two jobs for
the same registrable domain at once.

Before startup, the sandbox preflight removes containers orphaned by a crash.
Startup runs registered hooks (for example abandoned-sweep recovery), then
returns expired leases to pending, then starts background tasks and workers.
Everything runs on one asyncio thread, which is also the only user of the
SQLite connection.

Job telemetry (M8): `run_job` logs one INFO `job started` and one INFO `job
finished` per claimed job, from a fixed allowlist (`job_fields`): job id,
stage, case id, round, attempt and the registrable domain (the group key), plus
the outcome and duration at the end. Never the host name, URL, lease token or
error text. A failed attempt logs `job failed` with the exception class only;
the message stays in `jobs.last_error`.
"""

import asyncio
import contextlib
import logging
import os
import re
import socket
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from brandsentinel.discovery.certstream import CertStreamConsumer
from brandsentinel.discovery.dnstwist_runner import DnstwistRunner
from brandsentinel.discovery.events import DISCOVERY_LOG, checkpoint, replay_since_marker
from brandsentinel.logging import exception_fields
from brandsentinel.matching.matcher import Matcher
from brandsentinel.registry.model import Registry
from brandsentinel.store import FIREHOSE_SOURCE, Store
from brandsentinel.store.jobs import Job, LeaseLost
from brandsentinel.store.retention import prune_discovery_events, prune_rawlog

log = logging.getLogger(__name__)

Handler = Callable[[Job], Awaitable[None]]

# A domain is logged only when it looks like one: lowercase, LDH and dots.
_DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
# An exception's `outcome` (a fetch outcome such as `timeout`) is logged only
# when it is a short identifier, never free text.
_OUTCOME_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")


def _int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def job_fields(stage: str, job: Job) -> dict:
    """The allowlisted, privacy-safe fields of a job's lifecycle records."""
    fields: dict = {"job": job.id, "stage": stage, "attempt": job.attempts}
    for key in ("case_id", "round"):
        if (value := _int(job.payload.get(key))) is not None:
            fields[key] = value
    domain = job.payload.get("registrable_domain") or job.group_key
    if isinstance(domain, str) and _DOMAIN_RE.fullmatch(domain):
        fields["domain"] = domain
    return fields


def error_fields(error: BaseException) -> dict:
    """`exception_fields`, plus a fetch outcome the exception carries."""
    fields = exception_fields(error)
    outcome = getattr(error, "outcome", None)
    if isinstance(outcome, str) and _OUTCOME_RE.fullmatch(outcome):
        fields["fetch_outcome"] = outcome
    return fields


@dataclass
class Stage:
    name: str
    handler: Handler
    concurrency: int
    per_domain: bool = False
    # Running jobs allowed per registrable domain (job group key) in this stage.
    per_group_limit: int | None = None
    lease_seconds: float = 300.0
    poll_seconds: float = 1.0
    retry_delay_seconds: float = 60.0


@dataclass
class Orchestrator:
    store: Store
    owner: str = field(default_factory=lambda: f"{socket.gethostname()}:{os.getpid()}")
    stages: dict[str, Stage] = field(default_factory=dict)
    startup_hooks: list[Callable[[], object]] = field(default_factory=list)
    tasks: dict[str, Callable[[], Awaitable[None]]] = field(default_factory=dict)
    # The sandbox runner (a SandboxRunner) once preflight and the orphan sweep
    # passed (U23); None while sandboxes are unavailable. Sandbox stages (M6, M7)
    # register only when it is set.
    sandbox: object | None = None
    sandbox_disabled: list[str] = field(default_factory=list)
    # Why the browser stage (M7) is not registered although sandboxes run: the
    # network check, with its direct-egress probe, did not pass at startup.
    browser_disabled: list[str] = field(default_factory=list)
    _domain_locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    _domain_users: dict[str, int] = field(default_factory=dict)

    def register_stage(self, stage: Stage) -> None:
        if stage.name in self.stages:
            raise ValueError(f"stage {stage.name!r} already registered")
        self.stages[stage.name] = stage

    def add_task(self, name: str, factory: Callable[[], Awaitable[None]]) -> None:
        self.tasks[name] = factory

    def startup(self) -> int:
        for hook in self.startup_hooks:
            hook()
        recovered = self.store.jobs.recover_expired()
        if recovered:
            log.warning("recovered expired job leases", extra={"fields": {"jobs": recovered}})
        return recovered

    async def run(self, stop: asyncio.Event) -> None:
        self.startup()
        running = [
            asyncio.create_task(self._supervise(name, factory), name=name)
            for name, factory in self.tasks.items()
        ]
        for stage in self.stages.values():
            running += [
                asyncio.create_task(self._worker(stage, i), name=f"{stage.name}-{i}")
                for i in range(stage.concurrency)
            ]
        try:
            await stop.wait()
        finally:
            for t in running:
                t.cancel()
            await asyncio.gather(*running, return_exceptions=True)

    async def _supervise(self, name: str, factory: Callable[[], Awaitable[None]]) -> None:
        """Restart a background task that crashes, after a pause, and log why."""
        while True:
            try:
                await factory()
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error(
                    "background task crashed; restarting",
                    extra={"fields": {"task": name, **exception_fields(e)}},
                )
                await asyncio.sleep(30)

    # --- stage workers ---------------------------------------------------------

    async def _worker(self, stage: Stage, index: int) -> None:
        """Claim and run jobs forever. A store error is logged and retried after a
        capped pause; it never ends the worker."""
        owner = f"{self.owner}/{stage.name}-{index}"
        errors = 0
        while True:
            try:
                job = self.store.jobs.claim(
                    stage.name, owner, stage.lease_seconds, per_group_limit=stage.per_group_limit
                )
                if job is not None:
                    await self.run_job(stage, job)
                errors = 0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                errors += 1
                log.error(
                    "stage worker error",
                    extra={"fields": {"stage": stage.name, **exception_fields(e)}},
                )
                await asyncio.sleep(min(60.0, stage.poll_seconds * 2**errors))
                continue
            if job is None:
                await asyncio.sleep(stage.poll_seconds)

    async def run_job(self, stage: Stage, job: Job) -> None:
        """Run one claimed job, between a `job started` and a `job finished`
        record. Outcomes: completed, retry (failed, will be retried), failed (out
        of attempts), lease_lost, unrecorded (the failure could not be stored;
        the lease expires and the queue decides), cancelled (shutdown) and error
        (the store failed on completion)."""
        fields = job_fields(stage.name, job)
        log.info("job started", extra={"fields": fields})
        start = time.monotonic()
        outcome = "error"
        try:
            outcome = await self._run_job(stage, job)
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        finally:
            elapsed = int((time.monotonic() - start) * 1000)
            log.info(
                "job finished",
                extra={"fields": {**fields, "outcome": outcome, "duration_ms": elapsed}},
            )

    async def _run_job(self, stage: Stage, job: Job) -> str:
        # The lease is renewed from claim onwards, including while the job waits
        # for its registrable domain's lock.
        domain = (
            (job.group_key or job.payload.get("registrable_domain")) if stage.per_domain else None
        )
        work = asyncio.create_task(self._locked(stage, job, domain))
        renewer = asyncio.create_task(self._renew(stage, job, work))
        try:
            await work
        except asyncio.CancelledError:
            if not renewer.done():  # we were cancelled, not the lease
                raise
            log.warning("lease lost; handler cancelled", extra={"fields": {"job": job.id}})
            return "lease_lost"
        except Exception as e:
            return self._fail(stage, job, e)
        finally:
            renewer.cancel()
            # Wait for the renewer without suppressing CancelledError: a shutdown
            # that arrives here must cancel this worker, not be swallowed (the
            # worker would then run forever and Orchestrator.run never return).
            await asyncio.wait({renewer})
        try:
            self.store.jobs.complete(job)
        except LeaseLost:
            log.warning("lease lost before completion", extra={"fields": {"job": job.id}})
            return "lease_lost"
        return "completed"

    async def _locked(self, stage: Stage, job: Job, domain: str | None) -> None:
        async with self._domain_lock(domain):
            await stage.handler(job)

    def _fail(self, stage: Stage, job: Job, error: Exception) -> str:
        """Record a failed attempt; the message goes to the store only."""
        try:
            status = self.store.jobs.fail(
                job, f"{type(error).__name__}: {error}", retry_delay=stage.retry_delay_seconds
            )
        except (LeaseLost, sqlite3.Error) as e:
            # The lease expires and the job is retried; nothing else to do here.
            # Not log.exception: the traceback would chain the handler's error.
            log.error(
                "could not record job failure",
                extra={"fields": {"job": job.id, "stage": stage.name, **exception_fields(e)}},
            )
            return "lease_lost" if isinstance(e, LeaseLost) else "unrecorded"
        log.error(
            "job failed",
            extra={
                "fields": {
                    "job": job.id,
                    "stage": stage.name,
                    "status": status,
                    "attempt": job.attempts,
                    **error_fields(error),
                }
            },
        )
        return "failed" if status == "failed" else "retry"

    async def _renew(self, stage: Stage, job: Job, work: asyncio.Task) -> None:
        while True:
            await asyncio.sleep(stage.lease_seconds / 3)
            try:
                self.store.jobs.renew(job, stage.lease_seconds)
            except LeaseLost:
                work.cancel()
                return
            except sqlite3.Error as e:  # transient; the lease still has time left
                log.error(
                    "lease renewal failed", extra={"fields": {"job": job.id, **exception_fields(e)}}
                )

    @contextlib.asynccontextmanager
    async def _domain_lock(self, domain: str | None):
        if not domain:
            yield
            return
        lock = self._domain_locks.setdefault(domain, asyncio.Lock())
        self._domain_users[domain] = self._domain_users.get(domain, 0) + 1
        try:
            async with lock:
                yield
        finally:
            self._domain_users[domain] -= 1
            if not self._domain_users[domain]:  # keep the lock map bounded
                del self._domain_users[domain]
                del self._domain_locks[domain]


# --- the `run` service ------------------------------------------------------------

MAINTENANCE_SECONDS = 300.0


def maintenance(store: Store, now: float) -> None:
    """Checkpoint replay progress and enforce raw-log and event retention."""
    rl = store.config.rawlog
    checkpoint(store, now)
    prune_rawlog(store.rawlog(DISCOVERY_LOG), now=now, max_age_days=rl.discovery_max_age_days)
    prune_rawlog(
        store.rawlog(FIREHOSE_SOURCE),
        now=now,
        max_age_days=rl.firehose.max_age_days,
        max_bytes=rl.firehose.max_total_bytes,
    )
    prune_discovery_events(store.conn, now=now, max_age_days=rl.discovery_max_age_days)
    # Fairness bookkeeping for domains not served in a month carries no information.
    store.conn.execute("DELETE FROM job_groups WHERE last_claimed_at < ?", (now - 30 * 86400,))


async def _stop_when_idle(orch: Orchestrator, stop: asyncio.Event, clock) -> None:
    """Set `stop` once the run is idle twice in a row, a settle interval apart.

    It starts with the other tasks, after startup (lease recovery; the discovery
    log was replayed before). A handler queues its successor before its own job
    completes and promotion moves deferred work atomically, so a case with work
    left always shows a pending or running job; the second look covers what
    that argument might miss. The settle interval is the promotion interval
    plus two of the slowest worker polls. Workers are idle when `stop` is set,
    so no job is cancelled, and future rechecks stay where they are."""
    from brandsentinel.pipeline import scheduling

    store = orch.store
    poll = max((s.poll_seconds for s in orch.stages.values()), default=1.0)
    settle = store.config.scheduling.promote_interval_seconds + 2 * poll
    while True:
        await asyncio.sleep(poll)
        if not scheduling.idle_snapshot(store.conn, orch.stages, clock()).idle:
            continue
        await asyncio.sleep(settle)
        snap = scheduling.idle_snapshot(store.conn, orch.stages, clock())
        if snap.idle:
            log.info(
                "run idle; stopping",
                extra={
                    "fields": {
                        "deferred_not_due": snap.not_due_deferred,
                        "unserved_jobs": snap.unserved,
                    }
                },
            )
            stop.set()
            return


async def _prepare_sandbox(orch: Orchestrator, config) -> None:
    """Run the runtime preflight and the orphan sweep, before any stage exists and
    before any job lease is recovered (KTD2, AE18).

    The sweep also runs when only non-safety checks failed (for example the image
    is missing), so containers left by a crash never outlive a restart; it never
    runs against an endpoint that is unreachable or not rootless. Sandbox stages
    are available only when every check and the sweep passed.

    Untrusted content is executed only under a dedicated account (SP1, R50): when
    the account checks fail, or pass only because of
    `runtime.allow_developer_account`, sandbox stages stay disabled outside lab
    mode, whose content is synthetic."""
    from brandsentinel.sandbox.preflight import gate_hostile_content, prepare_runtime
    from brandsentinel.sandbox.runner import SandboxError, SandboxRunner

    runner, report = await prepare_runtime(config)
    runner = gate_hostile_content(config, runner, report)
    passed = {c.name for c in report.checks if c.ok}
    sweeper = runner or (
        SandboxRunner(config.sandbox, report.docker) if {"endpoint", "rootless"} <= passed else None
    )
    if sweeper is not None:
        try:
            removed = await asyncio.to_thread(sweeper.sweep_orphans)
            log.info("sandbox orphan sweep", extra={"fields": {"removed": removed}})
        except SandboxError as e:
            runner = None
            report.add("orphan_sweep", False, str(e)[:300])
    if runner is None:
        orch.sandbox_disabled = report.reasons()
        log.warning("sandbox stages disabled", extra={"fields": {"reasons": orch.sandbox_disabled}})
        return
    orch.sandbox = runner


async def _register_render(orch: Orchestrator, analysis, config, browser_client, media_client):
    """Register the browser stage only after the sandbox network check, with its
    direct-egress probe, passes (R41, R43). Otherwise render jobs wait (cases show
    `render pending`) and run once a restart finds the network sound."""
    from brandsentinel.pipeline.render import RenderStage
    from brandsentinel.sandbox.browser_client import build_browser_client
    from brandsentinel.sandbox.media_client import MediaClient

    if browser_client is None:
        browser_client, failed = await build_browser_client(orch.sandbox, config)
        if browser_client is None:
            orch.browser_disabled = failed
            log.warning("browser stage disabled", extra={"fields": {"reasons": failed}})
            return
    media = None
    if config.media.enabled:
        media = media_client or MediaClient(orch.sandbox, config.media)
    RenderStage(analysis, browser_client, media).register(orch)


async def run_service(
    store: Store,
    registry: Registry,
    *,
    certstream_enabled: bool,
    dnstwist_enabled: bool,
    stop: asyncio.Event,
    enrich_enabled: bool | None = None,
    fetch_enabled: bool | None = None,
    sandbox_enabled: bool | None = None,
    analysis=None,
    media_client=None,
    browser_client=None,
    clock: Callable[[], float] | None = None,
    until_idle: bool = False,
) -> Orchestrator:
    """Wire discovery sources, analysis stages, deferred-work promotion and
    maintenance into an orchestrator and run it until `stop` is set. Replays the
    discovery log before any source starts. `analysis` (an AnalysisStages)
    replaces the default network wiring, and `media_client` and `browser_client`
    the sandboxed clients, for tests.

    `until_idle` (M8) also sets `stop` once the run has no work left
    (`scheduling.idle_snapshot`), seen twice a settle interval apart. Refused
    with discovery on: CertStream and dnstwist never go idle."""
    from brandsentinel.pipeline import scheduling
    from brandsentinel.pipeline.stages import AnalysisStages, build_network

    if until_idle and (certstream_enabled or dnstwist_enabled):
        raise ValueError("until_idle needs CertStream and dnstwist off")
    clock = clock or time.time
    config = store.config
    matcher = Matcher(registry)
    orch = Orchestrator(store)

    if config.sandbox.enabled if sandbox_enabled is None else sandbox_enabled:
        await _prepare_sandbox(orch, config)

    stats = replay_since_marker(store, matcher, now=clock())
    log.info("discovery log replayed", extra={"fields": stats.__dict__})

    if dnstwist_enabled:
        runner = DnstwistRunner(store, matcher, registry, config, clock=clock)
        orch.startup_hooks.append(runner.recover_abandoned)
        orch.add_task("dnstwist", runner.run)
    if certstream_enabled:
        consumer = CertStreamConsumer(store, matcher, config, clock=clock)
        orch.add_task("certstream", consumer.run)

    enrich_on = config.enrich.enabled if enrich_enabled is None else enrich_enabled
    fetch_on = config.fetch.enabled if fetch_enabled is None else fetch_enabled
    sandbox_on = config.sandbox.enabled if sandbox_enabled is None else sandbox_enabled
    if enrich_on or fetch_on:
        if analysis is None:
            guard, fetcher = build_network(config)
            analysis = AnalysisStages(store, registry, guard=guard, fetcher=fetcher, clock=clock)
        analysis.media_enabled = sandbox_on and config.media.enabled
        analysis.register(orch, enrich=enrich_on, fetch=fetch_on)
        # The media stage exists only when the runtime preflight, the account
        # gate and the orphan sweep passed. Otherwise media jobs wait (cases show
        # `pending`), and run once a restart finds the sandbox available.
        if fetch_on and analysis.media_enabled and orch.sandbox is not None:
            from brandsentinel.pipeline.media import MediaStage
            from brandsentinel.sandbox.media_client import MediaClient

            MediaStage(analysis, media_client or MediaClient(orch.sandbox, config.media)).register(
                orch
            )
        analysis.render_enabled = sandbox_on and config.browser.enabled
        if fetch_on and analysis.render_enabled and orch.sandbox is not None:
            await _register_render(orch, analysis, config, browser_client, media_client)

    async def promote() -> None:
        interval = config.scheduling.promote_interval_seconds
        while True:
            moved = scheduling.promote(store.conn, store.jobs, config.scheduling, now=clock())
            if moved:
                log.info("deferred work promoted", extra={"fields": {"jobs": moved}})
            await asyncio.sleep(interval)

    orch.add_task("promote", promote)

    async def maintain() -> None:
        while True:
            maintenance(store, clock())
            await asyncio.sleep(MAINTENANCE_SECONDS)

    orch.add_task("maintenance", maintain)
    if until_idle:
        orch.add_task("idle", lambda: _stop_when_idle(orch, stop, clock))
    try:
        await orch.run(stop)
    finally:
        maintenance(store, clock())
    return orch
