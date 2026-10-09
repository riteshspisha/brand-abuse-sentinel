"""The single-process pipeline: discovery tasks plus one bounded worker pool per stage.

Stages register by name, so later units add enrichment, fetching and so on
without editing this module. Each stage runs `concurrency` workers that claim
jobs from the SQLite queue; a job's lease is renewed while its handler runs, and
a lost lease cancels the handler. Delivery is at-least-once (see store.jobs), so
handlers must be idempotent. Stages that set `per_domain` never run two jobs for
the same registrable domain at once.

Startup runs registered hooks (for example abandoned-sweep recovery, later the
sandbox orphan sweep), then returns expired leases to pending, then starts
background tasks and workers. Everything runs on one asyncio thread, which is
also the only user of the SQLite connection.
"""

import asyncio
import contextlib
import logging
import os
import socket
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from brandsentinel.discovery.certstream import CertStreamConsumer
from brandsentinel.discovery.dnstwist_runner import DnstwistRunner
from brandsentinel.discovery.events import DISCOVERY_LOG, checkpoint, replay_since_marker
from brandsentinel.matching.matcher import Matcher
from brandsentinel.registry.model import Registry
from brandsentinel.store import FIREHOSE_SOURCE, Store
from brandsentinel.store.jobs import Job, LeaseLost
from brandsentinel.store.retention import prune_discovery_events, prune_rawlog

log = logging.getLogger(__name__)

Handler = Callable[[Job], Awaitable[None]]


@dataclass
class Stage:
    name: str
    handler: Handler
    concurrency: int
    per_domain: bool = False
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
            except Exception:
                log.exception(
                    "background task crashed; restarting", extra={"fields": {"task": name}}
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
                job = self.store.jobs.claim(stage.name, owner, stage.lease_seconds)
                if job is not None:
                    await self.run_job(stage, job)
                errors = 0
            except asyncio.CancelledError:
                raise
            except Exception:
                errors += 1
                log.exception("stage worker error", extra={"fields": {"stage": stage.name}})
                await asyncio.sleep(min(60.0, stage.poll_seconds * 2**errors))
                continue
            if job is None:
                await asyncio.sleep(stage.poll_seconds)

    async def run_job(self, stage: Stage, job: Job) -> None:
        # The lease is renewed from claim onwards, including while the job waits
        # for its registrable domain's lock.
        domain = job.payload.get("registrable_domain") if stage.per_domain else None
        work = asyncio.create_task(self._locked(stage, job, domain))
        renewer = asyncio.create_task(self._renew(stage, job, work))
        try:
            await work
        except asyncio.CancelledError:
            if not renewer.done():  # we were cancelled, not the lease
                raise
            log.warning("lease lost; handler cancelled", extra={"fields": {"job": job.id}})
            return
        except Exception as e:
            self._fail(stage, job, e)
            return
        finally:
            renewer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renewer
        try:
            self.store.jobs.complete(job)
        except LeaseLost:
            log.warning("lease lost before completion", extra={"fields": {"job": job.id}})

    async def _locked(self, stage: Stage, job: Job, domain: str | None) -> None:
        async with self._domain_lock(domain):
            await stage.handler(job)

    def _fail(self, stage: Stage, job: Job, error: Exception) -> None:
        try:
            status = self.store.jobs.fail(
                job, f"{type(error).__name__}: {error}", retry_delay=stage.retry_delay_seconds
            )
        except (LeaseLost, sqlite3.Error):
            # The lease expires and the job is retried; nothing else to do here.
            log.exception("could not record job failure", extra={"fields": {"job": job.id}})
            return
        log.error(
            "job failed",
            extra={
                "fields": {
                    "job": job.id,
                    "stage": stage.name,
                    "status": status,
                    "attempt": job.attempts,
                    "error": str(error)[:500],
                }
            },
        )

    async def _renew(self, stage: Stage, job: Job, work: asyncio.Task) -> None:
        while True:
            await asyncio.sleep(stage.lease_seconds / 3)
            try:
                self.store.jobs.renew(job, stage.lease_seconds)
            except LeaseLost:
                work.cancel()
                return
            except sqlite3.Error:  # transient; the lease still has time left
                log.exception("lease renewal failed", extra={"fields": {"job": job.id}})

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


async def run_service(
    store: Store,
    registry: Registry,
    *,
    certstream_enabled: bool,
    dnstwist_enabled: bool,
    stop: asyncio.Event,
    clock: Callable[[], float] | None = None,
) -> Orchestrator:
    """Wire discovery sources and maintenance into an orchestrator and run it
    until `stop` is set. Replays the discovery log before any source starts."""
    clock = clock or time.time
    config = store.config
    matcher = Matcher(registry)
    orch = Orchestrator(store)

    stats = replay_since_marker(store, matcher, now=clock())
    log.info("discovery log replayed", extra={"fields": stats.__dict__})

    if dnstwist_enabled:
        runner = DnstwistRunner(store, matcher, registry, config, clock=clock)
        orch.startup_hooks.append(runner.recover_abandoned)
        orch.add_task("dnstwist", runner.run)
    if certstream_enabled:
        consumer = CertStreamConsumer(store, matcher, config, clock=clock)
        orch.add_task("certstream", consumer.run)

    async def maintain() -> None:
        while True:
            maintenance(store, clock())
            await asyncio.sleep(MAINTENANCE_SECONDS)

    orch.add_task("maintenance", maintain)
    try:
        await orch.run(stop)
    finally:
        maintenance(store, clock())
    return orch
