"""Command-line entry point.

Commands that later milestones implement are registered now as stubs, so the
command surface is stable and `--help` documents where each one lands.
"""

import asyncio
import json
import signal
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from brandsentinel import __version__
from brandsentinel.config import Config, ConfigError, load_config
from brandsentinel.discovery.dnstwist_runner import DnstwistRunner
from brandsentinel.discovery.events import replay as replay_events
from brandsentinel.discovery.submit import SubmissionError
from brandsentinel.discovery.submit import submit as submit_name
from brandsentinel.logging import configure_logging
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import InvalidName
from brandsentinel.pipeline import health, scheduling
from brandsentinel.pipeline.orchestrator import run_service
from brandsentinel.registry.legacy_import import LegacyImportError, missing_legacy, read_legacy
from brandsentinel.registry.loader import RegistryError, ValidationReport, load_registry
from brandsentinel.registry.model import Registry
from brandsentinel.store import open_store
from brandsentinel.store.db import schema_version
from brandsentinel.textsafe import escape_terminal

app = typer.Typer(
    name="brandsentinel",
    help="Local-first brand-abuse detection and triage.",
    no_args_is_help=True,
    add_completion=False,
)

# Command -> milestone that implements it.
_PLANNED = {
    "cases": ("M5", "List, inspect and label cases."),
    "report": ("M5", "Render analyst reports."),
    "export": ("M5", "Export cases (CSV)."),
    "eval": ("M8", "Run the model evaluation."),
}


registry_app = typer.Typer(help="Validate and inspect the Brand Registry.", no_args_is_help=True)
app.add_typer(registry_app, name="registry")
sandbox_app = typer.Typer(help="Sandbox runtime checks and maintenance.", no_args_is_help=True)
app.add_typer(sandbox_app, name="sandbox")


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Config YAML (default: $BRANDSENTINEL_CONFIG)."),
    ] = None,
) -> None:
    ctx.obj = {"config_path": config}


def _load(ctx: typer.Context) -> Config:
    try:
        return load_config(ctx.obj.get("config_path"))
    except ConfigError as e:
        typer.echo(escape_terminal(str(e)), err=True)
        raise typer.Exit(2) from e


@app.command()
def version() -> None:
    """Print the BrandSentinel version."""
    typer.echo(__version__)


@app.command()
def status(ctx: typer.Context) -> None:
    """Show store, queue, artifact and raw-log status."""
    config = _load(ctx)
    store = open_store(config)
    try:
        now = datetime.fromtimestamp(time.time(), UTC).isoformat(timespec="seconds")
        typer.echo(f"BrandSentinel {__version__} status at {now}")
        typer.echo(f"store: {config.db_path} (schema v{schema_version(store.conn)})")

        depths = store.jobs.depths()
        if depths:
            typer.echo("jobs:")
            for row in depths:
                typer.echo(
                    f"  {row['stage']:<10} {row['status']:<8} {row['queue_class']:<6} {row['n']}"
                )
        else:
            typer.echo("jobs: none")

        failures = store.jobs.recent_failures()
        if failures:
            typer.echo("recent failed jobs:")
            for row in failures:
                err = escape_terminal(row["last_error"] or "")
                typer.echo(f"  #{row['id']} {row['stage']} after {row['attempts']} attempts: {err}")

        count, total = store.blobs.stats()
        quotas = config.artifacts
        typer.echo(f"artifacts: {count} blobs, {total} of {quotas.max_store_bytes} bytes")
        if total >= int(quotas.max_store_bytes * (1 - quotas.reserve_fraction)):
            typer.echo(
                "  WARNING: store is in its reserved headroom; only strong-strength and"
                " manual cases can add artifacts"
            )

        _print_discovery(health.collect(store, config, time.time()), time.time())
        _print_analysis(store, config)
        _print_sandbox(config)

        sources = store.raw_sources()
        firehose = "on" if config.rawlog.firehose.enabled else "off"
        typer.echo(
            f"raw logs (firehose {firehose}):"
            if sources
            else f"raw logs: none (firehose {firehose})"
        )
        for source in sources:
            typer.echo(f"  {source:<20} {store.raw_bytes(source)} bytes")
    finally:
        store.close()


def _print_analysis(store, config: Config) -> None:
    conn = store.conn
    enrich = "on" if config.enrich.enabled else "off"
    fetch = "on" if config.fetch.enabled else "off"
    lab = " LAB MODE (lab hosts only, through the lab proxy)" if config.net.lab.enabled else ""
    typer.echo(f"analysis: enrich {enrich}, fetch {fetch}{lab}")
    for stage, outcome, n in conn.execute(
        "SELECT stage, outcome, COUNT(*) FROM stage_runs GROUP BY stage, outcome ORDER BY 1, 2"
    ):
        typer.echo(f"  {stage:<10} {escape_terminal(outcome):<26} {n}")
    d = scheduling.deferred_summary(conn, time.time())
    if d["total"]:
        typer.echo(f"deferred work: {d['total']} ({d['due']} due)")
        for domain, n in d["top_domains"]:
            typer.echo(f"  over allowance: {escape_terminal(domain)} {n}")


def _print_checks(title: str, report) -> None:
    """Print a preflight Report."""
    state = "ok" if report.ok else "FAILED"
    typer.echo(f"  {title}: {state}")
    for c in report.failures:
        typer.echo(f"    FAIL {c.name}: {escape_terminal(c.detail)}")
    for c in report.warnings:
        typer.echo(f"    WARNING {c.name}: {escape_terminal(c.detail)}")


def _print_sandbox(config: Config) -> None:
    from brandsentinel.sandbox import preflight
    from brandsentinel.sandbox.runner import DockerCli

    if not config.sandbox.enabled:
        typer.echo("sandbox: disabled by configuration")
        return
    account = preflight.check_account(config)
    runtime = asyncio.run(
        preflight.check_runtime(
            DockerCli(config.runtime.docker_host, config.runtime.docker_binary), config.sandbox
        )
    )
    enabled = account.ok and runtime.ok
    typer.echo(f"sandbox: {'available' if enabled else 'DISABLED'}")
    _print_checks("account", account)
    _print_checks("runtime", runtime)


def _ago(ts: float | None, now: float) -> str:
    if ts is None:
        return "never"
    when = datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")
    return f"{when} ({int(now - ts)}s ago)"


def _print_discovery(h: health.DiscoveryHealth, now: float) -> None:
    typer.echo(f"candidates: {h.candidates_total}")
    for source, n in sorted(h.candidates_by_source.items()):
        typer.echo(f"  seen by {source:<10} {n}")
    if h.certstream_enabled:
        state = "STALE" if h.certstream_stale else "live"
        typer.echo(f"certstream: {state}, last message {_ago(h.certstream_last_message_at, now)}")
        c = h.certstream_counters
        if c:
            typer.echo(
                f"  hour {c.get('hour')}: {c.get('certificates', 0)} certificates,"
                f" {c.get('matched_certificates', 0)} matched, {c.get('events', 0)} events,"
                f" {c.get('new_candidates', 0)} new candidates, {c.get('malformed', 0)} malformed"
            )
        typer.echo(f"  coverage gaps in last 24h: {int(h.open_gaps_seconds_24h)}s")
        for g in h.recent_gaps:
            end = _ago(g["ended_at"], now) if g["ended_at"] else "open"
            jumps = g["detail"].get("cert_index_jumps", {})
            missed = sum(j["missed"] for j in jumps.values())
            extra = f", ~{missed} log entries skipped" if jumps else ""
            typer.echo(
                f"  gap {_ago(g['started_at'], now)} -> {end}"
                f" ({escape_terminal(g['reason'])}{extra})"
            )
    else:
        typer.echo("certstream: disabled")
    if h.dnstwist_enabled:
        typer.echo("dnstwist sweeps:" if h.sweeps else "dnstwist: no sweeps yet")
        for sw in h.sweeps:
            line = f"  {sw.target:<24} {sw.status:<10} {_ago(sw.started_at, now)}"
            if sw.registered is not None:
                line += f" registered {sw.registered}, new {sw.new_count}"
            if sw.error:
                line += f" error: {escape_terminal(sw.error)}"
            typer.echo(line)
        for target in h.unhealthy_targets:
            typer.echo(f"  UNHEALTHY: {target} timed out on its last two sweeps")
    else:
        typer.echo("dnstwist: disabled")
    typer.echo(f"free disk: {h.free_disk_bytes} bytes" + (" (LOW)" if h.low_disk else ""))


@app.command()
def run(
    ctx: typer.Context,
    certstream: Annotated[
        bool | None, typer.Option(help="Consume CertStream (config default).")
    ] = None,
    dnstwist: Annotated[bool | None, typer.Option(help="Run scheduled dnstwist sweeps.")] = None,
    enrich: Annotated[
        bool | None, typer.Option(help="Run passive enrichment (config default).")
    ] = None,
    fetch: Annotated[
        bool | None, typer.Option(help="Run the hardened static fetch (config default).")
    ] = None,
    duration: Annotated[
        float | None, typer.Option(help="Stop after this many seconds (default: run forever).")
    ] = None,
    log_level: Annotated[str, typer.Option(help="Log level.")] = "INFO",
) -> None:
    """Run discovery (CertStream, dnstwist) and the pipeline until interrupted."""
    from brandsentinel.sandbox.preflight import check_account

    config = _load(ctx)
    account = check_account(config)
    for c in account.failures:
        typer.echo(f"refusing to start: {c.name}: {escape_terminal(c.detail)}", err=True)
    if not account.ok:
        raise typer.Exit(2)
    for c in account.warnings:
        typer.echo(f"WARNING {c.name}: {escape_terminal(c.detail)}", err=True)
    configure_logging(log_level.upper())
    registry, _ = _load_registry(config.registry_path, _overlay(config))
    store = open_store(config)

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        if duration is not None:
            loop.call_later(duration, stop.set)
        await run_service(
            store,
            registry,
            certstream_enabled=config.discovery.certstream.enabled
            if certstream is None
            else certstream,
            dnstwist_enabled=config.discovery.dnstwist.enabled if dnstwist is None else dnstwist,
            enrich_enabled=enrich,
            fetch_enabled=fetch,
            stop=stop,
        )

    try:
        asyncio.run(main())
    finally:
        store.close()


@app.command()
def submit(
    ctx: typer.Context,
    targets: Annotated[list[str], typer.Argument(help="URLs or domain names.")],
) -> None:
    """Submit URLs or domains for analysis (never suppressed)."""
    config = _load(ctx)
    registry, _ = _load_registry(config.registry_path, _overlay(config))
    matcher = Matcher(registry)
    store = open_store(config)
    failed = False
    try:
        for target in targets:
            try:
                r = submit_name(store, matcher, target)
            except OSError as e:
                typer.echo(f"error: cannot write discovery log: {e}", err=True)
                raise typer.Exit(1) from e
            except SubmissionError as e:
                failed = True
                typer.echo(
                    f"rejected {escape_terminal(target)}: {escape_terminal(str(e))}", err=True
                )
                continue
            state = "new case" if r.new_case else "existing case"
            typer.echo(f"{escape_terminal(r.host)}: {state} #{r.case_id}")
    finally:
        store.close()
    if failed:
        raise typer.Exit(1)


@app.command()
def sweep(
    ctx: typer.Context,
    targets: Annotated[
        list[str] | None, typer.Argument(help="Registry dnstwist targets (default: all).")
    ] = None,
) -> None:
    """Run dnstwist sweeps now, ignoring the schedule."""
    config = _load(ctx)
    configure_logging("WARNING")
    registry, _ = _load_registry(config.registry_path, _overlay(config))
    store = open_store(config)
    runner = DnstwistRunner(store, Matcher(registry), registry, config)
    known = runner.targets()
    chosen = targets or known
    unknown = [t for t in chosen if t not in known]
    if unknown:
        store.close()
        typer.echo(
            f"not registry dnstwist targets: {escape_terminal(', '.join(unknown))}", err=True
        )
        raise typer.Exit(2)
    failed = False
    try:
        for target in chosen:
            r = asyncio.run(runner.sweep(target))
            failed |= r.status not in ("ok",)
            line = f"{target}: {r.status}, {r.permutations} permutations, {r.registered} registered"
            line += f", {r.candidates} candidates, {len(r.new)} new"
            if r.error:
                line += f" ({escape_terminal(r.error)})"
            typer.echo(line)
    finally:
        store.close()
    if failed:
        raise typer.Exit(1)


@app.command()
def replay(
    ctx: typer.Context,
    since_hours: Annotated[
        float | None, typer.Option(help="Only records logged in the last N hours.")
    ] = None,
) -> None:
    """Re-ingest the discovery raw log (idempotent: nothing is duplicated)."""
    config = _load(ctx)
    registry, _ = _load_registry(config.registry_path, _overlay(config))
    store = open_store(config)
    try:
        since = time.time() - since_hours * 3600 if since_hours is not None else None
        stats = replay_events(store, Matcher(registry), since=since)
    finally:
        store.close()
    typer.echo(
        f"replayed {stats.records} records from {stats.segments} segments:"
        f" {stats.ingested} ingested, {stats.duplicates} already present, {stats.invalid} invalid"
    )


@app.command()
def analyze(
    ctx: typer.Context,
    domain: Annotated[str, typer.Argument(help="Domain name to analyze.")],
    passive: Annotated[
        bool,
        typer.Option(
            "--passive/--fetch",
            help="DNS, RDAP, TLS and similarity only (default), or also a static fetch.",
        ),
    ] = True,
) -> None:
    """Collect enrichment facts for one domain and print them. No case is created
    (RDAP answers are cached for reuse)."""
    from brandsentinel.enrich import run_sources
    from brandsentinel.matching.normalize import canonical_host, registrable_domain
    from brandsentinel.pipeline.stages import HTTP_FALLBACK, AnalysisStages, build_network

    config = _load(ctx)
    registry, _ = _load_registry(config.registry_path, _overlay(config))
    try:
        host, _ = canonical_host(domain)
    except InvalidName as e:
        typer.echo(f"invalid domain: {escape_terminal(str(e))}", err=True)
        raise typer.Exit(2) from e
    store = open_store(config)  # for the shared RDAP cache only
    try:
        guard, fetcher = build_network(config)
        stages = AnalysisStages(store, registry, guard=guard, fetcher=fetcher)

        async def main() -> list:
            obs = await run_sources(stages.context(host, registrable_domain(host)))
            out = [(o.source, o.name, o.value) for o in obs]
            if not passive:
                for url in (f"https://{host}/", f"http://{host}/"):
                    r = await fetcher.fetch(url, mode="evidence")
                    out.append(("fetcher", "http_fetch", r.to_fact()))
                    if r.outcome not in HTTP_FALLBACK:
                        break
            return out

        for source, name, value in asyncio.run(main()):
            text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
            typer.echo(f"== {source} / {name}")
            # split("\n"), not splitlines(): U+2028, NEL and friends inside values
            # must reach escape_terminal rather than become real line breaks.
            for line in text.split("\n"):
                typer.echo(escape_terminal(line))
    finally:
        store.close()


@app.command()
def proxy(
    ctx: typer.Context,
    listen: Annotated[
        list[str], typer.Option("--listen", help="ip:port to listen on (repeatable).")
    ],
    log_level: Annotated[str, typer.Option(help="Log level.")] = "INFO",
) -> None:
    """Run the egress proxy (inside its container; see docker/compose.yaml)."""
    from brandsentinel.net.netguard import DnsResolver, NetGuard, make_dns_resolver
    from brandsentinel.net.proxy import EgressProxy, parse_listen

    config = _load(ctx)
    try:
        addresses = [parse_listen(v) for v in listen]
    except ValueError as e:
        typer.echo(escape_terminal(str(e)), err=True)
        raise typer.Exit(2) from e
    configure_logging(log_level.upper())
    guard = NetGuard(config.net, DnsResolver(make_dns_resolver(config.net.dns)))
    egress = EgressProxy(config.proxy, guard)

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        servers = await egress.start(addresses)
        try:
            await stop.wait()
        finally:
            for server in servers:
                server.close()

    asyncio.run(main())


@sandbox_app.command("check")
def sandbox_check(
    ctx: typer.Context,
    network: Annotated[
        bool, typer.Option("--network/--no-network", help="Also check the sandbox network.")
    ] = True,
) -> None:
    """Run the sandbox preflight: account, rootless runtime and (with a direct-egress
    probe container) the sandbox network. Exits 1 if any check fails."""
    from brandsentinel.sandbox import preflight
    from brandsentinel.sandbox.runner import DockerCli, SandboxRunner

    config = _load(ctx)
    docker = DockerCli(config.runtime.docker_host, config.runtime.docker_binary)
    account = preflight.check_account(config)
    runtime = asyncio.run(preflight.check_runtime(docker, config.sandbox))
    _print_checks("account", account)
    _print_checks("runtime", runtime)
    reports = [account, runtime]
    if network and runtime.ok:
        runner = SandboxRunner(config.sandbox, docker)
        net = asyncio.run(preflight.check_network(docker, config.sandbox, runner))
        _print_checks(f"network {config.sandbox.network}", net)
        for c in net.checks:
            if c.ok and c.name == "direct_egress_blocked":
                typer.echo(f"    probe: {escape_terminal(c.detail)}")
        reports.append(net)
    if not all(r.ok for r in reports):
        raise typer.Exit(1)


@sandbox_app.command("sweep")
def sandbox_sweep(ctx: typer.Context) -> None:
    """Remove every sandbox container labelled with this instance (normally done
    automatically at startup, before job leases are recovered)."""
    from brandsentinel.sandbox.runner import DockerCli, SandboxError, SandboxRunner

    config = _load(ctx)
    docker = DockerCli(config.runtime.docker_host, config.runtime.docker_binary)
    try:
        removed = SandboxRunner(config.sandbox, docker).sweep_orphans()
    except SandboxError as e:
        typer.echo(escape_terminal(str(e)), err=True)
        raise typer.Exit(1) from e
    typer.echo(f"removed {removed} container(s) of instance {config.sandbox.instance}")


def _overlay(config: Config) -> Path | None:
    """The lab registry overlay, only in lab mode."""
    return config.net.lab.registry_overlay if config.net.lab.enabled else None


def _load_registry(path: Path, overlay: Path | None = None) -> tuple[Registry, ValidationReport]:
    try:
        return load_registry(path, overlay)
    except RegistryError as e:
        for err in e.errors:
            typer.echo(f"error: {escape_terminal(err)}", err=True)
        raise typer.Exit(1) from e


@registry_app.command("validate")
def registry_validate(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Option(help="Registry file (default: config).")] = None,
    overlay: Annotated[
        Path | None, typer.Option(help="Also merge this overlay (e.g. registry/lab-overlay.yaml).")
    ] = None,
    legacy_dir: Annotated[
        Path, typer.Option(help="Check coverage of the legacy scripts' inputs.")
    ] = Path("legacy"),
) -> None:
    """Validate the registry and report counts by status and tier."""
    registry_file = path or _load(ctx).registry_path
    registry, report = _load_registry(registry_file, overlay)
    for warning in report.warnings:
        typer.echo(f"warning: {escape_terminal(warning)}")

    missing: list[str] = []
    if legacy_dir.is_dir():
        try:
            missing = missing_legacy(registry, read_legacy(legacy_dir))
        except LegacyImportError as e:
            missing = [str(e)]
        for item in missing:
            typer.echo(f"error: legacy input missing: {escape_terminal(item)}", err=True)
    else:
        typer.echo(f"legacy coverage not checked: {escape_terminal(str(legacy_dir))} not found")

    typer.echo(f"registry {escape_terminal(str(registry_file))}:")
    for section, counts in report.counts.items():
        detail = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"
        typer.echo(f"  {section:<20} {detail}")
    if missing:
        raise typer.Exit(1)
    typer.echo("ok")


@app.command()
def match(
    ctx: typer.Context,
    names: Annotated[list[str] | None, typer.Argument(help="Domain names to match.")] = None,
    file: Annotated[
        Path | None, typer.Option("--file", "-f", help="File with one name per line.")
    ] = None,
    registry: Annotated[Path | None, typer.Option(help="Registry file (default: config).")] = None,
) -> None:
    """Match names against the registry and print one JSON result per line."""
    if registry is not None:
        loaded, report = _load_registry(registry)
    else:
        config = _load(ctx)
        loaded, report = _load_registry(config.registry_path, _overlay(config))
    for warning in report.warnings:
        typer.echo(f"warning: {escape_terminal(warning)}", err=True)
    matcher = Matcher(loaded)
    inputs = list(names or [])
    if file is not None:
        try:
            inputs += [line.strip() for line in file.read_text(encoding="utf-8").splitlines()]
        except (OSError, UnicodeDecodeError) as e:
            typer.echo(f"error: cannot read {escape_terminal(str(file))}: {e}", err=True)
            raise typer.Exit(1) from e
    failed = False
    for name in filter(None, inputs):
        try:
            typer.echo(matcher.match(name).to_json())
        except InvalidName as e:
            failed = True
            typer.echo(f"invalid name {escape_terminal(name)!s}: {e}", err=True)
    if failed:
        raise typer.Exit(1)


def _register_planned(name: str, milestone: str, summary: str) -> None:
    def planned(args: Annotated[list[str] | None, typer.Argument(hidden=True)] = None) -> None:
        typer.echo(f"'{name}' is not implemented yet (planned for {milestone}).", err=True)
        raise typer.Exit(2)

    app.command(
        name=name,
        help=f"{summary} [planned: {milestone}]",
        context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    )(planned)


for _name, (_milestone, _summary) in _PLANNED.items():
    _register_planned(_name, _milestone, _summary)
