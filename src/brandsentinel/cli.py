"""Command-line entry point.

Commands that later milestones implement are registered now as stubs, so the
command surface is stable and `--help` documents where each one lands.
"""

import asyncio
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
from brandsentinel.pipeline import health
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
    "analyze": ("M3", "Analyze one domain (e.g. --passive enrichment)."),
    "sandbox": ("M4", "Sandbox runtime checks and self-tests."),
    "cases": ("M5", "List, inspect and label cases."),
    "report": ("M5", "Render analyst reports."),
    "export": ("M5", "Export cases (CSV)."),
    "eval": ("M8", "Run the model evaluation."),
}


registry_app = typer.Typer(help="Validate and inspect the Brand Registry.", no_args_is_help=True)
app.add_typer(registry_app, name="registry")


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
    duration: Annotated[
        float | None, typer.Option(help="Stop after this many seconds (default: run forever).")
    ] = None,
    log_level: Annotated[str, typer.Option(help="Log level.")] = "INFO",
) -> None:
    """Run discovery (CertStream, dnstwist) and the pipeline until interrupted."""
    config = _load(ctx)
    configure_logging(log_level.upper())
    registry, _ = _load_registry(config.registry_path)
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
    registry, _ = _load_registry(config.registry_path)
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
    registry, _ = _load_registry(config.registry_path)
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
    registry, _ = _load_registry(config.registry_path)
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


def _load_registry(path: Path) -> tuple[Registry, ValidationReport]:
    try:
        return load_registry(path)
    except RegistryError as e:
        for err in e.errors:
            typer.echo(f"error: {escape_terminal(err)}", err=True)
        raise typer.Exit(1) from e


@registry_app.command("validate")
def registry_validate(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Option(help="Registry file (default: config).")] = None,
    legacy_dir: Annotated[
        Path, typer.Option(help="Check coverage of the legacy scripts' inputs.")
    ] = Path("legacy"),
) -> None:
    """Validate the registry and report counts by status and tier."""
    registry_file = path or _load(ctx).registry_path
    registry, report = _load_registry(registry_file)
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
    loaded, report = _load_registry(registry or _load(ctx).registry_path)
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
