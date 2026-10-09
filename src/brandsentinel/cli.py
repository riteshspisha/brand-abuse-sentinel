"""Command-line entry point.

Commands that later milestones implement are registered now as stubs, so the
command surface is stable and `--help` documents where each one lands.
"""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from brandsentinel import __version__
from brandsentinel.config import Config, ConfigError, load_config
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import InvalidName
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
    "run": ("M2", "Run discovery and the analysis pipeline."),
    "submit": ("M2", "Submit a URL or domain for analysis."),
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
