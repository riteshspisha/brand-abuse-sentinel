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
    "registry": ("M1", "Validate and maintain the Brand Registry."),
    "sandbox": ("M4", "Sandbox runtime checks and self-tests."),
    "cases": ("M5", "List, inspect and label cases."),
    "report": ("M5", "Render analyst reports."),
    "export": ("M5", "Export cases (CSV)."),
    "eval": ("M8", "Run the model evaluation."),
}


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
