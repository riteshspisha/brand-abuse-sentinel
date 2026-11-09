"""The CLI guard: a command that opens a store refuses root and a missing configuration.

These tests also run against the commit before the guard existed, so they import no
guard name at module level and pin the refusal texts as literals. Nothing here may reach
the network or Docker on either version: see the `_world` fixture.
"""

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest
import typer.main
import yaml
from typer.testing import CliRunner

import brandsentinel.cli as cli_module
from brandsentinel.cli import app
from brandsentinel.config import load_config

REPO = Path(__file__).resolve().parents[2]
ROOT_REFUSAL = "refusing to open a store as root"
SOURCE_REFUSAL = "refusing to open a store without a configuration"

STORE_COMMANDS = {
    # Arguments are valid up to the guard, so that a refusal is not a usage error.
    "status": ["status"],
    "run": ["run", "--no-certstream", "--no-dnstwist", "--duration", "0.1"],
    "submit": ["submit", "sadhguru-guard.example.com"],
    "sweep": ["sweep"],
    "replay": ["replay"],
    "analyze": ["analyze", "example.com"],
    "cases list": ["cases", "list"],
    "cases show": ["cases", "show", "1"],
    "cases label": ["cases", "label", "1", "--verdict", "benign"],
    "cases rescore": ["cases", "rescore", "--all"],
    "report": ["report", "--index"],
    "export csv": ["export", "csv"],
    "registry collect": ["registry", "collect"],
    "registry corpus": ["registry", "corpus"],
}
NON_STORE_COMMANDS = {
    # name: (arguments, the exit code it has always had here)
    "version": (["version"], 0),
    "match": (["match", "--registry", str(REPO / "registry/brands.yaml"), "x.example.com"], 0),
    "eval": (["eval"], 2),
    "registry validate": (
        [
            "registry",
            "validate",
            "--path",
            str(REPO / "registry/brands.yaml"),
            "--legacy-dir",
            "no-such-dir",
        ],
        0,
    ),
    "sandbox check": (["sandbox", "check", "--no-network"], 0),
    "sandbox selftest": (["sandbox", "selftest", "media"], 1),
    "sandbox sweep": (["sandbox", "sweep"], 0),
    "proxy": (["proxy", "--listen", "not-an-address"], 2),
}
STORE_IDS = sorted(STORE_COMMANDS)
NON_STORE_IDS = sorted(NON_STORE_COMMANDS)
# The ways of leaving the configuration source unset.
NO_SOURCE = {
    "unset": {},
    "empty_config_variable": {"BRANDSENTINEL_CONFIG": ""},
    "empty_data_dir_variable": {"BRANDSENTINEL_DATA_DIR": ""},
    "both_empty": {"BRANDSENTINEL_CONFIG": "", "BRANDSENTINEL_DATA_DIR": ""},
}


def _forbidden(*_args, **_kwargs):
    raise AssertionError("a guarded test reached the outside world")


async def _empty_report(*_args, **_kwargs):
    from brandsentinel.sandbox.preflight import Report

    return Report()


@pytest.fixture(autouse=True)
def _world(monkeypatch, tmp_path):
    """An empty working directory, no inherited source, and no way out: without a
    guard these commands would otherwise go on to contact real hosts or Docker."""
    from brandsentinel.sandbox.preflight import Report

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    for name in list(os.environ):
        if name.startswith("BRANDSENTINEL_"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    for target in (
        "brandsentinel.cli.run_service",
        "brandsentinel.cli.DnstwistRunner",
        "brandsentinel.pipeline.stages.build_network",
        "brandsentinel.sandbox.preflight.hostile_content_runtime",
    ):
        monkeypatch.setattr(target, _forbidden)
    monkeypatch.setattr("brandsentinel.cli._print_sandbox", lambda _config: None)
    monkeypatch.setattr("brandsentinel.sandbox.preflight.check_runtime", _empty_report)
    monkeypatch.setattr("brandsentinel.sandbox.preflight.check_account", lambda *_a, **_k: Report())

    async def no_runtime(_config):
        return None, Report()

    monkeypatch.setattr("brandsentinel.sandbox.preflight.prepare_runtime", no_runtime)
    monkeypatch.setattr("brandsentinel.sandbox.runner.SandboxRunner.sweep_orphans", lambda _self: 0)


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def _config(tmp_path: Path, **overrides) -> Path:
    """A configuration that gets each command as far as its store."""
    data = {
        "data_dir": str(tmp_path / "store"),
        "registry_path": str(REPO / "registry/brands.yaml"),
        "runtime": {"allow_developer_account": True},
        "sandbox": {"enabled": False},
        "analysis": {
            "policy": str(REPO / "config/policy.yaml"),
            "payment_providers": str(REPO / "config/payment_providers.yaml"),
        },
        "discovery": {"certstream": {"enabled": False}, "dnstwist": {"enabled": False}},
        **overrides,
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _tree(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


def _invoke(*args: str):
    return CliRunner().invoke(app, list(args))


def _assert_refused(result, refusal: str) -> None:
    assert result.exit_code == 2, result.output
    assert result.output.lstrip().startswith(refusal), result.output


def _block_store(monkeypatch) -> None:
    for target in (
        "brandsentinel.cli.open_store",
        "brandsentinel.store.open_store",
        "brandsentinel.store.connect",
    ):
        monkeypatch.setattr(target, _forbidden)


# --- refusals --------------------------------------------------------------------------


@pytest.mark.parametrize("command", STORE_IDS)
def test_root_is_refused_and_creates_nothing(command, tmp_path, as_root):
    config = _config(tmp_path)
    before = _tree(tmp_path)
    result = _invoke("-c", str(config), *STORE_COMMANDS[command])
    _assert_refused(result, ROOT_REFUSAL)
    assert _tree(tmp_path) == before


@pytest.mark.parametrize("source", sorted(NO_SOURCE))
@pytest.mark.parametrize("command", STORE_IDS)
def test_missing_source_is_refused_and_creates_nothing(command, source, tmp_path, monkeypatch):
    for name, value in NO_SOURCE[source].items():
        monkeypatch.setenv(name, value)
    before = _tree(tmp_path)
    result = _invoke(*STORE_COMMANDS[command])
    _assert_refused(result, SOURCE_REFUSAL)
    assert _tree(tmp_path) == before


@pytest.mark.parametrize("command", STORE_IDS)
def test_refusals_never_reach_the_store(command, tmp_path, monkeypatch):
    _block_store(monkeypatch)
    _assert_refused(_invoke(*STORE_COMMANDS[command]), SOURCE_REFUSAL)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    config = _config(tmp_path)
    _assert_refused(_invoke("-c", str(config), *STORE_COMMANDS[command]), ROOT_REFUSAL)


@pytest.mark.parametrize("command", STORE_IDS)
def test_root_is_refused_with_no_source_as_root(command, as_root):
    _assert_refused(_invoke(*STORE_COMMANDS[command]), ROOT_REFUSAL)


@pytest.mark.parametrize("command", ["run", "registry collect"])
def test_the_guard_comes_before_the_account_checks(command, tmp_path, monkeypatch):
    """A real root has both IDs at 0: the new refusal wins over `refusing to start`."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    result = _invoke("-c", str(_config(tmp_path)), *STORE_COMMANDS[command])
    _assert_refused(result, ROOT_REFUSAL)
    assert "refusing to start" not in result.output


# --- hostile and edge inputs -----------------------------------------------------------


@pytest.mark.parametrize("body", ["{ not: [yaml", "- a\n- list\n", "unknown_key: 1\n"])
def test_root_is_refused_before_a_bad_configuration_is_parsed(body, tmp_path, as_root):
    bad = tmp_path / "bad.yaml"
    bad.write_text(body, encoding="utf-8")
    result = _invoke("-c", str(bad), "status")
    _assert_refused(result, ROOT_REFUSAL)
    assert "bad.yaml" not in result.output


def test_root_is_refused_for_a_missing_configuration_file(tmp_path, as_root):
    result = _invoke("-c", str(tmp_path / "missing.yaml"), "status")
    _assert_refused(result, ROOT_REFUSAL)
    assert "missing.yaml" not in result.output


def test_refusal_carries_no_terminal_escape_from_a_hostile_path(as_root):
    result = _invoke("-c", "/tmp/\x1b[2Jevil.yaml", "status")
    _assert_refused(result, ROOT_REFUSAL)
    assert "\x1b" not in result.output


def test_a_mistyped_variable_is_not_a_source(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_CONFIGS", str(_config(tmp_path)))
    _assert_refused(_invoke("status"), SOURCE_REFUSAL)


def test_root_has_no_override(tmp_path, monkeypatch, as_root):
    for name in ("BRANDSENTINEL_ALLOW_ROOT", "BRANDSENTINEL_FORCE"):
        monkeypatch.setenv(name, "1")
    config = _config(tmp_path, runtime={"allow_developer_account": True})
    _assert_refused(_invoke("-c", str(config), "status"), ROOT_REFUSAL)


def test_help_still_works_as_root(as_root):
    assert _invoke("status", "--help").exit_code == 0


def test_a_real_process_with_no_source_leaves_its_directory_empty(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRANDSENTINEL_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    done = subprocess.run(
        [sys.executable, "-c", "from brandsentinel.cli import app; app()", "cases", "list"],
        cwd=empty,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 2, done.stderr
    assert done.stderr.startswith(SOURCE_REFUSAL)
    assert _tree(empty) == []


def test_argument_errors_still_come_before_the_guard(as_root):
    result = _invoke("report")
    assert result.exit_code == 2
    assert "give case numbers" in result.output


# --- what stays as it was --------------------------------------------------------------


@pytest.mark.parametrize("command", NON_STORE_IDS)
def test_non_store_commands_are_unchanged_as_root(command, tmp_path, monkeypatch, as_root):
    _block_store(monkeypatch)
    before = _tree(tmp_path)
    args, code = NON_STORE_COMMANDS[command]
    result = _invoke(*args)
    assert result.exit_code == code, result.output
    assert "refusing to open a store" not in result.output
    assert _tree(tmp_path) == before


@pytest.mark.parametrize("kind", ["option", "config_variable"])
def test_a_configuration_file_is_a_source(kind, tmp_path, monkeypatch):
    config = _config(tmp_path)
    if kind == "option":
        result = _invoke("-c", str(config), "status")
    else:
        monkeypatch.setenv("BRANDSENTINEL_CONFIG", str(config))
        result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "schema v5" in result.output
    assert (tmp_path / "store/brandsentinel.db").is_file()
    assert not (tmp_path / "cwd/data").exists()


def test_a_data_directory_variable_is_a_source(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "store"))
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "schema v5" in result.output
    assert (tmp_path / "store/brandsentinel.db").is_file()
    assert not (tmp_path / "cwd/data").exists()


def test_a_relative_data_dir_in_a_file_keeps_its_meaning(tmp_path):
    result = _invoke("-c", str(_config(tmp_path, data_dir="relative-store")), "status")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "cwd/relative-store/brandsentinel.db").is_file()


def test_known_residual_a_file_with_no_data_dir_still_means_dot_data(tmp_path):
    """Accepted under KTD-SOURCES; see docs/residual-review-findings."""
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    result = _invoke("-c", str(empty), "cases", "list")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "cwd/data/brandsentinel.db").is_file()


def test_the_lab_configuration_still_opens_its_store(tmp_path):
    result = _invoke("-c", str(REPO / "config/lab.yaml"), "status")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "cwd/data-lab/brandsentinel.db").is_file()


@pytest.mark.parametrize("value", [None, "", " ", "x"])
@pytest.mark.parametrize("variable", ["BRANDSENTINEL_CONFIG", "BRANDSENTINEL_DATA_DIR"])
def test_the_guard_and_load_config_agree_on_what_is_set(variable, value, monkeypatch):
    from brandsentinel.config import ConfigError, has_explicit_source

    if value is not None:
        monkeypatch.setenv(variable, value)
    try:
        honoured = load_config().data_dir != Path("data")
    except ConfigError:  # it tried to read that file
        honoured = True
    assert has_explicit_source() is honoured
    assert has_explicit_source() is bool(value)


def test_an_explicit_path_is_a_source_whatever_the_environment():
    from brandsentinel.config import has_explicit_source

    assert has_explicit_source(Path("anything.yaml"))
    assert not has_explicit_source(None)


# --- every command is classified -------------------------------------------------------

_MODULE_FUNCTIONS = {
    node.name: node
    for node in ast.parse(Path(cli_module.__file__).read_text(encoding="utf-8")).body
    if isinstance(node, ast.FunctionDef)
}
_STORE_OPENERS = {"open_store", "connect", "RawLog", "ensure_private_dir", "write_private"}


def _leaf_commands(group, prefix=()):
    for name, command in group.commands.items():
        if hasattr(command, "commands"):
            yield from _leaf_commands(command, (*prefix, name))
        else:
            yield " ".join((*prefix, name)), command.callback.__name__


def _bare_calls(node) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]


def _reaches_a_store(function: str, seen: set[str] | None = None) -> bool:
    seen = seen if seen is not None else set()
    if function in seen or function not in _MODULE_FUNCTIONS:
        return False
    seen.add(function)
    names = {call.func.id for call in _bare_calls(_MODULE_FUNCTIONS[function])}
    return bool(names & _STORE_OPENERS) or any(_reaches_a_store(n, seen) for n in names)


def _commands() -> dict[str, str]:
    return dict(_leaf_commands(typer.main.get_command(app)))


def test_every_command_is_classified():
    assert set(_commands()) == set(STORE_COMMANDS) | set(NON_STORE_COMMANDS)
    assert len(_commands()) == 22
    assert not set(STORE_COMMANDS) & set(NON_STORE_COMMANDS)


def test_the_classification_matches_the_code():
    opening = {name for name, fn in _commands().items() if _reaches_a_store(fn)}
    assert opening == set(STORE_COMMANDS)


@pytest.mark.parametrize("command", STORE_IDS)
def test_every_store_command_goes_through_the_guard_first(command):
    calls = _bare_calls(_MODULE_FUNCTIONS[_commands()[command]])
    lines = {name: [c.lineno for c in calls if c.func.id == name] for name in _STORE_OPENERS}
    guard = [c.lineno for c in calls if c.func.id == "_load_for_store"]
    assert len(guard) == 1, "exactly one guard call"
    assert not [c for c in calls if c.func.id == "_load"], "never the unguarded loader"
    assert all(guard[0] < line for found in lines.values() for line in found)
