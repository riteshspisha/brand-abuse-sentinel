"""The CLI's production-store enforcement (B3 U3, U5, U8).

Plan: docs/plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md.
Reuses B1's command table and its `_world` fixture (no network, no Docker). Root
ownership is simulated by patching the trusted UID to the test's own UID; the
installed-layout and user-namespace tests in tests/integration cover real layouts.
"""

import ast
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
import typer.main
import yaml
from tests.unit.test_cli_guard import STORE_COMMANDS, _world  # noqa: F401 - autouse fixture
from typer.testing import CliRunner

import brandsentinel.cli as cli_module
from brandsentinel.cli import app
from brandsentinel.store import identity, policy

REPO = Path(__file__).resolve().parents[2]
ME = os.getuid()
MY_NAME = pwd.getpwuid(ME).pw_name
STORE_REFUSAL = "refusing to open a store:"
ROOT_REFUSAL = "refusing to open a store as root"
MARKER = "brandsentinel_store: 1\nclass: production\n"
STORE_IDS = sorted(STORE_COMMANDS)


class Live:
    """A production installation under tmp: anchor chain, approved config, store, prefix."""

    def __init__(self, tmp: Path, monkeypatch) -> None:
        self.tmp = tmp
        root = tmp / "root"
        self.anchor = root / "etc" / "brandsentinel" / "production.yaml"
        self.anchor.parent.mkdir(parents=True)
        for d in (root, root / "etc", self.anchor.parent):
            d.chmod(0o755)
        self.prefix = tmp / "opt"
        self.package = (
            self.prefix / "venv" / "lib" / "python3.12" / "site-packages" / "brandsentinel"
        )
        self.package.mkdir(parents=True)
        self.etc = self.prefix / "etc"
        self.etc.mkdir()
        self.config = self.etc / "service.yaml"
        self.store = tmp / "home" / "data"
        self.store.mkdir(parents=True)
        self.write_config()
        self.write_anchor()
        monkeypatch.setattr(identity, "CHAIN_ROOT", root)
        monkeypatch.setattr(identity, "ANCHOR_PATH", self.anchor)
        monkeypatch.setattr(identity, "TRUSTED_UID", ME)
        monkeypatch.setattr(identity, "package_dir", lambda: self.package)
        monkeypatch.setattr(
            policy, "resolved_sys_path", lambda _entries, cwd: [self.prefix / "venv" / "bin"]
        )
        for name in policy.PYTHON_VARIABLES:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: ME)

    def write_anchor(self, account: str = MY_NAME) -> None:
        self.anchor.write_text(
            f"account: {account}\nstore_path: {self.store}\nconfig_path: {self.config}\n"
            f"install_prefix: {self.prefix}\ncomplete: true\n"
        )
        self.anchor.chmod(0o644)

    def config_data(self, **over) -> dict:
        data = {
            "data_dir": str(self.store),
            "registry_path": str(REPO / "registry/brands.yaml"),
            "analysis": {
                "policy": str(REPO / "config/policy.yaml"),
                "payment_providers": str(REPO / "config/payment_providers.yaml"),
            },
            "discovery": {
                "certstream": {"enabled": False},
                "dnstwist": {
                    "enabled": False,
                    "dictionary": str(REPO / "registry/dictionaries/brand-words.dict"),
                },
            },
            "sandbox": {"enabled": False},
        }
        data.update(over)
        return data

    def write_config(self, path: Path | None = None, **over) -> Path:
        path = path or self.config
        if path.exists():
            path.chmod(0o644)
        path.write_text(yaml.safe_dump(self.config_data(**over)), encoding="utf-8")
        path.chmod(0o444)  # not writable by the (simulated) account
        return path


@pytest.fixture
def live(tmp_path, monkeypatch) -> Live:
    return Live(tmp_path, monkeypatch)


def _invoke(*args: str):
    return CliRunner().invoke(app, list(args))


def _tree(root: Path) -> list[tuple[str, int]]:
    out = []
    for p in sorted(root.rglob("*")):
        try:
            out.append((p.relative_to(root).as_posix(), p.lstat().st_mtime_ns))
        except PermissionError:
            out.append((p.relative_to(root).as_posix(), -1))
    return out


def _forbidden(*_a, **_k):
    raise AssertionError("open_store was reached")


def _refused_with(result, *checks: str) -> None:
    assert result.exit_code == 2, result.output
    line = result.output.strip().splitlines()[-1]
    assert line.startswith(STORE_REFUSAL), result.output
    named = line[len(STORE_REFUSAL) :].strip().split(", ")
    for check in checks:
        assert check in named, result.output


# --- the passing path ------------------------------------------------------------------


def test_the_approved_invocation_opens_the_production_store(live):
    result = _invoke("-c", str(live.config), "status")
    assert result.exit_code == 0, result.output
    assert "store class: production (anchor path)" in result.output
    assert (live.store / "brandsentinel.db").is_file()


def test_store_check_passes_and_writes_nothing(live, monkeypatch):
    """AE9: the read-only check before any write."""
    monkeypatch.setattr(cli_module, "open_store", _forbidden)
    monkeypatch.setattr("brandsentinel.store.open_store", _forbidden)
    before = _tree(live.tmp)
    result = _invoke("-c", str(live.config), "store", "check")
    assert result.exit_code == 0, result.output
    assert "store class: production (anchor path)" in result.output
    assert _tree(live.tmp) == before


def test_development_status_names_its_class(tmp_path):
    """AE4: development as today, plus the class line."""
    result = _invoke("-c", str(REPO / "config/lab.yaml"), "status")
    assert result.exit_code == 0, result.output
    assert "store class: development (none)" in result.output


def test_development_works_beside_a_valid_anchor(live):
    result = _invoke("-c", str(REPO / "config/lab.yaml"), "status")
    assert result.exit_code == 0, result.output
    assert "store class: development (none)" in result.output


# --- refusals for every store command --------------------------------------------------


def _wrong_account(live, monkeypatch):
    live.write_anchor(account="nosuchaccount")
    return ["-c", str(live.config)], ["wrong_account"]


def _marked_copy(live, monkeypatch):
    copy = live.tmp / "copy"
    copy.mkdir()
    (copy / identity.MARKER_NAME).write_text(MARKER)
    path = live.write_config(live.tmp / "copy.yaml", data_dir=str(copy))
    return ["-c", str(path)], ["noncanonical_production_store"]


def _symlink_into_live(live, monkeypatch):
    link = live.tmp / "mine"
    link.symlink_to(live.store)
    path = live.write_config(live.tmp / "mine.yaml", data_dir=str(link))
    return ["-c", str(path)], ["noncanonical_production_store"]


def _ancestor(live, monkeypatch):
    path = live.write_config(live.tmp / "up.yaml", data_dir=str(live.store.parent))
    return ["-c", str(path)], ["noncanonical_production_store"]


def _relative_config(live, monkeypatch):
    monkeypatch.chdir(live.prefix)
    return ["-c", "etc/service.yaml"], ["config_not_absolute", "config_not_approved"]


def _config_variable(live, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_CONFIG", str(live.config))
    return [], ["config_source", "store_env_set"]


def _data_dir_variable(live, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(live.store))
    return ["-c", str(live.config)], ["store_env_set"]


def _symlinked_config(live, monkeypatch):
    link = live.tmp / "service-link.yaml"
    link.symlink_to(live.config)
    return ["-c", str(link)], ["config_symlink", "config_not_approved"]


def _copied_config(live, monkeypatch):
    path = live.write_config(live.store.parent / "service.yaml")
    return ["-c", str(path)], ["config_not_approved"]


def _developer_override(live, monkeypatch):
    live.write_config(runtime={"allow_developer_account": True})
    return ["-c", str(live.config)], ["developer_override"]


def _python_path(live, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(live.tmp))
    return ["-c", str(live.config)], ["python_env_set"]


def _checkout_code(live, monkeypatch):
    monkeypatch.setattr(identity, "package_dir", lambda: REPO / "src" / "brandsentinel")
    return ["-c", str(live.config)], ["code_not_installed"]


def _hard_linked_database(live, monkeypatch):
    (live.store / "brandsentinel.db").write_bytes(b"")
    os.link(live.store / "brandsentinel.db", live.tmp / "scratch.db")
    return ["-c", str(live.config)], ["store_integrity"]


def _missing_store(live, monkeypatch):
    live.store.rmdir()
    return ["-c", str(live.config)], ["store_missing"]


def _symlinked_scratch_artifacts(live, monkeypatch):
    scratch = live.tmp / "scratch"
    scratch.mkdir()
    (live.store / "artifacts").mkdir()
    (scratch / "artifacts").symlink_to(live.store / "artifacts")
    path = live.write_config(live.tmp / "scratch.yaml", data_dir=str(scratch))
    return ["-c", str(path)], ["store_integrity"]


def _installed_without_anchor(live, monkeypatch):
    live.anchor.unlink()
    record = live.prefix / "INSTALL"
    record.write_text("commit: x\n")
    monkeypatch.setattr(identity, "install_record_candidates", lambda: [record])
    path = live.write_config(live.tmp / "scratch.yaml", data_dir=str(live.tmp / "scratch"))
    return ["-c", str(path)], ["anchor_missing"]


def _unsafe_anchor(live, monkeypatch):
    live.anchor.chmod(0o666)
    path = live.write_config(live.tmp / "scratch.yaml", data_dir=str(live.tmp / "scratch"))
    return ["-c", str(path)], ["anchor_unsafe"]


SCENARIOS = {
    "M3-wrong-account": _wrong_account,
    "M4-symlink-into-live": _symlink_into_live,
    "M5-marked-copy": _marked_copy,
    "M6-relative-config": _relative_config,
    "M6-config-variable": _config_variable,
    "M6-data-dir-variable": _data_dir_variable,
    "M7-symlinked-config": _symlinked_config,
    "M7-copied-config": _copied_config,
    "M9-developer-override": _developer_override,
    "M10-pythonpath": _python_path,
    "M10-checkout-code": _checkout_code,
    "M11-hard-linked-database": _hard_linked_database,
    "M13-missing-store": _missing_store,
    "M14-unsafe-anchor": _unsafe_anchor,
    "M17-symlinked-scratch-artifacts": _symlinked_scratch_artifacts,
    "M18-installed-without-anchor": _installed_without_anchor,
    "M22-ancestor": _ancestor,
}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
@pytest.mark.parametrize("command", STORE_IDS)
def test_every_store_command_refuses_misuse(command, scenario, live, monkeypatch):
    args, checks = SCENARIOS[scenario](live, monkeypatch)
    monkeypatch.setattr(cli_module, "open_store", _forbidden)
    before = _tree(live.tmp)
    result = _invoke(*args, *STORE_COMMANDS[command])
    _refused_with(result, *checks)
    assert _tree(live.tmp) == before


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_store_check_refuses_the_same_misuse(scenario, live, monkeypatch):
    args, checks = SCENARIOS[scenario](live, monkeypatch)
    before = _tree(live.tmp)
    _refused_with(_invoke(*args, "store", "check"), *checks)
    assert _tree(live.tmp) == before


def test_the_developer_is_refused_without_touching_the_home(live, monkeypatch):
    """AE1, M3: the account's home is 0700; the refusal comes from the path alone."""
    live.write_anchor(account="nosuchaccount")
    home = live.store.parent
    home.chmod(0)
    try:
        result = _invoke("-c", str(live.config), "cases", "list")
    finally:
        home.chmod(0o700)
    _refused_with(result, "wrong_account")
    assert "store_missing" not in result.output


def test_root_at_the_canonical_store_gets_the_root_refusal(live, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    result = _invoke("-c", str(live.config), "status")
    assert result.exit_code == 2
    assert result.output.startswith(ROOT_REFUSAL)


def test_a_refusal_names_checks_only(live, monkeypatch):
    live.write_anchor(account="nosuchaccount")
    result = _invoke("-c", str(live.config), "status")
    _refused_with(result, "wrong_account")
    assert str(live.tmp) not in result.output
    assert "nosuchaccount" not in result.output


def test_a_real_process_refuses_a_marked_copy(tmp_path):
    copy = tmp_path / "copy"
    copy.mkdir()
    (copy / identity.MARKER_NAME).write_text(MARKER)
    config = tmp_path / "c.yaml"
    config.write_text(yaml.safe_dump({"data_dir": str(copy)}))
    root = tmp_path / "root"
    anchor = root / "etc" / "brandsentinel" / "production.yaml"
    anchor.parent.mkdir(parents=True)
    for d in (root, root / "etc", anchor.parent):
        d.chmod(0o755)
    anchor.write_text(
        f"account: {MY_NAME}\nstore_path: {tmp_path}/live\nconfig_path: {config}\n"
        f"install_prefix: {tmp_path}/opt\ncomplete: true\n"
    )
    anchor.chmod(0o644)
    program = (
        "from pathlib import Path\n"
        "from brandsentinel.store import identity\n"
        f"identity.CHAIN_ROOT = Path({str(root)!r})\n"
        f"identity.ANCHOR_PATH = Path({str(anchor)!r})\n"
        f"identity.TRUSTED_UID = {ME}\n"
        "from brandsentinel.cli import app\n"
        "app()\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BRANDSENTINEL_", "PYTHON"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    before = _tree(tmp_path)
    done = subprocess.run(  # noqa: S603 - fixed argv, test-built program
        [sys.executable, "-c", program, "-c", str(config), "cases", "list"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 2, done.stderr
    assert done.stderr.strip() == f"{STORE_REFUSAL} noncanonical_production_store"
    assert _tree(tmp_path) == before


# --- structure -------------------------------------------------------------------------

_FUNCTIONS = {
    node.name: node
    for node in ast.parse(Path(cli_module.__file__).read_text(encoding="utf-8")).body
    if isinstance(node, ast.FunctionDef)
}


def _calls(name: str) -> list[ast.Call]:
    return [
        n
        for n in ast.walk(_FUNCTIONS[name])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    ]


def _callbacks() -> dict[str, str]:
    def walk(group, prefix=()):
        for name, command in group.commands.items():
            if hasattr(command, "commands"):
                yield from walk(command, (*prefix, name))
            else:
                yield " ".join((*prefix, name)), command.callback.__name__

    return dict(walk(typer.main.get_command(app)))


@pytest.mark.parametrize("command", STORE_IDS)
def test_every_store_command_opens_with_the_authorization(command):
    calls = _calls(_callbacks()[command])
    names = [c.func.id for c in calls]
    assert "open_store" not in names, "never the unauthorized opener"
    guard = [c.lineno for c in calls if c.func.id == "_load_for_store"]
    opens = [c.lineno for c in calls if c.func.id == "_open_store"]
    assert len(guard) == 1 and opens and guard[0] < min(opens)


def test_store_check_never_opens_a_store():
    names = {c.func.id for c in _calls(_callbacks()["store check"])}
    assert "_load_for_store" in names
    assert not names & {"open_store", "_open_store", "connect", "RawLog", "write_private"}


def test_the_proxy_containers_never_run_as_root():
    """R12 refuses root for `proxy`; its containers must run it as a non-root user."""
    dockerfile = (REPO / "docker" / "Dockerfile.sandbox").read_text(encoding="utf-8")
    users = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("USER ")]
    assert users and users[-1] not in ("root", "0")
    for compose in sorted((REPO / "docker").glob("*.yaml")):
        services = yaml.safe_load(compose.read_text(encoding="utf-8")).get("services", {})
        for name, service in services.items():
            command = service.get("command") or []
            if "proxy" in command:
                user = str(service.get("user", users[-1]))
                assert user not in ("root", "0") and not user.startswith("0:"), (compose, name)


# --- review findings: refusals are named exit-2 refusals, never tracebacks -------------


def test_a_refusal_from_the_store_layer_is_a_named_refusal(live, monkeypatch):
    """The store layer repeats the checks; a store swapped after the policy is refused."""
    from brandsentinel.store.identity import StoreRefused

    def refuse(_data_dir, _authorization):
        raise StoreRefused(("store_not_authorized",))

    monkeypatch.setattr("brandsentinel.store.guard_open", refuse)
    result = _invoke("-c", str(live.config), "status")
    _refused_with(result, "store_not_authorized")
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_a_deleted_working_directory_is_a_named_refusal(live, monkeypatch, tmp_path):
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    result = _invoke("-c", str(live.config), "store", "check")
    _refused_with(result, "unclassifiable")


def test_an_os_error_while_deciding_is_a_named_refusal(live, monkeypatch):
    def broken(*_a, **_k):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(identity, "classify", broken)
    _refused_with(_invoke("-c", str(live.config), "status"), "unclassifiable")


def test_an_unstattable_live_store_for_the_account_is_unclassifiable(live, monkeypatch):
    real = os.stat

    def denied(path, *a, **k):
        if Path(path) == live.store:
            raise PermissionError(13, "denied")
        return real(path, *a, **k)

    monkeypatch.setattr(policy.os, "stat", denied)
    _refused_with(_invoke("-c", str(live.config), "store", "check"), "unclassifiable")
