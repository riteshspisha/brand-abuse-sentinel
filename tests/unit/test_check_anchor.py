"""`scripts/service-account/check_anchor.py` and the committed anchor template (B3 U6)."""

import importlib.util
import os
from pathlib import Path

import pytest
import yaml

from brandsentinel.store import identity

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "service-account" / "check_anchor.py"
TEMPLATE = REPO / "config" / "production-anchor.yaml"
ME = os.getuid()
MARKER = "brandsentinel_store: 1\nclass: production\n"


def _load_script():
    spec = importlib.util.spec_from_file_location("check_anchor", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_anchor = _load_script()


class Host:
    def __init__(self, tmp: Path, monkeypatch) -> None:
        self.root = tmp / "root"
        self.anchor = self.root / "etc" / "brandsentinel" / "production.yaml"
        self.anchor.parent.mkdir(parents=True)
        for d in (self.root, self.root / "etc", self.anchor.parent):
            d.chmod(0o755)
        self.prefix = tmp / "opt"
        self.package = (
            self.prefix / "venv" / "lib" / "python3.12" / "site-packages" / "brandsentinel"
        )
        self.package.mkdir(parents=True)
        (self.prefix / "etc").mkdir()
        self.config = self.prefix / "etc" / "service.yaml"
        self.store = tmp / "home" / "data"
        self.store.mkdir(parents=True)
        self.write_config(self.store)
        self.write_anchor(self.store)
        monkeypatch.setattr(identity, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(identity, "ANCHOR_PATH", self.anchor)
        monkeypatch.setattr(identity, "TRUSTED_UID", ME)
        monkeypatch.setattr(identity, "package_dir", lambda: self.package)

    def write_config(self, data_dir: Path) -> None:
        self.config.write_text(yaml.safe_dump({"data_dir": str(data_dir)}))

    def write_anchor(self, store: Path) -> None:
        self.anchor.write_text(
            f"account: svc\nstore_path: {store}\nconfig_path: {self.config}\n"
            f"install_prefix: {self.prefix}\ncomplete: true\n"
        )
        self.anchor.chmod(0o644)

    def mark(self) -> None:
        (self.store / identity.MARKER_NAME).write_text(MARKER)


@pytest.fixture
def host(tmp_path, monkeypatch) -> Host:
    return Host(tmp_path, monkeypatch)


def _main(host: Host, *extra: str) -> int:
    return check_anchor.main([str(host.prefix), *extra])


def test_the_committed_template_is_a_valid_anchor(tmp_path, monkeypatch):
    root = tmp_path / "root"
    anchor = root / "etc" / "brandsentinel" / "production.yaml"
    anchor.parent.mkdir(parents=True)
    for d in (root, root / "etc", anchor.parent):
        d.chmod(0o755)
    anchor.write_bytes(TEMPLATE.read_bytes())
    anchor.chmod(0o644)
    monkeypatch.setattr(identity, "CHAIN_ROOT", root)
    monkeypatch.setattr(identity, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    a = identity.load_anchor()
    assert a.account == "brandsentinel"
    assert (
        str(a.store_path) == yaml.safe_load((REPO / "config/service.yaml").read_text())["data_dir"]
    )
    assert a.config_path == Path("/opt/brandsentinel/etc/service.yaml")
    assert a.install_prefix == Path("/opt/brandsentinel")


def test_the_template_has_no_data_dir_key():
    """tests/unit/test_docs.py validates YAML with a `data_dir` key as a Config."""
    assert "data_dir" not in yaml.safe_load(TEMPLATE.read_text())


def test_a_good_installation_passes(host, capsys):
    host.mark()
    assert _main(host, "--marker") == 0
    assert "FAIL" not in capsys.readouterr().out


def test_the_marker_is_optional_without_the_flag(host):
    assert _main(host) == 0


@pytest.mark.parametrize(
    "damage, rule",
    [
        (lambda h: h.anchor.unlink(), "anchor_present"),
        (lambda h: h.anchor.chmod(0o666), "anchor_safe"),
        (lambda h: h.write_config(h.store.parent / "other"), "config_matches_anchor"),
        (lambda h: None, "marker_valid"),
    ],
    ids=["missing", "unsafe", "drift", "no-marker"],
)
def test_violations_are_reported(host, damage, rule, capsys):
    damage(host)
    assert _main(host, "--marker") == 1
    assert f"FAIL  {rule}" in capsys.readouterr().out


def test_a_symlink_in_the_store_path_is_a_violation(host, tmp_path, capsys):
    real = tmp_path / "real-home"
    host.store.parent.rename(real)
    host.store.parent.symlink_to(real)
    host.mark()
    assert _main(host, "--marker") == 1
    assert "FAIL  store_path_symlink_free" in capsys.readouterr().out


def test_code_outside_the_prefix_is_a_violation(host, monkeypatch, capsys):
    monkeypatch.setattr(identity, "package_dir", lambda: REPO / "src" / "brandsentinel")
    host.mark()
    assert _main(host, "--marker") == 1
    assert "FAIL  package_installed" in capsys.readouterr().out


def test_another_prefix_is_a_violation(host, tmp_path, capsys):
    host.mark()
    assert check_anchor.main([str(tmp_path / "elsewhere"), "--marker"]) == 1
    assert "FAIL  prefix_matches_anchor" in capsys.readouterr().out


def test_a_malformed_marker_is_a_violation(host, capsys):
    (host.store / identity.MARKER_NAME).write_text("class: development\n")
    assert _main(host, "--marker") == 1
    assert "FAIL  marker_valid" in capsys.readouterr().out


def test_an_unexpected_error_is_an_incomplete_inspection(host, monkeypatch, capsys):
    def broken():
        raise RuntimeError("boom")

    monkeypatch.setattr(identity, "load_anchor", broken)
    assert _main(host, "--marker") == 2


def test_usage_errors_are_incomplete(capsys):
    assert check_anchor.main([]) == 2


def test_the_checker_writes_nothing(host):
    host.mark()
    before = sorted((p, p.lstat().st_mtime_ns) for p in host.root.parent.rglob("*"))
    _main(host, "--marker")
    after = sorted((p, p.lstat().st_mtime_ns) for p in host.root.parent.rglob("*"))
    assert before == after


def test_validate_sh_runs_the_checker_with_the_marker():
    text = (REPO / "scripts" / "service-account" / "validate.sh").read_text()
    assert "check_anchor.py" in text and "--marker" in text


@pytest.mark.parametrize("variable", ["BRANDSENTINEL_CONFIG", "BRANDSENTINEL_DATA_DIR"])
def test_store_variables_make_the_check_incomplete(host, monkeypatch, variable, capsys):
    """Review finding: load_config honours them, so the comparison would not be the
    installed service.yaml's."""
    host.mark()
    monkeypatch.setenv(variable, str(host.store.parent / "other"))
    assert _main(host, "--marker") == 2


def test_validate_sh_fails_the_run_when_the_checker_fails():
    text = (REPO / "scripts" / "service-account" / "validate.sh").read_text()
    call = [
        line
        for line in text.splitlines()
        if "check_anchor.py" in line and "venv/bin/python" in line
    ]
    assert len(call) == 1 and "--marker" in call[0] and "-I -B" in call[0]
    assert 'fail "production anchor and store marker' in text
    assert 'ANCHOR_STATUS" -eq 0' in text
