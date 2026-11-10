"""`open_store` repeats the identity checks before it creates or touches anything (B3 U4).

The authorization stops accidental callers (a future command, a library caller), not
hostile Python, which can build one.
"""

import os
from pathlib import Path

import pytest

from brandsentinel.config import Config, SandboxSettings
from brandsentinel.store import identity, open_store
from brandsentinel.store.identity import Authorization, StoreRefused

ME = os.getuid()
MARKER = "brandsentinel_store: 1\nclass: production\n"


@pytest.fixture
def live(tmp_path, monkeypatch) -> Path:
    """A test anchor naming tmp/live/data as the production store."""
    root = tmp_path / "root"
    anchor_dir = root / "etc" / "brandsentinel"
    anchor_dir.mkdir(parents=True)
    for d in (root, root / "etc", anchor_dir):
        d.chmod(0o755)
    store = tmp_path / "live" / "data"
    anchor = anchor_dir / "production.yaml"
    anchor.write_text(
        f"account: svc\nstore_path: {store}\nconfig_path: {tmp_path}/service.yaml\n"
        f"install_prefix: {tmp_path}/opt\ncomplete: true\n"
    )
    anchor.chmod(0o644)
    monkeypatch.setattr(identity, "CHAIN_ROOT", root)
    monkeypatch.setattr(identity, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    return store


def _config(data_dir: Path) -> Config:
    return Config(data_dir=data_dir, sandbox=SandboxSettings(enabled=False))


def _tree(root: Path) -> list[tuple[str, int]]:
    return sorted((p.relative_to(root).as_posix(), p.lstat().st_mtime_ns) for p in root.rglob("*"))


def _authorization(path: Path) -> Authorization:
    st = os.stat(path)
    return Authorization(os.path.realpath(path), st.st_dev, st.st_ino, os.geteuid())


def test_a_development_store_opens_without_authorization(tmp_path):
    store = open_store(_config(tmp_path / "dev"))
    store.close()
    assert (tmp_path / "dev" / "brandsentinel.db").is_file()


def test_a_production_store_without_authorization_is_refused(live, tmp_path):
    """AE6, M16."""
    live.mkdir(parents=True)
    before = _tree(tmp_path)
    with pytest.raises(StoreRefused) as e:
        open_store(_config(live))
    assert e.value.checks == ("store_not_authorized",)
    assert _tree(tmp_path) == before


def test_the_matching_authorization_opens_the_production_store(live):
    live.mkdir(parents=True)
    store = open_store(_config(live), authorization=_authorization(live))
    store.close()
    assert (live / "brandsentinel.db").is_file()


def test_an_authorization_for_another_store_is_refused(live, tmp_path):
    live.mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(StoreRefused):
        open_store(_config(live), authorization=_authorization(other))


def test_an_authorization_for_another_user_is_refused(live):
    live.mkdir(parents=True)
    a = _authorization(live)
    with pytest.raises(StoreRefused):
        open_store(_config(live), authorization=Authorization(a.path, a.device, a.inode, ME + 1))


def test_a_store_replaced_after_the_policy_is_refused(live, tmp_path):
    live.mkdir(parents=True)
    approved = _authorization(live)
    live.rename(tmp_path / "moved-away")
    live.mkdir()
    with pytest.raises(StoreRefused):
        open_store(_config(live), authorization=approved)
    assert list(live.iterdir()) == []


def test_a_missing_production_store_is_never_created(live, tmp_path):
    before = _tree(tmp_path)
    with pytest.raises(StoreRefused):
        open_store(_config(live))
    assert not live.exists()
    assert _tree(tmp_path) == before


def test_a_marked_copy_elsewhere_is_refused(live, tmp_path):
    copy = tmp_path / "copy"
    copy.mkdir()
    (copy / identity.MARKER_NAME).write_text(MARKER)
    with pytest.raises(StoreRefused) as e:
        open_store(_config(copy), authorization=_authorization(copy))
    assert e.value.checks == ("noncanonical_production_store",)


def test_integrity_is_checked_before_connect_or_the_sweep(tmp_path):
    """AE7: a scratch store whose sha256/ab is a symlink into another store."""
    victim = tmp_path / "victim-store" / "artifacts" / "sha256" / "ab"
    victim.mkdir(parents=True)
    old_blob = victim / ("ab" + "0" * 62)
    old_blob.write_bytes(b"evidence")
    os.utime(old_blob, (0, 0))  # older than the sweep's one-hour cutoff
    scratch = tmp_path / "scratch"
    (scratch / "artifacts" / "sha256").mkdir(parents=True)
    (scratch / "artifacts" / "sha256" / "ab").symlink_to(victim)
    before = _tree(tmp_path / "victim-store")
    with pytest.raises(StoreRefused) as e:
        open_store(_config(scratch))
    assert e.value.checks == ("store_integrity",)
    assert old_blob.read_bytes() == b"evidence"
    assert _tree(tmp_path / "victim-store") == before
    assert not (scratch / "brandsentinel.db").exists()


def test_installed_code_without_an_anchor_still_opens_from_a_library(tmp_path, monkeypatch):
    """R2 is CLI-only: suites run from an installed venv keep their temporary stores."""
    record = tmp_path / "prefix" / "INSTALL"
    record.parent.mkdir()
    record.write_text("x")
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    monkeypatch.setattr(identity, "install_record_candidates", lambda: [record])
    assert identity.running_from_installation()
    store = open_store(_config(tmp_path / "scratch"))
    store.close()


def test_a_symlink_then_dotdot_cannot_reach_the_production_store(live, tmp_path):
    """Review finding: a lexically collapsed path must not hide the store it opens."""
    (live / "raw").mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    (other / "lnk").symlink_to(live / "raw")
    sneaky = Path(f"{other}/lnk/..")
    before = _tree(tmp_path)
    with pytest.raises(StoreRefused) as e:
        open_store(_config(sneaky))
    assert e.value.checks == ("noncanonical_production_store",)
    assert _tree(tmp_path) == before
