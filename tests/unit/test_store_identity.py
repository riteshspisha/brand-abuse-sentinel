"""Store identity (B3 U1): the production anchor, classification and store integrity.

Plan: docs/plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md (R1-R6).
Root ownership is simulated by building the anchor's directory chain under a temporary
root and patching the trusted UID to the test's own UID; nothing here reads /etc.
"""

import os
import stat
import sys
from pathlib import Path

import pytest

from brandsentinel.store import identity
from brandsentinel.store.identity import StoreRefused

ME = os.getuid()
# The real lookup: tests/conftest.py replaces it for every other test.
REAL_CANDIDATES = identity.install_record_candidates
MARKER = "brandsentinel_store: 1\nclass: production\n"


def _anchor_text(store: Path, config: Path, prefix: Path, *, account: str = "svc") -> str:
    return (
        f"account: {account}\n"
        f"store_path: {store}\n"
        f"config_path: {config}\n"
        f"install_prefix: {prefix}\n"
        "complete: true\n"
    )


class Host:
    """A fake host: a chain root standing in for `/`, `etc/brandsentinel` and the anchor."""

    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.etc = self.root / "etc"
        self.dir = self.etc / "brandsentinel"
        self.anchor = self.dir / "production.yaml"
        self.store = tmp_path / "live" / "data"
        self.config = tmp_path / "opt" / "etc" / "service.yaml"
        self.prefix = tmp_path / "opt"
        for d in (self.root, self.etc, self.dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)
        monkeypatch.setattr(identity, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(identity, "ANCHOR_PATH", self.anchor)
        monkeypatch.setattr(identity, "TRUSTED_UID", ME)
        monkeypatch.setattr(identity, "install_record_candidates", lambda: [])

    def write_anchor(self, text: str | None = None, mode: int = 0o644) -> None:
        self.anchor.write_text(
            text if text is not None else _anchor_text(self.store, self.config, self.prefix),
            encoding="utf-8",
        )
        self.anchor.chmod(mode)

    def make_store(self) -> Path:
        self.store.mkdir(parents=True, exist_ok=True)
        return self.store


@pytest.fixture
def host(tmp_path, monkeypatch) -> Host:
    return Host(tmp_path, monkeypatch)


def _tree(root: Path) -> list[tuple[str, int, int]]:
    out = []
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        out.append((p.relative_to(root).as_posix(), st.st_mode, st.st_mtime_ns))
    return out


def _refused(fn, *args) -> tuple[str, ...]:
    with pytest.raises(StoreRefused) as e:
        fn(*args)
    return e.value.checks


# --- the anchor: present, missing ------------------------------------------------------


def test_a_valid_anchor_is_read(host):
    host.write_anchor()
    a = identity.load_anchor()
    assert a.account == "svc"
    assert a.store_path == host.store
    assert a.config_path == host.config
    assert a.install_prefix == host.prefix


def test_a_missing_anchor_file_is_no_installation(host):
    assert identity.load_anchor() is None


def test_a_missing_anchor_directory_is_no_installation(host):
    host.dir.rmdir()
    assert identity.load_anchor() is None


def test_a_missing_etc_is_no_installation(host):
    host.dir.rmdir()
    host.etc.rmdir()
    assert identity.load_anchor() is None


# --- the anchor's directory chain ------------------------------------------------------


@pytest.mark.parametrize("which", ["root", "etc", "dir"])
@pytest.mark.parametrize("mode", [0o775, 0o757, 0o750, 0o700])
def test_an_unsafe_directory_in_the_chain_is_refused(host, which, mode):
    host.write_anchor()
    getattr(host, which).chmod(mode)
    try:
        assert _refused(identity.load_anchor) == ("anchor_unsafe",)
    finally:
        getattr(host, which).chmod(0o755)


@pytest.mark.parametrize("which", ["etc", "dir"])
def test_a_symlinked_directory_in_the_chain_is_refused(host, which, tmp_path):
    host.write_anchor()
    real = tmp_path / f"real-{which}"
    target = getattr(host, which)
    target.rename(real)
    target.symlink_to(real)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_dangling_symlink_for_the_anchor_directory_is_refused(host):
    host.dir.rmdir()
    host.dir.symlink_to(host.tmp / "nowhere")
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_file_where_a_directory_belongs_is_refused(host):
    host.dir.rmdir()
    host.dir.write_text("x")
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_chain_owned_by_someone_else_is_refused(host, monkeypatch):
    host.write_anchor()
    monkeypatch.setattr(identity, "TRUSTED_UID", ME + 1)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


# --- the anchor file -------------------------------------------------------------------


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o640, 0o600, 0o666])
def test_an_anchor_with_unsafe_mode_is_refused(host, mode):
    host.write_anchor(mode=mode)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_symlinked_anchor_is_refused(host, tmp_path):
    real = tmp_path / "real.yaml"
    real.write_text(_anchor_text(host.store, host.config, host.prefix))
    real.chmod(0o644)
    host.anchor.symlink_to(real)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_dangling_symlinked_anchor_is_refused(host):
    host.anchor.symlink_to(host.tmp / "nowhere.yaml")
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_fifo_anchor_is_refused_without_hanging(host):
    os.mkfifo(host.anchor, 0o644)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_directory_anchor_is_refused(host):
    host.anchor.mkdir(mode=0o755)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_a_hard_linked_anchor_is_refused(host, tmp_path):
    host.write_anchor()
    os.link(host.anchor, tmp_path / "second-name")
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_an_oversized_anchor_is_refused(host):
    text = _anchor_text(host.store, host.config, host.prefix)
    host.write_anchor("# " + "x" * (64 * 1024) + "\n" + text)
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("complete: true\n", ""),  # truncated before the sentinel
        lambda t: t.replace("complete: true\n", "complete: tr"),  # inside the sentinel
        lambda t: t[: t.index("install_prefix:") + 20],  # inside a value
        lambda t: t.replace("complete: true\n", "complete: false\n"),
        lambda t: "complete: true\n" + t.replace("complete: true\n", ""),  # sentinel not last
        lambda t: t + "extra: 1\n",
        lambda t: t.replace("account: svc", "account: 'a b'"),
        lambda t: "{ not: [yaml",
        lambda t: "- a list\n",
        lambda t: "",
    ],
    ids=[
        "no-sentinel",
        "truncated-sentinel",
        "truncated-value",
        "sentinel-false",
        "sentinel-not-last",
        "unknown-key",
        "bad-account",
        "invalid-yaml",
        "not-a-mapping",
        "empty",
    ],
)
def test_a_malformed_or_truncated_anchor_is_refused(host, mutate):
    host.write_anchor(mutate(_anchor_text(host.store, host.config, host.prefix)))
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


@pytest.mark.parametrize("field", ["store_path", "config_path", "install_prefix"])
@pytest.mark.parametrize("value", ["relative/path", "/a/../b", "/a//b", "/a/./b", "/a/b/"])
def test_anchor_paths_must_be_absolute_and_normal(host, field, value):
    text = _anchor_text(host.store, host.config, host.prefix)
    lines = [
        f"{field}: {value}" if line.startswith(f"{field}:") else line for line in text.splitlines()
    ]
    host.write_anchor("\n".join(lines) + "\n")
    assert _refused(identity.load_anchor) == ("anchor_unsafe",)


def test_the_anchor_is_read_from_the_file_that_was_opened(host, monkeypatch):
    """A rename over the anchor after it is opened does not change what is parsed."""
    host.write_anchor()
    replacement = host.dir / "next.yaml"
    replacement.write_text(_anchor_text(host.tmp / "other", host.config, host.prefix))
    replacement.chmod(0o644)
    real_fstat = os.fstat

    def fstat_then_replace(fd):
        result = real_fstat(fd)
        if not replacement.exists():
            return result
        os.replace(replacement, host.anchor)
        return result

    monkeypatch.setattr(identity.os, "fstat", fstat_then_replace)
    assert identity.load_anchor().store_path == host.store


def test_the_anchor_is_parsed_with_no_escape_in_its_error(host):
    host.write_anchor("account: \x1b[2J\n")
    with pytest.raises(StoreRefused) as e:
        identity.load_anchor()
    assert "\x1b" not in str(e.value)


# --- running from an installation ------------------------------------------------------


def _install_record(prefix: Path) -> Path:
    prefix.mkdir(parents=True, exist_ok=True)
    record = prefix / "INSTALL"
    record.write_text("commit: x\n")
    return record


def test_a_root_owned_install_record_means_installed(tmp_path, monkeypatch):
    record = _install_record(tmp_path / "prefix")
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    monkeypatch.setattr(identity, "install_record_candidates", lambda: [record])
    assert identity.running_from_installation()


def test_an_install_record_owned_by_someone_else_is_not_an_installation(tmp_path, monkeypatch):
    record = _install_record(tmp_path / "prefix")
    monkeypatch.setattr(identity, "TRUSTED_UID", ME + 1)
    monkeypatch.setattr(identity, "install_record_candidates", lambda: [record])
    assert not identity.running_from_installation()


def test_a_symlinked_install_record_is_not_an_installation(tmp_path, monkeypatch):
    record = _install_record(tmp_path / "prefix")
    link = tmp_path / "INSTALL"
    link.symlink_to(record)
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    monkeypatch.setattr(identity, "install_record_candidates", lambda: [link])
    assert not identity.running_from_installation()


def _fake_install(tmp_path: Path) -> tuple[Path, Path]:
    """A scratch layout like install.sh's: <P>/venv/lib/python3.12/site-packages/brandsentinel."""
    prefix = tmp_path / "inst"
    package = prefix / "venv" / "lib" / "python3.12" / "site-packages" / "brandsentinel"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    _install_record(prefix)
    return prefix, package


def test_candidates_include_the_prefix_beside_sys_prefix(tmp_path, monkeypatch):
    prefix, _package = _fake_install(tmp_path)
    monkeypatch.setattr(sys, "prefix", str(prefix / "venv"))
    assert prefix / "INSTALL" in REAL_CANDIDATES()


def test_candidates_include_the_prefix_of_the_package_directory(tmp_path, monkeypatch):
    """`PYTHONHOME` or another interpreter changes `sys.prefix`, not where the code is."""
    prefix, package = _fake_install(tmp_path)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(identity, "_package_dir", lambda: package)
    assert prefix / "INSTALL" in REAL_CANDIDATES()


def test_a_checkout_has_no_candidate_with_a_record(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "checkout" / ".venv"))
    monkeypatch.setattr(
        identity, "_package_dir", lambda: tmp_path / "checkout" / "src" / "brandsentinel"
    )
    monkeypatch.setattr(identity, "TRUSTED_UID", ME)
    monkeypatch.setattr(identity, "install_record_candidates", REAL_CANDIDATES)
    assert not identity.running_from_installation()


# --- classification --------------------------------------------------------------------


def test_with_no_anchor_and_no_marker_a_store_is_development(tmp_path):
    c = identity.classify(tmp_path / "s", None)
    assert not c.production and c.signal == "none"


def test_with_no_anchor_a_marker_still_classifies_production(tmp_path):
    s = tmp_path / "s"
    s.mkdir()
    (s / identity.MARKER_NAME).write_text(MARKER)
    c = identity.classify(s, None)
    assert c.production and c.signal == "marker" and not c.canonical


def test_the_anchor_store_path_is_production_and_canonical(host):
    host.write_anchor()
    a = identity.load_anchor()
    c = identity.classify(host.store, a)
    assert c.production and c.canonical and c.signal == "anchor path"


def test_the_live_path_is_recognized_without_touching_the_home(host, monkeypatch):
    """The developer cannot search the account's 0700 home (AE1, M3)."""
    host.write_anchor()
    a = identity.load_anchor()
    host.make_store()
    home = host.store.parent
    seen = []
    for name in ("lstat", "stat", "open", "scandir", "listdir"):
        real = getattr(os, name)

        def spy(path, *args, _real=real, **kwargs):
            seen.append(str(path))
            return _real(path, *args, **kwargs)

        monkeypatch.setattr(identity.os, name, spy)
    home.chmod(0)
    try:
        c = identity.classify(host.store, a)
        nested = identity.classify(host.store / "sub", a)
    finally:
        home.chmod(0o700)
    assert c.production and c.canonical
    assert nested.production and not nested.canonical
    assert not [p for p in seen if p.startswith(str(home))]


def test_a_configured_path_without_the_marker_is_still_production(host):
    """M15: deleting the marker does not declassify the live store."""
    host.write_anchor()
    host.make_store()
    c = identity.classify(host.store, identity.load_anchor())
    assert c.production and c.canonical


def test_a_relative_spelling_of_the_live_path_is_not_canonical(host, monkeypatch):
    host.write_anchor()
    monkeypatch.chdir(host.store.parent.parent)
    c = identity.classify(Path("live/data"), identity.load_anchor())
    assert c.production and not c.canonical


@pytest.mark.parametrize("relation", ["under", "ancestor", "grandparent"])
def test_paths_under_or_above_the_live_store_are_noncanonical(host, relation):
    host.write_anchor()
    path = {
        "under": host.store / "x",
        "ancestor": host.store.parent,
        "grandparent": host.store.parent.parent,
    }[relation]
    c = identity.classify(path, identity.load_anchor())
    assert c.production and not c.canonical


def test_a_sibling_sharing_a_string_prefix_is_development(host):
    host.write_anchor()
    c = identity.classify(Path(str(host.store) + "2"), identity.load_anchor())
    assert not c.production


def test_a_symlink_into_the_live_store_is_production_and_noncanonical(host, tmp_path):
    host.write_anchor()
    host.make_store()
    link = tmp_path / "mine"
    link.symlink_to(host.store)
    c = identity.classify(link, identity.load_anchor())
    assert c.production and not c.canonical


def test_a_symlink_into_the_unreadable_home_is_still_recognized(host, tmp_path):
    """M4: the target's path, not its contents, identifies it."""
    host.write_anchor()
    host.make_store()
    link = tmp_path / "mine"
    link.symlink_to(host.store)
    host.store.parent.chmod(0)
    try:
        c = identity.classify(link, identity.load_anchor())
    finally:
        host.store.parent.chmod(0o700)
    assert c.production and not c.canonical


def test_a_symlink_to_an_uninspectable_place_is_unclassifiable(host, tmp_path):
    host.write_anchor()
    blocked = tmp_path / "blocked"
    (blocked / "inner").mkdir(parents=True)
    link = tmp_path / "mine"
    link.symlink_to(blocked / "inner")
    blocked.chmod(0)
    try:
        assert _refused(identity.classify, link, identity.load_anchor()) == ("unclassifiable",)
    finally:
        blocked.chmod(0o700)


def test_the_same_directory_by_device_and_inode_is_production(host, tmp_path, monkeypatch):
    """M12: a bind mount shows the live store's device and inode under another path."""
    host.write_anchor()
    host.make_store()
    other = tmp_path / "bind"
    other.mkdir()
    live = os.stat(host.store)
    real_stat = os.stat

    def stat_as_bind(path, *args, **kwargs):
        if Path(path) == other:
            return live
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(identity.os, "stat", stat_as_bind)
    c = identity.classify(other, identity.load_anchor())
    assert c.production and not c.canonical and c.signal == "device and inode"


def test_an_unreachable_live_store_skips_only_the_inode_signal(host, tmp_path):
    host.write_anchor()
    host.make_store()
    host.store.parent.chmod(0)
    mine = tmp_path / "scratch"
    mine.mkdir()
    try:
        c = identity.classify(mine, identity.load_anchor())
    finally:
        host.store.parent.chmod(0o700)
    assert not c.production


def test_a_marked_copy_elsewhere_is_production_and_noncanonical(host, tmp_path):
    host.write_anchor()
    copy = tmp_path / "trial" / "data"
    copy.mkdir(parents=True)
    (copy / identity.MARKER_NAME).write_text(MARKER)
    c = identity.classify(copy, identity.load_anchor())
    assert c.production and not c.canonical and c.signal == "marker"


@pytest.mark.parametrize(
    "make",
    [
        lambda p: p.write_text("class: production\n"),
        lambda p: p.write_text("brandsentinel_store: 2\nclass: production\n"),
        lambda p: p.write_text(MARKER + "extra: 1\n"),
        lambda p: p.write_text("{ not yaml"),
        lambda p: p.write_text("x" * 5000),
        lambda p: p.mkdir(),
        lambda p: p.symlink_to(p.parent / "elsewhere"),
        lambda p: (p.write_text(MARKER), p.chmod(0)),
    ],
    ids=[
        "no-version",
        "wrong-version",
        "extra-key",
        "bad-yaml",
        "oversized",
        "directory",
        "symlink",
        "unreadable",
    ],
)
def test_a_bad_marker_is_unclassifiable(tmp_path, make):
    s = tmp_path / "s"
    s.mkdir()
    marker = s / identity.MARKER_NAME
    make(marker)
    try:
        assert _refused(identity.classify, s, None) == ("unclassifiable",)
    finally:
        if marker.exists() and not marker.is_symlink():
            marker.chmod(0o600)


def test_an_unreadable_ancestor_is_unclassifiable(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0)
    try:
        assert _refused(identity.classify, blocked / "s", None) == ("unclassifiable",)
    finally:
        blocked.chmod(0o700)


def test_classification_writes_nothing(host, tmp_path):
    host.write_anchor()
    s = tmp_path / "s"
    s.mkdir()
    (s / identity.MARKER_NAME).write_text(MARKER)
    before = _tree(tmp_path)
    identity.classify(s, identity.load_anchor())
    identity.classify(tmp_path / "missing" / "deeper", identity.load_anchor())
    assert _tree(tmp_path) == before


# --- integrity (R6) --------------------------------------------------------------------


def _scratch_store(tmp_path: Path) -> Path:
    s = tmp_path / "s"
    for d in ("raw/certstream", "artifacts/tmp", "artifacts/sha256/ab", "cache", "reports"):
        (s / d).mkdir(parents=True)
    (s / "brandsentinel.db").write_bytes(b"")
    (s / "artifacts/sha256/ab" / ("ab" + "0" * 62)).write_bytes(b"blob")
    (s / "raw/certstream/seg.jsonl.gz").write_bytes(b"seg")
    return s


def test_a_normal_store_passes(tmp_path):
    identity.check_integrity(_scratch_store(tmp_path))


def test_a_missing_store_passes(tmp_path):
    identity.check_integrity(tmp_path / "nothing-yet")


@pytest.mark.parametrize(
    "entry",
    [
        "raw",
        "raw/certstream",
        "artifacts",
        "artifacts/tmp",
        "artifacts/sha256",
        "artifacts/sha256/ab",
        "cache",
        "reports",
    ],
)
def test_a_symlinked_store_directory_is_refused(tmp_path, entry):
    """M17, AE7: the sweep and the writers follow these into another store."""
    s = _scratch_store(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    victim = s / entry
    victim.rename(other / "moved")
    victim.symlink_to(other / "moved")
    before = _tree(other)
    assert _refused(identity.check_integrity, s) == ("store_integrity",)
    assert _tree(other) == before


@pytest.mark.parametrize(
    "name",
    [
        "brandsentinel.db",
        "brandsentinel.db-wal",
        "brandsentinel.db-shm",
        "brandsentinel.db-journal",
    ],
)
def test_a_symlinked_database_file_is_refused(tmp_path, name):
    s = _scratch_store(tmp_path)
    target = tmp_path / "elsewhere.db"
    target.write_bytes(b"")
    (s / name).unlink(missing_ok=True)
    (s / name).symlink_to(target)
    assert _refused(identity.check_integrity, s) == ("store_integrity",)


@pytest.mark.parametrize(
    "name",
    [
        "brandsentinel.db",
        "brandsentinel.db-wal",
        "brandsentinel.db-shm",
        "brandsentinel.db-journal",
    ],
)
def test_a_hard_linked_database_file_is_refused(tmp_path, name):
    """M11: SQLite writes reach every name of a hard-linked database."""
    s = _scratch_store(tmp_path)
    (s / name).write_bytes(b"")
    os.link(s / name, tmp_path / "second-name")
    assert _refused(identity.check_integrity, s) == ("store_integrity",)


def test_hard_linked_blobs_and_segments_are_accepted(tmp_path):
    """The store only creates or unlinks these names, so a link elsewhere is unaffected."""
    s = _scratch_store(tmp_path)
    os.link(s / "artifacts/sha256/ab" / ("ab" + "0" * 62), tmp_path / "blob-link")
    os.link(s / "raw/certstream/seg.jsonl.gz", tmp_path / "seg-link")
    identity.check_integrity(s)


def test_a_database_that_is_not_a_regular_file_is_refused(tmp_path):
    s = _scratch_store(tmp_path)
    (s / "brandsentinel.db").unlink()
    (s / "brandsentinel.db").mkdir()
    assert _refused(identity.check_integrity, s) == ("store_integrity",)


def test_integrity_writes_nothing(tmp_path):
    s = _scratch_store(tmp_path)
    before = _tree(tmp_path)
    identity.check_integrity(s)
    assert _tree(tmp_path) == before


# --- the module never writes -----------------------------------------------------------


def test_the_identity_module_calls_no_write_api():
    import ast

    source = Path(identity.__file__).read_text(encoding="utf-8")
    names = {
        (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call)
    }
    writes = {
        "mkdir",
        "makedirs",
        "write",
        "write_text",
        "write_bytes",
        "unlink",
        "remove",
        "rename",
        "replace",
        "chmod",
        "chown",
        "symlink",
        "link",
        "rmdir",
        "truncate",
    }
    assert not names & writes
    flags = [n.attr for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Attribute)]
    assert not {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"} & set(flags)


def test_mode_bits_used_in_the_tests_mean_what_they_say():
    assert stat.S_IWGRP == 0o020 and stat.S_IWOTH == 0o002
