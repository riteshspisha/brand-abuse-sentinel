"""The image approval record reader (B7 U14, first step).

Plan: docs/plans/2026-11-10-002-chore-b7-production-promotion-plan.md (U14, KTD12, OB8).
Root ownership is simulated by building the record's directory chain under a temporary
root and patching the trusted UID to the test's own UID; nothing here reads /etc.
"""

import inspect
import os
import stat
from pathlib import Path

import pytest

from brandsentinel.store import approval, identity
from brandsentinel.store.approval import ApprovalRefused

ME = os.getuid()
ID = "sha256:" + "0123456789abcdef" * 4
RECORD = f"image_id: {ID}\ncomplete: true\n"


class Host:
    """A fake host: a chain root standing in for `/`, `etc/brandsentinel` and the record."""

    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.etc = self.root / "etc"
        self.dir = self.etc / "brandsentinel"
        self.record = self.dir / "image-approval.yaml"
        for d in (self.root, self.etc, self.dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)
        monkeypatch.setattr(approval, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(approval, "APPROVAL_PATH", self.record)
        monkeypatch.setattr(approval, "TRUSTED_UID", ME)

    def write(self, data: str | bytes = RECORD, mode: int = 0o644) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.record.write_bytes(data)
        self.record.chmod(mode)


@pytest.fixture
def host(tmp_path, monkeypatch) -> Host:
    return Host(tmp_path, monkeypatch)


def _refused() -> str:
    with pytest.raises(ApprovalRefused) as e:
        approval.load_approval()
    return e.value.check


# --- the fixed location ----------------------------------------------------------------


def test_the_record_lives_beside_the_anchor_at_the_approved_path():
    # tests/conftest.py redirects both locations for every test: compare the sources.
    source = inspect.getsource(approval)
    assert 'APPROVAL_PATH = Path("/etc/brandsentinel/image-approval.yaml")' in source
    assert 'CHAIN_ROOT = Path("/")' in source
    assert "TRUSTED_UID = 0\n" in source
    assert 'ANCHOR_PATH = Path("/etc/brandsentinel/production.yaml")' in inspect.getsource(identity)


def test_no_environment_variable_selects_the_record():
    source = inspect.getsource(approval)
    assert "os.environ" not in source
    assert "environ[" not in source
    assert "getenv" not in source


# --- present, missing -----------------------------------------------------------------


def test_a_valid_record_is_read(host):
    host.write()
    assert approval.load_approval() == approval.ImageApproval(image_id=ID)


def test_a_missing_record_is_none(host):
    assert approval.load_approval() is None


def test_a_missing_record_directory_is_none(host):
    host.dir.rmdir()
    assert approval.load_approval() is None


def test_a_missing_etc_is_none(host):
    host.dir.rmdir()
    host.etc.rmdir()
    assert approval.load_approval() is None


def test_missing_unsafe_and_malformed_are_distinct(host):
    assert approval.load_approval() is None
    host.write("image_id: nope\ncomplete: true\n")
    assert _refused() == "approval_malformed"
    host.write(mode=0o666)
    assert _refused() == "approval_unsafe"


# --- the directory chain --------------------------------------------------------------


@pytest.mark.parametrize("which", ["root", "etc", "dir"])
@pytest.mark.parametrize("mode", [0o775, 0o757, 0o750, 0o700])
def test_an_unsafe_directory_in_the_chain_is_refused(host, which, mode):
    host.write()
    getattr(host, which).chmod(mode)
    try:
        assert _refused() == "approval_unsafe"
    finally:
        getattr(host, which).chmod(0o755)


@pytest.mark.parametrize("which", ["etc", "dir"])
def test_a_symlinked_directory_in_the_chain_is_refused(host, which, tmp_path):
    host.write()
    real = tmp_path / f"real-{which}"
    target = getattr(host, which)
    target.rename(real)
    target.symlink_to(real)
    assert _refused() == "approval_unsafe"


def test_a_dangling_symlink_for_the_record_directory_is_refused(host):
    host.dir.rmdir()
    host.dir.symlink_to(host.tmp / "nowhere")
    assert _refused() == "approval_unsafe"


def test_a_file_where_a_directory_belongs_is_refused(host):
    host.dir.rmdir()
    host.dir.write_text("x")
    assert _refused() == "approval_unsafe"


def test_a_chain_owned_by_someone_else_is_refused(host, monkeypatch):
    host.write()
    monkeypatch.setattr(approval, "TRUSTED_UID", ME + 1)
    assert _refused() == "approval_unsafe"


def test_a_missing_chain_root_is_refused(host, monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "CHAIN_ROOT", tmp_path / "absent")
    monkeypatch.setattr(approval, "APPROVAL_PATH", tmp_path / "absent" / "etc" / "x.yaml")
    assert _refused() == "approval_unsafe"


def test_a_record_outside_the_chain_root_is_refused(host, monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "APPROVAL_PATH", tmp_path / "elsewhere" / "image-approval.yaml")
    assert _refused() == "approval_unsafe"


@pytest.mark.parametrize(
    "path",
    ["etc/brandsentinel/image-approval.yaml", "/etc/../etc/brandsentinel/x.yaml", "/etc//x.yaml"],
)
def test_a_relative_or_unnormalized_record_path_is_refused(host, monkeypatch, path):
    monkeypatch.setattr(approval, "CHAIN_ROOT", Path("/"))
    monkeypatch.setattr(approval, "APPROVAL_PATH", Path(path) if "//" not in path else path)
    assert _refused() == "approval_unsafe"


def test_a_directory_swapped_for_a_symlink_after_its_check_is_not_followed(host, monkeypatch):
    """Each directory is opened relative to the descriptor of the one above it, so a
    swap of `etc` after the root was checked cannot redirect the walk."""
    host.write()
    decoy = host.tmp / "decoy"
    (decoy / "brandsentinel").mkdir(parents=True)
    for d in (decoy, decoy / "brandsentinel"):
        d.chmod(0o755)
    (decoy / "brandsentinel" / "image-approval.yaml").write_text(
        "image_id: sha256:" + "f" * 64 + "\ncomplete: true\n"
    )
    (decoy / "brandsentinel" / "image-approval.yaml").chmod(0o644)
    real_fstat = os.fstat
    swapped = []

    def fstat_then_swap(fd):
        result = real_fstat(fd)
        if not swapped:
            swapped.append(True)
            host.etc.rename(host.tmp / "etc-aside")
            host.etc.symlink_to(decoy)
        return result

    monkeypatch.setattr(approval.os, "fstat", fstat_then_swap)
    assert _refused() == "approval_unsafe"


# --- the record file ------------------------------------------------------------------


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o640, 0o600, 0o666, 0o662])
def test_a_record_with_unsafe_mode_is_refused(host, mode):
    host.write(mode=mode)
    assert _refused() == "approval_unsafe"


def test_a_record_owned_by_someone_else_is_refused(host, monkeypatch):
    host.write()
    real_fstat = os.fstat

    def other_owner(fd):
        st = real_fstat(fd)
        if stat.S_ISREG(st.st_mode):
            fields = list(st)
            fields[stat.ST_UID] = ME + 1
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(approval.os, "fstat", other_owner)
    assert _refused() == "approval_unsafe"


def test_a_symlinked_record_is_refused(host, tmp_path):
    real = tmp_path / "real.yaml"
    real.write_text(RECORD)
    real.chmod(0o644)
    host.record.symlink_to(real)
    assert _refused() == "approval_unsafe"


def test_a_dangling_symlinked_record_is_refused(host):
    host.record.symlink_to(host.tmp / "nowhere.yaml")
    assert _refused() == "approval_unsafe"


def test_a_fifo_record_is_refused_without_hanging(host):
    os.mkfifo(host.record, 0o644)
    assert _refused() == "approval_unsafe"


def test_a_directory_record_is_refused(host):
    host.record.mkdir(mode=0o755)
    assert _refused() == "approval_unsafe"


def test_a_hard_linked_record_is_refused(host, tmp_path):
    host.write()
    os.link(host.record, host.dir / "second-name")
    assert _refused() == "approval_unsafe"


def test_an_oversized_record_is_refused(host):
    host.write("#" * (approval.MAX_APPROVAL_BYTES + 1) + "\n" + RECORD)
    assert _refused() == "approval_unsafe"


def test_an_oversized_record_is_refused_before_it_is_read(host, monkeypatch):
    host.write("#" * (approval.MAX_APPROVAL_BYTES + 1) + "\n" + RECORD)

    def never(fd, n):
        raise AssertionError("an oversized record must be refused on its size alone")

    monkeypatch.setattr(approval.os, "read", never)
    assert _refused() == "approval_unsafe"


def test_a_record_that_grows_past_the_cap_while_read_is_refused(host, monkeypatch):
    host.write()
    real_read = os.read

    def endless(fd, n):
        real_read(fd, n)
        return b"x" * n

    monkeypatch.setattr(approval.os, "read", endless)
    assert _refused() == "approval_unsafe"


def test_a_read_error_is_unsafe(host, monkeypatch):
    host.write()

    def broken(fd, n):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(approval.os, "read", broken)
    assert _refused() == "approval_unsafe"


def test_a_permission_error_on_the_chain_is_unsafe(host, monkeypatch):
    host.write()
    real_open = os.open

    def denied(path, flags, *a, **k):
        if os.fspath(path) == "brandsentinel":
            raise PermissionError(13, "denied", "brandsentinel")
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(approval.os, "open", denied)
    assert _refused() == "approval_unsafe"


def test_the_record_is_read_from_the_file_that_was_opened(host, monkeypatch):
    """A rename over the record after it is opened does not change what is parsed."""
    host.write()
    replacement = host.dir / "next.yaml"
    replacement.write_text("image_id: sha256:" + "e" * 64 + "\ncomplete: true\n")
    replacement.chmod(0o644)
    real_fstat = os.fstat

    def fstat_then_replace(fd):
        result = real_fstat(fd)
        if stat.S_ISREG(result.st_mode) and replacement.exists():
            os.replace(replacement, host.record)
        return result

    monkeypatch.setattr(approval.os, "fstat", fstat_then_replace)
    assert approval.load_approval().image_id == ID


def test_every_descriptor_is_closed(host, monkeypatch):
    host.write()
    opened, closed = [], []
    real_open, real_close = os.open, os.close

    def tracking_open(*a, **k):
        fd = real_open(*a, **k)
        opened.append(fd)
        return fd

    def tracking_close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(approval.os, "open", tracking_open)
    monkeypatch.setattr(approval.os, "close", tracking_close)
    approval.load_approval()
    host.record.chmod(0o666)
    with pytest.raises(ApprovalRefused):
        approval.load_approval()
    assert sorted(opened) == sorted(closed)
    assert opened


# --- ownership and descriptor lifecycle ------------------------------------------------


def _report_as_foreign(monkeypatch, path: Path) -> None:
    """fstat reports `path` (matched by device and inode) as owned by another UID. Every
    other stat is real, so the record itself still passes its owner check."""
    target = path.stat()
    key = (target.st_dev, target.st_ino)
    real_fstat = os.fstat

    def fstat(fd):
        st = real_fstat(fd)
        if (st.st_dev, st.st_ino) == key:
            fields = list(st)
            fields[stat.ST_UID] = ME + 1
            return os.stat_result(fields)
        return st

    monkeypatch.setattr(approval.os, "fstat", fstat)


@pytest.mark.parametrize("which", ["root", "etc", "dir"])
def test_a_directory_owned_by_someone_else_is_refused_while_the_record_is_trusted(
    host, monkeypatch, which
):
    host.write()
    assert approval.load_approval() == approval.ImageApproval(image_id=ID)  # the control
    _report_as_foreign(monkeypatch, getattr(host, which))
    assert _refused() == "approval_unsafe"


def test_only_the_foreign_directory_differs_in_the_owner_regression(host, monkeypatch):
    """The regression above changes one directory's owner and nothing else: with the
    record reported as foreign instead, the record's own check is what refuses it."""
    host.write()
    _report_as_foreign(monkeypatch, host.record)
    assert _refused() == "approval_unsafe"
    monkeypatch.undo()
    monkeypatch.setattr(approval, "CHAIN_ROOT", host.root)
    monkeypatch.setattr(approval, "APPROVAL_PATH", host.record)
    monkeypatch.setattr(approval, "TRUSTED_UID", ME)
    assert approval.load_approval() == approval.ImageApproval(image_id=ID)


_UNSAFE_STATES = {
    "group-writable": 0o775,
    "other-writable": 0o757,
    "not-traversable-by-others": 0o750,
    "foreign-owner": None,
}


@pytest.mark.parametrize("state", sorted(_UNSAFE_STATES))
@pytest.mark.parametrize("which", ["root", "etc", "dir"])
def test_a_missing_entry_beneath_an_unsafe_directory_is_refused_not_absent(
    host, monkeypatch, which, state
):
    """Absence is reported only below directories that passed their checks."""
    below = {"root": [host.dir, host.etc], "etc": [host.dir], "dir": []}[which]
    for d in below:
        d.rmdir()
    target = getattr(host, which)
    assert approval.load_approval() is None  # the control: safe chain, entry missing
    mode = _UNSAFE_STATES[state]
    if mode is None:
        _report_as_foreign(monkeypatch, target)
    else:
        target.chmod(mode)
    try:
        assert _refused() == "approval_unsafe"
    finally:
        target.chmod(0o755)


def _setup_symlinked_dir(h):
    h.write()
    real = h.tmp / "real-dir"
    h.dir.rename(real)
    h.dir.symlink_to(real)


def _setup_hard_link(h):
    h.write()
    os.link(h.record, h.tmp / "second-name")


_LIFECYCLE = {
    "valid": (lambda h: h.write(), "ok"),
    "missing-record": (lambda h: None, "none"),
    "missing-dir": (lambda h: h.dir.rmdir(), "none"),
    "missing-etc": (lambda h: (h.dir.rmdir(), h.etc.rmdir()), "none"),
    "unsafe-dir-mode": (lambda h: (h.write(), h.etc.chmod(0o775)), "unsafe"),
    "unsafe-dir-missing-record": (lambda h: h.dir.chmod(0o775), "unsafe"),
    "symlinked-dir": (_setup_symlinked_dir, "unsafe"),
    "unsafe-record-mode": (lambda h: h.write(mode=0o666), "unsafe"),
    "symlinked-record": (lambda h: h.record.symlink_to(h.tmp / "elsewhere"), "unsafe"),
    "fifo-record": (lambda h: os.mkfifo(h.record, 0o644), "unsafe"),
    "hard-linked-record": (_setup_hard_link, "unsafe"),
    "oversized-record": (lambda h: h.write("x" * (approval.MAX_APPROVAL_BYTES + 1)), "unsafe"),
    "malformed-record": (lambda h: h.write("image_id: nope\ncomplete: true\n"), "malformed"),
}


class _Descriptors:
    """Tracks the descriptors the reader holds. Numbers are reused once closed, so it
    keeps the set of open ones: closing one that is not open is a double close, and one
    still open at the end is a leak."""

    def __init__(self) -> None:
        self.live: set[int] = set()
        self.opens = 0
        self.closes = 0
        self.double_closes = 0


def _track_descriptors(monkeypatch, fail_on_close: int | None = None) -> _Descriptors:
    """With `fail_on_close`, that close call releases the descriptor and then reports an
    error, as Linux close does."""
    fds = _Descriptors()
    real_open, real_close = os.open, os.close

    def tracking_open(*a, **k):
        fd = real_open(*a, **k)
        fds.live.add(fd)
        fds.opens += 1
        return fd

    def tracking_close(fd):
        fds.closes += 1
        if fd in fds.live:
            fds.live.discard(fd)
            real_close(fd)
        else:
            fds.double_closes += 1
        if fds.closes == fail_on_close:
            raise OSError(5, "I/O error")

    monkeypatch.setattr(approval.os, "open", tracking_open)
    monkeypatch.setattr(approval.os, "close", tracking_close)
    return fds


def _outcome() -> str:
    try:
        result = approval.load_approval()
    except ApprovalRefused as e:
        return e.check.removeprefix("approval_")
    return "none" if result is None else "ok"


@pytest.mark.parametrize("case", sorted(_LIFECYCLE))
def test_every_descriptor_is_closed_exactly_once_on_every_path(host, monkeypatch, case):
    setup, expected = _LIFECYCLE[case]
    setup(host)
    fds = _track_descriptors(monkeypatch)
    try:
        assert _outcome() == expected
    finally:
        for d in (host.root, host.etc, host.dir):
            if d.is_dir() and not d.is_symlink():
                d.chmod(0o755)
    assert fds.live == set()
    assert fds.double_closes == 0
    assert fds.opens == fds.closes


@pytest.mark.parametrize("failing_close", [1, 2, 3, 4])
def test_a_failing_close_is_unsafe_without_a_leak_or_a_double_close(
    host, monkeypatch, failing_close
):
    """A valid read closes four descriptors: the chain root and etc as the walk moves
    down, the record, then the record's directory. Whichever close reports an error, the
    result is a named refusal, every successor descriptor is still closed, and no
    descriptor is closed twice."""
    host.write()
    fds = _track_descriptors(monkeypatch, fail_on_close=failing_close)
    with pytest.raises(ApprovalRefused) as e:
        approval.load_approval()
    assert e.value.check == "approval_unsafe"
    assert e.value.__cause__ is None
    assert fds.live == set()
    assert fds.double_closes == 0


def test_a_valid_read_closes_four_descriptors(host, monkeypatch):
    """Pins the count the failing-close test above relies on."""
    host.write()
    fds = _track_descriptors(monkeypatch)
    assert approval.load_approval() is not None
    assert fds.opens == fds.closes == 4
    assert fds.live == set()


# --- the record's content -------------------------------------------------------------

H = "0123456789abcdef" * 4


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        f"image_id: {ID}\n",  # truncated before the sentinel
        f"image_id: {ID}\ncomplete: true",  # cut before the final newline
        f"image_id: {ID}\ncomplete: tr",
        f"image_id: sha256:{H[:30]}",  # cut inside the value
        f"image_id: {ID}\ncomplete: false\n",
        f"image_id: {ID}\ncomplete: True\n",
        f"image_id: {ID}\ncomplete: yes\n",
        f"image_id: {ID}\ncomplete: 'true'\n",
        f"complete: true\nimage_id: {ID}\n",  # sentinel not last
        f"image_id: {ID}\nimage_id: {ID}\ncomplete: true\n",  # duplicate key
        "image_id: sha256:" + "f" * 64 + f"\nimage_id: {ID}\ncomplete: true\n",
        f"image_id: {ID}\ncomplete: true\ncomplete: true\n",
        f"image_id: {ID}\nextra: 1\ncomplete: true\n",  # unexpected key
        f"image_id: {ID}\ncomplete: true\nextra: 1\n",
        "complete: true\n",  # missing key
        f"image: {ID}\ncomplete: true\n",
        f"Image_Id: {ID}\ncomplete: true\n",
        f"# approved\nimage_id: {ID}\ncomplete: true\n",  # comment
        f"image_id: {ID} # approved\ncomplete: true\n",
        f"---\nimage_id: {ID}\ncomplete: true\n",  # YAML document marker
        f"image_id: {ID}\ncomplete: true\n...\n",
        f"{{image_id: {ID}, complete: true}}\n",  # flow mapping
        f"image_id: &a {ID}\ncomplete: true\n",  # anchor
        f"image_id: !!str {ID}\ncomplete: true\n",  # tag
        f'image_id: "{ID}"\ncomplete: true\n',  # quoted
        f"image_id: '{ID}'\ncomplete: true\n",
        f"image_id:  {ID}\ncomplete: true\n",  # extra space
        f"image_id:\t{ID}\ncomplete: true\n",
        f" image_id: {ID}\ncomplete: true\n",  # indented
        f"image_id: {ID} \ncomplete: true\n",  # trailing space
        f"image_id: {ID}\ncomplete: true \n",
        f"image_id: {ID}\r\ncomplete: true\r\n",  # CRLF
        f"﻿image_id: {ID}\ncomplete: true\n",  # byte order mark
        f"image_id: {ID}\n\ncomplete: true\n",  # blank line
        f"image_id: {ID}\ncomplete: true\n\n",
        f"image_id: {ID.upper()}\ncomplete: true\n",
        f"image_id: sha256:{H.upper()}\ncomplete: true\n",
        f"image_id: SHA256:{H}\ncomplete: true\n",
        f"image_id: sha256:{H[:63]}\ncomplete: true\n",
        f"image_id: sha256:{H}0\ncomplete: true\n",
        f"image_id: sha512:{H}{H}\ncomplete: true\n",
        f"image_id: {H}\ncomplete: true\n",  # no algorithm
        "image_id: sha256:" + "g" * 64 + "\ncomplete: true\n",
        "image_id: sha256:" + chr(0x661) * 64 + "\ncomplete: true\n",  # non-ASCII digits
        "image_id: brandsentinel-sandbox:local\ncomplete: true\n",  # a tag
        f"image_id: brandsentinel-sandbox@{ID}\ncomplete: true\n",
        "image_id: \x1b[2J\ncomplete: true\n",
        "image_id: [sha256]\ncomplete: true\n",
        "- a list\n",
    ],
)
def test_a_malformed_or_truncated_record_is_refused(host, text):
    host.write(text)
    assert _refused() == "approval_malformed"


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe" + RECORD.encode("utf-16-le"),
        RECORD.encode().replace(b"true", b"tr\x00ue"),
        b"image_id: sha256:" + b"\xe9" * 64 + b"\ncomplete: true\n",
        b"\x00" + RECORD.encode(),
    ],
)
def test_a_record_with_invalid_bytes_is_refused(host, data):
    host.write(data)
    assert _refused() == "approval_malformed"


# --- errors carry nothing from the host -----------------------------------------------


@pytest.mark.parametrize(
    "setup",
    [
        lambda h: h.write("image_id: \x1b[2J secret\ncomplete: true\n"),
        lambda h: h.write(mode=0o666),
        lambda h: h.record.symlink_to(h.tmp / "secret-target"),
    ],
    ids=["malformed", "mode", "symlink"],
)
def test_errors_name_the_check_only(host, setup):
    setup(host)
    with pytest.raises(ApprovalRefused) as e:
        approval.load_approval()
    assert str(e.value) == e.value.check
    assert e.value.args == (e.value.check,)
    assert e.value.__cause__ is None
    assert e.value.__context__ is None or e.value.__suppress_context__
    text = repr(e.value) + str(e.value)
    for leak in ("secret", "\x1b", str(host.tmp), "image-approval", "brandsentinel/"):
        assert leak not in text


def test_the_check_names_are_stable():
    assert ApprovalRefused.UNSAFE == "approval_unsafe"
    assert ApprovalRefused.MALFORMED == "approval_malformed"


def test_the_record_form_is_also_valid_yaml_naming_the_same_id():
    """The fixed form is a subset of YAML, so a YAML reader (U13's tooling, a human)
    agrees with this reader on what the record says."""
    import yaml

    assert yaml.safe_load(RECORD) == {"image_id": ID, "complete": True}
