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
    assert Path("/etc/brandsentinel/image-approval.yaml") == approval.APPROVAL_PATH
    # tests/conftest.py redirects identity.ANCHOR_PATH for every test: compare the source.
    assert 'ANCHOR_PATH = Path("/etc/brandsentinel/production.yaml")' in inspect.getsource(identity)
    assert approval.APPROVAL_PATH.parent == Path("/etc/brandsentinel")
    assert Path("/") == approval.CHAIN_ROOT
    assert approval.TRUSTED_UID == 0


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
