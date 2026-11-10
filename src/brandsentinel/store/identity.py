"""Which store is production, and whether a store's layout is safe to open (B3).

Plan: docs/plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md.

- The **anchor** (`/etc/brandsentinel/production.yaml`, root-owned, outside the install
  prefix) names the production store, its approved configuration, the account and the
  install prefix. It is believed only for its ownership and location, never its content
  alone (R1, R2).
- **Classification** decides whether a configured `data_dir` is the production store
  (R3-R5). The first step is lexical, so the live path is recognized without searching
  the service account's 0700 home. The **marker** inside a production store is an
  accidental-misuse signal, not an identity: whoever can write the directory can remove
  it.
- **Integrity** refuses a store whose database files, or the directories the store code
  writes and deletes in, are symlinks, or whose database files are hard-linked (R6).

Everything here only reads metadata and two small files. Nothing is created or changed.
Tests replace the module attributes `ANCHOR_PATH`, `CHAIN_ROOT`, `TRUSTED_UID` and
`install_record_candidates`; the environment never selects them.
"""

import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

ANCHOR_PATH = Path("/etc/brandsentinel/production.yaml")
CHAIN_ROOT = Path("/")
TRUSTED_UID = 0
MARKER_NAME = "BRANDSENTINEL-STORE"
MAX_ANCHOR_BYTES = 64 * 1024
MAX_MARKER_BYTES = 4096

_ANCHOR_KEYS = ("account", "store_path", "config_path", "install_prefix", "complete")
_ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_MARKER = {"brandsentinel_store": 1, "class": "production"}
DATABASE_FILES = (
    "brandsentinel.db",
    "brandsentinel.db-wal",
    "brandsentinel.db-shm",
    "brandsentinel.db-journal",
)
# Directories that the store writes, migrates or deletes through (traced in the plan):
# the blob writer and orphan sweep, raw-log writer and pruning, RDAP cache, reports.
STORE_DIRECTORIES = ("raw", "artifacts", "artifacts/tmp", "artifacts/sha256", "cache", "reports")
# Their entries are directories the same code walks into (`sha256/<xx>`, `raw/<source>`).
WALKED_DIRECTORIES = ("raw", "artifacts/sha256")


class StoreRefused(Exception):
    """A store may not be opened. `checks` are stable names; no path or value is kept."""

    def __init__(self, checks: tuple[str, ...]) -> None:
        super().__init__(", ".join(checks))
        self.checks = checks


@dataclass(frozen=True)
class Anchor:
    account: str
    store_path: Path
    config_path: Path
    install_prefix: Path


@dataclass(frozen=True)
class Classification:
    production: bool
    signal: str  # "anchor path", "resolved path", "device and inode", "marker" or "none"
    canonical: bool  # the configured data_dir is literally the anchor's store path


@dataclass(frozen=True)
class Authorization:
    """What the production policy approved. It stops accidental callers of `open_store`,
    not hostile Python, which can build one."""

    path: str
    device: int
    inode: int
    euid: int


def _unsafe() -> StoreRefused:
    return StoreRefused(("anchor_unsafe",))


# --- the anchor ------------------------------------------------------------------------


def _safe_directory(st: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == TRUSTED_UID
        and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and bool(st.st_mode & stat.S_IXOTH)
    )


def _chain() -> list[Path] | None:
    """CHAIN_ROOT and each directory down to the anchor's parent; None if the anchor
    does not lie under CHAIN_ROOT (a broken test or build)."""
    try:
        rel = ANCHOR_PATH.parent.relative_to(CHAIN_ROOT)
    except ValueError:
        return None
    out = [CHAIN_ROOT]
    for part in rel.parts:
        out.append(out[-1] / part)
    return out


def load_anchor() -> Anchor | None:
    """The anchor, or None when it is missing (R2). Anything else unsafe raises."""
    chain = _chain()
    if chain is None:
        raise _unsafe()
    for directory in chain:
        try:
            st = os.lstat(directory)
        except FileNotFoundError:
            return None  # every existing ancestor passed: no anchor on this host
        except OSError as e:
            raise _unsafe() from e
        if not _safe_directory(st):
            raise _unsafe()
    try:
        fd = os.open(ANCHOR_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:  # ELOOP for a symlink, EACCES, ...
        raise _unsafe() from e
    try:
        st = os.fstat(fd)
        if not (
            stat.S_ISREG(st.st_mode)
            and st.st_uid == TRUSTED_UID
            and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and st.st_mode & stat.S_IROTH
            and st.st_nlink == 1
            and st.st_size <= MAX_ANCHOR_BYTES
        ):
            raise _unsafe()
        data = _read_capped(fd, MAX_ANCHOR_BYTES)
    except OSError as e:
        raise _unsafe() from e
    finally:
        os.close(fd)
    if data is None:
        raise _unsafe()
    return _parse_anchor(data)


def _read_capped(fd: int, cap: int) -> bytes | None:
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 8192)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > cap:
            return None
        chunks.append(chunk)


def _normal_absolute(value: object) -> Path | None:
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    if os.path.normpath(value) != value or "//" in value:
        return None
    return Path(value)


def _parse_anchor(data: bytes) -> Anchor:
    try:
        text = data.decode("utf-8")
        loaded = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as e:
        raise _unsafe() from e
    lines = [line for line in text.splitlines() if line.strip()]
    # The sentinel must be the last line, so a write cut short is refused.
    if not lines or lines[-1].strip() != "complete: true":
        raise _unsafe()
    if not isinstance(loaded, dict) or tuple(loaded) != _ANCHOR_KEYS:
        raise _unsafe()
    if loaded["complete"] is not True:
        raise _unsafe()
    account = loaded["account"]
    if not isinstance(account, str) or not _ACCOUNT.match(account):
        raise _unsafe()
    paths = [_normal_absolute(loaded[k]) for k in ("store_path", "config_path", "install_prefix")]
    if any(p is None for p in paths):
        raise _unsafe()
    return Anchor(account, *paths)


# --- running from an installation ------------------------------------------------------


def package_dir() -> Path:
    import brandsentinel

    return Path(brandsentinel.__file__).resolve().parent


def install_record_candidates() -> list[Path]:
    """Where an `INSTALL` record would sit if this code runs from an installation:
    beside `sys.prefix` (the venv), and above the package directory
    (<P>/venv/lib/pythonX.Y/site-packages/brandsentinel -> <P>), which `PYTHONHOME` or
    another interpreter cannot move."""
    out = [Path(sys.prefix).parent / "INSTALL"]
    package = package_dir()
    parents = package.parents
    if (
        len(parents) > 4
        and parents[0].name == "site-packages"
        and parents[1].name.startswith("python")
        and parents[2].name == "lib"
    ):
        out.append(parents[4] / "INSTALL")
    return list(dict.fromkeys(out))


def running_from_installation() -> bool:
    for record in install_record_candidates():
        try:
            st = os.lstat(record)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid == TRUSTED_UID:
            return True
    return False


# --- classification --------------------------------------------------------------------


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _related(path: Path, store: Path) -> bool:
    """Equal to, under, or an ancestor of the store, by path components."""
    return _within(path, store) or store in path.parents or path in store.parents


def _absolute(data_dir: Path) -> Path:
    """The path as the kernel will resolve it: absolute, but '..' is kept, because
    `link/..` is the link target's parent, not the link's directory."""
    return data_dir if data_dir.is_absolute() else Path.cwd() / data_dir


def _inspect_ancestors(path: Path) -> None:
    """The configured path, or its nearest existing ancestor, must be inspectable."""
    for candidate in (path, *path.parents):
        try:
            os.lstat(candidate)
            return
        except FileNotFoundError:
            continue
        except NotADirectoryError:
            continue
        except OSError as e:
            raise StoreRefused(("unclassifiable",)) from e


def _read_marker(directory: Path) -> bool:
    """True for a valid production marker, False for none; anything else raises."""
    try:
        fd = os.open(
            directory / MARKER_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as e:
        raise StoreRefused(("unclassifiable",)) from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MARKER_BYTES:
            raise StoreRefused(("unclassifiable",))
        data = _read_capped(fd, MAX_MARKER_BYTES)
    except OSError as e:
        raise StoreRefused(("unclassifiable",)) from e
    finally:
        os.close(fd)
    try:
        loaded = yaml.safe_load((data or b"").decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as e:
        raise StoreRefused(("unclassifiable",)) from e
    if data is None or loaded != _MARKER:
        raise StoreRefused(("unclassifiable",))
    return True


def classify(data_dir: Path, anchor: Anchor | None) -> Classification:
    """Production or development, before anything under `data_dir` is read (R3-R5)."""
    path = _absolute(data_dir)
    if anchor is not None:
        store = anchor.store_path
        # Lexical: no filesystem call at all. Collapsing '..' here can only add a
        # production verdict, never remove one: every later step uses `path` itself.
        if _related(Path(os.path.normpath(path)), store):
            return Classification(True, "anchor path", str(data_dir) == str(store))
    _inspect_ancestors(path)
    if anchor is not None:
        store = anchor.store_path
        resolved = Path(os.path.realpath(path))
        real_store = Path(os.path.realpath(store))
        if _related(resolved, store) or _related(resolved, real_store):
            return Classification(True, "resolved path", False)
        try:
            live = os.stat(store)
        except OSError:
            live = None  # this caller cannot reach the live store: skip this signal only
        if live is not None:
            try:
                st = os.stat(path)
            except (FileNotFoundError, NotADirectoryError):
                st = None
            except OSError as e:
                raise StoreRefused(("unclassifiable",)) from e
            if st is not None and (st.st_dev, st.st_ino) == (live.st_dev, live.st_ino):
                return Classification(True, "device and inode", False)
    try:
        st = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return Classification(False, "none", False)
    except OSError as e:
        raise StoreRefused(("unclassifiable",)) from e
    if stat.S_ISDIR(st.st_mode) and _read_marker(path):
        return Classification(True, "marker", False)
    return Classification(False, "none", False)


# --- integrity -------------------------------------------------------------------------


def check_integrity(data_dir: Path) -> None:
    """Refuse links the store would write or delete through (R6). Files inside the
    directories are not inspected: the store only creates or unlinks those names."""
    try:
        _check_integrity(data_dir)
    except OSError as e:
        raise StoreRefused(("store_integrity",)) from e


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _check_integrity(data_dir: Path) -> None:
    if _lstat_or_none(data_dir) is None:
        return
    for name in DATABASE_FILES:
        st = _lstat_or_none(data_dir / name)
        if st is not None and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
            raise StoreRefused(("store_integrity",))
    for name in STORE_DIRECTORIES:
        st = _lstat_or_none(data_dir / name)
        if st is not None and not stat.S_ISDIR(st.st_mode):
            raise StoreRefused(("store_integrity",))
    for name in WALKED_DIRECTORIES:
        if _lstat_or_none(data_dir / name) is None:
            continue
        with os.scandir(data_dir / name) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise StoreRefused(("store_integrity",))


# --- the store layer's check -----------------------------------------------------------


def authorization_matches(auth: Authorization, data_dir: Path) -> bool:
    try:
        st = os.stat(data_dir)
    except OSError:
        return False
    return (
        auth.path == os.path.realpath(_absolute(data_dir))
        and (auth.device, auth.inode) == (st.st_dev, st.st_ino)
        and auth.euid == os.geteuid()
    )


def guard_open(data_dir: Path, authorization: Authorization | None) -> Classification:
    """The check `open_store` repeats before it creates or touches anything (R15)."""
    anchor = load_anchor()
    found = classify(data_dir, anchor)
    if found.production:
        if anchor is None:
            raise StoreRefused(("anchor_missing",))
        if not found.canonical:
            raise StoreRefused(("noncanonical_production_store",))
        if authorization is None or not authorization_matches(authorization, data_dir):
            raise StoreRefused(("store_not_authorized",))
    check_integrity(data_dir)
    return found


__all__ = [
    "ANCHOR_PATH",
    "MARKER_NAME",
    "Anchor",
    "Authorization",
    "Classification",
    "StoreRefused",
    "check_integrity",
    "classify",
    "guard_open",
    "load_anchor",
    "running_from_installation",
]
