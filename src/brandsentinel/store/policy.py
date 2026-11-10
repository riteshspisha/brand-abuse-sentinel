"""The production policy (B3 R7-R11) and the CLI's whole decision before a store opens.

Plan: docs/plans/2026-11-10-001-feat-b3-production-store-enforcement-plan.md.

`evaluate` is a pure function over `Facts`. `authorize` gathers the facts, runs the
anchor, classification, canonical-location, policy and integrity checks in the plan's
order (R14), and returns what `open_store` needs, or raises `StoreRefused` naming every
failed check. These are accident controls for the authorized account and fail-closed
refusals for everyone else; they are not a boundary against a deliberate account or
root (see docs/concepts/security.md).
"""

import os
import pwd
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from brandsentinel.config import ENV_CONFIG, ENV_DATA_DIR, Config, ConfigSourceFacts
from brandsentinel.store import identity
from brandsentinel.store.identity import (
    Anchor,
    Authorization,
    Classification,
    StoreRefused,
)

# Every check name, in the order refusals list them.
CHECKS = (
    "anchor_unsafe",
    "anchor_missing",
    "unclassifiable",
    "noncanonical_production_store",
    "wrong_account",
    "store_owner",
    "account_checks",
    "developer_override",
    "config_source",
    "config_not_absolute",
    "config_not_normal",
    "config_symlink",
    "config_not_regular",
    "config_not_root_owned",
    "config_writable",
    "config_not_approved",
    "path_not_absolute",
    "store_env_set",
    "code_not_installed",
    "python_env_set",
    "store_missing",
    "store_integrity",
    "store_not_authorized",
)
PYTHON_VARIABLES = ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP")

__all__ = ["CHECKS", "ConfigSourceFacts", "Decision", "Facts", "StoreRefused", "authorize"]


@dataclass(frozen=True)
class Facts:
    anchor: Anchor
    config: Config
    source: ConfigSourceFacts | None
    env: Mapping[str, str]
    euid: int
    ruid: int
    account_uid: int | None
    account_ok: bool  # check_account found no failure
    account_warned: bool  # ... and no warning (the developer override)
    package_dir: Path  # resolved
    sys_path: Sequence[Path]  # resolved, existing entries
    prefix: Path  # the anchor's install prefix, resolved
    store: os.stat_result | None  # stat of the store directory; None if missing


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _writable_by_others(st: os.stat_result) -> bool:
    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def path_failures(config: Config) -> list[str]:
    """R10: the paths a production run uses are absolute."""
    paths = [
        config.data_dir,
        config.registry_path,
        config.analysis.payment_providers,
        config.analysis.policy,
    ]
    if config.discovery.dnstwist.dictionary is not None:
        paths.append(config.discovery.dnstwist.dictionary)
    if config.net.lab.enabled:
        paths.append(config.net.lab.registry_overlay)
    return [] if all(p.is_absolute() for p in paths) else ["path_not_absolute"]


def _source_failures(f: Facts) -> list[str]:
    s = f.source
    if s is None or not s.option:
        return ["config_source"]
    out = []
    if not s.given.startswith("/"):
        out.append("config_not_absolute")
    if os.path.normpath(s.given) != s.given or "//" in s.given:
        out.append("config_not_normal")
    if not s.symlink_free:
        out.append("config_symlink")
    if not stat.S_ISREG(s.st.st_mode):
        out.append("config_not_regular")
    if (
        s.st.st_uid != identity.TRUSTED_UID
        or s.parent is None
        or not stat.S_ISDIR(s.parent.st_mode)
        or s.parent.st_uid != identity.TRUSTED_UID
    ):
        out.append("config_not_root_owned")
    if (
        _writable_by_others(s.st)
        or (s.parent is not None and _writable_by_others(s.parent))
        or (s.st.st_uid == f.euid and s.st.st_mode & stat.S_IWUSR)
    ):
        out.append("config_writable")
    if s.given != str(f.anchor.config_path):
        out.append("config_not_approved")
    return out


def evaluate(f: Facts) -> list[str]:
    """Every failed production check, in CHECKS order; empty when the policy passes."""
    out: list[str] = []
    account_right = f.account_uid is not None and f.euid == f.ruid == f.account_uid
    if not account_right:
        out.append("wrong_account")
    elif f.store is not None and f.store.st_uid != f.account_uid:
        out.append("store_owner")
    if not f.account_ok or f.account_warned:
        out.append("account_checks")
    if f.config.runtime.allow_developer_account:
        out.append("developer_override")
    out += _source_failures(f)
    out += path_failures(f.config)
    if f.env.get(ENV_CONFIG) or f.env.get(ENV_DATA_DIR):
        out.append("store_env_set")
    if not _under(f.package_dir, f.prefix / "venv"):
        out.append("code_not_installed")
    if any(f.env.get(v) for v in PYTHON_VARIABLES) or not all(
        _under(p, f.prefix) for p in f.sys_path
    ):
        out.append("python_env_set")
    # The store itself is looked at only for the right account: for anyone else it is
    # an unreadable home, and the refusal must not depend on searching it.
    if account_right and f.store is None:
        out.append("store_missing")
    return sorted(set(out), key=CHECKS.index)


# --- gathering facts -------------------------------------------------------------------


def account_uid(anchor: Anchor) -> int | None:
    try:
        return pwd.getpwnam(anchor.account).pw_uid
    except KeyError:
        return None


def resolved_sys_path(entries: Sequence[str], *, cwd: Path) -> list[Path]:
    out = []
    for entry in entries:
        path = Path(entry) if entry else cwd
        if not path.is_absolute():
            path = cwd / path
        if path.exists():
            out.append(path.resolve())
    return out


@dataclass(frozen=True)
class Decision:
    classification: Classification
    authorization: Authorization | None  # None for a development store


def _refuse(checks: list[str]) -> StoreRefused:
    return StoreRefused(tuple(sorted(set(checks), key=CHECKS.index)))


def authorize(config: Config, source: ConfigSourceFacts | None) -> Decision:
    """The CLI's decision for a store command (R14). Raises StoreRefused."""
    from brandsentinel.sandbox import preflight

    anchor = identity.load_anchor()
    if anchor is None and identity.running_from_installation():
        raise _refuse(["anchor_missing"])  # an installation whose anchor is gone (R2)
    found = identity.classify(config.data_dir, anchor)
    if not found.production:
        identity.check_integrity(config.data_dir)
        return Decision(found, None)
    if anchor is None:
        raise _refuse(["anchor_missing"])
    if not found.canonical:
        raise _refuse(["noncanonical_production_store"])

    uid = account_uid(anchor)
    euid, ruid = os.geteuid(), os.getuid()
    account_right = uid is not None and euid == ruid == uid
    store_stat = None
    if account_right:
        try:
            store_stat = os.stat(anchor.store_path)
        except FileNotFoundError:
            store_stat = None
        except OSError as e:
            raise _refuse(["unclassifiable"]) from e
    report = preflight.check_account(config)
    cwd = Path.cwd()
    facts = Facts(
        anchor=anchor,
        config=config,
        source=source,
        env=dict(os.environ),
        euid=euid,
        ruid=ruid,
        account_uid=uid,
        account_ok=report.ok,
        account_warned=bool(report.warnings),
        package_dir=identity._package_dir(),
        sys_path=resolved_sys_path(sys.path, cwd=cwd),
        prefix=anchor.install_prefix.resolve(),
        store=store_stat,
    )
    failures = evaluate(facts)
    if account_right and store_stat is not None:
        try:
            identity.check_integrity(anchor.store_path)
        except StoreRefused:
            failures.append("store_integrity")
    if failures:
        raise _refuse(failures)
    real = os.path.realpath(anchor.store_path)
    return Decision(
        found,
        Authorization(real, store_stat.st_dev, store_stat.st_ino, euid),
    )
