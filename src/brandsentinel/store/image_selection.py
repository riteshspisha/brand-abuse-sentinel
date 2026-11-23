"""Whether runtime image identity is enforced on this host (B7 U14, KTD12 option C).

Plan: docs/plans/2026-11-10-002-chore-b7-production-promotion-plan.md (U14, D1-D4).

Enforcement means that sandbox stages and the browser gate run only on the image ID
named by the root-owned approval record (`store/approval.py`). This module only decides
whether that applies; nothing here reads the record, talks to Docker, opens a store or
changes a file. Later steps call it once per run: the sandbox preflight and runner, and
U13's scripts through the installed interpreter (`-I -B`), so every caller selects by
the same rule.

The rule (`decide`, a pure function):
- **An anchor exists.** Its account must exist on the host (D2), else
  `anchor_account_unknown`. Enforce when the effective **or** the real user ID is the
  account's (D3), whatever the store; otherwise enforce when `identity.classify` says the
  configured `data_dir` is production.
- **No anchor.** Refuse (`anchor_missing`) when this code runs from an installation or
  the configured `data_dir` classifies as production, for example by its marker (D1).
  Otherwise this is a development host: do not enforce.
- **Unknown states are never development.** An unsafe anchor (`anchor_unsafe`) or a
  store that cannot be classified (`unclassifiable`) is refused; the caller disables
  sandbox stages.

Production is detected only by the existing helpers (`identity.load_anchor`,
`identity.running_from_installation`, `identity.classify`, `policy.account_uid`); there
is no second detector here. Selecting enforcement authorizes nothing: opening the
production store still needs `policy.authorize`, which requires both user IDs to be the
account's.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from brandsentinel.store import identity, policy
from brandsentinel.store.identity import Anchor, StoreRefused


class SelectionRefused(Exception):
    """Whether to enforce cannot be decided safely. `check` is a stable name; no path,
    account name or value is kept, and the underlying error is not chained."""

    ANCHOR_UNSAFE = "anchor_unsafe"
    ANCHOR_MISSING = "anchor_missing"
    ACCOUNT_UNKNOWN = "anchor_account_unknown"
    UNCLASSIFIABLE = "unclassifiable"
    CHECKS = (ANCHOR_UNSAFE, ANCHOR_MISSING, ACCOUNT_UNKNOWN, UNCLASSIFIABLE)

    def __init__(self, check: str) -> None:
        super().__init__(check)
        self.check = check


@dataclass(frozen=True)
class Selection:
    enforce: bool
    reason: str  # "anchor_account", "production_store" or "development"


@dataclass(frozen=True)
class Facts:
    anchor: Anchor | None
    installed: bool  # this code runs from an installation (an `INSTALL` record)
    euid: int
    ruid: int
    account_uid: int | None  # the anchor account's UID; None if unknown or no anchor
    production: bool  # identity.classify(data_dir, anchor).production

    def __post_init__(self) -> None:
        if self.anchor is None and self.account_uid is not None:
            raise ValueError("an account UID needs an anchor")


def decide(facts: Facts) -> Selection:
    """The rule over gathered facts. Raises SelectionRefused."""
    if facts.anchor is None:
        if facts.installed or facts.production:
            raise SelectionRefused(SelectionRefused.ANCHOR_MISSING)
        return Selection(False, "development")
    if facts.account_uid is None:
        raise SelectionRefused(SelectionRefused.ACCOUNT_UNKNOWN)
    if facts.account_uid in (facts.euid, facts.ruid):
        return Selection(True, "anchor_account")
    if facts.production:
        return Selection(True, "production_store")
    return Selection(False, "development")


def gather(data_dir: Path) -> Facts:
    """The host facts for a configured `data_dir`, reading only the anchor, the install
    records and the metadata `identity.classify` reads. Raises SelectionRefused."""
    try:
        anchor = identity.load_anchor()
    except StoreRefused:
        raise SelectionRefused(SelectionRefused.ANCHOR_UNSAFE) from None
    except OSError:
        raise SelectionRefused(SelectionRefused.ANCHOR_UNSAFE) from None
    try:
        installed = anchor is None and identity.running_from_installation()
        production = identity.classify(data_dir, anchor).production
    except (StoreRefused, OSError, ValueError, RuntimeError):
        # ValueError: a NUL byte in the path; RuntimeError: a symlink loop on resolve.
        raise SelectionRefused(SelectionRefused.UNCLASSIFIABLE) from None
    try:
        account = None if anchor is None else policy.account_uid(anchor)
    except (OSError, ValueError):
        # The password database could not answer: the account is not known.
        raise SelectionRefused(SelectionRefused.ACCOUNT_UNKNOWN) from None
    return Facts(
        anchor=anchor,
        installed=installed,
        euid=os.geteuid(),
        ruid=os.getuid(),
        account_uid=account,
        production=production,
    )


def select(data_dir: Path) -> Selection:
    """Whether image identity is enforced for a run configured with `data_dir`. Callers
    resolve once per run. Raises SelectionRefused, which disables sandbox stages."""
    return decide(gather(data_dir))
