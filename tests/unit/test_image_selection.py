"""Whether runtime image identity is enforced (B7 U14 selection rule, KTD12 option C).

Plan: docs/plans/2026-11-10-002-chore-b7-production-promotion-plan.md (U14, D1-D4).
`decide` is tested as a pure function over every combination of facts; `select` is
tested on a fake host built under a temporary root (the same anchor chain the identity
tests use), with the account lookup and the user IDs patched. Nothing here reads /etc,
opens a store or talks to Docker.
"""

import inspect
import itertools
import os
import subprocess
import sys
from pathlib import Path

import pytest

from brandsentinel.store import approval, identity, image_selection, policy
from brandsentinel.store.identity import Anchor, StoreRefused
from brandsentinel.store.image_selection import Facts, Selection, SelectionRefused

ME = os.getuid()
ACCOUNT_UID = ME + 4242
OTHER_UID = ME + 4343


def _anchor(store: Path = Path("/var/lib/brandsentinel/data")) -> Anchor:
    return Anchor(
        account="brandsentinel",
        store_path=store,
        config_path=Path("/opt/brandsentinel/config/service.yaml"),
        install_prefix=Path("/opt/brandsentinel"),
    )


def _facts(**overrides) -> Facts:
    base = dict(
        anchor=_anchor(),
        installed=False,
        euid=OTHER_UID,
        ruid=OTHER_UID,
        account_uid=ACCOUNT_UID,
        production=False,
    )
    base.update(overrides)
    return Facts(**base)


def _refused(facts: Facts) -> str:
    with pytest.raises(SelectionRefused) as e:
        image_selection.decide(facts)
    return e.value.check


# --- the decision matrix (pure) --------------------------------------------------------


def _expected(anchor, installed, euid_is_account, ruid_is_account, known, production):
    """The approved rule, written independently of the implementation (D1-D3)."""
    if not anchor:
        if installed or production:
            return "anchor_missing"
        return Selection(False, "development")
    if not known:
        return "anchor_account_unknown"
    if euid_is_account or ruid_is_account:
        return Selection(True, "anchor_account")
    if production:
        return Selection(True, "production_store")
    return Selection(False, "development")


_MATRIX = list(itertools.product([True, False], repeat=6))


@pytest.mark.parametrize(
    ("anchor", "installed", "euid_is_account", "ruid_is_account", "known", "production"),
    _MATRIX,
    ids=["-".join(f"{n}={int(v)}" for n, v in zip("aieukp", row, strict=True)) for row in _MATRIX],
)
def test_the_full_selection_matrix(
    anchor, installed, euid_is_account, ruid_is_account, known, production
):
    account = ACCOUNT_UID if known else None
    facts = _facts(
        anchor=_anchor() if anchor else None,
        installed=installed,
        euid=ACCOUNT_UID if euid_is_account else OTHER_UID,
        ruid=ACCOUNT_UID if ruid_is_account else OTHER_UID,
        account_uid=account if anchor else None,
        production=production,
    )
    expected = _expected(anchor, installed, euid_is_account, ruid_is_account, known, production)
    if isinstance(expected, str):
        assert _refused(facts) == expected
    else:
        assert image_selection.decide(facts) == expected


def test_a_developer_on_a_host_with_an_anchor_and_a_development_store_is_not_enforced():
    assert image_selection.decide(_facts()) == Selection(False, "development")


@pytest.mark.parametrize(("euid", "ruid"), [(ACCOUNT_UID, OTHER_UID), (OTHER_UID, ACCOUNT_UID)])
def test_either_user_id_being_the_account_enforces(euid, ruid):
    """D3: neither identity bypasses enforcement, even on a development store."""
    selection = image_selection.decide(_facts(euid=euid, ruid=ruid))
    assert selection == Selection(True, "anchor_account")


def test_the_account_is_enforced_on_a_development_store():
    selection = image_selection.decide(_facts(euid=ACCOUNT_UID, ruid=ACCOUNT_UID))
    assert selection.enforce


def test_an_unknown_account_is_refused_even_for_a_production_store():
    assert _refused(_facts(account_uid=None, production=True)) == "anchor_account_unknown"


def test_an_unknown_account_is_refused_even_when_a_user_id_could_match():
    """No user ID can be compared with an account that does not exist; refuse, never
    fall through to the store classification."""
    assert _refused(_facts(account_uid=None, euid=ACCOUNT_UID)) == "anchor_account_unknown"


@pytest.mark.parametrize("installed", [True, False])
def test_a_marked_store_without_an_anchor_is_refused(installed):
    assert (
        _refused(_facts(anchor=None, account_uid=None, production=True, installed=installed))
        == "anchor_missing"
    )


def test_an_installation_without_an_anchor_is_refused():
    assert _refused(_facts(anchor=None, account_uid=None, installed=True)) == "anchor_missing"


def test_a_development_host_without_an_anchor_is_not_enforced():
    selection = image_selection.decide(_facts(anchor=None, account_uid=None))
    assert selection == Selection(False, "development")


def test_facts_cannot_name_an_account_without_an_anchor():
    with pytest.raises(ValueError):
        _facts(anchor=None, account_uid=ACCOUNT_UID)


def test_the_decision_is_pure():
    source = inspect.getsource(image_selection.decide)
    for call in ("os.", "identity.", "policy.", "open(", "Path("):
        assert call not in source


def test_the_check_names_are_stable():
    assert SelectionRefused.CHECKS == (
        "anchor_unsafe",
        "anchor_missing",
        "anchor_account_unknown",
        "unclassifiable",
    )
    assert set(SelectionRefused.CHECKS) - {"anchor_account_unknown"} <= set(policy.CHECKS)


# --- gathering the facts on a fake host -------------------------------------------------


class Host:
    """A temporary chain root standing in for `/`, with an anchor slot, an install record
    slot and a store, all built by the test. tests/conftest.py already points the anchor
    and the install records at an empty root; this replaces those with its own."""

    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.tmp_path = tmp_path
        self.root = tmp_path / "root"
        self.anchor_dir = self.root / "etc" / "brandsentinel"
        self.anchor_dir.mkdir(parents=True)
        for d in (self.root, self.root / "etc", self.anchor_dir):
            d.chmod(0o755)
        self.anchor_path = self.anchor_dir / "production.yaml"
        self.store = tmp_path / "srv" / "data"
        self.dev = tmp_path / "dev" / "data"
        self.install_record = tmp_path / "install" / "INSTALL"
        self.mp = monkeypatch
        monkeypatch.setattr(identity, "CHAIN_ROOT", self.root)
        monkeypatch.setattr(identity, "ANCHOR_PATH", self.anchor_path)
        monkeypatch.setattr(identity, "TRUSTED_UID", ME)
        monkeypatch.setattr(identity, "install_record_candidates", lambda: [self.install_record])
        self.users(OTHER_UID, OTHER_UID)
        self.accounts({"brandsentinel": ACCOUNT_UID})

    def write_anchor(self, *, account: str = "brandsentinel") -> None:
        self.anchor_path.write_text(
            f"account: {account}\n"
            f"store_path: {self.store}\n"
            "config_path: /opt/brandsentinel/config/service.yaml\n"
            "install_prefix: /opt/brandsentinel\n"
            "complete: true\n"
        )
        self.anchor_path.chmod(0o644)

    def mark(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / identity.MARKER_NAME).write_text("brandsentinel_store: 1\nclass: production\n")

    def install(self) -> None:
        self.install_record.parent.mkdir(parents=True, exist_ok=True)
        self.install_record.write_text("installed\n")

    def users(self, euid: int, ruid: int) -> None:
        self.mp.setattr(image_selection.os, "geteuid", lambda: euid)
        self.mp.setattr(image_selection.os, "getuid", lambda: ruid)

    def accounts(self, table: dict[str, int]) -> None:
        def lookup(anchor):
            return table.get(anchor.account)

        self.mp.setattr(policy, "account_uid", lookup)


@pytest.fixture
def host(tmp_path, monkeypatch) -> Host:
    return Host(tmp_path, monkeypatch)


def _select_refused(data_dir: Path) -> str:
    with pytest.raises(SelectionRefused) as e:
        image_selection.select(data_dir)
    return e.value.check


def test_no_anchor_and_a_development_store_is_not_enforced(host):
    assert image_selection.select(host.dev) == Selection(False, "development")


def test_no_anchor_on_an_installation_is_refused(host):
    host.install()
    assert _select_refused(host.dev) == "anchor_missing"


def test_no_anchor_and_a_marked_store_is_refused(host):
    host.mark(host.dev)
    assert _select_refused(host.dev) == "anchor_missing"


def test_no_anchor_and_a_marked_ancestor_is_not_production(host):
    """Classification reads the marker in the configured directory only (identity's
    rule); this pins that the selection adds no second detector of its own."""
    host.mark(host.dev.parent)
    assert image_selection.select(host.dev) == Selection(False, "development")


def test_an_unsafe_anchor_is_refused(host):
    host.write_anchor()
    host.anchor_path.chmod(0o666)
    assert _select_refused(host.dev) == "anchor_unsafe"


def test_a_malformed_anchor_is_refused(host):
    host.anchor_path.write_text("account: brandsentinel\n")
    host.anchor_path.chmod(0o644)
    assert _select_refused(host.dev) == "anchor_unsafe"


def test_a_symlinked_anchor_is_refused(host, tmp_path):
    real = tmp_path / "real-anchor.yaml"
    host.write_anchor()
    host.anchor_path.rename(real)
    host.anchor_path.symlink_to(real)
    assert _select_refused(host.dev) == "anchor_unsafe"


def test_an_unknown_account_is_refused_on_the_host(host):
    host.write_anchor(account="nobody-here")
    assert _select_refused(host.dev) == "anchor_account_unknown"


def test_the_policy_account_lookup_returns_none_for_an_unknown_account():
    """The gathering uses the policy's own lookup, unpatched here: an account missing
    from the password database is None there, which the rule refuses."""
    anchor = Anchor(
        account="bs-no-such-account-u14",
        store_path=Path("/var/lib/brandsentinel/data"),
        config_path=Path("/opt/brandsentinel/config/service.yaml"),
        install_prefix=Path("/opt/brandsentinel"),
    )
    assert policy.account_uid(anchor) is None


def test_select_gathers_the_account_through_the_policy_lookup(host):
    host.write_anchor()
    host.accounts({})
    assert _select_refused(host.dev) == "anchor_account_unknown"


@pytest.mark.parametrize(
    ("euid", "ruid", "expected"),
    [
        (ACCOUNT_UID, ACCOUNT_UID, Selection(True, "anchor_account")),
        (ACCOUNT_UID, OTHER_UID, Selection(True, "anchor_account")),
        (OTHER_UID, ACCOUNT_UID, Selection(True, "anchor_account")),
        (OTHER_UID, OTHER_UID, Selection(False, "development")),
    ],
)
def test_user_ids_on_a_development_store(host, euid, ruid, expected):
    host.write_anchor()
    host.users(euid, ruid)
    assert image_selection.select(host.dev) == expected


def test_the_anchor_store_path_is_production(host):
    host.write_anchor()
    assert image_selection.select(host.store) == Selection(True, "production_store")


def test_a_path_under_the_anchor_store_is_production(host):
    host.write_anchor()
    assert image_selection.select(host.store / "sub") == Selection(True, "production_store")


def test_a_symlink_to_the_anchor_store_is_production(host, tmp_path):
    host.write_anchor()
    host.store.mkdir(parents=True)
    link = tmp_path / "alias"
    link.symlink_to(host.store)
    assert image_selection.select(link) == Selection(True, "production_store")


def test_a_marked_copy_elsewhere_is_production_with_an_anchor(host):
    host.write_anchor()
    host.mark(host.dev)
    assert image_selection.select(host.dev) == Selection(True, "production_store")


def test_an_unclassifiable_marker_is_refused(host):
    host.write_anchor()
    host.dev.mkdir(parents=True)
    (host.dev / identity.MARKER_NAME).write_text("not: a marker\n")
    assert _select_refused(host.dev) == "unclassifiable"


def test_an_unclassifiable_marker_is_refused_without_an_anchor(host):
    host.dev.mkdir(parents=True)
    (host.dev / identity.MARKER_NAME).write_text("not: a marker\n")
    assert _select_refused(host.dev) == "unclassifiable"


def test_an_uninspectable_store_path_is_refused(host, monkeypatch):
    host.write_anchor()
    real_lstat = os.lstat

    def denied(path, *a, **k):
        if Path(path) == host.dev:
            raise PermissionError(13, "denied")
        return real_lstat(path, *a, **k)

    monkeypatch.setattr(identity.os, "lstat", denied)
    assert _select_refused(host.dev) == "unclassifiable"


def test_a_lost_working_directory_is_unclassifiable_not_development(host, monkeypatch):
    def gone():
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(identity.Path, "cwd", staticmethod(gone))
    assert _select_refused(Path("relative/data")) == "unclassifiable"


def test_the_account_is_enforced_even_when_its_store_cannot_be_classified(host):
    """The account is enforced on any store; an unclassifiable store is still refused,
    which disables sandbox stages rather than running them unchecked."""
    host.write_anchor()
    host.users(ACCOUNT_UID, ACCOUNT_UID)
    host.dev.mkdir(parents=True)
    (host.dev / identity.MARKER_NAME).write_text("not: a marker\n")
    assert _select_refused(host.dev) == "unclassifiable"


def test_selection_refusals_carry_the_check_only(host):
    host.write_anchor()
    host.anchor_path.chmod(0o666)
    with pytest.raises(SelectionRefused) as e:
        image_selection.select(host.dev)
    assert str(e.value) == e.value.check == "anchor_unsafe"
    assert e.value.__cause__ is None
    assert e.value.__context__ is None or e.value.__suppress_context__
    assert str(host.root) not in repr(e.value)


def test_an_os_error_reading_the_anchor_is_unsafe(host, monkeypatch):
    def broken():
        raise OSError(5, "I/O error")

    monkeypatch.setattr(identity, "load_anchor", broken)
    assert _select_refused(host.dev) == "anchor_unsafe"


def test_a_nul_byte_in_the_data_dir_is_unclassifiable(host):
    host.write_anchor()
    assert _select_refused(host.tmp_path / "da\x00ta") == "unclassifiable"


def test_a_symlink_loop_while_detecting_the_installation_is_unclassifiable(host, monkeypatch):
    def loop():
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(identity, "running_from_installation", loop)
    assert _select_refused(host.dev) == "unclassifiable"


@pytest.mark.parametrize("error", [OSError(5, "I/O error"), ValueError("embedded null")])
def test_a_failing_account_lookup_is_an_unknown_account(host, monkeypatch, error):
    host.write_anchor()

    def failing(anchor):
        raise error

    monkeypatch.setattr(policy, "account_uid", failing)
    assert _select_refused(host.dev) == "anchor_account_unknown"


def test_a_store_refusal_never_escapes_unnamed(host, monkeypatch):
    def boom(*a, **k):
        raise StoreRefused(("store_integrity",))

    monkeypatch.setattr(identity, "classify", boom)
    assert _select_refused(host.dev) == "unclassifiable"


# --- no side effects --------------------------------------------------------------------


def _tree(root: Path) -> dict[str, tuple[int, int, int]]:
    out = {}
    for path in sorted(root.rglob("*")):
        st = os.lstat(path)
        out[str(path)] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return out


@pytest.mark.parametrize("marked", [False, True])
def test_selection_changes_nothing_and_opens_no_store(host, monkeypatch, tmp_path, marked):
    host.write_anchor()
    host.dev.mkdir(parents=True)
    if marked:
        host.mark(host.dev)
    before = _tree(tmp_path)

    def no_store(*a, **k):
        raise AssertionError("a store was opened")

    import brandsentinel.store as store_pkg

    monkeypatch.setattr(store_pkg, "open_store", no_store)
    monkeypatch.setattr(identity, "check_integrity", no_store)
    image_selection.select(host.dev)
    assert _tree(tmp_path) == before
    assert not (host.dev / "brandsentinel.db").exists()


def test_selection_does_not_create_a_missing_data_dir(host):
    host.write_anchor()
    image_selection.select(host.dev)
    assert not host.dev.exists()


def test_the_module_uses_no_docker_and_no_environment():
    source = inspect.getsource(image_selection)
    for word in ("docker", "subprocess", "os.environ", "environ[", "getenv", "open_store"):
        assert word not in source


# --- the approval record stays put ------------------------------------------------------


def test_no_environment_variable_moves_the_approval_record(tmp_path):
    """A fresh interpreter with plausible variables set still names the fixed path."""
    env = {**os.environ}
    for name in (
        "BRANDSENTINEL_APPROVAL",
        "BRANDSENTINEL_IMAGE_APPROVAL",
        "BRANDSENTINEL_APPROVAL_PATH",
        "BRANDSENTINEL_ETC",
        "BRANDSENTINEL_CONFIG",
        "BRANDSENTINEL_DATA_DIR",
    ):
        env[name] = str(tmp_path / "elsewhere.yaml")
    code = (
        "from brandsentinel.store import approval;"
        "print(approval.APPROVAL_PATH, approval.CHAIN_ROOT, approval.TRUSTED_UID)"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv built by the test
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.split() == ["/etc/brandsentinel/image-approval.yaml", "/", "0"]


def test_the_suite_never_reads_the_host_approval_record():
    """tests/conftest.py points the record at an empty root for every test, as it does
    for the anchor; an unpatched read therefore finds nothing."""
    assert Path("/etc/brandsentinel/image-approval.yaml") != approval.APPROVAL_PATH
    assert Path("/") != approval.CHAIN_ROOT
    assert approval.load_approval() is None
