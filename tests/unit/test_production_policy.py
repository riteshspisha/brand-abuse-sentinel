"""The production policy and the single configuration read (B3 U2: R7-R11, R16).

The policy is a pure function over facts; `gather` collects those facts. Root ownership
is simulated by patching the trusted UID to the test's own UID.
"""

import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from brandsentinel.config import Config, ConfigError, load_config, load_config_once
from brandsentinel.store import identity, policy
from brandsentinel.store.identity import Anchor

REPO = Path(__file__).resolve().parents[2]
ME = os.getuid()


def _stat(mode: int, uid: int = 0, nlink: int = 1) -> os.stat_result:
    return os.stat_result((mode, 1, 1, nlink, uid, 0, 10, 0, 0, 0))


REG = stat.S_IFREG | 0o644
DIR = stat.S_IFDIR | 0o755


@pytest.fixture(autouse=True)
def _root_is_trusted(monkeypatch):
    """The facts below use UID 0 as the owner of root-owned files, as on a real host."""
    monkeypatch.setattr(identity, "TRUSTED_UID", 0)


@pytest.fixture
def anchor() -> Anchor:
    return Anchor(
        account="svc",
        store_path=Path("/var/lib/svc/data"),
        config_path=Path("/opt/bs/etc/service.yaml"),
        install_prefix=Path("/opt/bs"),
    )


def _config(**over) -> Config:
    data = {
        "data_dir": "/var/lib/svc/data",
        "registry_path": "/opt/bs/src/registry/brands.yaml",
        "discovery": {"dnstwist": {"dictionary": "/opt/bs/src/registry/d.dict"}},
        "analysis": {
            "payment_providers": "/opt/bs/src/config/payment_providers.yaml",
            "policy": "/opt/bs/src/config/policy.yaml",
        },
    }
    data.update(over)
    return Config.model_validate(data)


@pytest.fixture
def facts(anchor) -> policy.Facts:
    """Everything right: the approved invocation by the account on the live store."""
    return policy.Facts(
        anchor=anchor,
        config=_config(),
        source=policy.ConfigSourceFacts(
            given="/opt/bs/etc/service.yaml",
            option=True,
            st=_stat(REG),
            symlink_free=True,
            parent=_stat(DIR),
        ),
        env={},
        euid=1001,
        ruid=1001,
        account_uid=1001,
        account_ok=True,
        account_warned=False,
        package_dir=Path("/opt/bs/venv/lib/python3.12/site-packages/brandsentinel"),
        sys_path=[Path("/opt/bs/venv/bin"), Path("/opt/bs/python/cpython/lib/python3.12")],
        prefix=Path("/opt/bs"),
        store=_stat(stat.S_IFDIR | 0o700, uid=1001),
    )


def test_the_approved_invocation_passes(facts):
    assert policy.evaluate(facts) == []


@pytest.mark.parametrize(
    "change, check",
    [
        (dict(euid=1002, ruid=1002), "wrong_account"),
        (dict(ruid=1002), "wrong_account"),
        (dict(account_uid=None), "wrong_account"),
        (dict(account_ok=False), "account_checks"),
        (dict(account_warned=True), "account_checks"),
        (dict(env={"BRANDSENTINEL_CONFIG": "/opt/bs/etc/service.yaml"}), "store_env_set"),
        (dict(env={"BRANDSENTINEL_DATA_DIR": "/var/lib/svc/data"}), "store_env_set"),
        (dict(env={"PYTHONPATH": "/tmp/x"}), "python_env_set"),
        (dict(env={"PYTHONHOME": "/x"}), "python_env_set"),
        (dict(env={"PYTHONUSERBASE": "/x"}), "python_env_set"),
        (dict(env={"PYTHONSTARTUP": "/x"}), "python_env_set"),
        (dict(sys_path=[Path("/opt/bs/venv/bin"), Path("/tmp/writable")]), "python_env_set"),
        (dict(package_dir=Path("/home/dev/checkout/src/brandsentinel")), "code_not_installed"),
        (dict(package_dir=Path("/opt/bs/src/src/brandsentinel")), "code_not_installed"),
        (
            dict(
                package_dir=Path("/opt/bs.prev-x/venv/lib/python3.12/site-packages/brandsentinel")
            ),
            "code_not_installed",
        ),
        (dict(store=None), "store_missing"),
        (dict(store=_stat(stat.S_IFDIR | 0o700, uid=1002)), "store_owner"),
    ],
)
def test_each_check_fails_alone(facts, change, check):
    assert policy.evaluate(replace(facts, **change)) == [check]


@pytest.mark.parametrize(
    "source, check",
    [
        (dict(option=False), "config_source"),
        (dict(symlink_free=False), "config_symlink"),
        (dict(st=_stat(stat.S_IFIFO | 0o644)), "config_not_regular"),
        (dict(st=_stat(stat.S_IFDIR | 0o755)), "config_not_regular"),
        (dict(parent=_stat(DIR, uid=1001)), "config_not_root_owned"),
        (dict(parent=None), "config_not_root_owned"),
        (dict(st=_stat(stat.S_IFREG | 0o664)), "config_writable"),
        (dict(st=_stat(stat.S_IFREG | 0o646)), "config_writable"),
        (dict(parent=_stat(stat.S_IFDIR | 0o775)), "config_writable"),
    ],
)
def test_each_source_check_fails_alone(facts, source, check):
    assert policy.evaluate(replace(facts, source=replace(facts.source, **source))) == [check]


@pytest.mark.parametrize(
    "given, checks",
    [
        ("etc/service.yaml", ["config_not_absolute", "config_not_approved"]),
        ("/opt/bs/etc/../etc/service.yaml", ["config_not_normal", "config_not_approved"]),
        ("/opt/bs//etc/service.yaml", ["config_not_normal", "config_not_approved"]),
    ],
)
def test_another_spelling_of_the_approved_path_is_refused(facts, given, checks):
    assert policy.evaluate(replace(facts, source=replace(facts.source, given=given))) == checks


def test_a_config_owned_by_the_account_is_neither_root_owned_nor_safe(facts):
    owned = replace(facts.source, st=_stat(REG, uid=1001))
    assert policy.evaluate(replace(facts, source=owned)) == [
        "config_not_root_owned",
        "config_writable",
    ]


def test_another_absolute_config_is_not_approved(facts):
    moved = replace(facts.source, given="/var/lib/svc/service.yaml")
    assert policy.evaluate(replace(facts, source=moved)) == ["config_not_approved"]


def test_no_configuration_file_is_a_source_failure(facts):
    assert policy.evaluate(replace(facts, source=None)) == ["config_source"]


def test_the_developer_override_is_refused(facts):
    config = _config(runtime={"allow_developer_account": True})
    assert policy.evaluate(replace(facts, config=config)) == ["developer_override"]


@pytest.mark.parametrize(
    "over",
    [
        {"registry_path": "registry/brands.yaml"},
        {"discovery": {"dnstwist": {"dictionary": "registry/d.dict"}}},
        {"analysis": {"payment_providers": "x.yaml", "policy": "/opt/bs/src/config/policy.yaml"}},
        {"analysis": {"payment_providers": "/x.yaml", "policy": "config/policy.yaml"}},
    ],
)
def test_relative_production_paths_are_refused(facts, over):
    assert policy.evaluate(replace(facts, config=_config(**over))) == ["path_not_absolute"]


def test_the_lab_overlay_counts_only_in_lab_mode(facts):
    lab = _config(
        net={"lab": {"enabled": True}},
        sandbox={"enabled": False},
        discovery={
            "certstream": {"enabled": False},
            "dnstwist": {"enabled": False, "dictionary": "/opt/bs/src/registry/d.dict"},
        },
    )
    assert policy.evaluate(replace(facts, config=lab)) == ["path_not_absolute"]


def test_the_committed_service_configuration_passes_the_path_rule(facts):
    """Its inherited relative lab-overlay default is ignored while lab mode is off."""
    service = load_config(REPO / "config" / "service.yaml")
    assert policy.path_failures(service) == []


def test_failures_are_all_reported_in_a_stable_order(facts):
    bad = replace(
        facts,
        euid=1002,
        ruid=1002,
        env={"PYTHONPATH": "/x", "BRANDSENTINEL_DATA_DIR": "/y"},
        source=replace(facts.source, given="etc/service.yaml"),
        config=_config(runtime={"allow_developer_account": True}),
    )
    first = policy.evaluate(bad)
    assert first == policy.evaluate(bad)
    assert first == sorted(first, key=policy.CHECKS.index)
    assert set(first) >= {
        "wrong_account",
        "developer_override",
        "config_not_absolute",
        "store_env_set",
        "python_env_set",
    }


def test_a_wrong_account_gives_no_store_checks(facts):
    """The store is not inspected for a wrong account (it may be an unreadable home)."""
    bad = replace(facts, euid=1002, ruid=1002, store=None)
    assert "store_missing" not in policy.evaluate(bad)


def test_every_check_name_is_known():
    assert len(set(policy.CHECKS)) == len(policy.CHECKS)
    assert all(name.isidentifier() for name in policy.CHECKS)


# --- gathering facts -------------------------------------------------------------------


def test_gather_reads_the_account_by_name(monkeypatch, anchor):
    import pwd

    class Entry:
        pw_uid = 4242

    monkeypatch.setattr(pwd, "getpwnam", lambda name: Entry() if name == "svc" else None)
    assert policy.account_uid(anchor) == 4242


def test_an_unknown_account_has_no_uid(monkeypatch, anchor):
    import pwd

    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(pwd, "getpwnam", missing)
    assert policy.account_uid(anchor) is None


def test_sys_path_entries_are_resolved_and_missing_ones_skipped(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    got = policy.resolved_sys_path([str(link), str(tmp_path / "absent"), ""], cwd=tmp_path)
    assert got == [real, tmp_path.resolve()]


# --- the single configuration read -----------------------------------------------------


def _write(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("name", ["lab.yaml", "service.yaml", "brandsentinel.example.yaml"])
def test_the_single_read_parses_like_load_config(name, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    path = REPO / "config" / name
    config, source = load_config_once(path)
    assert config == load_config(path)
    assert source.option and source.given == str(path)
    assert stat.S_ISREG(source.st.st_mode)


def test_the_environment_variable_source_is_recorded(monkeypatch, tmp_path):
    path = _write(tmp_path / "c.yaml", {"data_dir": str(tmp_path / "s")})
    monkeypatch.setenv("BRANDSENTINEL_CONFIG", str(path))
    config, source = load_config_once(None)
    assert config.data_dir == tmp_path / "s"
    assert not source.option


def test_a_data_dir_variable_alone_has_no_source(monkeypatch, tmp_path):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "s"))
    config, source = load_config_once(None)
    assert config.data_dir == tmp_path / "s" and source is None


def test_a_symlinked_development_config_loads_as_today(tmp_path):
    real = _write(tmp_path / "real.yaml", {"data_dir": str(tmp_path / "s")})
    link = tmp_path / "link.yaml"
    link.symlink_to(real)
    config, source = load_config_once(link)
    assert config == load_config(link)
    assert not source.symlink_free


def test_a_symlinked_directory_component_is_recorded(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    _write(real / "c.yaml", {})
    (tmp_path / "via").symlink_to(real)
    _config, source = load_config_once(tmp_path / "via" / "c.yaml")
    assert not source.symlink_free


def test_a_plain_path_is_symlink_free(tmp_path):
    _config, source = load_config_once(_write(tmp_path / "c.yaml", {}))
    assert source.symlink_free
    assert stat.S_ISDIR(source.parent.st_mode)


def test_a_fifo_with_a_writer_loads_as_today(tmp_path):
    import threading

    fifo = tmp_path / "pipe.yaml"
    os.mkfifo(fifo)
    body = yaml.safe_dump({"data_dir": str(tmp_path / "s")}).encode()

    def writer():
        with open(fifo, "wb") as f:
            f.write(body)

    t = threading.Thread(target=writer)
    t.start()
    config, source = load_config_once(fifo)
    t.join(5)
    assert config.data_dir == tmp_path / "s"
    assert stat.S_ISFIFO(source.st.st_mode)


def test_the_file_that_was_opened_is_the_one_parsed(tmp_path, monkeypatch):
    """M8: a rename over the path after it was opened is never read."""
    path = _write(tmp_path / "c.yaml", {"data_dir": "/first"})
    other = _write(tmp_path / "other.yaml", {"data_dir": "/second"})
    import brandsentinel.config as config_module

    real_fstat = os.fstat

    def fstat_then_replace(fd):
        result = real_fstat(fd)
        if other.exists():
            os.replace(other, path)
        return result

    monkeypatch.setattr(config_module.os, "fstat", fstat_then_replace)
    config, _source = load_config_once(path)
    assert config.data_dir == Path("/first")


@pytest.mark.parametrize("body", ["{ not: [yaml", "- a\n", "unknown_key: 1\n"])
def test_bad_files_fail_as_load_config_does(body, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(body)
    with pytest.raises(ConfigError) as single:
        load_config_once(path)
    with pytest.raises(ConfigError) as old:
        load_config(path)
    assert str(single.value) == str(old.value)


def test_a_missing_file_fails_as_load_config_does(tmp_path):
    with pytest.raises(ConfigError):
        load_config_once(tmp_path / "missing.yaml")


def test_a_directory_fails_as_load_config_does(tmp_path):
    with pytest.raises(ConfigError):
        load_config_once(tmp_path)


def test_unknown_variables_are_still_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("BRANDSENTINEL_NETWORK", "x")
    with pytest.raises(ConfigError):
        load_config_once(_write(tmp_path / "c.yaml", {}))


# --- the whole decision (authorize) ----------------------------------------------------


def test_identity_helpers_are_shared_with_the_policy():
    assert policy.StoreRefused is identity.StoreRefused


def test_the_configuration_is_opened_exactly_once(tmp_path, monkeypatch):
    """Review finding: a non-blocking open, close and blocking reopen of a FIFO could
    close a descriptor twice, or lose the FIFO's writer and hang. One open only."""
    import brandsentinel.config as config_module

    path = _write(tmp_path / "c.yaml", {})
    fifo = tmp_path / "pipe.yaml"
    os.mkfifo(fifo)
    real_open = os.open
    opened = []

    def counting_open(p, flags, *args):
        opened.append(str(p))
        return real_open(p, flags, *args)

    monkeypatch.setattr(config_module.os, "open", counting_open)
    load_config_once(path)
    assert opened == [str(path)]

    import threading

    t = threading.Thread(target=lambda: fifo.write_bytes(b"{}\n"))
    t.start()
    load_config_once(fifo)
    t.join(5)
    assert not t.is_alive()
    assert opened == [str(path), str(fifo)]


def test_an_unreadable_sys_path_entry_is_kept_unresolved(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    (blocked / "inner").mkdir(parents=True)
    blocked.chmod(0)
    try:
        got = policy.resolved_sys_path([str(blocked / "inner")], cwd=tmp_path)
    finally:
        blocked.chmod(0o700)
    assert got == [blocked / "inner"]
