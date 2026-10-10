from pathlib import Path

import pytest
from typer.testing import CliRunner

from brandsentinel.cli import app

runner = CliRunner()
REPO = Path(__file__).parents[2]


@pytest.fixture(autouse=True)
def _repo_cwd(monkeypatch):
    # The default registry and legacy paths are relative to the repository root.
    monkeypatch.chdir(REPO)


COMMANDS = [
    "run",
    "submit",
    "status",
    "analyze",
    "cases",
    "report",
    "export",
    "registry",
    "sandbox",
    "proxy",
    "eval",
]


def test_help_lists_every_registered_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in COMMANDS:
        assert name in result.output


@pytest.mark.parametrize("name", ["eval"])
def test_planned_commands_exit_non_zero_with_milestone(name):
    result = runner.invoke(app, [name, "--anything", "x"])
    assert result.exit_code == 2
    assert "not implemented yet" in result.output


def test_status_on_empty_store(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "schema v4" in result.output
    assert "jobs: none" in result.output
    assert "artifacts: 0 blobs" in result.output
    assert "firehose off" in result.output
    assert (tmp_path / "data" / "brandsentinel.db").exists()


def test_status_escapes_untrusted_job_errors(tmp_path, monkeypatch):
    from brandsentinel.config import Config
    from brandsentinel.store import open_store

    data = tmp_path / "data"
    store = open_store(Config(data_dir=data))
    job_id, _ = store.jobs.enqueue("fetch", {}, max_attempts=1)
    # The job queue sanitizes on write; this simulates a pre-existing raw value.
    store.jobs.fail(store.jobs.claim("fetch", "w", 60), "boom")
    store.conn.execute("UPDATE jobs SET last_error = ? WHERE id = ?", ("x\x1b]0;t\x07", job_id))
    store.close()

    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(data))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "\\x1b]0;t\\x07" in result.output


def test_invalid_config_exits_2(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("nope: 1\n")
    result = runner.invoke(app, ["--config", str(bad), "status"])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_status_warns_when_store_is_in_reserve(tmp_path):
    from brandsentinel.config import ArtifactQuotas, Config
    from brandsentinel.store import open_store
    from brandsentinel.store.records import create_case, upsert_candidate

    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"data_dir: {tmp_path / 'data'}\n"
        "artifacts:\n  max_store_bytes: 100\n  reserve_fraction: 0.5\n"
    )
    result = runner.invoke(app, ["--config", str(cfg), "status"])
    assert "reserved headroom" not in result.output

    store = open_store(
        Config(
            data_dir=tmp_path / "data",
            artifacts=ArtifactQuotas(max_store_bytes=100, reserve_fraction=0.5),
        )
    )
    cand, _ = upsert_candidate(store.conn, "a.test", match_strength="strong")
    case = create_case(store.conn, cand)
    store.blobs.put(b"x" * 50, case_id=case, registrable_domain="a.test")
    store.close()
    result = runner.invoke(app, ["--config", str(cfg), "status"])
    assert result.exit_code == 0
    assert "reserved headroom" in result.output


def test_status_skips_invalid_raw_directories(tmp_path, monkeypatch):
    raw = tmp_path / "data" / "raw"
    (raw / "Not A Source").mkdir(parents=True)
    (raw / "discovery").mkdir()
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "discovery" in result.output and "Not A Source" not in result.output


def _write_registry(tmp_path, data):
    import yaml

    path = tmp_path / "brands.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_registry_validate_reports_counts_and_legacy_coverage():
    result = runner.invoke(app, ["registry", "validate"])
    assert result.exit_code == 0, result.output
    assert "high/legacy-unverified 10" in result.output
    assert "legacy-unverified 7" in result.output
    assert "abhishek" in result.output  # warning: exclusion can never apply
    assert "legacy coverage not checked" not in result.output
    assert result.output.rstrip().endswith("ok")


def test_registry_validate_fails_on_unconfirmed_suppression(tmp_path, registry_data):
    registry_data["domains"][0]["suppresses"] = True
    path = _write_registry(tmp_path, registry_data)
    result = runner.invoke(app, ["registry", "validate", "--path", str(path)])
    assert result.exit_code == 1
    assert "only confirmed domains may suppress" in result.output


def test_registry_validate_fails_when_legacy_input_is_missing(tmp_path, registry_data):
    registry_data["exclusions"] = registry_data["exclusions"][1:]
    path = _write_registry(tmp_path, registry_data)
    result = runner.invoke(app, ["registry", "validate", "--path", str(path)])
    assert result.exit_code == 1
    assert "odisha" in result.output


def test_registry_errors_are_escaped(tmp_path, registry_data):
    registry_data["domains"][0]["brand"] = "x\x1b[31m"
    path = _write_registry(tmp_path, registry_data)
    result = runner.invoke(app, ["registry", "validate", "--path", str(path)])
    assert result.exit_code == 1
    assert "\x1b" not in result.output


def test_match_prints_one_json_line_per_name(tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("fakeisha.info\n\nsave-soil.shop\n")
    result = runner.invoke(app, ["match", "sadhguru.org.verify-login.xyz", "--file", str(names)])
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.startswith("{")]
    assert len(lines) == 3
    assert '"candidate":true' in lines[0] and '"candidate":false' in lines[1]


def test_match_escapes_invalid_names_and_exits_1():
    result = runner.invoke(app, ["match", "bad\x1b[2Jname.com"])
    assert result.exit_code == 1
    assert "\x1b" not in result.output
    assert "invalid name" in result.output


def test_match_unreadable_file_exits_1(tmp_path):
    result = runner.invoke(app, ["match", "--file", str(tmp_path / "missing.txt")])
    assert result.exit_code == 1
    assert "cannot read" in result.output


def test_submit_creates_case_and_status_shows_discovery(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["submit", "https://sadhguru-donate.example.com/x", "isha.in"])
    assert result.exit_code == 0, result.output
    assert "sadhguru-donate.example.com: new case #1" in result.output
    again = runner.invoke(app, ["submit", "sadhguru-donate.example.com"])
    assert "existing case #1" in again.output

    status = runner.invoke(app, ["status"])
    assert status.exit_code == 0, status.output
    assert "candidates: 2" in status.output
    assert "seen by manual" in status.output
    assert "certstream: STALE, last message never" in status.output
    assert "dnstwist: no sweeps yet" in status.output


def test_submit_rejects_bad_input(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["submit", "ftp://\x1bx.com"])
    assert result.exit_code == 1
    assert "\x1b" not in result.output


def test_replay_is_idempotent_from_the_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    runner.invoke(app, ["submit", "sadhguru-x.com"])
    result = runner.invoke(app, ["replay"])
    assert result.exit_code == 0, result.output
    assert "0 ingested, 1 already present" in result.output


def test_sweep_refuses_targets_outside_the_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["sweep", "evil.com"])
    assert result.exit_code == 2
    assert "not registry dnstwist targets" in result.output


def _dev_config(tmp_path, **sections) -> str:
    """A config for running the service from this checkout: the developer
    override (the test account owns the code) and no sandbox runtime."""
    import yaml

    data = {
        "data_dir": str(tmp_path / "data"),
        "runtime": {"allow_developer_account": True},
        "sandbox": {"enabled": False},
        **sections,
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def test_run_with_sources_disabled_starts_and_stops(tmp_path):
    args = ["-c", _dev_config(tmp_path), "run", "--no-certstream", "--no-dnstwist"]
    result = runner.invoke(app, [*args, "--duration", "0.2"])
    assert result.exit_code == 0, result.output


def test_run_refuses_uid_0_even_with_the_developer_override(tmp_path, monkeypatch):
    monkeypatch.setattr("brandsentinel.sandbox.preflight.os.getuid", lambda: 0)
    args = ["-c", _dev_config(tmp_path), "run", "--no-certstream", "--no-dnstwist"]
    result = runner.invoke(app, [*args, "--duration", "0.2"])
    assert result.exit_code == 2
    assert "refusing to start: not_root" in result.output


def test_run_as_code_owner_refuses_without_the_developer_override(tmp_path):
    import yaml

    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"data_dir": str(tmp_path / "data"), "sandbox": {"enabled": False}})
    )
    result = runner.invoke(
        app, ["-c", str(path), "run", "--no-certstream", "--no-dnstwist", "--duration", "0.2"]
    )
    assert result.exit_code == 2
    assert "refusing to start: not_code_owner" in result.output


def test_run_with_the_developer_override_warns(tmp_path):
    args = ["-c", _dev_config(tmp_path), "run", "--no-certstream", "--no-dnstwist"]
    result = runner.invoke(app, [*args, "--duration", "0.2"])
    assert result.exit_code == 0, result.output
    assert "WARNING not_code_owner" in result.output


def test_status_reports_sandbox_disabled_with_reasons(tmp_path):
    cfg = _dev_config(
        tmp_path,
        sandbox={"enabled": True},
        runtime={"docker_host": f"unix://{tmp_path}/missing.sock"},
    )
    result = runner.invoke(app, ["-c", cfg, "status"])
    assert result.exit_code == 0, result.output
    assert "sandbox: DISABLED" in result.output
    assert "FAIL endpoint" in result.output


def test_sandbox_check_fails_closed_without_a_runtime(tmp_path):
    cfg = _dev_config(tmp_path, runtime={"docker_host": f"unix://{tmp_path}/missing.sock"})
    result = runner.invoke(app, ["-c", cfg, "sandbox", "check"])
    assert result.exit_code == 1
    assert "runtime: FAILED" in result.output


def test_analyze_rejects_invalid_domains(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    for bad in ["bad..name", "127.0.0.1", "x" * 300 + ".com"]:
        result = runner.invoke(app, ["analyze", bad])
        assert result.exit_code == 2 and "invalid domain" in result.output


def test_run_with_analysis_stages_disabled(tmp_path):
    args = ["-c", _dev_config(tmp_path), "run", "--no-certstream", "--no-dnstwist"]
    args += ["--no-enrich", "--no-fetch"]
    result = runner.invoke(app, [*args, "--duration", "0.2"])
    assert result.exit_code == 0, result.output


def test_status_reports_analysis_and_deferred_work(tmp_path, monkeypatch):
    from brandsentinel.config import Config
    from brandsentinel.pipeline import scheduling
    from brandsentinel.store import open_store

    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    config = Config(data_dir=tmp_path / "data")
    store = open_store(config)
    for i in range(20):
        scheduling.schedule(
            store.conn,
            store.jobs,
            config.scheduling,
            stage="enrich",
            payload={},
            group_key="flood\x1b[31m.com",
            queue_class="weak",
            dedupe_key=f"k{i}",
            now=0.0,
        )
    store.close()
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "analysis: enrich on, fetch on" in result.output
    assert "deferred work: 16 (16 due)" in result.output
    assert "over allowance: flood\\x1b[31m.com 16" in result.output
