import pytest
from typer.testing import CliRunner

from brandsentinel.cli import app

runner = CliRunner()

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
    "eval",
]


def test_help_lists_every_registered_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in COMMANDS:
        assert name in result.output


@pytest.mark.parametrize("name", ["run", "analyze", "registry", "eval"])
def test_planned_commands_exit_non_zero_with_milestone(name):
    result = runner.invoke(app, [name, "--anything", "x"])
    assert result.exit_code == 2
    assert "not implemented yet" in result.output


def test_status_on_empty_store(tmp_path, monkeypatch):
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "schema v1" in result.output
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
