from pathlib import Path

import pytest

from brandsentinel.config import ENV_CONFIG, ENV_DATA_DIR, ConfigError, load_config

EXAMPLE = Path(__file__).parents[2] / "config" / "brandsentinel.example.yaml"


def test_example_config_loads_with_stage_defaults():
    cfg = load_config(EXAMPLE)
    assert cfg.stages.enrich == 8
    assert cfg.stages.fetch == 4
    assert cfg.stages.media == 2
    assert cfg.stages.render == 1
    assert cfg.stages.decision == 1
    assert cfg.stages.per_domain_fetch == 1
    assert cfg.rawlog.firehose.enabled is False


def test_example_config_matches_builtin_defaults():
    assert load_config(EXAMPLE) == load_config(None)


def test_unknown_key_fails_with_key_name(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("stages:\n  fetchh: 3\n")
    with pytest.raises(ConfigError, match=r"stages\.fetchh"):
        load_config(path)


def test_unknown_top_level_key_fails(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("lab_allow_cidr: 10.0.0.0/8\n")
    with pytest.raises(ConfigError, match="lab_allow_cidr"):
        load_config(path)


def test_invalid_value_fails(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("artifacts:\n  reserve_fraction: 1.5\n")
    with pytest.raises(ConfigError, match=r"artifacts\.reserve_fraction"):
        load_config(path)


def test_non_mapping_and_bad_yaml_fail(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(path)
    path.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(path)


def test_missing_file_fails(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")


def test_env_overrides_path_only(tmp_path, monkeypatch):
    path = tmp_path / "c.yaml"
    path.write_text("stages:\n  fetch: 2\n")
    monkeypatch.setenv(ENV_CONFIG, str(path))
    monkeypatch.setenv(ENV_DATA_DIR, str(tmp_path / "elsewhere"))
    cfg = load_config()
    assert cfg.stages.fetch == 2
    assert cfg.data_dir == tmp_path / "elsewhere"
    assert cfg.db_path == tmp_path / "elsewhere" / "brandsentinel.db"


def test_lease_for_falls_back_to_default():
    cfg = load_config(None)
    assert cfg.jobs.lease_for("render") == 300.0
    assert cfg.jobs.lease_for("unknown-stage") == cfg.jobs.default_lease_seconds


@pytest.mark.parametrize(
    ("yaml_text", "needle"),
    [
        ("jobs:\n  lease_seconds:\n    fetch: 0\n", "jobs.lease_seconds.fetch"),
        ("jobs:\n  lease_seconds:\n    fetch: -5\n", "jobs.lease_seconds.fetch"),
        ("jobs:\n  lease_seconds:\n    fetchh: 60\n", "fetchh"),
    ],
)
def test_lease_seconds_must_be_positive_and_name_known_stages(tmp_path, yaml_text, needle):
    path = tmp_path / "c.yaml"
    path.write_text(yaml_text)
    with pytest.raises(ConfigError, match=needle):
        load_config(path)
