"""Release identity: one version, declared in pyproject.toml, the package and
uv.lock, and reported by `brandsentinel version`. The store, bundle and policy
schema versions are separate and do not follow it."""

import tomllib
from pathlib import Path

from typer.testing import CliRunner

import brandsentinel
from brandsentinel.cli import app

REPO = Path(__file__).parents[2]


def test_every_declaration_of_the_release_version_agrees():
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    lock = tomllib.loads((REPO / "uv.lock").read_text())
    (locked,) = [p["version"] for p in lock["package"] if p["name"] == "brandsentinel"]
    assert project == brandsentinel.__version__ == locked == "0.2.0"
    out = CliRunner().invoke(app, ["version"])
    assert out.exit_code == 0 and out.output.strip() == project


def test_schema_versions_are_independent_of_the_release():
    from brandsentinel.evidence.bundle import SCHEMA_VERSION
    from brandsentinel.store.db import _migration_files

    assert _migration_files()[-1][0] == 5  # store schema v5, as M7
    assert SCHEMA_VERSION == "bundle/4"  # M7 reads every score (pinned in test_policy)
    policy = (REPO / "config" / "policy.yaml").read_text()
    assert "policy/5" in policy
