"""The offline demo (docs/demo/offline_demo.py, docs/guide/demo.md) runs end to end and
its store reads back through the real CLI, so the tutorial cannot silently rot."""

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "docs/demo/offline_demo.py"


def _env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRANDSENTINEL_")}
    env.update(extra)
    return env


def _run(*args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed interpreter and script
        [sys.executable, *args],
        cwd=REPO,
        env=env or _env(),
        capture_output=True,
        text=True,
        timeout=180,
    )


def _cli(config: Path, *args) -> subprocess.CompletedProcess:
    exe = str(Path(sys.executable).with_name("brandsentinel"))
    return subprocess.run(  # noqa: S603 - the installed entry point, fixed arguments
        [exe, "-c", str(config), *args], env=_env(), capture_output=True, text=True, timeout=60
    )


def test_offline_demo_scores_every_site_as_expected_and_the_cli_reads_it(tmp_path):
    out = tmp_path / "demo"
    r = _run(str(DEMO), str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    rows = [ln for ln in r.stdout.splitlines() if ln.rstrip().endswith("]")]
    assert len(rows) == 5 and all(ln.endswith("[ok]") for ln in rows), r.stdout
    assert (out / "demo.yaml").exists() and (out / "data" / "brandsentinel.db").exists()

    listing = _cli(out / "demo.yaml", "cases", "list")
    assert listing.returncode == 0, listing.stderr
    assert "donation_fraud" in listing.stdout and "donate-luminafoundation.test" in listing.stdout
    shown = _cli(out / "demo.yaml", "cases", "show", "1")
    assert (
        "payment_brand_unconfirmed_payee" in shown.stdout
        and "not a finding of fraud" in shown.stdout
    )


def test_offline_demo_refuses_an_existing_directory(tmp_path):
    r = _run(str(DEMO), str(tmp_path))
    assert r.returncode == 2 and "exists" in r.stderr


def test_offline_demo_refuses_a_redirecting_environment(tmp_path):
    r = _run(
        str(DEMO), str(tmp_path / "demo"), env=_env(BRANDSENTINEL_DATA_DIR=str(tmp_path / "other"))
    )
    assert r.returncode == 2 and "BRANDSENTINEL_DATA_DIR" in r.stderr
    assert not (tmp_path / "demo").exists() and not (tmp_path / "other").exists()


def test_offline_demo_refuses_the_production_location():
    r = _run(str(DEMO), "/var/lib/brandsentinel/demo-should-not-exist")
    assert r.returncode == 2 and "production" in r.stderr
