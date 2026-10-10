"""U15 CLI: cases list/show/label/rescore, report and export, with escaped output."""

import csv
import io

import pytest
from tests.detection_support import REPO, lab_site, scorer, seed_case
from typer.testing import CliRunner

from brandsentinel.cli import app
from brandsentinel.config import load_config
from brandsentinel.store import open_store
from brandsentinel.triage import load_labelled_cases

runner = CliRunner()
RLO = chr(0x202E)  # built from its code point; never written literally


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A lab-mode config (lab registry overlay) over a scratch data dir with two cases."""
    cfg = tmp_path / "lab.yaml"
    cfg.write_text((REPO / "config/lab.yaml").read_text().replace("data_dir: data-lab", ""))
    monkeypatch.setenv("BRANDSENTINEL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(REPO)  # registry, overlay and policy paths are repo-relative
    config = load_config(cfg)
    store = open_store(config)
    from tests.detection_support import lab_registry

    title = f"<title>Lumina Foundation \x1b]0;pwned\x07 {RLO}gnp.exe</title><p>hello</p>"
    ids = []
    for html, url in [
        (lab_site("donation-fraud")[1], "http://donate-luminafoundation.test/"),
        (title, "http://hostile-luminafoundation.test/"),
    ]:
        ids.append(seed_case(store, html, url, registry=lab_registry()))
        scorer(store).score(ids[-1])
    store.close()
    return ["-c", str(cfg)], ids, config


def run(args, *extra):
    result = runner.invoke(app, [*args, *extra])
    return result


def test_cases_show_escapes_terminal_control_sequences(env):
    args, ids, _ = env
    r = run(args, "cases", "show", str(ids[1]))
    assert r.exit_code == 0, r.output
    assert "\x1b" not in r.output and "\x07" not in r.output and RLO not in r.output
    # The sanitizing fact writer already dropped the controls; nothing live remains.
    assert "pwned" in r.output


def test_cases_show_json_is_ascii_and_escaped(env):
    args, ids, _ = env
    r = run(args, "cases", "show", str(ids[0]), "--json")
    assert r.exit_code == 0 and '"priority": "P1"' in r.output
    assert all(ord(c) < 128 for c in r.output)


def test_cases_list_orders_by_priority_and_filters(env):
    args, ids, _ = env
    r = run(args, "cases", "list")
    assert r.exit_code == 0
    lines = r.output.strip().split("\n")[1:]
    assert lines[0].split()[0] == str(ids[0]) and "P1" in lines[0]
    only = run(args, "cases", "list", "--priority", "P1", "--category", "donation_fraud")
    assert only.output.count("\n") == 2
    assert run(args, "cases", "list", "--priority", "P9").exit_code == 2
    assert "no cases" in run(args, "cases", "list", "--source", "dnstwist").output


def test_labels_are_recorded_and_retrievable_by_the_evaluation_loader(env):
    args, ids, config = env
    assert (
        run(args, "cases", "label", str(ids[0]), "--verdict", "abusive", "--by", "a1").exit_code
        == 0
    )
    r = run(
        args,
        "cases",
        "label",
        str(ids[0]),
        "--question",
        "payment_or_donation_abuse",
        "--value",
        "yes",
    )
    assert r.exit_code == 0
    assert run(args, "cases", "label", str(ids[0]), "--verdict", "evil").exit_code == 2
    assert run(args, "cases", "label", "999", "--verdict", "benign").exit_code == 2
    store = open_store(config)
    try:
        assert load_labelled_cases(store.conn) == {
            ids[0]: {"overall": "abusive", "payment_or_donation_abuse": "yes"}
        }
    finally:
        store.close()
    assert "analyst_verdict" in run(args, "export", "csv").output


def test_rescore_is_idempotent(env):
    args, _, _ = env
    r = run(args, "cases", "rescore", "--all")
    assert r.exit_code == 0 and r.output.count("(unchanged)") == 2


def test_report_and_export_write_owner_only_files(env, tmp_path):
    args, _, _ = env
    out = tmp_path / "reports"
    r = run(args, "report", "--index", "--out", str(out))
    assert r.exit_code == 0, r.output
    files = sorted(p.name for p in out.iterdir())
    assert files == ["case-1.html", "case-2.html", "index.html"]
    assert all((out / f).stat().st_mode & 0o777 == 0o600 for f in files)
    path = tmp_path / "cases.csv"
    assert run(args, "export", "csv", "-o", str(path)).exit_code == 0
    rows = list(csv.reader(io.StringIO(path.read_text())))
    assert len(rows) == 3 and path.stat().st_mode & 0o777 == 0o600
    assert run(args, "report", "77").exit_code == 1


def test_report_requires_a_target(env):
    args, _, _ = env
    assert run(args, "report").exit_code == 2


def test_rescore_reextract_rebuilds_features_from_the_stored_page(env):
    args, ids, config = env
    store = open_store(config)
    try:
        before = store.conn.execute("SELECT COUNT(*) FROM features").fetchone()[0]
    finally:
        store.close()
    r = run(args, "cases", "rescore", str(ids[0]), "--reextract")
    assert r.exit_code == 0 and "P1 donation_fraud" in r.output
    store = open_store(config)
    try:
        after = store.conn.execute("SELECT COUNT(*) FROM features").fetchone()[0]
    finally:
        store.close()
    assert after > before


def test_cases_show_and_list_escape_hostile_text_that_reached_the_store(env):
    # Bypass the sanitizing fact writer: put live control sequences straight into
    # the stored policy result and bundle, as a future writer bug might.
    args, ids, config = env
    store = open_store(config)
    try:
        row = store.conn.execute(
            "SELECT id, result_json, bundle_json FROM scores WHERE case_id = ?", (ids[1],)
        ).fetchone()
        evil = "\x1b]0;owned\x07" + RLO + "evil"
        result = row[1].replace(
            '"summary":"',
            '"summary":"'
            + evil.replace("\x1b", "\\u001b").replace("\x07", "\\u0007").replace(RLO, "\\u202e"),
        )
        bundle = row[2].replace('"title":"', '"title":"\\u001b[31m')
        store.conn.execute(
            "UPDATE scores SET result_json = ?, bundle_json = ? WHERE id = ?",
            (result, bundle, row[0]),
        )
        store.conn.commit()
    finally:
        store.close()
    for cmd in (["cases", "show", str(ids[1])], ["cases", "list"]):
        out = run(args, *cmd).output
        assert "\x1b" not in out and "\x07" not in out and RLO not in out, cmd
    assert "\\x1b]0;owned\\x07" in run(args, "cases", "show", str(ids[1])).output


def test_cases_list_filters(env):
    args, ids, _ = env
    assert str(ids[0]) in run(args, "cases", "list", "--source", "manual").output
    assert "no cases" in run(args, "cases", "list", "--strength", "weak").output
    assert run(args, "cases", "list", "--strength", "strong").output.count("\n") == 3
    assert "no cases" in run(args, "cases", "list", "--status", "closed").output
    assert "no cases" in run(args, "cases", "list", "--since", "2999-01-01").output
    assert run(args, "cases", "list", "--since", "2000-01-01").output.count("\n") == 3
    assert run(args, "cases", "list", "--since", "yesterday").exit_code == 2
    assert run(args, "cases", "list", "--limit", "1").output.count("\n") == 2
    assert "no cases" in run(args, "cases", "list", "--label", "official_domain").output
    assert run(args, "cases", "list", "--category", "made_up").exit_code == 2


def test_rescore_reports_missing_cases_and_bad_policy(env, tmp_path):
    args, _, _ = env
    r = run(args, "cases", "rescore", "999")
    assert r.exit_code == 1
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        (REPO / "config/lab.yaml").read_text().replace("data_dir: data-lab", "")
        + "\nanalysis:\n  policy: /nonexistent/policy.yaml\n"
    )
    r = runner.invoke(app, ["-c", str(bad), "cases", "rescore", "--all"])
    assert r.exit_code == 2 and "invalid policy" in r.output
    r = runner.invoke(app, ["-c", str(bad), "analyze", "x.test"])
    assert r.exit_code == 2


def test_csv_to_a_pipe_is_the_exact_csv(env, tmp_path):
    args, _, _ = env
    path = tmp_path / "out.csv"
    run(args, "export", "csv", "-o", str(path))
    piped = run(args, "export", "csv").output  # CliRunner stdout is not a TTY
    assert piped.replace("\r\n", "\n") == path.read_text().replace("\r\n", "\n")
