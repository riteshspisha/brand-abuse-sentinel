"""Manual submissions enter the same intake and are never suppressed."""

import json

import pytest
from tests.conftest import build_matcher, confirm_domain

from brandsentinel.discovery.submit import SubmissionError, parse_submission, submit


def test_submitted_url_creates_one_case_and_one_job(store, matcher):
    r = submit(store, matcher, "https://login.Example-Donate.com/pay?x=1")
    assert r.outcome == "candidate" and r.new_case
    case = store.conn.execute("SELECT * FROM cases").fetchone()
    assert case["subject_url"] == "https://login.Example-Donate.com/pay?x=1"
    assert store.conn.execute("SELECT name, match_strength FROM candidates").fetchone()[:] == (
        "login.example-donate.com",
        "strong",
    )
    again = submit(store, matcher, "login.example-donate.com")
    assert not again.new_case and again.case_id == r.case_id
    assert store.conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


def test_submitted_official_domain_is_processed_and_marked_official(store, registry_data):
    confirm_domain(registry_data, "isha.in")
    m = build_matcher(registry_data)
    r = submit(store, m, "www.isha.in")
    assert r.outcome == "candidate"
    match = json.loads(store.conn.execute("SELECT match_json FROM discovery_events").fetchone()[0])
    assert match["suppressed_by"] == "isha.in"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "ftp://x.com",
        "javascript:alert(1)",
        "http://user:pw@x.com/",
        "x.com/path",
        "*.x.com",
        "bad..name",
        "x.com\x1b[2J",
        "a" * 3000,
    ],
)
def test_invalid_submissions_are_rejected(bad):
    with pytest.raises(SubmissionError):
        parse_submission(bad)


def test_idn_submission_is_canonicalized():
    host, url = parse_submission("sadhgur\u00fc.com")
    assert host == "xn--sadhgur-t2a.com" and url is None
