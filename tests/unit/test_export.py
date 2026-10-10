"""U15 CSV export: stable columns, formula neutralization, one row per case."""

import csv
import io

import pytest
from tests.detection_support import lab_site, scorer, seed_case

from brandsentinel.triage import list_cases, load_case
from brandsentinel.triage.export import COLUMNS, _cell, to_csv


@pytest.mark.parametrize(
    ("raw", "cell"),
    [
        ('=HYPERLINK("http://x")', '\'=HYPERLINK("http://x")'),
        (" =HYPERLINK(1)", "' =HYPERLINK(1)"),
        ("\t=cmd", "'\t=cmd"),
        ("\r=cmd", "' =cmd"),
        ("+1+1", "'+1+1"),
        ("-2", "'-2"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("plain text", "plain text"),
        ("line\nbreak", "line break"),
        (42, "42"),
        (None, ""),
    ],
)
def test_cells_are_neutralized(raw, cell):
    assert _cell(raw) == cell


def test_csv_has_stable_columns_and_one_row_per_case(store):
    for site in ("donation-fraud", "news-critical", "unrelated-yoga"):
        expected, html = lab_site(site)
        scorer(store).score(seed_case(store, html, expected["url"]))
    reports = [load_case(store.conn, c.case_id) for c in list_cases(store.conn)]
    rows = list(csv.reader(io.StringIO(to_csv(reports))))
    assert tuple(rows[0]) == COLUMNS and len(rows) == 4
    first = dict(zip(COLUMNS, rows[1], strict=True))
    assert first["priority"] == "P1" and first["category"] == "donation_fraud"
    assert "rivers.relief.fund@quickpaybank=claims_brand_unconfirmed" in first["payee_attribution"]
    assert first["reasons"].startswith("payment_brand_unconfirmed_payee(+55)")
    assert first["policy_version"] == "policy/2" and len(first["bundle_sha256"]) == 64


def test_hostile_page_values_cannot_become_formulas(store):
    html = (
        '<title>=HYPERLINK("http://evil.test","x") Lumina Foundation</title>'
        "<p>We are the official partner of Lumina Foundation.</p>"
    )
    scorer(store).score(seed_case(store, html, "http://x-luminafoundation.test/"))
    reports = [load_case(store.conn, c.case_id) for c in list_cases(store.conn)]
    for row in list(csv.reader(io.StringIO(to_csv(reports))))[1:]:
        for value in row:
            stripped = value.lstrip()
            assert not stripped or stripped[0] not in "=+-@" or value.startswith("'"), value
