"""U15 HTML and text reports: escaping, CSP, no live links, every lab case renders."""

import re
from pathlib import Path

import pytest
from markupsafe import escape
from tests.detection_support import lab_sites, scorer, seed_case

from brandsentinel.triage import list_cases, load_case
from brandsentinel.triage.report import (
    CSP,
    render_case_html,
    render_case_text,
    render_index_html,
    write_private,
)

FIXTURES = Path(__file__).parent / "fixtures" / "html"


def scored(store, html, url):
    case_id = seed_case(store, html, url)
    scorer(store).score(case_id)
    return load_case(store.conn, case_id)


def test_script_in_title_renders_as_escaped_text(store):
    r = scored(
        store,
        "<title><script>alert(1)</script> Lumina Foundation</title><p>x</p>",
        "http://evil-luminafoundation.test/",
    )
    html = render_case_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script" not in html.lower()


def test_report_declares_csp_and_has_no_links_to_candidate_urls(store):
    r = scored(
        store, (FIXTURES / "hostile.html").read_bytes(), "http://evil-luminafoundation.test/x"
    )
    html = render_case_html(r)
    # Autoescaped inside the attribute; a browser decodes &#39; back to a quote.
    assert f'<meta http-equiv="Content-Security-Policy" content="{escape(CSP)}">' in html
    assert "default-src 'none'" in CSP and "form-action 'none'" in CSP
    assert '<meta name="referrer" content="no-referrer">' in html
    assert not re.search(r"<a\s", html, re.I)  # a case report links nowhere
    assert "<form" not in html.lower() and "<iframe" not in html.lower()
    assert "javascript:" not in html  # the hostile href is not rendered as a link or text
    assert "evil-luminafoundation.test/x" in html  # URLs appear as text


def test_index_links_only_to_local_case_reports(store):
    scored(store, "<title>Lumina Foundation</title>", "http://a-luminafoundation.test/")
    cases = list_cases(store.conn)
    html = render_index_html(cases, 1_760_000_000.0)
    hrefs = re.findall(r'href="([^"]*)"', html)
    assert hrefs and all(re.fullmatch(r"case-\d+\.html", h) for h in hrefs)


@pytest.mark.parametrize("site", lab_sites())
def test_every_lab_case_renders_in_html_and_text(store, site):
    from tests.detection_support import lab_site

    expected, html = lab_site(site)
    r = scored(store, html, expected["url"])
    page = render_case_html(r)
    assert r.result.priority in page and r.result.category in page
    for reason in r.result.reasons:
        assert reason.rule in page
    text = "\n".join(render_case_text(r))
    assert f"Case #{r.summary.case_id}" in text and r.result.summary in text


def test_donation_report_separates_payment_facts_attribution_and_evidence(store):
    from tests.detection_support import lab_site

    expected, html = lab_site("donation-fraud")
    r = scored(store, html, expected["url"])
    page = render_case_html(r)
    assert "Observed fact</th><th>Attribution</th><th>Evidence" in page
    assert "rivers.relief.fund@quickpaybank" in page and "claims_brand_unconfirmed" in page
    assert "payment/1" in page and "not a finding of fraud" in page


def test_unscored_case_renders(store):
    from tests.detection_support import lab_registry

    from brandsentinel.discovery.submit import submit
    from brandsentinel.matching.matcher import Matcher

    res = submit(store, Matcher(lab_registry()), "http://new-luminafoundation.test/")
    r = load_case(store.conn, res.case_id)
    assert "unscored" in render_case_html(r)
    assert "not scored yet" in "\n".join(render_case_text(r))


def test_reports_are_written_owner_only(tmp_path):
    path = write_private(tmp_path / "reports" / "case-1.html", "<p>x</p>")
    assert path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "reports").stat().st_mode & 0o077 == 0
