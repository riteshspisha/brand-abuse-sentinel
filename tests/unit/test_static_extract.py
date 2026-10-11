"""U12 page_content and commerce extractors over lab sites and hard-negative fixtures."""

from pathlib import Path

import pytest
from tests.detection_support import context, lab_site

from brandsentinel.analysis import Page, run_extractors
from brandsentinel.analysis.commerce import commerce
from brandsentinel.analysis.static import page_content

FIXTURES = Path(__file__).parent / "fixtures" / "html"


def page(html: str | bytes, url: str = "http://site.test/") -> Page:
    text = html.decode() if isinstance(html, bytes) else html
    return Page(text, url, context())


def lab(site: str) -> Page:
    expected, html = lab_site(site)
    return page(html, expected["url"])


def test_same_origin_password_form_is_recorded_with_brand_context():
    v = page_content(lab("disguised-credential"))
    (form,) = v["forms"]
    assert form["action"] == "http://lumina-watch-news.test/verify"
    assert form["method"] == "POST" and not form["cross_origin"]
    assert form["password_fields"] == 1 and form["identity_fields"] == 1
    assert {b["brand"] for b in form["brands_in_context"]} >= {"lumina-foundation"}
    assert v["credential"]["password_forms"] == [0]
    assert v["credential"]["cross_origin_credential_forms"] == []
    cues = {lu["cue"] for lu in v["lures"]}
    assert "confirm your account" in cues


def test_cross_origin_password_form_sets_cross_origin():
    html = (
        '<title>Lumina Foundation</title><form action="https://grab.other-domain.test/x"'
        ' method="post"><input type="password" name="p"></form>'
    )
    v = page_content(page(html, "https://lumina-login.test/"))
    assert v["forms"][0]["cross_origin"] is True
    assert v["forms"][0]["action_registrable_domain"] == "other-domain.test"
    assert v["credential"]["cross_origin_credential_forms"] == [0]
    assert v["credential"]["credential_action_domains"] == ["other-domain.test"]


def test_otp_and_password_outside_forms_are_counted():
    html = (
        '<input type="password" id="pw"><form action="/v"><input autocomplete="one-time-code">'
        '<input name="verification_code"></form>'
    )
    v = page_content(page(html))
    assert v["credential"]["password_fields"] == 1
    assert v["credential"]["password_fields_outside_forms"] == 1
    assert v["credential"]["otp_fields"] == 2 and v["credential"]["otp_forms"] == [0]


def test_form_action_resolves_against_base_href_and_javascript_actions_are_kept_inert():
    html = '<base href="https://cdn.test/a/"><form action="post.php"><input type="password"></form>'
    v = page_content(page(html, "https://site.test/"))
    assert v["forms"][0]["action"] == "https://cdn.test/a/post.php"
    hostile = page_content(page((FIXTURES / "hostile.html").read_bytes()))
    assert hostile["forms"][0]["action"] is None
    assert hostile["forms"][0]["action_scheme"] == "javascript"


def test_script_redirects_are_recorded_as_facts():
    html = (Path(__file__).parents[2] / "labsites/redirects/js-redirect.html").read_text()
    v = page_content(page(html, "http://go-luminafoundation.test/js-redirect.html"))
    assert v["script_redirects"] == [
        {"kind": "location_replace", "url": "http://login-luminafoundation.test/"}
    ]
    more = page_content(
        page(
            "<script>window.location.href = '/next'; location.assign(\"https://x.test/\")</script>"
        )
    )
    assert {"kind": "location_assign", "url": "http://site.test/next"} in more["script_redirects"]
    assert {"kind": "location_replace", "url": "https://x.test/"} in more["script_redirects"]


def test_meta_refresh_is_recorded_by_page_basics():
    html = (Path(__file__).parents[2] / "labsites/redirects/meta-refresh.html").read_bytes()
    results = {
        r.extractor.name: r.value
        for r in run_extractors(html, "text/html", None, "http://go-luminafoundation.test/")
    }
    assert results["page_basics"]["meta_refresh"] == [
        {"delay": 0.0, "url": "http://donate-luminafoundation.test/"}
    ]


def test_empty_body_with_only_scripts_is_a_js_shell():
    v = page_content(lab("js-login"))
    assert v["js_shell"] and not v["empty"] and not v["image_only"]
    assert page_content(lab("image-only"))["image_only"]
    assert page_content(page("<html><body></body></html>"))["empty"]


def test_parking_page_cues():
    v = page_content(lab("typosquat-parked"))
    assert {c["category"] for c in v["parked_cues"]} == {"for_sale", "parking_service"}
    assert {c["category"] for c in page_content(lab("cloaking"))["parked_cues"]} == {"placeholder"}


def test_outbound_domains_and_messaging_links():
    html = (
        '<a href="https://partner.test/a">a</a><a href="/local">b</a><a href="https://wa.me/123">w</a>'
        '<a href="tel:+1">t</a><a href="upi://pay?pa=x@ybl">u</a>'
    )
    links = page_content(page(html, "https://site.test/"))["links"]
    assert links["external_domains"] == ["partner.test", "wa.me"]
    assert links["messaging"] == [{"channel": "whatsapp", "url": "https://wa.me/123"}]
    assert links["schemes"] == {"tel": 1, "upi": 1}


def test_malformed_and_truncated_html_gives_partial_features_without_raising():
    html = (FIXTURES / "truncated_login.html").read_bytes()
    results = {
        r.extractor.name: r
        for r in run_extractors(html, "text/html", None, "https://lumina-members.test/", context())
    }
    assert all(r.error is None for r in results.values()), results
    v = results["page_content"].value
    assert v["credential"]["password_fields"] == 1 and v["credential"]["otp_fields"] == 1
    assert v["credential"]["cross_origin_credential_forms"] == [0]
    garbage = run_extractors(
        b"<<<>><form><input type=password<<", "text/html", None, "x", context()
    )
    assert all(r.error is None for r in garbage)


def test_hostile_markup_does_not_break_extraction():
    results = run_extractors(
        (FIXTURES / "hostile.html").read_bytes(), "text/html", None, "https://h.test/", context()
    )
    assert all(r.error is None for r in results)
    v = next(r.value for r in results if r.extractor.name == "page_content")
    assert "<script>" in v["title"]  # recorded verbatim; sanitized at storage and escaped at output


def test_large_pages_are_bounded():
    html = "<p>" + "Lumina Foundation donate now. " * 20000 + "</p>"
    v = page_content(page(html))
    assert len(v["text_excerpt"]) <= 1500 and v["text_chars"] <= 200_000
    many = "".join(f'<form action="/f{i}"><input></form>' for i in range(100))
    assert len(page_content(page(many))["forms"]) == 20


@pytest.mark.parametrize(
    ("site", "expected"),
    [
        ("false-association", True),
        ("unrelated-yoga", True),
        ("donation-fraud", False),
        ("news-critical", False),
    ],
)
def test_commerce_indicators(site, expected):
    assert commerce(lab(site))["commerce"] is expected


def test_commerce_prices_and_calls_to_action():
    v = commerce(page((FIXTURES / "shop_razorpay.html").read_bytes()))
    assert "rs. 1,499" in v["prices"] and "add to cart" in v["calls_to_action"] and v["cart"]
    assert commerce(page("<p>Open 24 hours 7 days</p>"))["prices"] == []  # "rs 7" is not a price


def test_headings_exclude_inline_style_and_script_text():
    html = "<h1><style>.c{font-size:24px}</style>Real heading<script>x=1</script></h1>"
    v = page_content(page(html))
    assert v["headings"] == ["Real heading"]
