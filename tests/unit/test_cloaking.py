"""Static-versus-rendered comparison (U19, R48, KTD23, AE17), over the values the
real extractors produce for lab pages."""

from tests.detection_support import LAB, context, lab_site

from brandsentinel.analysis import run_extractors
from brandsentinel.sandbox import cloaking


def view(html: bytes | str, url: str, status: int = 200) -> dict:
    data = html.encode() if isinstance(html, str) else html
    values = {
        r.extractor.name: r.value
        for r in run_extractors(data, "text/html", "utf-8", url, context())
        if r.value
    }
    return cloaking.summary(values, url, status)


GIFT = "http://luminafoundation-gift.test/"
BENIGN = (LAB / "cloaking" / "benign" / "index.html").read_bytes()
FRAUD = (LAB / "cloaking" / "fraud" / "index.html").read_bytes()
LOGIN_RENDERED = """<html><head><title>Lumina Foundation - Member Sign In</title></head><body>
<h1>Lumina Foundation Members</h1><form action="/session" method="post">
<input type="email" name="email"><input type="password" name="password"></form></body></html>"""


def test_ae17_a_harmless_static_page_and_a_donation_page_in_the_browser_is_cloaking():
    c = cloaking.compare(view(BENIGN, GIFT), view(FRAUD, GIFT))
    assert c["suspected"] and c["score_on"] == "rendered"
    fields = {d["field"] for d in c["differences"]}
    assert {"brands", "payment"} <= fields
    assert c["rendered"]["payees"] == ["festival.gifts@quickpaybank"]


def test_a_js_shell_that_the_browser_completes_is_not_cloaking():
    _, shell = lab_site("js-login")
    url = "http://login-luminafoundation.test/"
    c = cloaking.compare(view(shell, url), view(LOGIN_RENDERED, url))
    assert not c["suspected"] and c["expected_difference"] == "static_shell"
    assert {d["field"] for d in c["differences"]} >= {"credential_form"}
    assert c["score_on"] == "rendered"


def test_the_same_page_both_ways_is_not_cloaking():
    c = cloaking.compare(view(FRAUD, GIFT), view(FRAUD, GIFT))
    assert not c["suspected"] and c["differences"] == []


def test_abuse_shown_only_to_the_static_fetcher_is_scored_on_the_static_page():
    # Cloaking aimed at browsers: the policy must not lose what the fetcher saw.
    c = cloaking.compare(view(FRAUD, GIFT), view(BENIGN, GIFT))
    assert c["suspected"] and c["score_on"] == "static"


def test_an_error_for_the_fetcher_and_a_page_for_the_browser_is_cloaking():
    c = cloaking.compare(view("<h1>403 Forbidden</h1>", GIFT, 403), view(FRAUD, GIFT))
    assert c["suspected"] and "status" in {d["field"] for d in c["differences"]}


def test_ending_on_another_site_is_cloaking_unless_the_static_page_announced_it():
    js = (LAB / "redirects" / "js-redirect.html").read_bytes()
    start = "http://go-luminafoundation.test/js-redirect.html"
    landed = view(LOGIN_RENDERED, "http://login-luminafoundation.test/")
    announced = cloaking.compare(view(js, start), landed)
    assert "final_site" not in {d["field"] for d in announced["differences"]}
    plain = "<html><head><title>Go</title></head><body><p>" + "Welcome back. " * 20 + "</p>"
    silent = cloaking.compare(view(plain, start), landed)
    assert silent["suspected"] and "final_site" in {d["field"] for d in silent["differences"]}
