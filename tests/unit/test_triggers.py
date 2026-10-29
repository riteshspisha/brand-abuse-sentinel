"""Render triggers (U19, R19, KTD23, AE10): which statically analyzed cases are
rendered in the browser, and why."""

import pytest
from tests.detection_support import LAB, bundle_for_html, lab_site

from brandsentinel.sandbox import triggers

SHELL = '<html><head><title>Loading</title></head><body><div id="app"></div>' \
        '<script src="/app.js"></script></body></html>'  # fmt: skip
FULL = (
    "<html><head><title>Sunrise notes</title></head><body><h1>Garden diary</h1>"
    + "<p>" + "We planted tomatoes and basil along the fence this spring. " * 12 + "</p>"
    + '<img src="/a.png" alt="garden"></body></html>'
)  # fmt: skip


def decide(html, url, *, strength="strong", rate=0.0, enabled=True, status=200, outcome="ok",
           images=None, little=200):  # fmt: skip
    b = bundle_for_html(html, url, status=status, outcome=outcome)
    imgs = images if images is not None else {"images": [{"url": "/a.png"}]}
    return triggers.decide(b, imgs, strength=strength, sample_rate=rate,
                           little_text_chars=little, enabled=enabled)  # fmt: skip


def test_ae10_a_js_shell_on_a_brand_matching_domain_renders_with_reason_js_shell():
    _, html = lab_site("js-login")
    d = decide(html, "http://login-luminafoundation.test/")
    assert d["triggered"] and "js_shell" in d["reasons"]
    assert d["url"] == "http://login-luminafoundation.test/" and d["browser_enabled"]


def test_a_complete_static_page_does_not_render_unless_sampled():
    d = decide(FULL, "http://sunrise-yoga-studio.test/")
    assert not d["triggered"] and d["skipped"] == "no_trigger"
    sampled = decide(FULL, "http://sunrise-yoga-studio.test/", rate=1.0)
    assert sampled["triggered"] and sampled["reasons"] == ["sample"] and sampled["sampled"]


def test_a_js_shell_on_an_unrelated_domain_does_not_render():
    assert not decide(SHELL, "http://sunrise-yoga-studio.test/", strength="weak")["triggered"]


def test_a_strong_domain_answering_403_statically_renders_with_reason_static_error():
    d = decide("<h1>Forbidden</h1>", "http://luminafoundatoin.test/", status=403)
    assert d["triggered"] and "static_error" in d["reasons"]


def test_a_weak_strength_error_page_does_not_render_for_the_error():
    d = decide("<h1>Forbidden</h1>", "http://sunrise-yoga-studio.test/", strength="weak",
               status=403)  # fmt: skip
    assert "static_error" not in d["reasons"]


def test_a_parked_decoy_on_a_strong_domain_renders():
    _, html = lab_site("typosquat-parked")
    d = decide(html, "http://luminafoundatoin.test/")
    assert d["triggered"] and "decoy_page" in d["reasons"]


def test_a_script_redirect_on_a_strong_domain_renders():
    redirect = (LAB / "redirects" / "js-redirect.html").read_bytes()
    d = decide(redirect, "http://go-luminafoundation.test/js-redirect.html")
    assert d["triggered"] and "script_redirect" in d["reasons"]


def test_payment_hints_without_payment_forms_render():
    html = ("<html><head><title>Lumina Foundation Programs</title>"
            '<script src="https://checkout.razorpay.com/v1/checkout.js"></script></head>'
            "<body><h1>Lumina Foundation</h1><p>" + "Program fee details follow. " * 20
            + '</p><img src="/x.png"></body></html>')  # fmt: skip
    d = decide(html, "http://pay-luminafoundation.test/")
    assert d["triggered"] and "form_hints_without_forms" in d["reasons"]


def test_a_brand_page_without_images_renders_for_visual_matching():
    html = (
        "<html><head><title>Lumina Foundation</title></head><body><h1>Lumina Foundation</h1>"
        + "<p>" + "Our programs and retreats for everyone. " * 15 + "</p></body></html>"
    )  # fmt: skip
    d = decide(html, "http://lumina-foundation-org.test/", images={})
    assert "no_static_images" in d["reasons"]


def test_never_on_the_official_domain_or_without_a_static_response():
    _, html = lab_site("js-login")
    official = decide(html, "http://luminafoundation.test/", rate=1.0)
    assert not official["triggered"] and official["skipped"] == "official_domain"
    blocked = decide(html, "http://login-luminafoundation.test/", outcome="blocked", rate=1.0)
    assert not blocked["triggered"] and blocked["skipped"] == "no_static_response"


def test_the_decision_is_recorded_even_when_the_browser_is_disabled():
    _, html = lab_site("js-login")
    d = decide(html, "http://login-luminafoundation.test/", enabled=False)
    assert d["triggered"] and d["browser_enabled"] is False


@pytest.mark.parametrize("rate", [0.0, 0.1, 0.5, 1.0])
def test_sampling_is_stable_and_follows_the_rate(rate):
    picks = [triggers.sampled(case, 0, rate) for case in range(2000)]
    assert picks == [triggers.sampled(case, 0, rate) for case in range(2000)]
    assert abs(sum(picks) / len(picks) - rate) < 0.04
    assert all(picks) if rate == 1.0 else True
    assert not any(picks) if rate == 0.0 else True
