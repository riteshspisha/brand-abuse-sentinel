"""U12 payment extractor: providers, payees, attribution (AE6, AE7)."""

from pathlib import Path

import pytest
from tests.detection_support import context, lab_registry, lab_site

from brandsentinel.analysis import AnalysisContext, Page
from brandsentinel.analysis.payment import parse_upi, payment

FIXTURES = Path(__file__).parent / "fixtures" / "html"


def pay(html, url="http://site.test/", ctx=None):
    text = html.decode() if isinstance(html, bytes) else html
    return payment(Page(text, url, ctx or context()))


def lab(site):
    expected, html = lab_site(site)
    return pay(html, expected["url"])


def obs(v, kind=None):
    return [o for o in v["observations"] if kind is None or o["kind"] == kind]


def test_ae6_donation_page_upi_payee_attributed_as_unconfirmed_brand_claim():
    # Covers AE6 (with a Razorpay script added to the lab donation page).
    _, html = lab_site("donation-fraud")
    html = html.replace(
        b"</head>", b'<script src="https://checkout.razorpay.com/v1/checkout.js"></script></head>'
    )
    v = pay(html, "http://donate-luminafoundation.test/")
    assert [p["provider"] for p in v["providers"]] == ["razorpay"]
    (upi,) = obs(v, "upi")
    assert upi["payee_identifier"] == "rivers.relief.fund@quickpaybank"
    assert upi["payee_name"] == "Lumina Relief" and upi["amount"] == "1000"
    assert upi["attribution"] == "claims_brand_unconfirmed"
    assert "Lumina Foundation" in upi["reason"]
    (bank,) = obs(v, "bank_account")
    assert bank["payee_identifier"] == "000123456789" and bank["ifsc"] == "LUMN0000001"
    assert "donate" in v["donation_cues"]
    assert v["qr_images"] == ["http://donate-luminafoundation.test/static/upi-qr.png"]


def test_ae7_unrelated_yoga_studio_with_stripe_is_unrelated():
    # Covers AE7.
    v = lab("unrelated-yoga")
    assert [p["provider"] for p in v["providers"]] == ["stripe"]
    assert {o["attribution"] for o in v["observations"]} == {"unrelated"}


def test_registry_known_payee_is_attributed_to_the_registry_entry():
    html = (Path(__file__).parents[2] / "labsites/official/donate.html").read_bytes()
    v = pay(html, "http://luminafoundation.test/donate.html")
    known = [o for o in obs(v, "upi") if o["attribution"] == "registry_known_payee"]
    assert {o["payee_identifier"] for o in known} == {"lumina.foundation@lumenbank"}
    assert known[0]["registry_payee"]["id"] == "lumina-foundation-upi"


def test_benign_shop_providers_keys_and_text_vpa_but_no_brand_claim():
    v = pay((FIXTURES / "shop_razorpay.html").read_bytes(), "https://greenmat.example/")
    vias = {(p["provider"], p["via"]) for p in v["providers"]}
    assert ("razorpay", "script") in vias and ("razorpay", "form_action") in vias
    assert [k["key"] for k in v["merchant_keys"]] == []  # key in an input value, not script
    assert [o["payee_identifier"] for o in obs(v, "upi")] == ["greenmatco@okicici"]
    assert "support@greenmat.example" not in str(v["vpas_in_text"])  # e-mail is not a VPA
    assert {o["attribution"] for o in v["observations"]} == {"unrelated"}


def test_card_fields_by_autocomplete_and_name():
    html = (
        '<form action="/pay"><input autocomplete="cc-number"><input name="cvv">'
        '<input name="card_expiry"></form>'
    )
    v = pay(html)
    assert v["card_fields"] == 3 and v["card_field_forms"] == [0]


def test_upi_link_parsing_edge_cases():
    assert parse_upi("upi://pay?pn=NoPayee") is None
    assert parse_upi("https://x/pay?pa=a@b") is None
    p = parse_upi("upi://pay?pa=Some.One%40okaxis&pn=Isha%20Foundation&am=10")
    assert p["pa"] == "some.one@okaxis" and p["pn"] == "Isha Foundation" and p["pa_valid"]
    long = parse_upi("upi://pay?pa=" + "a" * 5000 + "@x&pn=" + "b" * 5000)
    assert len(long["pa"]) <= 300 and len(long["pn"]) <= 200 and len(long["link"]) <= 500
    assert parse_upi("upi://pay?pa=ab@ybl")["pa_valid"] is True
    assert parse_upi("upi://pay?pa=not a vpa")["pa_valid"] is False


def test_upi_links_in_inline_script_and_text_are_found():
    v = pay("<script>var u='upi://pay?pa=hidden@ybl&pn=X'</script><p>pay to upi://pay?pa=t@ibl</p>")
    assert {o["payee_identifier"] for o in obs(v, "upi")} == {"hidden@ybl", "t@ibl"}


def test_without_a_registry_attribution_is_unknown():
    _, html = lab_site("donation-fraud")
    v = pay(html, ctx=AnalysisContext(lexicon=None, providers=None))
    assert {o["attribution"] for o in v["observations"]} == {"unknown"}
    assert v["providers"] == [] and v["catalog_version"] is None


@pytest.mark.parametrize("site", ["news-critical", "parody", "unrelated-tourism"])
def test_pages_without_payment_identifiers_have_no_payee_observations(site):
    assert lab(site)["payee_identifiers"] == 0


def test_lab_registry_has_the_confirmed_payee():
    assert [p.id for p in lab_registry().confirmed_payees()] == ["lumina-foundation-upi"]
