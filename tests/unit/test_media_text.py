"""Image text and QR payloads (analysis/media_text.py): brands, donation cues,
payees, and the near-registry-payee guard."""

import pytest
from tests.detection_support import lab_registry

from brandsentinel.analysis.association import BrandLexicon
from brandsentinel.analysis.media_text import OCR_MISREAD, media_text

LEX = BrandLexicon.from_registry(lab_registry())
REAL = "lumina.foundation@lumenbank"  # the lab's confirmed payee


def ocr(text: str) -> dict:
    return {"sha256": "a" * 64, "role": "page_image", "ocr_text": text, "qr": []}


@pytest.mark.parametrize(
    ("vpa", "near"),
    [
        ("lumina.foundati0n@lumenbank", True),  # one edit
        ("lumina.foundatio@lumenbnk", True),  # two edits
        ("lumina.fondatio@lumenbnk", False),  # three edits
        (REAL, False),  # the payee itself
    ],
)
def test_near_registry_payee_guard(vpa, near):
    (o,) = media_text([ocr(f"UPI: {vpa}")], LEX, [])["observations"]
    if near:
        assert o["attribution"] == OCR_MISREAD and o["brands"] == ["lumina-foundation"]
    else:
        assert o["attribution"] != OCR_MISREAD
    if vpa == REAL:
        assert o["attribution"] == "registry_known_payee"


def test_qr_identifiers_are_exact_never_misread():
    qr = {"sha256": "b" * 64, "role": "qr", "ocr_text": "",
          "qr": ["upi://pay?pa=lumina.foundati0n@lumenbank&pn=Lumina"]}  # fmt: skip
    (o,) = media_text([qr], LEX, [])["observations"]
    assert o["source"] == "qr_code" and o["attribution"] == "claims_brand_unconfirmed"


def test_brands_donation_cues_and_presented():
    out = media_text([ocr("Lumina Foundation flood relief: donate today")], LEX, [])
    assert out["presented"] == ["lumina-foundation"] and "donate" in out["donation_cues"]
    weak = media_text([ocr("Lumina lanterns at the valley festival")], LEX, [])
    assert weak["presented"] == []  # a common word alone presents nothing


def test_without_a_registry_nothing_is_derived():
    assert media_text([ocr("Lumina Foundation")], None, []) == {"available": False}
