"""Which images a case's media analysis examines (pipeline/media.decide)."""

from brandsentinel.evidence.bundle import (
    AssociationBlock,
    EvidenceBundle,
    Http,
    PageBlock,
    Subject,
)
from brandsentinel.pipeline.media import decide


def brand_bundle(**kw) -> EvidenceBundle:
    return EvidenceBundle(
        subject=Subject(case_id=1, status="open", host="x.test"),
        http=Http(fetched=True, outcome="ok", status=200, analysis_round=0),
        page=PageBlock(available=True, text_chars=500),
        association=AssociationBlock(
            available=True, presented=["lumina-foundation"], strong_mention=True
        ),
        **kw,
    )


def img(n, **kw):
    return {"url": f"http://x.test/{n}.png", "index": n, "logo_hints": [], "qr_hint": False, **kw}


def test_qr_decoys_take_at_most_half_the_slots_and_the_rest_is_reported():
    images = {
        "images": [img(i, qr_hint=True) for i in range(10)] + [img(20, logo_hints=["file_name"])],
        "icons": [{"url": "http://x.test/favicon.ico", "rel": "icon"}],
    }
    d = decide(brand_bundle(), images, enabled=True, cap=8)
    roles = [c["role"] for c in d["candidates"]]
    assert roles.count("qr") == 4 and "logo" in roles and "favicon" in roles
    assert d["images_not_selected"] == 11 - len([r for r in roles if r != "favicon"])


def test_unhinted_page_images_fill_the_remaining_slots_on_a_brand_page():
    d = decide(brand_bundle(), {"images": [img(1), img(2)], "icons": []}, enabled=True, cap=8)
    assert [c["role"] for c in d["candidates"]] == ["page_image", "page_image"]
    assert all(c["qr"] and c["ocr"] for c in d["candidates"])


def test_every_candidate_gets_qr_decoding_and_duplicates_merge():
    shared = "http://x.test/1.png"
    images = {"images": [img(1)], "icons": [{"url": shared, "rel": "icon"}]}
    d = decide(brand_bundle(), images, enabled=True, cap=8)
    (c,) = d["candidates"]
    assert c["role"] == "favicon" and c["qr"] and c["ocr"]  # OCR merged from the page image


def test_unrelated_and_official_pages_are_not_collected():
    plain = EvidenceBundle(
        subject=Subject(case_id=1, status="open", host="x.test"),
        http=Http(fetched=True, outcome="ok", status=200),
        page=PageBlock(available=True, text_chars=500),
    )
    assert (
        decide(plain, {"images": [img(1)]}, enabled=True, cap=8)["skipped"] == "not_brand_related"
    )
