"""policy/3 over visual evidence (U17, KTD17, R29): a visual match or OCR text is
never proof alone; missing visual evidence is never a benign verdict; bundles
without media data score as before."""

import json

from tests.detection_support import policy
from tests.unit.test_policy import LUMINA, brand_page, bundle

from brandsentinel.evidence.bundle import (
    AssociationBlock,
    Discovery,
    EditorialBlock,
    EvidenceBundle,
    PageBlock,
    PaymentBlock,
    PaymentObservation,
    RegistryContext,
    VisualBlock,
    VisualImage,
    VisualMatch,
    bundle_json,
)
from brandsentinel.policy.scorer import evaluate

LOGO_SHA = "a" * 64
OTHER_SHA = "b" * 64
REF = {
    "corpus_id": 1,
    "brand": "lumina-foundation",
    "kind": "logo",
    "origin": "registry_asset",
    "asset_id": "lumina-logo",
    "reference_page": None,
    "source": "registry/assets/lab/lumina-logo.png",
    "sha256": "c" * 64,
}


def match(method="perceptual") -> VisualMatch:
    return VisualMatch(
        image_sha256=LOGO_SHA,
        image_ref="http://x.test/logo.png",
        role="logo",
        method=method,
        phash_distance=2,
        dhash_distance=3,
        reference=REF,
        refs=["feature:9", "fact:8", f"artifact:{LOGO_SHA}"],
    )


def visual(**kw) -> VisualBlock:
    return VisualBlock(
        **{
            "status": "complete",
            "analysis_round": 0,
            "matches": [match()],
            "corpus_entries": 1,
            "refs": ["fact:7", "fact:8"],
            **kw,
        }
    )


STRONG_DOMAIN = Discovery(
    domain_match="strong",
    hits=[{"type": "keyword", "keyword": "luminafoundation", "brand": "lumina-foundation"}],
    refs=["discovery_event:1"],
)
WEAK_DOMAIN = Discovery(
    domain_match="weak",
    hits=[{"type": "low_tier_token", "keyword": "lumina", "brand": "lumina-foundation"}],
    refs=["discovery_event:1"],
)


def rules(result) -> set[str]:
    return {r.rule for r in result.reasons}


def test_copied_logo_on_a_lookalike_presenting_the_brand_is_p1_impersonation():
    r = evaluate(
        bundle(discovery=STRONG_DOMAIN, association=brand_page(), visual=visual()), policy()
    )
    assert {"copied_asset_match", "lookalike_domain_brand_content"} <= rules(r)
    assert r.priority == "P1" and r.category == "impersonation"
    reason = next(x for x in r.reasons if x.rule == "copied_asset_match")
    assert f"artifact:{LOGO_SHA}" in reason.evidence and "feature:9" in reason.evidence
    assert "registry/assets/lab/lumina-logo.png" in reason.explanation
    assert "the domain name matches Lumina Foundation" in reason.explanation


def test_a_visual_match_alone_never_reaches_p1_or_p2():
    r = evaluate(bundle(visual=visual()), policy())
    assert rules(r) == {"visual_match_uncorroborated"}
    assert r.priority == "P4" and r.category != "impersonation"
    assert any("not treated as impersonation" in m for m in r.manual_review)


def test_ocr_of_the_matched_image_itself_is_not_corroboration():
    ocr = [{"brand": "lumina-foundation", "strength": "strong", "images": [LOGO_SHA]}]
    v = visual(ocr_brands=ocr, ocr_presented=["lumina-foundation"])
    assert "copied_asset_match" not in rules(evaluate(bundle(visual=v), policy()))


def test_brand_text_in_another_image_corroborates():
    ocr = [{"brand": "lumina-foundation", "strength": "strong", "images": [OTHER_SHA]}]
    v = visual(ocr_brands=ocr, ocr_presented=["lumina-foundation"])
    r = evaluate(bundle(visual=v), policy())
    assert "copied_asset_match" in rules(r)
    assert "another image on the page shows" in next(
        x.explanation for x in r.reasons if x.rule == "copied_asset_match"
    )


def test_corroboration_must_be_for_the_matched_brand():
    other = AssociationBlock(
        available=True,
        brands=[{**LUMINA, "brand": "master-orin", "name": "Master Orin"}],
        presented=["master-orin"],
        strong_mention=True,
    )
    assert "copied_asset_match" not in rules(
        evaluate(bundle(association=other, visual=visual()), policy())
    )


def test_a_mere_body_mention_is_not_presentation():
    mention = AssociationBlock(
        available=True,
        brands=[{**LUMINA, "locations": ["body"], "strong_locations": ["body"]}],
        presented=[],
        strong_mention=True,
    )
    assert "copied_asset_match" not in rules(
        evaluate(bundle(association=mention, visual=visual()), policy())
    )


def test_weak_domain_corroboration_alone_stays_below_p2():
    r = evaluate(bundle(discovery=WEAK_DOMAIN, visual=visual()), policy())
    assert "copied_asset_match" in rules(r) and r.priority == "P3"


def test_official_domain_and_confirmed_partner_are_never_flagged_for_their_logo():
    for reg in (
        RegistryContext(official_domain="luminafoundation.test"),
        RegistryContext(
            confirmed_relationships=[
                {"from": "brand:lumina-foundation", "to": "domain:x.test", "type": "partner"}
            ]
        ),
    ):
        r = evaluate(bundle(association=brand_page(), registry=reg, visual=visual()), policy())
        assert not {"copied_asset_match", "visual_match_uncorroborated"} & rules(r)


def test_editorial_cues_do_not_lower_a_copied_asset_finding():
    """R29/AE15 for visuals: an article with the brand's logo stays at P3 for
    review; adding article markup or a parody label changes nothing."""
    plain = evaluate(bundle(association=brand_page(), visual=visual()), policy())
    news = evaluate(
        bundle(
            association=brand_page(),
            visual=visual(),
            editorial=EditorialBlock(
                editorial=True, article_markup={"present": True}, parody_cues=["satire"]
            ),
        ),
        policy(),
    )
    assert plain.score == news.score and plain.priority == news.priority == "P3"
    assert "editorial_or_critical" in news.labels


def _qr_payee(attribution="claims_brand_unconfirmed", ident="rivers.relief.fund@quickpaybank"):
    return PaymentObservation(
        kind="upi",
        source="qr_code",
        identifier_type="upi_vpa",
        payee_identifier=ident,
        payee_name="Lumina Relief",
        attribution=attribution,
        attributed_brands=["lumina-foundation"],
        extractor_version="media_text/1",
        refs=["feature:11", "fact:8"],
    )


def test_image_only_appeal_with_qr_payee_is_donation_fraud():
    """FA4: brand and appeal exist only in images."""
    b = bundle(
        page=PageBlock(available=True, image_only=True, text_chars=0),
        incomplete=["image_only"],
        payment=PaymentBlock(observations=[_qr_payee()], refs=["feature:11"]),
        visual=visual(matches=[], ocr_presented=["lumina-foundation"], donation_cues=["donate"]),
    )
    r = evaluate(b, policy())
    assert "payment_brand_unconfirmed_payee" in rules(r)
    assert r.category == "donation_fraud" and r.priority in ("P1", "P2")


def test_ocr_misread_of_the_registry_payee_is_neither_abuse_nor_relief():
    obs = _qr_payee("possible_ocr_misread_of_registry_payee", "lumina.foundati0n@lumenbank")
    obs = obs.model_copy(update={"source": "image_text", "payee_name": None})
    r = evaluate(
        bundle(association=brand_page(), payment=PaymentBlock(observations=[obs])), policy()
    )
    assert not {"payment_brand_unconfirmed_payee", "confirmed_payee"} & rules(r)
    assert any("misreading by OCR" in m for m in r.manual_review)


def test_missing_visual_evidence_is_unknown_never_benign():
    page = brand_page()
    for status, unknown in (
        ("pending", "media analysis is queued"),
        ("failed", "media analysis failed"),
        ("disabled", "media analysis is disabled"),
    ):
        v = VisualBlock(status=status, reasons=["qr_candidates"])
        r = evaluate(bundle(association=page, visual=v, incomplete=[f"media_{status}"]), policy())
        assert "needs_media" in r.flags and any(unknown in u for u in r.unknowns)


def test_rejected_images_are_reported_and_labelled():
    v = visual(
        matches=[],
        status="partial",
        images=[VisualImage(ref="http://x.test/b.png", role="logo", status="rejected",
                            reason="decompression_bomb")],
        rejected=[{"ref": "http://x.test/b.png", "role": "logo", "reason": "decompression_bomb"}],
    )  # fmt: skip
    r = evaluate(
        bundle(association=brand_page(), visual=v, incomplete=["media_rejected"]), policy()
    )
    assert "media_rejected" in r.labels
    assert any("decompression_bomb" in m and "not benign" in m for m in r.manual_review)


def test_bundles_without_media_data_score_as_before():
    """Backward compatibility: a stored bundle/2 document loads and, having no
    visual block, fires exactly the rules it fired under policy/2."""
    current = bundle(discovery=STRONG_DOMAIN, association=brand_page())
    doc = json.loads(bundle_json(current))
    doc["schema_version"] = "bundle/2"
    del doc["visual"]
    old = EvidenceBundle.model_validate(doc)
    assert old.schema_version == "bundle/2" and old.visual.status == "not_run"
    a, b = evaluate(old, policy()), evaluate(current, policy())
    assert (a.score, a.priority, a.category, rules(a)) == (
        b.score,
        b.priority,
        b.category,
        rules(b),
    )
    assert not {"copied_asset_match", "visual_match_uncorroborated"} & rules(a)
