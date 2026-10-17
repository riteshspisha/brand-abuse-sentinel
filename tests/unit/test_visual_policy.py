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
        visual=visual(
            matches=[],
            ocr_presented=["lumina-foundation"],
            ocr_brands=[{**LUMINA, "images": [OTHER_SHA]}],
            donation_cues=["donate"],
        ),
    )
    r = evaluate(b, policy())
    reason = next(x for x in r.reasons if x.rule == "payment_brand_unconfirmed_payee")
    assert "under Lumina Foundation" in reason.explanation  # the name, read from the image
    assert r.category == "donation_fraud" and r.priority in ("P1", "P2")


def test_lookalike_of_the_registry_payee_in_image_text_is_an_unconfirmed_payee():
    """Review fix: an OCR identifier within two characters of the confirmed
    payee may be a misreading or a deliberate lookalike: never relief, counted
    as an unconfirmed payee of that brand, and explained for review."""
    obs = _qr_payee("possible_ocr_misread_of_registry_payee", "lumina.foundati0n@lumenbank")
    obs = obs.model_copy(update={"source": "image_text", "payee_name": None})
    r = evaluate(
        bundle(association=brand_page(), payment=PaymentBlock(observations=[obs])), policy()
    )
    assert "payment_brand_unconfirmed_payee" in rules(r) and "confirmed_payee" not in rules(r)
    assert any("never as relief" in m for m in r.manual_review)


def test_payee_resting_on_the_matched_images_own_text_is_not_corroboration():
    """Review fix: a nameless QR payee attributed only because the matched logo
    itself reads as the brand does not corroborate copied_asset_match."""
    ocr = [{"brand": "lumina-foundation", "strength": "strong", "images": [LOGO_SHA]}]
    payee = _qr_payee().model_copy(
        update={"payee_name": None, "attribution_reason": "page presents Lumina Foundation (...)"}
    )
    b = bundle(
        payment=PaymentBlock(observations=[payee]),
        visual=visual(ocr_brands=ocr, ocr_presented=["lumina-foundation"]),
    )
    assert "copied_asset_match" not in rules(evaluate(b, policy()))
    # A QR payee from another image whose own name names the brand does tie it.
    named = _qr_payee().model_copy(
        update={"attribution_reason": "payee name 'Lumina Relief' ...", "image_sha256": OTHER_SHA}
    )
    b2 = bundle(payment=PaymentBlock(observations=[named]), visual=visual(ocr_brands=ocr))
    assert "copied_asset_match" in rules(evaluate(b2, policy()))


def test_unexamined_images_are_reported():
    r = evaluate(
        bundle(association=brand_page(), visual=visual(matches=[], images_not_selected=3)), policy()
    )
    assert any("3 page image(s) were not examined" in u for u in r.unknowns)


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


# --- a matched image must not corroborate itself through a payee (PR #9) --------------


def _media_payee(image, attribution="possible_ocr_misread_of_registry_payee", source="image_text"):
    reason = (
        "read by OCR within two characters of confirmed registry payee lumina-foundation-upi"
        if attribution == "possible_ocr_misread_of_registry_payee"
        else "payee name 'Lumina Foundation' names Lumina Foundation; not a confirmed payee"
    )
    return PaymentObservation(
        kind="upi",
        source=source,
        identifier_type="upi_vpa",
        payee_identifier="lumina.foundati0n@lumenbank",
        attribution=attribution,
        attribution_reason=reason,
        attributed_brands=["lumina-foundation"],
        extractor_version="media_text/1",
        image_sha256=image,
        refs=["feature:11", "fact:8"],
    )


def _corroborated(*payees, **visual_kw) -> set[str]:
    b = bundle(payment=PaymentBlock(observations=list(payees)), visual=visual(**visual_kw))
    return rules(evaluate(b, policy()))


def test_ocr_lookalike_payee_from_the_matched_image_does_not_corroborate():
    fired = _corroborated(_media_payee(LOGO_SHA))
    assert "copied_asset_match" not in fired and "visual_match_uncorroborated" in fired
    assert "payment_brand_unconfirmed_payee" in fired  # the lookalike payee still scores


def test_qr_payee_named_for_the_brand_from_the_matched_image_does_not_corroborate():
    p = _media_payee(LOGO_SHA, "claims_brand_unconfirmed", "qr_code")
    assert "copied_asset_match" not in _corroborated(p)


def test_the_same_payees_from_an_unmatched_image_corroborate():
    assert "copied_asset_match" in _corroborated(_media_payee(OTHER_SHA))
    qr = _media_payee(OTHER_SHA, "claims_brand_unconfirmed", "qr_code")
    assert "copied_asset_match" in _corroborated(qr)


def test_page_text_payee_named_for_the_brand_corroborates():
    page = _media_payee(None, "claims_brand_unconfirmed", "deep_link")
    assert "copied_asset_match" in _corroborated(page)


def test_one_independent_payee_is_enough_among_self_derived_ones():
    fired = _corroborated(_media_payee(LOGO_SHA), _media_payee(OTHER_SHA))
    assert "copied_asset_match" in fired


def test_every_matched_image_is_excluded_not_only_the_first():
    second = match().model_copy(
        update={"image_sha256": OTHER_SHA, "image_ref": "http://x.test/b.png"}
    )
    fired = _corroborated(_media_payee(OTHER_SHA), matches=[match(), second])
    assert "copied_asset_match" not in fired


def test_media_payee_of_unknown_source_image_is_not_counted_as_independent():
    """A bundle stored before the source image was recorded (image_sha256 None)
    cannot show the payee came from elsewhere; it does not corroborate."""
    assert "copied_asset_match" not in _corroborated(_media_payee(None))


def test_credential_and_text_corroboration_are_unaffected():
    fired = rules(
        evaluate(
            bundle(
                association=brand_page(),
                payment=PaymentBlock(observations=[_media_payee(LOGO_SHA)]),
                visual=visual(),
            ),
            policy(),
        )
    )
    assert "copied_asset_match" in fired  # the page presents the brand itself


def test_stored_bundle3_without_payee_image_still_loads():
    """bundle/3 documents written before image_sha256 existed load (default None)."""
    current = bundle(payment=PaymentBlock(observations=[_media_payee(LOGO_SHA)]), visual=visual())
    doc = json.loads(bundle_json(current))
    for o in doc["payment"]["observations"]:
        del o["image_sha256"]
    old = EvidenceBundle.model_validate(doc)
    assert old.payment.observations[0].image_sha256 is None
