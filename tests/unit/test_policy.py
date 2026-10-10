"""U14 policy scorer.

Two layers of tests, so a false positive or negative can be traced to the layer
that caused it:

- pure policy tests over hand-written EvidenceBundles (no HTML, no extractors);
- end-to-end policy tests over real lab and fixture HTML (extractors + policy).
"""

from pathlib import Path

import pytest
import yaml
from tests.detection_support import (
    REPO,
    bundle_for_html,
    lab_registry,
    lab_site,
    lab_sites,
    policy,
    score_html,
    score_lab,
)

from brandsentinel.evidence.bundle import (
    AssociationBlock,
    CredentialBlock,
    Discovery,
    EditorialBlock,
    EvidenceBundle,
    Http,
    PageBlock,
    PaymentBlock,
    PaymentObservation,
    RegistryContext,
    Subject,
)
from brandsentinel.policy.rules import RULES
from brandsentinel.policy.scorer import Policy, PolicyError, evaluate

FIXTURES = Path(__file__).parent / "fixtures" / "html"
LUMINA = {
    "brand": "lumina-foundation",
    "name": "Lumina Foundation",
    "strength": "strong",
    "count": 3,
    "locations": ["title", "body"],
    "strong_locations": ["title"],
}


# --- pure policy (hand-written bundles) ----------------------------------------------


def bundle(**blocks) -> EvidenceBundle:
    base = {
        "subject": Subject(case_id=1, status="open", host="x.test", registrable_domain="x.test"),
        "http": Http(
            fetched=True,
            outcome="ok",
            status=200,
            final_url="http://x.test/",
            refs=["fact:1", "artifact:aa"],
        ),
        "page": PageBlock(available=True, title="t", text_chars=500, refs=["feature:2"]),
    }
    base.update(blocks)
    return EvidenceBundle(**base)


def brand_page(**kw) -> AssociationBlock:
    return AssociationBlock(
        available=True,
        brands=[LUMINA],
        presented=["lumina-foundation"],
        strong_mention=True,
        refs=["feature:3"],
        **kw,
    )


def payee(attribution="claims_brand_unconfirmed", ident="fake@okaxis", **kw) -> PaymentObservation:
    return PaymentObservation(
        kind="upi",
        identifier_type="upi_vpa",
        payee_identifier=ident,
        payee_name="Isha Foundation",
        attribution=attribution,
        attributed_brands=["lumina-foundation"],
        extractor_version="payment/1",
        refs=["feature:4", "fact:1"],
        **kw,
    )


def gateway(attribution="claims_brand_unconfirmed", source="script") -> PaymentObservation:
    return PaymentObservation(
        kind="gateway",
        provider="razorpay",
        source=source,
        attribution=attribution,
        extractor_version="payment/1",
        refs=["feature:4"],
    )


def credential_form(**kw) -> CredentialBlock:
    form = {
        "index": 0,
        "method": "POST",
        "action": "http://x.test/login",
        "cross_origin": False,
        "password_fields": 1,
        "otp_fields": 0,
        "brands_in_context": [{"brand": "lumina-foundation", "strength": "strong"}],
        **kw,
    }
    return CredentialBlock(
        password_fields=1,
        forms=[form],
        cross_origin_forms=int(form["cross_origin"]),
        refs=["feature:2"],
    )


def rules_of(result):
    return {r.rule for r in result.reasons}


def test_ae6_brand_donation_unconfirmed_upi_and_gateway_is_high_but_gateway_alone_is_zero():
    # Covers AE6: the combination raises priority; the gateway alone contributes nothing.
    b = bundle(
        association=brand_page(),
        payment=PaymentBlock(
            observations=[payee(), gateway()],
            donation_cues=["donate"],
            providers=[{"provider": "razorpay", "name": "Razorpay"}],
            refs=["feature:4"],
        ),
    )
    r = evaluate(b, policy())
    assert r.priority in ("P1", "P2") and r.category == "donation_fraud"
    gateway_only = bundle(
        association=brand_page(),
        payment=PaymentBlock(
            observations=[gateway()], providers=[{"provider": "razorpay"}], refs=["feature:4"]
        ),
    )
    g = evaluate(gateway_only, policy())
    assert g.score == 0 and g.priority == "no_action" and "payment_gateway_present" in g.labels


def test_ae7_unrelated_checkout_without_brand_is_no_action():
    b = bundle(
        payment=PaymentBlock(
            observations=[
                gateway("unrelated", "form_action"),
                payee("unrelated", "studio@okicici"),
            ],
            card_fields=2,
            providers=[{"provider": "stripe"}],
        )
    )
    r = evaluate(b, policy())
    assert r.priority == "no_action" and r.category == "unrelated" and r.score == 0


def test_brand_mention_alone_is_never_high():
    r = evaluate(
        bundle(
            association=brand_page(),
            discovery=Discovery(domain_match="strong", hits=[{"type": "keyword", "keyword": "x"}]),
        ),
        policy(),
    )
    # Lookalike + brand content is impersonation evidence; without the lookalike
    # domain the same content is just a mention.
    plain = evaluate(bundle(association=brand_page()), policy())
    assert plain.priority == "no_action" and plain.category == "benign_related"
    assert r.category == "impersonation"


def test_page_provided_editorial_signals_never_lower_a_score():
    abusive = dict(
        association=brand_page(),
        credential=credential_form(),
        discovery=Discovery(domain_match="weak", hits=[{"type": "token"}]),
    )
    plain = evaluate(bundle(**abusive), policy())
    dressed = evaluate(
        bundle(
            **abusive,
            editorial=EditorialBlock(
                editorial=True,
                article_markup={"present": True, "schema_types": ["newsarticle"]},
                byline="By Staff",
                parody_cues=["parody", "satire"],
                disclaimer_cues=["not affiliated"],
                refs=["feature:5"],
            ),
        ),
        policy(),
    )
    assert dressed.score == plain.score and dressed.priority == plain.priority
    assert plain.priority in ("P1", "P2")
    assert "editorial_or_critical" in dressed.labels and "editorial_or_critical" not in plain.labels
    assert any("did not lower" in m for m in dressed.manual_review)


def test_attacker_disclaimer_does_not_suppress_payment_abuse():
    disclaimed = brand_page(disclaimers=[{"kind": "affiliated", "snippet": "not affiliated"}])
    b = bundle(
        association=disclaimed,
        payment=PaymentBlock(observations=[payee()], donation_cues=["donate"]),
    )
    r = evaluate(b, policy())
    assert r.priority in ("P1", "P2") and "disclaimer_present" in r.labels


def test_confirmed_payee_lowers_score_and_cites_the_registry():
    unknown = bundle(
        association=brand_page(),
        payment=PaymentBlock(observations=[payee()], donation_cues=["donate"]),
    )
    known = bundle(
        association=brand_page(),
        payment=PaymentBlock(
            observations=[
                payee(
                    "registry_known_payee",
                    registry_payee={
                        "id": "lumina-upi",
                        "name": "Lumina Foundation",
                        "brand": "lumina-foundation",
                    },
                )
            ],
            donation_cues=["donate"],
        ),
    )
    ru, rk = evaluate(unknown, policy()), evaluate(known, policy())
    assert rk.score < ru.score
    relief = next(x for x in rk.reasons if x.rule == "confirmed_payee")
    assert relief.points < 0 and "registry:payee:lumina-upi" in relief.evidence


def test_conflicting_indicators_known_and_unknown_payees_with_parody_label():
    b = bundle(
        association=brand_page(disclaimers=[{"kind": "affiliated", "snippet": "parody"}]),
        editorial=EditorialBlock(editorial=True, parody_cues=["parody"]),
        payment=PaymentBlock(
            observations=[
                payee(
                    "registry_known_payee",
                    "lumina.foundation@lumenbank",
                    registry_payee={"id": "p1", "name": "L", "brand": "lumina-foundation"},
                ),
                payee(),
            ],
            donation_cues=["donate"],
        ),
        credential=credential_form(cross_origin=True, action_registrable_domain="evil.test"),
    )
    r = evaluate(b, policy())
    fired = rules_of(r)
    assert {
        "credential_form_brand",
        "credential_cross_origin",
        "payment_brand_unconfirmed_payee",
        "donation_appeal_unconfirmed_payee",
    } <= fired
    # A known payee beside an unconfirmed one earns no relief (decoy payee).
    assert "confirmed_payee" not in fired
    assert r.category == "credential_phishing" and r.priority == "P1"
    assert "editorial_or_critical" in r.labels


def test_credential_form_without_brand_tie_is_not_abuse_but_flagged():
    form = credential_form(brands_in_context=[])
    r = evaluate(bundle(association=brand_page(), credential=form), policy())
    assert "credential_form_brand" not in rules_of(r) and r.priority == "no_action"
    assert any("credential form is present" in m for m in r.manual_review)


def test_official_domain_is_no_action_whatever_the_content():
    b = bundle(
        association=brand_page(),
        credential=credential_form(),
        payment=PaymentBlock(observations=[payee()], donation_cues=["donate"]),
        registry=RegistryContext(official_domain="luminafoundation.test"),
    )
    r = evaluate(b, policy())
    assert r.priority == "no_action" and r.category == "benign_related"
    assert rules_of(r) == {"official_domain"} and "official_domain" in r.labels


def test_redirect_to_official_domain_is_relief_not_impersonation():
    b = bundle(
        association=brand_page(),
        discovery=Discovery(domain_match="strong", hits=[{"type": "keyword"}]),
        registry=RegistryContext(final_url_official_domain="luminafoundation.test"),
    )
    r = evaluate(b, policy())
    assert "lookalike_domain_brand_content" not in rules_of(r)
    assert "redirects_to_official" in rules_of(r) and r.priority in ("P4", "no_action")


def test_confirmed_relationship_blocks_false_association():
    claims = brand_page(
        claims=[{"kind": "partner", "brands": ["lumina-foundation"], "snippet": "official partner"}]
    )
    rel = [{"from": "domain:x.test", "to": "brand:lumina-foundation", "type": "partner"}]
    r = evaluate(
        bundle(association=claims, registry=RegistryContext(confirmed_relationships=rel)), policy()
    )
    assert "false_association_claim" not in rules_of(r) and "confirmed_relationship" in rules_of(r)
    assert evaluate(bundle(association=claims), policy()).category == "false_association"


def test_unobserved_content_is_insufficient_evidence_never_benign():
    for page, http in [
        (PageBlock(available=True, js_shell=True), Http(fetched=True, outcome="ok")),
        (PageBlock(), Http(fetched=True, outcome="connect_error")),
        (PageBlock(), Http()),
    ]:
        incomplete = (
            ["js_shell"]
            if page.js_shell
            else (["fetch_connect_error"] if http.fetched else ["not_fetched"])
        )
        b = bundle(
            page=page,
            http=http,
            incomplete=incomplete,
            discovery=Discovery(domain_match="strong", hits=[{"type": "keyword"}]),
        )
        r = evaluate(b, policy())
        assert r.category == "insufficient_evidence" and r.priority == "P3", incomplete
        assert "manual_review" in r.flags
    quiet = evaluate(
        bundle(page=PageBlock(available=True, image_only=True), incomplete=["image_only"]), policy()
    )
    assert quiet.priority == "P4" and "needs_media" in quiet.flags  # floored, not no_action


def test_parked_typosquat_is_p3_never_p1_or_p2():
    b = bundle(
        page=PageBlock(available=True, parked_cues=[{"category": "for_sale", "cue": "x"}]),
        discovery=Discovery(domain_match="strong", hits=[{"type": "official_lookalike"}]),
        infrastructure={"domain_age_days": 3, "dns_mixed_private": True},
    )
    r = evaluate(b, policy())
    assert r.score >= 50 and r.priority == "P3" and r.capped and r.category == "typosquat_parked"


def test_model_judgment_flags_review_on_p3_but_not_p1_and_never_changes_priority():
    p3 = bundle(
        page=PageBlock(available=True, parked_cues=[{"category": "for_sale", "cue": "x"}]),
        discovery=Discovery(domain_match="strong", hits=[{"type": "keyword"}]),
    )
    judgment = [{"probabilities": {"brand_impersonation": 0.95}}]
    r = evaluate(p3, policy(), judgment)
    assert r.priority == "P3" and "model_suggests_review" in r.flags
    p1 = bundle(association=brand_page(), credential=credential_form())
    assert "model_suggests_review" not in evaluate(p1, policy(), judgment).flags
    assert evaluate(p1, policy(), judgment).priority == evaluate(p1, policy()).priority


def test_changing_a_weight_in_policy_yaml_changes_the_score(tmp_path):
    data = yaml.safe_load((REPO / "config/policy.yaml").read_text())
    data["points"]["false_association_claim"] = 5
    data["version"] = "policy/test"
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    changed = Policy.load(path)
    b = bundle(association=brand_page(claims=[{"kind": "partner", "brands": [], "snippet": "x"}]))
    assert evaluate(b, changed).score == 5 and evaluate(b, policy()).score == 45
    assert evaluate(b, changed).policy_version == "policy/test"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["points"].pop("blocked_redirect"),
        lambda d: d["points"].update(made_up_rule=5),
        lambda d: d["thresholds"].update(P2=90),
        lambda d: d["points"].update(official_domain=-5),
        lambda d: d.update(max_priority_without_abuse="P0"),
    ],
)
def test_invalid_policies_are_refused(tmp_path, mutate):
    data = yaml.safe_load((REPO / "config/policy.yaml").read_text())
    mutate(data)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(PolicyError):
        Policy.load(path)


def test_every_rule_is_documented_and_weighted():
    assert set(policy().points) == set(RULES)
    assert all(r.summary for r in RULES.values())
    assert {r.kind for r in RULES.values()} == {"abuse", "supporting", "relief"}


# --- extractors + policy over real HTML ------------------------------------------------

STATIC_SITES = [s for s in lab_sites() if lab_site(s)[0]["detected_by"] == "static"]
LATER_SITES = [s for s in lab_sites() if lab_site(s)[0]["detected_by"] != "static"]


@pytest.mark.parametrize("site", STATIC_SITES)
def test_static_lab_sites_reach_their_expected_band_category_and_labels(site):
    expected = lab_site(site)[0]["expected"]
    _, r = score_lab(site)
    assert r.priority in expected["priority"], (site, r.summary)
    assert r.category == expected["category"], (site, r.summary)
    for label in expected["labels"]:
        if label != "official_domain":
            assert label in r.labels, (site, label, r.labels)


@pytest.mark.parametrize("site", LATER_SITES)
def test_media_and_browser_lab_sites_are_never_reported_benign_statically(site):
    # Their abuse is visible only to media analysis (M6) or a browser (M7). Static
    # analysis must say what it could not see rather than call them benign.
    _, r = score_lab(site)
    assert r.category not in ("benign_related", "unrelated"), (site, r.summary)
    assert r.priority != "no_action"
    assert r.flags or r.reasons, site


def test_ae15_credential_page_scores_the_same_without_article_markup_and_disclaimer():
    # Covers AE15 with the disguised-credential lab page.
    expected, html = lab_site("disguised-credential")
    _, dressed = score_html(html, expected["url"])
    stripped = (
        html.replace(b'<meta property="og:type" content="article">', b"")
        .replace(b"<article>", b"<div>")
        .replace(b"</article>", b"</div>")
        .replace(b'<p class="byline">By Staff Writer</p>', b"")
        .replace(b"<p><em>Parody disclaimer: this site is satire.</em></p>", b"")
    )
    stripped = (
        stripped.split(b'<script type="application/ld+json">')[0]
        + b"</head>"
        + stripped.split(b"</head>", 1)[1]
    )
    b_plain, plain = score_html(stripped, expected["url"])
    assert not b_plain.editorial.editorial and not b_plain.editorial.parody_cues
    assert dressed.score == plain.score and dressed.priority == plain.priority == "P1"
    assert "editorial_or_critical" in dressed.labels and "editorial_or_critical" not in plain.labels


def test_ae16_critical_news_article_is_editorial_at_p4_or_no_action():
    _, r = score_lab("news-critical")
    assert r.category == "editorial_or_critical" and r.priority in ("P4", "no_action")
    assert not [x for x in r.reasons if x.kind == "abuse"]


def test_hard_negative_news_site_with_its_own_login_form():
    b, r = score_html(
        (FIXTURES / "news_with_login.html").read_bytes(), "https://metrotimes-news.test/2026/lumina"
    )
    assert b.credential.cross_origin_forms == 1  # its own SSO domain
    assert not [x for x in r.reasons if x.kind == "abuse"], r.summary
    assert r.category == "editorial_or_critical" and r.priority in ("P4", "no_action")
    assert "manual_review" in r.flags  # the unexplained credential form is surfaced


def test_hard_negative_benign_shop_with_razorpay_and_upi():
    _, r = score_html((FIXTURES / "shop_razorpay.html").read_bytes(), "https://greenmat.test/")
    assert r.priority == "no_action" and r.category == "unrelated"
    assert {"commerce", "payment_gateway_present"} <= set(r.labels)


def test_blocked_redirect_and_empty_pages():
    hops = [
        {
            "url": "http://go-luminafoundation.test/to-metadata",
            "status": 302,
            "location": "http://169.254.169.254/latest/meta-data/",
        },
        {"url": "http://169.254.169.254/latest/meta-data/", "error": {"kind": "blocked"}},
    ]
    b, r = score_html(
        b"",
        "http://go-luminafoundation.test/to-metadata",
        outcome="blocked_redirect",
        hops=hops,
        error={"kind": "blocked_address"},
    )
    assert "blocked_redirect" in rules_of(r) and r.category == "insufficient_evidence"
    assert r.priority == "P3" and b.http.redirect_chain[0].location.startswith("http://169.254")
    _, empty = score_html(b"<html><body></body></html>", "http://x-luminafoundation.test/")
    assert empty.category == "insufficient_evidence" and "empty_page" in empty.unknowns


def test_truncated_page_keeps_findings_and_asks_for_review():
    expected, html = lab_site("disguised-credential")
    cut = html.index(b'name="password">') + len(b'name="password">')  # body ends mid-form
    _, r = score_html(html[:cut], expected["url"], truncated="raw_cap")
    assert r.priority == "P1" and any("truncated" in m for m in r.manual_review)


def test_every_reason_cites_evidence_that_exists_in_the_bundle():
    registry = lab_registry()
    for site in lab_sites():
        b, r = score_lab(site)
        known = set(
            b.http.refs
            + b.page.refs
            + b.credential.refs
            + b.payment.refs
            + b.association.refs
            + b.commerce.refs
            + b.editorial.refs
            + b.infrastructure.refs
            + b.discovery.refs
        )
        payees = {p.id for p in registry.payees}
        domains = {d.name for d in registry.domains}
        for reason in r.reasons:
            assert reason.evidence, (site, reason.rule)
            for ref in reason.evidence:
                kind, _, value = ref.partition(":")
                if kind == "registry":
                    sub, _, name = value.partition(":")
                    assert name in (payees if sub == "payee" else domains), ref
                else:
                    assert ref in known, (site, reason.rule, ref)


def test_scoring_is_deterministic():
    expected, html = lab_site("donation-fraud")
    first = evaluate(bundle_for_html(html, expected["url"]), policy())
    second = evaluate(bundle_for_html(html, expected["url"]), policy())
    assert first.model_dump_json() == second.model_dump_json()


def test_weak_domain_token_with_an_unrelated_login_is_not_credential_abuse():
    # A common word in the domain (a place or a person called Lumina/Isha) plus a
    # site login must not read as brand credential phishing.
    form = credential_form(brands_in_context=[])
    weak = Discovery(domain_match="weak", hits=[{"type": "token", "keyword": "lumina"}])
    r = evaluate(bundle(credential=form, discovery=weak), policy())
    assert "credential_form_brand" not in rules_of(r) and r.priority in ("P4", "no_action")
    with_brand = evaluate(
        bundle(credential=form, discovery=weak, association=brand_page()), policy()
    )
    assert "credential_form_brand" in rules_of(with_brand)


def test_client_redirect_compares_registrable_domains():
    page = PageBlock(
        available=True,
        meta_refresh=[{"url": "http://evilx.test/"}],
        script_redirects=[{"kind": "location_assign", "url": "http://a.x.test/"}],
    )
    r = evaluate(
        bundle(page=page, discovery=Discovery(domain_match="strong", hits=[{"type": "keyword"}])),
        policy(),
    )
    reason = next(x for x in r.reasons if x.rule == "client_redirect_offsite")
    assert "evilx.test" in reason.explanation and "a.x.test" not in reason.explanation


def test_final_url_with_port_is_parsed_for_official_redirect():
    b = bundle_for_html("<title>Lumina Foundation</title>", "http://luminafoundation.test:8080/")
    assert b.http.final_host == "luminafoundation.test"


def test_weak_term_near_a_form_does_not_tie_credentials_to_the_brand():
    weak_near = credential_form(
        brands_in_context=[{"brand": "lumina-foundation", "strength": "weak"}]
    )
    r = evaluate(bundle(credential=weak_near), policy())
    assert "credential_form_brand" not in rules_of(r)


def test_confirmed_partner_login_and_checkout_are_not_abuse():
    rel = [{"from": "domain:x.test", "to": "brand:lumina-foundation", "type": "partner"}]
    b = bundle(
        association=brand_page(),
        credential=credential_form(cross_origin=True),
        payment=PaymentBlock(observations=[payee()], donation_cues=["donate"]),
        registry=RegistryContext(confirmed_relationships=rel),
    )
    r = evaluate(b, policy())
    assert not [x for x in r.reasons if x.kind == "abuse"]
    assert r.priority == "no_action" and "confirmed_relationship" in rules_of(r)


def test_redirect_to_official_is_explained_but_gives_no_points():
    b = bundle(registry=RegistryContext(final_url_official_domain="luminafoundation.test"))
    reason = next(x for x in evaluate(b, policy()).reasons if x.rule == "redirects_to_official")
    assert reason.points == 0
