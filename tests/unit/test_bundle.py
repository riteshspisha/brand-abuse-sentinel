"""U13 EvidenceBundle: determinism, bounds, sanitizing, provenance, schema."""

import json

from tests.detection_support import bundle_for_html, lab_site, scorer, seed_case

from brandsentinel.evidence.bundle import (
    EvidenceBundle,
    bundle_json,
    bundle_schema,
    bundle_sha256,
)
from brandsentinel.evidence.models import FactRecord

BIDI = chr(0x202E)


def test_same_facts_and_features_give_byte_identical_bundles(store):
    expected, html = lab_site("donation-fraud")
    case_id = seed_case(store, html, expected["url"])
    s = scorer(store)
    first, second = s.bundle(case_id), s.bundle(case_id)
    assert bundle_json(first) == bundle_json(second)
    assert bundle_sha256(first) == bundle_sha256(second)
    # A stored score's bundle rebuilds identically from the stored records (FA7).
    out = s.score(case_id)
    stored = store.conn.execute("SELECT bundle_json FROM scores WHERE id = ?", (out.score_id,))
    assert stored.fetchone()[0] == bundle_json(s.bundle(case_id))


def test_large_page_text_respects_snippet_caps():
    html = "<title>Lumina Foundation</title><p>" + ("Lumina Foundation relief. " * 2000) + "</p>"
    assert len(html) > 50_000
    b = bundle_for_html(html, "http://donate-luminafoundation.test/")
    assert len(b.snippets) <= 20
    assert all(len(s.text) <= 300 for s in b.snippets)
    assert len(b.page.text_excerpt) <= 1000


def test_bidi_and_control_characters_are_removed_from_snippets():
    html = f"<title>Lumina{BIDI} Foundation \x1b[31m red</title><p>Donate{BIDI} now</p>"
    b = bundle_for_html(html, "http://x-luminafoundation.test/")
    blob = bundle_json(b)
    assert BIDI not in json.loads(blob)["page"]["title"]
    assert "\x1b" not in json.loads(blob)["page"]["title"]
    assert all(BIDI not in s.text and "\x1b" not in s.text for s in b.snippets)


def test_payment_observations_carry_fact_blob_and_extractor_refs():
    expected, html = lab_site("donation-fraud")
    b = bundle_for_html(html, expected["url"])
    (upi,) = [o for o in b.payment.observations if o.kind == "upi"]
    assert upi.extractor_version == "payment/1"
    assert "fact:100" in upi.refs
    assert any(r.startswith("feature:") for r in upi.refs)
    assert f"artifact:{b.http.body_sha256}" in upi.refs


def test_discovery_similarity_is_separate_from_observed_behaviour():
    expected, html = lab_site("donation-fraud")
    b = bundle_for_html(html, expected["url"])
    assert b.discovery.domain_match == "strong"
    assert {h["type"] for h in b.discovery.hits} >= {"keyword", "official_lookalike"}
    assert b.discovery.refs == ["discovery_event:e1"]
    assert b.discovery.sources[0].source == "manual"
    assert b.http.final_url == expected["url"] and b.page.title.startswith("Lumina Foundation")


def test_failed_fetch_records_what_is_missing():
    b = bundle_for_html(
        b"",
        "http://dead-luminafoundation.test/",
        outcome="connect_error",
        error={"kind": "connect_error"},
    )
    assert b.http.fetched and b.http.outcome == "connect_error"
    assert "fetch_connect_error" in b.incomplete and not b.page.available
    assert "enrichment_not_run" in b.incomplete


def test_enrichment_errors_and_round_selection():
    facts = [
        FactRecord(
            id=1,
            source="dns",
            name="dns_records",
            collector_version="dns/1",
            observed_at=1.0,
            artifact_refs=[],
            value={
                "status": "ok",
                "analysis_round": 0,
                "records": {"A": {"values": ["192.0.2.1"]}},
                "address_policy": {"all_public": True, "dns_mixed_private": True},
            },
        ),
        FactRecord(
            id=2,
            source="rdap",
            name="rdap_error",
            collector_version="enrich/1",
            observed_at=1.0,
            artifact_refs=[],
            value={"kind": "timeout", "analysis_round": 0},
        ),
    ]
    b = bundle_for_html("<title>x</title>", "http://a-luminafoundation.test/", facts=facts)
    assert b.infrastructure.dns["a"] == ["192.0.2.1"] and b.infrastructure.dns_mixed_private
    assert b.infrastructure.errors[0]["kind"] == "timeout"
    assert "enrichment_error_rdap" in b.incomplete
    assert {"fact:1", "fact:2"} <= set(b.infrastructure.refs)


def test_bundle_json_validates_against_exported_schema():
    expected, html = lab_site("donation-fraud")
    b = bundle_for_html(html, expected["url"])
    schema = bundle_schema()
    assert schema["title"] == "EvidenceBundle"
    assert set(schema["properties"]) == set(EvidenceBundle.model_fields)
    again = EvidenceBundle.model_validate(json.loads(bundle_json(b)))
    assert bundle_json(again) == bundle_json(b)
