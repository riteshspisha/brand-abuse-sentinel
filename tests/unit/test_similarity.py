"""Similarity measures against the registry (U10)."""

from brandsentinel.enrich.similarity import similarity
from brandsentinel.registry.model import Registry


def brands(result):
    return {b["keyword"]: b for b in result["brands"]}


def test_one_edit_from_a_brand_keyword(registry_data):
    r = similarity("sadhgurru.com", Registry.model_validate(registry_data))
    b = brands(r)["sadhguru"]
    assert b["min_label_distance"] == 1 and b["closest_label"] == "sadhgurru"
    assert not b["contains"]
    assert r["closest_official_domains"][0] == {"domain": "sadhguru.org", "distance": 1}


def test_containment_and_hyphenated_parts(registry_data):
    r = similarity("donate-sadhguru-help.org", Registry.model_validate(registry_data))
    b = brands(r)["sadhguru"]
    assert b["contains"] and b["skeleton_contains"] and b["min_label_distance"] == 0


def test_homoglyph_needs_the_skeleton(registry_data):
    r = similarity("sadhgur\u03c5.com", Registry.model_validate(registry_data))  # Greek upsilon
    b = brands(r)["sadhguru"]
    assert r["idn"] and not b["contains"] and b["skeleton_contains"]
