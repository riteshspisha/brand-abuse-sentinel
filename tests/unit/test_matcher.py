from pathlib import Path

import pytest
import yaml
from tests.conftest import confirm_domain

from brandsentinel.matching.matcher import MATCHER_VERSION, Matcher
from brandsentinel.matching.normalize import InvalidName
from brandsentinel.registry.loader import validate
from brandsentinel.registry.model import Registry

CASES = yaml.safe_load((Path(__file__).parent / "fixtures" / "legacy_cases.yaml").read_text())


@pytest.fixture
def matchers(registry_data) -> dict[str, Matcher]:
    committed = Registry.model_validate(registry_data)
    confirm_domain(registry_data, "isha.in")
    confirm_domain(registry_data, "sadhguru.org")
    confirmed = Registry.model_validate(registry_data)
    validate(confirmed)
    return {"committed": Matcher(committed), "confirmed": Matcher(confirmed)}


@pytest.mark.parametrize("case", CASES, ids=[f"{c['registry']}:{c['name']}" for c in CASES])
def test_regression_case(matchers, case):
    result = matchers[case["registry"]].match(case["name"])
    assert result.candidate is case["candidate"], result.to_json()
    if "strength" in case:
        assert result.strength == case["strength"], result.to_json()
    assert result.suppressed_by == case.get("suppressed_by"), result.to_json()
    if result.suppressed_by:
        assert result.strength is None
        assert "suppressed:official_domain" in result.notes
    present = {(h.type, h.keyword, h.reason) for h in result.hits}
    for hit_type, keyword, reason in case.get("hits", []):
        assert (hit_type, keyword, reason) in present, result.to_json()
    if case.get("no_hits"):
        assert result.hits == (), result.to_json()
    if "only_hit_types" in case:
        assert {h.type for h in result.hits} == set(case["only_hit_types"]), result.to_json()
    for note in case.get("notes", []):
        assert note in result.notes, result.to_json()
    if "labels" in case:
        assert list(result.labels) == case["labels"]
    for term in case.get("context", []):
        assert any(term in h.context for h in result.hits), result.to_json()
    if "distance" in case:
        assert [h.distance for h in result.hits if h.type == "fuzzy"] == [case["distance"]]


@pytest.mark.security
def test_confirming_a_legacy_entry_turns_its_label_into_suppression(registry_data):
    # AE20: reported while legacy-unverified; suppressed once a maintainer confirms it.
    before = Matcher(Registry.model_validate(registry_data)).match("shop.ishalife.com")
    assert before.candidate and before.labels == ("legacy_whitelist_unverified",)
    confirm_domain(registry_data, "ishalife.com")
    after = Matcher(Registry.model_validate(registry_data)).match("shop.ishalife.com")
    assert not after.candidate and after.suppressed_by == "ishalife.com"


def test_confirmed_domain_without_suppress_flag_is_reported_not_suppressed(registry_data):
    confirm_domain(registry_data, "isha.in", suppresses=False)
    result = Matcher(Registry.model_validate(registry_data)).match("donate.isha.in")
    assert result.candidate and result.suppressed_by is None
    assert ("registry_domain", "confirmed") in {(h.type, h.status) for h in result.hits}


def test_rejected_domain_is_neither_suppressed_nor_labelled(registry_data):
    for d in registry_data["domains"]:
        if d["name"] == "ishaoutreach.org":
            d["status"] = "rejected"
    result = Matcher(Registry.model_validate(registry_data)).match("ishaoutreach.org")
    assert result.labels == ()
    assert not any(h.type == "registry_domain" for h in result.hits)


def test_exclusion_cancels_only_its_own_keyword(registry_data):
    # "vishal" is scoped to isha; scoping one to sadhguru must not affect isha hits.
    registry_data["exclusions"].append(
        {
            "term": "sadhgurukul",
            "scope": "sadhguru",
            "status": "candidate",
            "provenance": [{"source": "test", "recorded_by": "t", "recorded_at": "2026-10-08"}],
        }
    )
    m = Matcher(Registry.model_validate(registry_data))
    assert not any(h.keyword == "sadhguru" for h in m.match("sadhgurukul.com").hits)
    assert any(h.keyword == "sadhguru" for h in m.match("sadhguru-kul.com").hits)
    assert any(h.type == "token" for h in m.match("sadhgurukul-isha.com").hits)


def test_rejected_keyword_is_not_used(registry_data):
    registry_data["brands"][0]["keywords"][0]["status"] = "rejected"  # ishafoundation
    result = Matcher(Registry.model_validate(registry_data)).match("ishafoundationx.com")
    assert not any(h.keyword == "ishafoundation" for h in result.hits)


def test_unicode_input_matches_like_its_punycode(matchers):
    m = matchers["committed"]
    assert m.match("sadhgurü.com").to_json() == m.match("xn--sadhgur-t2a.com").to_json()


def test_cyrillic_lookalike_matches_as_homoglyph(matchers):
    name = "s" + chr(0x0430) + "dhguru-donate.com"  # Cyrillic a
    result = matchers["committed"].match(name)
    assert result.host.startswith("xn--")
    assert ("keyword", "sadhguru", "homoglyph") in {
        (h.type, h.keyword, h.reason) for h in result.hits
    }
    assert result.strength == "strong"


@pytest.mark.security
def test_invisible_characters_in_idn_do_not_hide_a_brand(matchers):
    name = "sadh" + chr(0x200B) + "guru.com"  # zero-width space
    result = matchers["committed"].match(name)
    assert result.unicode_host == "sadhguru.com"
    assert result.candidate


@pytest.mark.parametrize(
    "bad", ["", "   ", "has space.com", "a..b", "10.0.0.1", "x" * 300, "a\x00b.com"]
)
def test_invalid_names_raise(matchers, bad):
    with pytest.raises(InvalidName):
        matchers["committed"].match(bad)


def test_output_is_byte_identical_across_runs_and_instances(registry_data):
    names = [c["name"] for c in CASES]
    first = [Matcher(Registry.model_validate(registry_data)).match(n).to_json() for n in names]
    second = [Matcher(Registry.model_validate(registry_data)).match(n).to_json() for n in names]
    assert first == second
    assert all(f'"matcher_version":"{MATCHER_VERSION}"' in line for line in first)


def test_output_is_ascii_only(matchers):
    line = matchers["committed"].match("xn--sadhgur-t2a.com").to_json()
    assert line.isascii()
    assert "\\u00fc" in line


def test_registry_digest_tracks_registry_changes(registry_data):
    before = Matcher(Registry.model_validate(registry_data)).registry_digest
    confirm_domain(registry_data, "isha.in")
    assert Matcher(Registry.model_validate(registry_data)).registry_digest != before


def _hit_keys(result):
    return {(h.type, h.keyword) for h in result.hits}


# Review findings: lookalike and inserted characters must not hide a brand keyword.
EVASIONS = [
    # (name built from code points, expected hit)
    (chr(0x0251) + "diyogi-tickets.com", ("keyword", "adiyogi")),  # Latin alpha
    ("dhy" + chr(0x0251) + "nalinga.org", ("keyword", "dhyanalinga")),
    ("sh" + chr(0x0251) + "mbhavi-course.com", ("keyword", "shambhavi")),
    (chr(0x0269) + "sha-in.com", ("official_lookalike", "isha.in")),  # Latin iota
    ("adiyo" + chr(0x3164) + "gi-donate.com", ("keyword", "adiyogi")),  # Hangul filler
    ("adiyo" + chr(0x0915) + "gi.com", ("keyword", "adiyogi")),  # Devanagari letter
    ("adiyo" + chr(0x20DD) + "gi.com", ("keyword", "adiyogi")),  # enclosing mark (Me)
    ("adiyo" + chr(0x0903) + "gi.com", ("keyword", "adiyogi")),  # spacing mark (Mc)
    ("sadh" + chr(0x3164) + "guru-donate.com", ("keyword", "sadhguru")),
    ("ishain-login.com", ("official_lookalike", "isha.in")),  # dot dropped
    ("sadh.guru", ("keyword", "sadhguru")),  # brand split by a dot
    ("inner.engineering", ("keyword", "innerengineering")),
]


@pytest.mark.security
@pytest.mark.parametrize(
    ("name", "expected"), EVASIONS, ids=[e[0].encode("unicode_escape").decode() for e in EVASIONS]
)
def test_lookalike_and_inserted_characters_are_matched(matchers, name, expected):
    result = matchers["committed"].match(name)
    assert expected in _hit_keys(result), result.to_json()
    assert result.strength == "strong"


@pytest.mark.security
def test_unmapped_lookalike_falls_back_to_fuzzy_for_every_high_tier_keyword(matchers):
    name = "adiyog" + chr(0xA647) + ".com"  # Cyrillic small iota, not in the table
    result = matchers["committed"].match(name)
    assert ("fuzzy", "adiyogi") in _hit_keys(result), result.to_json()


def test_invisible_character_spoof_is_reported_as_homoglyph(matchers):
    result = matchers["committed"].match("sadh" + chr(0x200B) + "guru.com")
    (hit,) = [h for h in result.hits if h.keyword == "sadhguru"]
    assert hit.reason == "homoglyph"


def test_plain_ascii_brand_next_to_an_idn_label_stays_substring(matchers):
    result = matchers["committed"].match("sadhguru.xn--sadhgur-t2a.com")
    (hit,) = [h for h in result.hits if h.keyword == "sadhguru" and h.type == "keyword"]
    assert hit.reason == "substring"


@pytest.mark.parametrize(
    ("name", "distance"),
    [("sadhgruu.com", 2), ("sdhgr.com", None), ("sadhgu.com", 2), ("sadhgxx-x.com", None)],
)
def test_fuzzy_distance_and_length_bounds(matchers, name, distance):
    result = matchers["committed"].match(name)
    got = [h.distance for h in result.hits if h.type == "fuzzy" and h.keyword == "sadhguru"]
    assert got == ([distance] if distance else [])


def test_fuzzy_brand_hit_is_context_for_isha_affix(matchers):
    result = matchers["committed"].match("ishaa-sadhgurru.com")
    (affix,) = [h for h in result.hits if h.type == "affix"]
    assert "brand:sadhguru" in affix.context


def _third_party(registry_data, rel_type="authorized_domain", rel_from="brand:save-soil"):
    from tests.conftest import confirm_domain

    prov = [{"source": "t", "recorded_by": "t", "recorded_at": "2026-10-08",
             "verified_by": "m", "verified_at": "2026-10-08"}]  # fmt: skip
    registry_data["domains"].append(
        {"name": "savesoil.wordpress.com", "brand": "save-soil", "kind": "third_party",
         "status": "candidate", "provenance": prov}
    )  # fmt: skip
    confirm_domain(registry_data, "savesoil.wordpress.com")
    registry_data["relationships"].append(
        {"from": rel_from, "to": "domain:savesoil.wordpress.com", "type": rel_type,
         "status": "confirmed", "provenance": prov}
    )  # fmt: skip
    registry = Registry.model_validate(registry_data)
    validate(registry)
    return Matcher(registry)


@pytest.mark.security
def test_third_party_domain_suppresses_only_its_exact_host(registry_data):
    m = _third_party(registry_data)
    assert m.match("savesoil.wordpress.com").suppressed_by == "savesoil.wordpress.com"
    assert m.match("donate.savesoil.wordpress.com").candidate
