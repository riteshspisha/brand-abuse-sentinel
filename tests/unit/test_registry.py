import pytest
import yaml
from tests.conftest import REGISTRY_PATH, confirm_domain

from brandsentinel.registry.loader import RegistryError, load_registry, validate
from brandsentinel.registry.model import Registry

PROV = [{"source": "test", "recorded_by": "t", "recorded_at": "2026-10-08"}]
LEGACY_WHITELIST = [
    "isha.in",
    "sadhguru.org",
    "innerengineering.com",
    "consciousplanet.org",
    "ishalife.com",
    "ishaoutreach.org",
]


def _check(data: dict):
    return validate(Registry.model_validate(data))


def _errors(data: dict) -> str:
    with pytest.raises((RegistryError, ValueError)) as e:
        _check(data)
    return str(e.value)


@pytest.fixture
def committed():
    registry, report = load_registry(REGISTRY_PATH)
    return registry, report


# Tests on the committed registry assert invariants that still hold after a
# maintainer confirms or rejects entries; status-specific behavior is tested on
# modified copies (registry_data).


def test_committed_registry_validates_with_counts(committed):
    _, report = committed
    tiers = {k.split("/")[0] for k in report.counts["keywords"]}
    assert tiers == {"high", "low"}
    assert sum(report.counts["keywords"].values()) == 11
    assert "exclusion 'abhishek' does not contain 'isha', so it can never apply" in report.warnings


def test_only_verified_confirmed_domains_suppress_in_committed_registry(committed):
    registry, _ = committed
    for d in registry.domains:
        if d.suppresses:
            assert d.status == "confirmed"
            assert any(p.verified_by and p.verified_at for p in d.provenance)


def test_savesoil_org_entered_as_a_non_suppressing_candidate(registry_data):
    # AE5: candidate status never suppresses, and it was not imported as confirmed.
    (d,) = [d for d in registry_data["domains"] if d["name"] == "savesoil.org"]
    assert d["provenance"][0]["source"].endswith("#R12")
    d["status"] = "candidate"
    registry = Registry.model_validate(registry_data)
    assert "savesoil.org" not in {x.name for x in registry.suppressing_domains()}


def test_legacy_whitelist_never_suppresses_unless_confirmed(committed):
    registry, _ = committed
    by_name = {d.name: d for d in registry.domains}
    for name in LEGACY_WHITELIST:
        d = by_name[name]
        assert d.status in ("legacy-unverified", "confirmed", "rejected")
        assert not d.suppresses or d.status == "confirmed"


def test_dnstwist_targets_are_official_confirmed_or_legacy_domains(committed):
    registry, _ = committed
    targets = {d.name for d in registry.dnstwist_targets()}
    assert targets == {*LEGACY_WHITELIST, "ishafoundation.org"}


def test_every_exclusion_is_scoped_to_isha(committed):
    registry, _ = committed
    assert {e.scope for e in registry.exclusions} == {"isha"}


def test_exclusion_without_scope_fails(registry_data):
    del registry_data["exclusions"][0]["scope"]
    assert "scope" in _errors(registry_data)


def test_exclusion_scoped_to_unknown_keyword_fails(registry_data):
    registry_data["exclusions"][0]["scope"] = "nosuchword"
    assert "nosuchword" in _errors(registry_data)


@pytest.mark.security
@pytest.mark.parametrize("status", ["candidate", "legacy-unverified", "rejected"])
def test_unconfirmed_domain_marked_to_suppress_fails(registry_data, status):
    registry_data["domains"][0].update(status=status, suppresses=True)
    assert "only confirmed domains may suppress" in _errors(registry_data)


def test_confirmed_suppressing_domain_passes(registry_data):
    confirm_domain(registry_data, "isha.in")
    assert [d.name for d in Registry.model_validate(registry_data).suppressing_domains()] == [
        "isha.in"
    ]
    _check(registry_data)


def test_confirmed_entry_needs_a_verifier(registry_data):
    registry_data["domains"][0]["status"] = "confirmed"
    assert "verified_by" in _errors(registry_data)


def test_third_party_domain_suppresses_only_with_confirmed_relationship(registry_data):
    registry_data["domains"].append(
        {"name": "partner-ngo.org", "brand": "save-soil", "kind": "third_party",
         "status": "candidate", "provenance": PROV}
    )  # fmt: skip
    confirm_domain(registry_data, "partner-ngo.org")
    assert "authorized_domain relationship" in _errors(registry_data)

    registry_data["relationships"].append(
        {"from": "brand:save-soil", "to": "domain:partner-ngo.org", "type": "authorized_domain",
         "status": "confirmed",
         "provenance": [{**PROV[0], "verified_by": "m", "verified_at": "2026-10-08"}]}
    )  # fmt: skip
    _check(registry_data)


def test_relationship_to_unknown_brand_names_both_ends(registry_data):
    registry_data["relationships"].append(
        {"from": "brand:sadhguru", "to": "brand:ghost-brand", "type": "founder_of",
         "status": "candidate", "provenance": PROV}
    )  # fmt: skip
    message = _errors(registry_data)
    assert "brand:sadhguru" in message and "brand:ghost-brand" in message


def test_candidate_payee_is_not_a_confirmed_payee(registry_data):
    registry_data["payees"] = [
        {"id": "p1", "name": "Isha Donations", "brand": "isha-foundation", "status": "candidate",
         "identifiers": [{"type": "upi_vpa", "value": "isha@bank"}], "provenance": PROV}
    ]  # fmt: skip
    registry = Registry.model_validate(registry_data)
    validate(registry)
    assert registry.confirmed_payees() == []

    verified = [{**PROV[0], "verified_by": "m", "verified_at": "2026-10-08"}]
    confirmed = {**registry_data["payees"][0], "id": "p2", "status": "confirmed"}
    confirmed["provenance"] = verified
    registry_data["payees"].append(confirmed)
    assert [p.id for p in Registry.model_validate(registry_data).confirmed_payees()] == ["p2"]


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d["domains"].append(dict(d["domains"][0])), "duplicate domain"),
        (lambda d: d["domains"][0].update(name="ISHA.in"), "write it as 'isha.in'"),
        (lambda d: d["domains"][0].update(name="co.in"), "public suffix"),
        (lambda d: d["domains"][0].update(brand="ghost"), "unknown brand 'ghost'"),
        (lambda d: d["brands"][0]["keywords"][1].update(fuzzy=True), "cannot be fuzzy"),
        (lambda d: d["brands"][1]["keywords"].append(d["brands"][0]["keywords"][1]),
         "duplicate keyword"),
        (lambda d: d["brands"][0]["keywords"][0].update(term="Isha-Foundation"), "lowercase ASCII"),
        (lambda d: d.update(unknown_section=[]), "unknown_section"),
        (lambda d: d["reference_pages"].append(
            {"url": "http://isha.sadhguru.org/", "brand": "sadhguru", "status": "candidate",
             "provenance": PROV}), "https"),
    ],
)  # fmt: skip
def test_invalid_registry_is_rejected(registry_data, mutate, needle):
    mutate(registry_data)
    assert needle in _errors(registry_data)


def test_loader_reports_yaml_and_schema_errors_with_locations(tmp_path, registry_data):
    path = tmp_path / "r.yaml"
    path.write_text("brands: [unclosed\n")
    with pytest.raises(RegistryError, match="invalid YAML"):
        load_registry(path)
    registry_data["domains"][0]["status"] = "approved"
    path.write_text(yaml.safe_dump(registry_data))
    with pytest.raises(RegistryError, match=r"domains\.0\.status"):
        load_registry(path)


@pytest.mark.security
@pytest.mark.parametrize(
    ("rel_type", "rel_from", "status"),
    [
        ("impersonated_on", "brand:save-soil", "confirmed"),  # wrong type
        ("authorized_domain", "brand:sadhguru", "confirmed"),  # another brand
        ("authorized_domain", "brand:save-soil", "candidate"),
        ("authorized_domain", "brand:save-soil", "legacy-unverified"),
    ],
)
def test_only_a_confirmed_authorized_domain_link_from_its_brand_unlocks_suppression(
    registry_data, rel_type, rel_from, status
):
    registry_data["domains"].append(
        {"name": "partner-ngo.org", "brand": "save-soil", "kind": "third_party",
         "status": "candidate", "provenance": PROV}
    )  # fmt: skip
    confirm_domain(registry_data, "partner-ngo.org")
    prov = (
        PROV
        if status != "confirmed"
        else [{**PROV[0], "verified_by": "m", "verified_at": "2026-10-08"}]
    )
    registry_data["relationships"].append(
        {"from": rel_from, "to": "domain:partner-ngo.org", "type": rel_type,
         "status": status, "provenance": prov}
    )  # fmt: skip
    assert "authorized_domain relationship" in _errors(registry_data)
