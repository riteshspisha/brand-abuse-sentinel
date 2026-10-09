from collections import Counter
from pathlib import Path

import pytest
from tests.conftest import REGISTRY_PATH, REPO

from brandsentinel.registry.legacy_import import LegacyImportError, missing_legacy, read_legacy
from brandsentinel.registry.loader import load_registry
from brandsentinel.registry.model import Registry

LEGACY = REPO / "legacy"


def test_reads_every_legacy_constant_with_its_line():
    entries = read_legacy(LEGACY)
    assert Counter(e.kind for e in entries) == {
        "strict_keyword": 1,
        "brand_keyword": 10,
        "fuzzy_target": 4,
        "exclusion": 8,
        "whitelist": 6,
        "dnstwist_target": 3,
    }
    by = {(e.kind, e.value): e.source for e in entries}
    assert by[("strict_keyword", "isha")] == "legacy/monitor_certstream.py:22"
    assert by[("brand_keyword", "cauverycalling")] == "legacy/monitor_certstream.py:26"
    assert by[("whitelist", "ishalife.com")] == "legacy/monitor_certstream.py:32"
    assert by[("dnstwist_target", "ishafoundation.org")] == "legacy/dnstwist.py:9"


def test_committed_registry_covers_every_legacy_input_with_provenance():
    registry, _ = load_registry(REGISTRY_PATH)
    assert missing_legacy(registry, read_legacy(LEGACY)) == []


def test_legacy_entries_are_legacy_unverified():
    registry, _ = load_registry(REGISTRY_PATH)
    legacy_terms = {e.value for e in read_legacy(LEGACY)}
    statuses = {
        *(k.status for b in registry.brands for k in b.keywords if k.term in legacy_terms),
        *(e.status for e in registry.exclusions),
        *(d.status for d in registry.domains if d.name in legacy_terms),
    }
    assert statuses == {"legacy-unverified"}


def test_isha_is_low_tier_and_brand_keywords_high_tier():
    registry, _ = load_registry(REGISTRY_PATH)
    tiers = {k.term: k.tier for _, k in registry.keywords()}
    assert tiers.pop("isha") == "low"
    assert set(tiers.values()) == {"high"}
    fuzzy = {k.term for _, k in registry.keywords() if k.fuzzy}
    assert fuzzy == {"sadhguru", "innerengineering", "savesoil", "ishafoundation"}


def test_missing_entry_and_missing_provenance_are_reported(registry_data):
    registry_data["exclusions"] = registry_data["exclusions"][1:]  # drop odisha
    registry_data["domains"][0]["provenance"] = registry_data["domains"][0]["provenance"][:1]
    missing = missing_legacy(Registry.model_validate(registry_data), read_legacy(LEGACY))
    assert any("'odisha'" in m and "not in the registry" in m for m in missing)
    assert any("'isha.in'" in m and "legacy/dnstwist.py:9" in m for m in missing)


def test_scripts_are_parsed_not_executed(tmp_path: Path):
    marker = tmp_path / "executed"
    for name, body in {
        "monitor_certstream.py": (
            f"open({str(marker)!r}, 'w')\nimport boto3\n"
            "STRICT_KEYWORDS = ['isha']\nBRAND_KEYWORDS = ['a']\nTARGET_BRANDS = []\n"
            "EXCLUSIONS = []\nWHITELIST = []\n"
        ),
        "dnstwist.py": "DOMAINS = ['x.org']\n",
    }.items():
        (tmp_path / name).write_text(body)
    assert len(read_legacy(tmp_path)) == 3
    assert not marker.exists()


@pytest.mark.parametrize(
    ("certstream_source", "needle"),
    [
        ("STRICT_KEYWORDS = 'isha'\n", "is not a list"),
        ("STRICT_KEYWORDS = ['isha', 3]\n", "non-string"),
        ("STRICT_KEYWORDS = [\n", "cannot parse"),
    ],
)
def test_malformed_legacy_constants_fail(tmp_path: Path, certstream_source, needle):
    (tmp_path / "monitor_certstream.py").write_text(certstream_source)
    (tmp_path / "dnstwist.py").write_text("DOMAINS = []\n")
    with pytest.raises(LegacyImportError, match=needle):
        read_legacy(tmp_path)


def test_missing_legacy_file_fails(tmp_path: Path):
    with pytest.raises(LegacyImportError, match="cannot parse"):
        read_legacy(tmp_path)


def test_missing_constant_fails(tmp_path: Path):
    (tmp_path / "monitor_certstream.py").write_text("STRICT_KEYWORDS = ['isha']\n")
    (tmp_path / "dnstwist.py").write_text("DOMAINS = []\n")
    with pytest.raises(LegacyImportError, match="BRAND_KEYWORDS"):
        read_legacy(tmp_path)
