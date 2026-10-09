"""RDAP response parsing and bootstrap lookup (U10)."""

import pytest

from brandsentinel.enrich.rdap import RdapError, base_url_for, parse_rdap

NOW = 1_760_000_000.0  # 2025-10-09T08:53:20Z


def test_minimal_document_parses_with_gaps_as_none():
    r = parse_rdap({"ldhName": "x.com"}, NOW)
    assert r["ldh_name"] == "x.com" and r["registered_at"] is None
    assert r["domain_age_days"] is None and r["registrar"] is None and not r["redacted"]


def test_dates_status_and_redaction():
    doc = {
        "events": [
            {"eventAction": "registration", "eventDate": "2025-10-04T08:53:20Z"},
            {"eventAction": "last changed", "eventDate": "2025-10-05T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "not a date"},
        ],
        "status": ["client hold", 7],
        "redacted": [{"name": {"type": "Registrant Name"}}],
    }
    r = parse_rdap(doc, NOW)
    assert r["domain_age_days"] == 5 and r["status"] == ["client hold"]
    assert r["last_changed_at"].startswith("2025-10-05") and r["redacted"]


@pytest.mark.parametrize("doc", [[], "x", None, 5])
def test_non_object_is_malformed(doc):
    with pytest.raises(RdapError):
        parse_rdap(doc, NOW)


def test_hostile_shapes_do_not_crash():
    doc = {
        "entities": ["x", {"roles": "registrar", "vcardArray": "bad"}, {"roles": [1]}],
        "events": [None, {"eventAction": 3}],
        "nameservers": [None, {"ldhName": None}],
    }
    r = parse_rdap(doc, NOW)
    assert r["nameservers"] == [] and r["registrar"] is None


def test_bootstrap_longest_suffix_and_https_preference():
    boot = {
        "services": [
            [["uk"], ["http://uk.example/rdap", "https://uk.example/rdap"]],
            [["co.uk"], ["https://co-uk.example/rdap/"]],
            "junk",
        ]
    }
    assert base_url_for(boot, "shop.example.co.uk") == "https://co-uk.example/rdap/"
    assert base_url_for(boot, "example.uk") == "https://uk.example/rdap/"
    assert base_url_for(boot, "example.com") is None
