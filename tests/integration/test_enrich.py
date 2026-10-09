"""Passive enrichment against the local harness: DNS, RDAP, TLS, similarity (U10)."""

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from tests.security.harness import harness_stages, rdap_bootstrap

from brandsentinel.enrich import SOURCES, run_sources
from brandsentinel.registry.model import Registry
from brandsentinel.store.records import upsert_candidate


def registry(registry_data) -> Registry:
    return Registry.model_validate(registry_data)


def collect(stages, host, registrable="harness.test"):
    obs = asyncio.run(run_sources(stages.context(host, registrable)))
    return {o.name: o.value for o in obs}


def rdap_doc(name: str, registered: datetime) -> dict:
    return {
        "objectClassName": "domain",
        "ldhName": name,
        "events": [
            {"eventAction": "registration", "eventDate": registered.isoformat()},
            {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
        ],
        "status": ["active"],
        "entities": [
            {
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse@registrar.example"]],
                        ],
                    }
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]],
            },
        ],
        "nameservers": [{"ldhName": "NS1.Example.net"}],
    }


def test_domain_age_comes_from_rdap_fetched_through_the_fetcher(harness, store, registry_data):
    harness.recorder.rdap["fresh.test"] = rdap_doc(
        "fresh.test", datetime.now(UTC) - timedelta(days=5, hours=1)
    )
    stages = harness_stages(harness, store, registry(registry_data))
    facts = collect(stages, "www.fresh.test", "fresh.test")
    rdap = facts["rdap_registration"]
    assert rdap["domain_age_days"] == 5
    assert rdap["registrar"] == {"name": "Example Registrar", "iana_id": "9999"}
    assert rdap["abuse_contact"]["email"] == "abuse@registrar.example"
    assert rdap["redacted"] is True and rdap["nameservers"] == ["ns1.example.net"]
    assert rdap["source_url"].endswith("/rdap/domain/fresh.test") and not rdap["cached"]
    # A second subdomain of the same registrable domain reuses the lookup.
    again = collect(stages, "login.fresh.test", "fresh.test")["rdap_registration"]
    assert again["cached"] and again["domain_age_days"] == 5


def test_rdap_not_found_and_unknown_tld_are_error_facts(harness, store, registry_data):
    stages = harness_stages(harness, store, registry(registry_data))
    assert collect(stages, "x.unregistered.test", "unregistered.test")["rdap_error"]["kind"] == (
        "not_found"
    )
    assert collect(stages, "x.example.zz", "example.zz")["rdap_error"]["kind"] == "no_rdap_service"


def test_rdap_timeout_records_an_error_and_other_sources_still_report(
    harness, store, registry_data
):
    boot = rdap_bootstrap(harness, f"https://blackhole.harness.test:{harness.blackhole.port}/")
    stages = harness_stages(
        harness, store, registry(registry_data), bootstrap=boot, read_timeout_seconds=0.5
    )
    facts = collect(stages, "secure.harness.test")
    assert facts["rdap_error"]["kind"] == "timeout"
    assert facts["dns_records"]["status"] == "ok" and "similarity" in facts


def test_rdap_server_redirect_to_a_private_address_is_refused(harness, store, registry_data):
    harness.recorder.rdap["redir.test"] = {"redirect": "http://10.0.0.5/rdap/domain/redir.test"}
    stages = harness_stages(harness, store, registry(registry_data))
    err = collect(stages, "redir.test", "redir.test")["rdap_error"]
    assert err["kind"] == "blocked_redirect"
    assert err["detail"]["error"]["class"] == "private"


def test_self_signed_certificate_is_parsed_and_fails_verification(harness, store, registry_data):
    stages = harness_stages(
        harness, store, registry(registry_data), tls_port=harness.selfsigned.port
    )
    tls = collect(stages, "selfsigned.harness.test")["tls_certificate"]
    cert = tls["certificate"]
    assert cert["self_signed"] and cert["san_dns"] == ["selfsigned.harness.test"]
    assert (
        cert["subject"] == "CN=selfsigned.harness.test" and cert["not_after"] > cert["not_before"]
    )
    assert tls["verification_passes"] is False and "self-signed" in tls["verification_error"]
    assert tls["address"] == "127.77.0.2"


def test_certificate_naming_an_official_domain_is_recorded(harness, store, registry_data):
    stages = harness_stages(harness, store, registry(registry_data))
    facts = collect(stages, "secure.harness.test")
    assert facts["tls_certificate"]["verification_passes"] is True
    matches = facts["tls_official_san"]["matches"]
    assert {"san": "isha.sadhguru.org", "domain": "sadhguru.org"}.items() <= matches[0].items()


def test_tls_to_a_private_address_is_refused_by_netguard(harness, store, registry_data):
    stages = harness_stages(harness, store, registry(registry_data))
    err = collect(stages, "private.harness.test")["tls_error"]
    assert err["kind"] == "blocked_address"


def test_dns_records_keep_per_type_status(harness, store, registry_data):
    harness.dns.set(
        "rich.harness.test",
        A=["127.77.0.1"],
        MX=["10 mail.rich.harness.test."],
        TXT=['"v=spf1 -all"'],
        NS="servfail",
    )
    stages = harness_stages(harness, store, registry(registry_data))
    d = collect(stages, "rich.harness.test")["dns_records"]
    assert d["status"] == "partial"
    assert d["records"]["A"]["values"] == ["127.77.0.1"]
    assert d["records"]["MX"]["values"] == ["10 mail.rich.harness.test."]
    assert d["records"]["TXT"]["values"] == ["v=spf1 -all"]
    assert d["records"]["NS"]["status"] == "servfail"
    assert d["records"]["AAAA"]["status"] == "no_answer"
    assert d["address_policy"]["all_public"]


@pytest.mark.parametrize(
    ("host", "status"),
    [("nope.harness.test", "nxdomain"), ("timeout.harness.test", "error")],
)
def test_dns_failures_are_facts_not_crashes(harness, store, registry_data, host, status):
    stages = harness_stages(harness, store, registry(registry_data))
    d = collect(stages, host)["dns_records"]
    assert d["status"] == status


def test_mixed_private_answers_are_flagged(harness, store, registry_data):
    stages = harness_stages(harness, store, registry(registry_data))
    policy = collect(stages, "mixed.harness.test")["dns_records"]["address_policy"]
    assert policy["dns_mixed_private"] and not policy["all_public"]
    assert {"ip": "192.168.1.10", "class": "private"} in policy["addresses"]


def test_a_crashing_source_becomes_an_error_fact(harness, store, registry_data, monkeypatch):
    async def boom(ctx):
        raise RuntimeError("source exploded")

    monkeypatch.setitem(SOURCES, "boom", boom)
    stages = harness_stages(harness, store, registry(registry_data))
    facts = collect(stages, "secure.harness.test")
    assert facts["boom_error"]["kind"] == "RuntimeError"
    assert "dns_records" in facts and "tls_certificate" in facts


def test_enrich_stage_writes_facts_and_the_age_feature(harness, store, registry_data):
    harness.recorder.rdap["harness.test"] = rdap_doc(
        "harness.test", datetime.now(UTC) - timedelta(days=5, hours=1)
    )
    cand, _ = upsert_candidate(
        store.conn,
        "secure.harness.test",
        match_strength="strong",
        registrable_domain="harness.test",
    )
    case_id = store.conn.execute(
        "INSERT INTO cases (candidate_id, created_at, updated_at) VALUES (?, ?, ?)",
        (cand, time.time(), time.time()),
    ).lastrowid
    stages = harness_stages(harness, store, registry(registry_data))
    from brandsentinel.store.jobs import Job

    job = Job(1, "enrich", "strong", {"case_id": case_id, "round": 0}, 1, 3, "t", "tok", 0)
    asyncio.run(stages.enrich(job))
    names = {
        r[0] for r in store.conn.execute("SELECT name FROM facts WHERE case_id = ?", (case_id,))
    }
    assert {"dns_records", "rdap_registration", "tls_certificate", "similarity"} <= names
    age = store.conn.execute(
        "SELECT value_json, fact_refs FROM features WHERE name = 'domain_age_days'"
    ).fetchone()
    assert json.loads(age[0]) == 5 and json.loads(age[1])


@pytest.mark.parametrize(
    ("host", "server", "error_part"),
    [
        ("expired.harness.test", "expired", "expired"),
        ("wronghost.harness.test", "secure", "mismatch"),
    ],
)
def test_tls_verification_failures_are_named(
    harness, store, registry_data, host, server, error_part
):
    stages = harness_stages(
        harness, store, registry(registry_data), tls_port=getattr(harness, server).port
    )
    tls = collect(stages, host)["tls_certificate"]
    assert tls["verification_passes"] is False and error_part in tls["verification_error"].lower()


def test_tls_against_a_non_tls_port_is_an_error_fact(harness, store, registry_data):
    stages = harness_stages(harness, store, registry(registry_data), tls_port=harness.http.port)
    assert collect(stages, "site.harness.test")["tls_error"]["kind"] in (
        "handshake_failed",
        "connect_error",
        "timeout",
    )


def test_bootstrap_failure_backs_off_instead_of_refetching(harness, store, registry_data, tmp_path):
    from tests.security.harness import harness_fetcher

    from brandsentinel.config import EnrichSettings
    from brandsentinel.enrich.rdap import RdapClient

    url = f"https://dead.harness.test:{harness.dead_port}/dns.json"
    client = RdapClient(
        harness_fetcher(harness), EnrichSettings(rdap_bootstrap_url=url), tmp_path / "cache"
    )
    calls = []
    real = client._get_json

    async def counting(u, n):
        calls.append(u)
        return await real(u, n)

    client._get_json = counting

    async def go():
        return await asyncio.gather(
            *(client.lookup("x.test") for _ in range(5)), return_exceptions=True
        )

    errors = asyncio.run(go())
    assert len(calls) == 1  # one refresh, then backoff
    assert {e.kind for e in errors} == {"bootstrap_unavailable"}
