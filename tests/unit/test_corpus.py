"""The reference corpus loader and registry reference assets (U17, R13, FA3):
only confirmed official assets and pages establish authoritative references."""

import json

import pytest

from brandsentinel.registry.loader import RegistryError, validate
from brandsentinel.registry.model import ReferenceAsset, Registry
from brandsentinel.visual.corpus import load_corpus

SHA = "52b0e3eef1b9fd8e97bc25a2c475b6968606575db9bc14fcd4c69de9c13ffcb1"
PROV = [
    {
        "source": "maintainer",
        "recorded_by": "t",
        "recorded_at": "2026-10-11",
        "verified_by": "m",
        "verified_at": "2026-10-11",
    }
]


def registry(assets=(), pages=(), domains=None) -> Registry:
    return Registry.model_validate(
        {
            "version": 1,
            "brands": [{"id": "lumina", "name": "Lumina Foundation", "status": "confirmed",
                        "provenance": PROV}],
            "domains": domains if domains is not None else [
                {"name": "lumina.org", "brand": "lumina", "status": "confirmed",
                 "provenance": PROV}
            ],
            "reference_assets": list(assets),
            "reference_pages": list(pages),
        }
    )  # fmt: skip


def asset(**kw) -> dict:
    return {
        "id": "logo",
        "brand": "lumina",
        "kind": "logo",
        "path": "lab/logo.png",
        "sha256": SHA,
        "status": "confirmed",
        "provenance": PROV,
        **kw,
    }


def page(**kw) -> dict:
    return {
        "url": "https://www.lumina.org/",
        "brand": "lumina",
        "status": "confirmed",
        "provenance": PROV,
        **kw,
    }


def add(conn, **kw):
    row = {
        "brand": "lumina",
        "kind": "logo",
        "origin": "registry_asset",
        "asset_id": "logo",
        "reference_page": None,
        "source": "registry/assets/lab/logo.png",
        "sha256": SHA,
        "phash": "e5328e8e386d9267",
        "dhash": "0f0f0f0f0f0f0f0f",
        "favicon_mmh3": 1,
        "width": 256,
        "height": 256,
        "format": "PNG",
        "luma_stddev": 40.0,
        "tls_mode": None,
        "trusted_reference": 1,
        "provenance_json": json.dumps({}),
        "collector_version": "collector/1",
        "worker_version": "media_worker/1",
        "collected_at": 1.0,
        **kw,
    }
    cols = ", ".join(row)
    conn.execute(
        f"INSERT INTO reference_corpus ({cols}) VALUES ({', '.join('?' * len(row))})",  # noqa: S608
        tuple(row.values()),
    )


COLLECTED = {
    "origin": "collected",
    "asset_id": None,
    "reference_page": "https://www.lumina.org/",
    "source": "https://www.lumina.org/logo.png",
    "tls_mode": "verified",
    "trusted_reference": 1,
}


def test_confirmed_asset_with_matching_pin_is_used(store):
    add(store.conn)
    corpus = load_corpus(store.conn, registry([asset()]))
    assert [e.asset_id for e in corpus.entries] == ["logo"] and not corpus.rejected


@pytest.mark.parametrize(
    ("assets", "why"),
    [
        ([], "no longer exists"),
        ([asset(status="candidate")], "is candidate"),
        ([asset(status="rejected")], "is rejected"),
        ([asset(sha256="0" * 64)], "pinned sha256 differs"),
    ],
)
def test_registry_asset_not_vouched_for_now_is_not_used(store, assets, why):
    add(store.conn)
    corpus = load_corpus(store.conn, registry(assets))
    assert corpus.entries == () and why in corpus.rejected[0][1]


def test_collected_entry_from_a_confirmed_page_over_verified_tls_is_used(store):
    add(store.conn, **COLLECTED)
    assert len(load_corpus(store.conn, registry(pages=[page()])).entries) == 1


@pytest.mark.parametrize(
    ("row", "pages", "why"),
    [
        ({"tls_mode": "evidence"}, [page()], "evidence TLS mode"),
        ({"trusted_reference": 0}, [page()], "not as a trusted reference"),
        ({}, [page(status="candidate")], "not a confirmed reference page"),
        ({}, [], "not a confirmed reference page"),
        ({"source": "https://cdn.other.org/logo.png"}, [page()], "not a confirmed official"),
        ({"source": "http://www.lumina.org/logo.png"}, [page()], "not a confirmed official"),
    ],
    ids=["evidence-mode", "untrusted", "candidate-page", "unknown-page", "offsite", "http"],
)
def test_collected_entries_the_registry_does_not_vouch_for_are_refused(store, row, pages, why):
    add(store.conn, **{**COLLECTED, **row})
    corpus = load_corpus(store.conn, registry(pages=pages))
    assert corpus.entries == () and why in corpus.rejected[0][1]


def test_unconfirming_the_official_domain_withdraws_collected_entries(store):
    add(store.conn, **COLLECTED)
    reg = registry(
        pages=[page()],
        domains=[{"name": "lumina.org", "brand": "lumina", "status": "candidate",
                  "provenance": PROV}],
    )  # fmt: skip
    assert load_corpus(store.conn, reg).entries == ()


def test_retired_rows_are_not_loaded_and_version_tracks_entries(store):
    add(store.conn)
    v1 = load_corpus(store.conn, registry([asset()])).version
    store.conn.execute("UPDATE reference_corpus SET active = 0")
    corpus = load_corpus(store.conn, registry([asset()]))
    assert (
        corpus.entries == () and corpus.version != v1 and corpus.version.startswith("corpus/1:0:")
    )


# --- registry reference assets -----------------------------------------------------------


@pytest.mark.parametrize(
    "kw",
    [
        {"path": "../etc/passwd"},
        {"path": "/abs/logo.png"},
        {"path": "a/../../b.png"},
        {"path": None, "url": "http://lumina.org/logo.png"},
        {"url": "https://lumina.org/logo.png"},  # both path and url
        {"path": None},  # neither
        {"sha256": None},  # confirmed without a pin
        {"sha256": "ABC"},
    ],
)
def test_reference_asset_schema_refuses(kw):
    with pytest.raises(ValueError):
        ReferenceAsset.model_validate(asset(**kw))


def test_candidate_asset_may_omit_its_pin():
    assert ReferenceAsset.model_validate(asset(status="candidate", sha256=None)).sha256 is None


def test_confirmed_url_asset_must_be_on_a_confirmed_official_domain():
    ok = asset(path=None, url="https://img.lumina.org/logo.png")
    validate(registry([ok]))
    off = asset(path=None, url="https://cdn.example.net/logo.png")
    with pytest.raises(RegistryError, match="not a confirmed official domain"):
        validate(registry([off]))
    report = validate(registry([{**off, "status": "candidate"}]))
    assert any("cannot be confirmed" in w for w in report.warnings)


def test_unknown_brand_and_duplicate_ids_fail_validation():
    with pytest.raises(RegistryError) as e:
        validate(registry([asset(), asset(brand="nobody")]))
    assert any("duplicate reference asset id" in x for x in e.value.errors)
    assert any("unknown brand 'nobody'" in x for x in e.value.errors)


def test_lab_overlay_reference_asset_pin_matches_its_file():
    import hashlib
    from pathlib import Path

    from brandsentinel.registry.loader import load_registry

    root = Path(__file__).parents[2]
    reg, _ = load_registry(root / "registry/brands.yaml", root / "registry/lab-overlay.yaml")
    (a,) = reg.reference_assets
    data = (root / "registry" / "assets" / a.path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == a.sha256 and a.status == "confirmed"
