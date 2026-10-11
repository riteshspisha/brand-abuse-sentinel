"""Helpers for detection tests: lab registry, contexts, and bundles built from HTML.

`bundle_for_html` runs the real extractors over a page and wraps their output in
the same records the store would hold (one final `http_fetch` fact plus one
feature per extractor), then builds the EvidenceBundle. Policy tests can thus
start from real HTML without a database or network, and pure policy tests can
start from hand-written bundles instead.
"""

import hashlib
from functools import cache
from pathlib import Path

import yaml

from brandsentinel.analysis import AnalysisContext, run_extractors
from brandsentinel.analysis.association import BrandLexicon
from brandsentinel.analysis.payment import ProviderCatalog
from brandsentinel.evidence.bundle import CaseInputs, EvidenceBundle, build_bundle
from brandsentinel.evidence.models import FactRecord, FeatureRecord
from brandsentinel.matching.matcher import Matcher
from brandsentinel.matching.normalize import canonical_host, registrable_domain
from brandsentinel.policy.scorer import Policy, PolicyResult, evaluate
from brandsentinel.registry.loader import load_registry
from brandsentinel.registry.model import Registry

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "labsites"


@cache
def lab_registry() -> Registry:
    registry, _ = load_registry(REPO / "registry/brands.yaml", REPO / "registry/lab-overlay.yaml")
    return registry


@cache
def catalog() -> ProviderCatalog:
    return ProviderCatalog.load(REPO / "config/payment_providers.yaml")


@cache
def policy() -> Policy:
    return Policy.load(REPO / "config/policy.yaml")


def context(registry: Registry | None = None) -> AnalysisContext:
    registry = registry or lab_registry()
    return AnalysisContext(BrandLexicon.from_registry(registry), catalog())


def lab_site(site: str) -> tuple[dict, bytes]:
    """expected.yaml and the HTML the static fetcher receives (the cloaking site
    serves its benign page to the fetcher's honest user agent)."""
    expected = yaml.safe_load((LAB / site / "expected.yaml").read_text())
    page = LAB / site / "index.html"
    if not page.exists():
        page = LAB / site / "benign" / "index.html"
    return expected, page.read_bytes()


def lab_sites() -> list[str]:
    return sorted(p.parent.name for p in LAB.glob("*/expected.yaml"))


def bundle_for_html(
    html: bytes | str,
    url: str,
    *,
    registry: Registry | None = None,
    status: int = 200,
    outcome: str = "ok",
    source: str = "manual",
    facts: list[FactRecord] = (),
    hops: list[dict] | None = None,
    error: dict | None = None,
    truncated: str | None = None,
) -> EvidenceBundle:
    registry = registry or lab_registry()
    data = html.encode() if isinstance(html, str) else html
    host, _ = canonical_host(url.split("//", 1)[1].split("/", 1)[0].split(":")[0])
    match = Matcher(registry).match(host)
    sha = hashlib.sha256(data).hexdigest()
    fetch_value = {
        "requested_url": url,
        "final_url": url if outcome == "ok" else None,
        "status": status if outcome == "ok" else None,
        "outcome": outcome,
        "error": error,
        "final": True,
        "analysis_round": 0,
        "hops": hops
        if hops is not None
        else [{"url": url, "status": status, "address": "192.0.2.1"}],
        "body": {
            "content_type": "text/html",
            "sha256": sha,
            "decoded_bytes": len(data),
            "truncated": truncated,
        }
        if outcome == "ok"
        else None,
        "body_stored": outcome == "ok",
    }
    fetch = FactRecord(
        id=100,
        source="fetcher",
        name="http_fetch",
        value=fetch_value,
        artifact_refs=[sha] if outcome == "ok" else [],
        collector_version="fetcher/1",
        observed_at=1_760_000_000.0,
    )
    features = []
    if outcome == "ok":
        for i, r in enumerate(
            run_extractors(data, "text/html", "utf-8", url, context(registry)), start=200
        ):
            value = r.value if r.value is not None else {"error": r.error}
            features.append(
                FeatureRecord(
                    id=i,
                    name=r.extractor.name,
                    value={**value, "analysis_round": 0},
                    extractor_version=r.extractor.version,
                    fact_refs=[fetch.id],
                    computed_at=1_760_000_000.0,
                )
            )
    inputs = CaseInputs(
        case_id=1,
        status="open",
        subject_url=url,
        created_at=1_760_000_000.0,
        host=host,
        registrable_domain=registrable_domain(host),
        match_strength="strong",
        sources=[
            {
                "source": source,
                "first_seen": 1_759_990_000.0,
                "last_seen": 1_759_990_000.0,
                "observations": 1,
            }
        ],
        events=[
            {
                "source": source,
                "observed_at": 1_759_990_000.0,
                "match": match.to_dict(),
                "context": {"submitted": url, "url": url},
                "event_id": "e1",
            }
        ],
        facts=[*facts, fetch],
        features=features,
    )
    return build_bundle(inputs, BrandLexicon.from_registry(registry), registry)


def score_html(html, url, **kw) -> tuple[EvidenceBundle, PolicyResult]:
    b = bundle_for_html(html, url, **kw)
    return b, evaluate(b, policy())


def score_lab(site: str, **kw) -> tuple[EvidenceBundle, PolicyResult]:
    expected, html = lab_site(site)
    return score_html(html, expected["url"], **kw)


def seed_case(
    store,
    html: bytes | str,
    url: str,
    *,
    registry: Registry | None = None,
    status: int = 200,
    round_: int = 0,
    now: float = 1_760_000_000.0,
) -> int:
    """Submit `url` and store a final fetch of `html` with extractor features, as
    the fetch stage would (without network). Returns the case id."""
    from brandsentinel.discovery.submit import submit
    from brandsentinel.store.records import add_fact, add_feature

    registry = registry or lab_registry()
    data = html.encode() if isinstance(html, str) else html
    result = submit(store, Matcher(registry), url, now=now)
    case_id = result.case_id
    sha = store.blobs.put(
        data,
        case_id=case_id,
        registrable_domain=registrable_domain(result.host),
        content_type="text/html",
        role="page",
    )
    fetch_id = add_fact(
        store.conn,
        case_id,
        source="fetcher",
        name="http_fetch",
        value={
            "requested_url": url,
            "final_url": url,
            "status": status,
            "outcome": "ok",
            "final": True,
            "attempt": 1,
            "analysis_round": round_,
            "body_stored": True,
            "hops": [{"url": url, "status": status, "address": "192.0.2.10"}],
            "body": {"content_type": "text/html", "sha256": sha, "decoded_bytes": len(data)},
        },
        collector_version="fetcher/1",
        artifact_refs=[sha],
        now=now,
    )
    for r in run_extractors(data, "text/html", "utf-8", url, context(registry)):
        value = r.value if r.value is not None else {"error": r.error}
        add_feature(
            store.conn,
            case_id,
            name=r.extractor.name,
            value={**value, "analysis_round": round_},
            extractor_version=r.extractor.version,
            fact_refs=[fetch_id],
            now=now,
        )
    return case_id


def scorer(store, registry: Registry | None = None):
    from brandsentinel.policy.scorer import CaseScorer

    return CaseScorer(
        store.conn, registry or lab_registry(), policy(), clock=lambda: 1_760_000_100.0
    )
