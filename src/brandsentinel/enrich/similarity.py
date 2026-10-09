"""Domain-similarity measures against the Brand Registry (U10).

Pure and deterministic: edit distance from each name label to each brand
keyword, whether the confusable skeleton or the hyphen-folded name contains the
keyword, and edit distance from the registrable label to each official domain's.
These are measurements for the policy layer, not verdicts.
"""

from rapidfuzz.distance import Levenshtein

from brandsentinel.matching.normalize import normalize, registrable_domain
from brandsentinel.registry.model import Registry

COLLECTOR_VERSION = "similarity/1"
MAX_OFFICIAL = 5


def _label_of(domain: str) -> str:
    rd = registrable_domain(domain) or domain
    return rd.split(".", 1)[0]


def similarity(host: str, registry: Registry) -> dict:
    n = normalize(host)
    labels = [p for p in n.skeleton.split(".") if p]
    parts = labels + [p for label in labels for p in label.split("-") if p and p != label]
    brands = []
    for brand, kw in registry.keywords():
        term = kw.term
        distances = [(Levenshtein.distance(p.replace("-", ""), term), p) for p in parts]
        best, closest = min(distances) if distances else (None, None)
        brands.append(
            {
                "brand": brand.id,
                "keyword": term,
                "tier": kw.tier,
                "min_label_distance": best,
                "closest_label": closest,
                "contains": term in n.host.replace("-", ""),
                "skeleton_contains": term in n.folded,
            }
        )
    own = _label_of(n.host)
    official = sorted(
        (
            {"domain": d.name, "distance": Levenshtein.distance(own, _label_of(d.name))}
            for d in registry.domains
            if d.kind == "official"
        ),
        key=lambda x: (x["distance"], x["domain"]),
    )[:MAX_OFFICIAL]
    return {
        "host": n.host,
        "unicode_host": n.unicode_host,
        "idn": n.idn,
        "registrable_domain": n.registrable_domain,
        "brands": brands,
        "closest_official_domains": official,
    }
