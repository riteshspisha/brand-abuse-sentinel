"""Load and validate the Brand Registry YAML."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from brandsentinel.matching.normalize import InvalidName, canonical_host, registrable_domain
from brandsentinel.registry.model import Registry

# The one relationship type that lets a third-party domain suppress findings.
AUTHORIZED_DOMAIN = "authorized_domain"


class RegistryError(Exception):
    """The registry is unreadable or fails validation."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class ValidationReport:
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, Counter] = field(default_factory=dict)


def load_registry(path: Path) -> tuple[Registry, ValidationReport]:
    """Parse, schema-check and cross-check a registry file. Raises RegistryError."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise RegistryError([f"cannot read registry {path}: {e}"]) from e
    except yaml.YAMLError as e:
        raise RegistryError([f"invalid YAML in {path}: {e}"]) from e
    try:
        registry = Registry.model_validate(raw)
    except ValidationError as e:
        errors = [
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in e.errors()
        ]
        raise RegistryError(errors) from e
    return registry, validate(registry)


def _duplicates(values: list) -> list:
    return sorted(v for v, n in Counter(values).items() if n > 1)


def validate(registry: Registry) -> ValidationReport:
    """Cross-entry checks. Raises RegistryError listing every error found."""
    errors: list[str] = []
    report = ValidationReport()
    brand_ids = {b.id for b in registry.brands}
    keywords = [k for b in registry.brands for k in b.keywords]
    terms = {k.term: k for k in keywords}
    domains = {d.name for d in registry.domains}
    payees = {p.id for p in registry.payees}

    for what, values in (
        ("brand id", [b.id for b in registry.brands]),
        ("keyword", [k.term for k in keywords]),
        ("context term", [t.term for t in registry.context_terms]),
        ("exclusion", [(e.term, e.scope) for e in registry.exclusions]),
        ("domain", [d.name for d in registry.domains]),
        ("payee id", [p.id for p in registry.payees]),
        ("reference page", [r.url for r in registry.reference_pages]),
    ):
        errors += [f"duplicate {what}: {v}" for v in _duplicates(values)]

    for k in keywords:
        if k.tier == "low" and k.fuzzy:
            errors.append(f"keyword {k.term}: low-tier keywords cannot be fuzzy")

    for e in registry.exclusions:
        if e.scope not in terms:
            errors.append(f"exclusion {e.term}: scope {e.scope!r} is not a keyword")
        elif e.scope not in e.term:
            report.warnings.append(
                f"exclusion {e.term!r} does not contain {e.scope!r}, so it can never apply"
            )

    for owner, brand in (
        *((f"domain {d.name}", d.brand) for d in registry.domains),
        *((f"payee {p.id}", p.brand) for p in registry.payees),
        *((f"reference page {r.url}", r.brand) for r in registry.reference_pages),
    ):
        if brand not in brand_ids:
            errors.append(f"{owner}: unknown brand {brand!r}")

    for d in registry.domains:
        try:
            host, wildcard = canonical_host(d.name)
        except InvalidName as e:
            errors.append(f"domain {d.name!r}: {e}")
            continue
        if host != d.name or wildcard:
            errors.append(f"domain {d.name!r}: write it as {host!r}")
        elif not registrable_domain(host):
            errors.append(f"domain {d.name}: is a public suffix, not a registrable domain")

    def resolves(ref: str) -> bool:
        kind, _, value = ref.partition(":")
        return value in {"brand": brand_ids, "domain": domains, "payee": payees}.get(kind, ())

    authorized = set()  # (brand ref, domain ref) pairs a maintainer confirmed
    for r in registry.relationships:
        bad = [ref for ref in (r.from_, r.to) if not resolves(ref)]
        if bad:
            errors.append(f"relationship {r.from_} -{r.type}-> {r.to}: unknown {', '.join(bad)}")
        elif r.status == "confirmed" and r.type == AUTHORIZED_DOMAIN:
            authorized.add((r.from_, r.to))

    for d in registry.domains:
        if not d.suppresses:
            continue
        if d.status != "confirmed":
            errors.append(f"domain {d.name}: only confirmed domains may suppress (is {d.status})")
        elif d.kind == "third_party" and (f"brand:{d.brand}", f"domain:{d.name}") not in authorized:
            errors.append(
                f"domain {d.name}: a third-party domain suppresses only with a confirmed"
                f" {AUTHORIZED_DOMAIN} relationship from brand:{d.brand}"
            )

    if errors:
        raise RegistryError(errors)

    report.counts = {
        "brands": Counter(b.status for b in registry.brands),
        "keywords": Counter(f"{k.tier}/{k.status}" for k in keywords),
        "context terms": Counter(t.status for t in registry.context_terms),
        "exclusions": Counter(e.status for e in registry.exclusions),
        "domains": Counter(d.status for d in registry.domains),
        "suppressing domains": Counter(d.status for d in registry.suppressing_domains()),
        "relationships": Counter(r.status for r in registry.relationships),
        "payees": Counter(p.status for p in registry.payees),
        "reference pages": Counter(r.status for r in registry.reference_pages),
    }
    return report
