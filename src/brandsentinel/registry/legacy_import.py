"""Read the legacy scripts' configuration constants and check registry coverage.

The scripts are parsed with `ast`, never imported or executed (they import boto3
and connect to services at import time). Each value is reported with its file
and line, which is the provenance `source` the registry records for it.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from brandsentinel.registry.model import Registry

# (file, constant) -> legacy kind
LEGACY_CONSTANTS = {
    ("monitor_certstream.py", "STRICT_KEYWORDS"): "strict_keyword",
    ("monitor_certstream.py", "BRAND_KEYWORDS"): "brand_keyword",
    ("monitor_certstream.py", "TARGET_BRANDS"): "fuzzy_target",
    ("monitor_certstream.py", "EXCLUSIONS"): "exclusion",
    ("monitor_certstream.py", "WHITELIST"): "whitelist",
    ("dnstwist.py", "DOMAINS"): "dnstwist_target",
}


class LegacyImportError(Exception):
    pass


@dataclass(frozen=True)
class LegacyEntry:
    kind: str
    value: str
    source: str  # "legacy/<file>:<line>"


def read_legacy(legacy_dir: Path) -> list[LegacyEntry]:
    entries = []
    for filename in sorted({f for f, _ in LEGACY_CONSTANTS}):
        path = legacy_dir / filename
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as e:
            raise LegacyImportError(f"cannot parse {path}: {e}") from e
        wanted = {c: k for (f, c), k in LEGACY_CONSTANTS.items() if f == filename}
        found = set()
        for node in tree.body:
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
                continue
            target = node.targets[0]
            if not (isinstance(target, ast.Name) and target.id in wanted):
                continue
            if not isinstance(node.value, ast.List):
                raise LegacyImportError(f"{filename}:{node.lineno} {target.id} is not a list")
            found.add(target.id)
            for elt in node.value.elts:
                if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
                    raise LegacyImportError(f"{filename}:{elt.lineno} non-string in {target.id}")
                source = f"legacy/{filename}:{elt.lineno}"
                entries.append(LegacyEntry(wanted[target.id], elt.value, source))
        missing = sorted(set(wanted) - found)
        if missing:
            raise LegacyImportError(f"{filename}: constants not found: {missing}")
    return entries


def missing_legacy(registry: Registry, entries: list[LegacyEntry]) -> list[str]:
    """Legacy inputs absent from the registry, or present without their provenance."""
    sources: dict[tuple[str, str], set[str]] = {}

    def record(kind: str, value: str, provenance) -> None:
        sources.setdefault((kind, value), set()).update(p.source for p in provenance)

    for brand in registry.brands:
        for k in brand.keywords:
            record("low" if k.tier == "low" else "high", k.term, k.provenance)
            if k.fuzzy:
                record("fuzzy", k.term, k.provenance)
    for e in registry.exclusions:
        record(f"exclusion:{e.scope}", e.term, e.provenance)
    for d in registry.domains:
        record("domain", d.name, d.provenance)

    expected_key = {
        "strict_keyword": "low",
        "brand_keyword": "high",
        "fuzzy_target": "fuzzy",
        "exclusion": "exclusion:isha",
        "whitelist": "domain",
        "dnstwist_target": "domain",
    }
    missing = []
    for entry in entries:
        key = (expected_key[entry.kind], entry.value)
        if key not in sources:
            missing.append(f"{entry.kind} {entry.value!r} ({entry.source}) is not in the registry")
        elif entry.source not in sources[key]:
            missing.append(f"{entry.kind} {entry.value!r} lacks provenance {entry.source}")
    return missing
