"""The trusted reference corpus (U17, R13, FA3).

Rows are written by the collector (`registry collect`). Loading re-checks every
active row against the *current* registry, because only confirmed official
assets and pages may establish an authoritative brand reference:

- `registry_asset` rows: the asset still exists, is confirmed, belongs to the
  same brand and pins the same sha256;
- `collected` rows: fetched with verified TLS (`tls_mode` verified,
  `trusted_reference` true; anything fetched in `evidence` mode is refused), the
  reference page is still confirmed for the brand, and the image's host is a
  confirmed official domain of the brand.

A row failing any check is left out of matching and reported, never trusted.
The corpus `version` is a digest of the entries used, recorded with every
match so a decision can be traced to the corpus it was made against.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit

from brandsentinel.registry.model import Registry

CORPUS_FORMAT = "corpus/1"


@dataclass(frozen=True)
class CorpusEntry:
    id: int
    brand: str
    kind: str
    origin: str
    asset_id: str | None
    reference_page: str | None
    source: str
    sha256: str
    phash: str
    dhash: str
    favicon_mmh3: int | None
    width: int
    height: int
    luma_stddev: float
    tls_mode: str | None
    trusted_reference: bool

    def reference(self) -> dict:
        """What a match records about the reference it matched."""
        return {
            "corpus_id": self.id,
            "brand": self.brand,
            "kind": self.kind,
            "origin": self.origin,
            "asset_id": self.asset_id,
            "reference_page": self.reference_page,
            "source": self.source,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class Corpus:
    entries: tuple[CorpusEntry, ...]
    rejected: tuple[tuple[int, str], ...] = ()  # (row id, why)

    @property
    def version(self) -> str:
        keyed = sorted((e.id, e.sha256, e.phash, e.dhash) for e in self.entries)
        digest = hashlib.sha256(json.dumps(keyed).encode()).hexdigest()[:16]
        return f"{CORPUS_FORMAT}:{len(self.entries)}:{digest}"


_COLUMNS = (
    "id, brand, kind, origin, asset_id, reference_page, source, sha256, phash, dhash,"
    " favicon_mmh3, width, height, luma_stddev, tls_mode, trusted_reference"
)


def check_entry(e: CorpusEntry, registry: Registry) -> str | None:
    """Why `e` may not serve as an authoritative reference now, or None."""
    if e.origin == "registry_asset":
        asset = next((a for a in registry.reference_assets if a.id == e.asset_id), None)
        if asset is None:
            return "registry asset no longer exists"
        if asset.status != "confirmed":
            return f"registry asset is {asset.status}"
        if asset.brand != e.brand or asset.sha256 != e.sha256:
            return "registry asset brand or pinned sha256 differs"
        if asset.url is not None and not (e.tls_mode == "verified" and e.trusted_reference):
            return "asset URL was not fetched with verified TLS"
        return None
    if e.origin == "collected":
        if e.tls_mode != "verified" or not e.trusted_reference:
            return f"fetched in {e.tls_mode or 'unknown'} TLS mode, not as a trusted reference"
        page = next((p for p in registry.reference_pages if p.url == e.reference_page), None)
        if page is None or page.status != "confirmed" or page.brand != e.brand:
            return "reference page is not a confirmed reference page of the brand"
        try:
            host = (urlsplit(e.source).hostname or "").lower()
        except ValueError:
            host = ""
        if not e.source.startswith("https://") or not registry.on_confirmed_official_domain(
            e.brand, host
        ):
            return "image host is not a confirmed official domain of the brand"
        return None
    return f"unknown origin {e.origin!r}"


def load_corpus(conn: sqlite3.Connection, registry: Registry) -> Corpus:
    entries, rejected = [], []
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM reference_corpus WHERE active = 1 ORDER BY id"  # noqa: S608
    ).fetchall()
    for r in rows:
        e = CorpusEntry(*r[:15], trusted_reference=bool(r[15]))
        why = check_entry(e, registry)
        if why is None:
            entries.append(e)
        else:
            rejected.append((e.id, why))
    return Corpus(tuple(entries), tuple(rejected))
