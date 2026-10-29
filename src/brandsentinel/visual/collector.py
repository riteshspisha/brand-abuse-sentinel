"""The reference collector, `registry collect` (U17, R13, R14, FA3).

Builds the trusted reference corpus from two sources, and only these:

- confirmed registry reference assets: a file under `registry/assets/` or an
  https URL on a confirmed official domain of the brand; the bytes must match
  the asset's pinned sha256;
- confirmed reference pages: fetched with verified TLS through the hardened
  fetcher (`purpose="reference"`), with every hop restricted to https on a
  confirmed official domain of the page's brand. From each page the favicon,
  logo candidates and og:image are collected under the same restrictions. With
  a browser client (M7), the page is also rendered in the browser sandbox with
  verified TLS, and its screenshot becomes a `screenshot` entry when every
  navigation and redirect stayed on https on a confirmed official domain of
  the brand.

Every image is hashed by the media sandbox, never in this process. Third-party
domains, payment destinations and images hosted elsewhere that appear on
official pages are recorded as `candidate` observations for a maintainer to
review (R14); they never enter the corpus and never suppress anything.
Candidate (unconfirmed) pages and assets are skipped and reported.

A source that cannot be examined this run (fetch failed, sandbox failed) keeps
its earlier corpus entries; an entry is retired only when its source was
examined successfully and no longer yields it.
"""

import hashlib
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from brandsentinel.analysis import AnalysisContext, host_of, registrable_of, run_extractors
from brandsentinel.analysis.association import BrandLexicon
from brandsentinel.config import MediaSettings
from brandsentinel.net.fetcher import Fetcher, FetchResult
from brandsentinel.registry.model import ReferenceAsset, ReferencePage, Registry
from brandsentinel.sandbox.media_client import MAX_ITEMS, WORKER_VERSION, MediaClient, MediaItem
from brandsentinel.sandbox.runner import SandboxError
from brandsentinel.store.db import transaction
from brandsentinel.textsafe import sanitize_fact

log = logging.getLogger(__name__)

COLLECTOR_VERSION = "collector/1"
PAGE_TYPES = ("text/html", "application/xhtml+xml")
MAX_ICONS = 3
MAX_OG = 2
MAX_LOGOS = 5


@dataclass
class Source:
    """One image to hash, with what makes it authoritative."""

    brand: str
    kind: str
    origin: str  # registry_asset | collected
    source: str  # URL, or registry/assets path
    data: bytes
    tls_mode: str | None
    trusted_reference: bool
    provenance: dict
    asset_id: str | None = None
    reference_page: str | None = None


@dataclass
class CollectReport:
    assets: list[dict] = field(default_factory=list)
    pages: list[dict] = field(default_factory=list)
    images: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    added: int = 0
    unchanged: int = 0
    retired: int = 0


class Collector:
    def __init__(
        self,
        conn: sqlite3.Connection,
        registry: Registry,
        fetcher: Fetcher,
        media: MediaClient,
        settings: MediaSettings,
        assets_dir: Path,
        *,
        providers=None,
        browser=None,  # a BrowserClient: reference page screenshots (M7)
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.conn = conn
        self.browser = browser
        self.registry = registry
        self.fetcher = fetcher
        self.media = media
        self.settings = settings
        self.assets_dir = assets_dir
        self.clock = clock
        self.context = AnalysisContext(
            lexicon=BrandLexicon.from_registry(registry), providers=providers
        )

    # --- sources -------------------------------------------------------------------

    def _official(self, brand: str) -> Callable[[str], bool]:
        return lambda host: self.registry.on_confirmed_official_domain(brand, host)

    async def _fetch_image(self, url: str, brand: str) -> FetchResult:
        return await self.fetcher.fetch(
            url,
            mode="verified",
            purpose="reference",
            accept=self.settings.accept_types,
            max_bytes=self.settings.max_image_bytes,
            host_allowed=self._official(brand),
        )

    @staticmethod
    def _usable(r: FetchResult) -> str | None:
        """Why a reference fetch cannot be used, or None."""
        if r.outcome != "ok":
            return f"fetch {r.outcome}: {json.dumps(r.error)[:200] if r.error else ''}".strip()
        if not r.trusted_reference:
            return "not a trusted reference fetch (verified TLS on every hop)"
        if r.body is None or not r.body.data:
            return f"no accepted body (status {r.status})"
        if r.body.truncated:
            return f"body truncated ({r.body.truncated})"
        return None

    def _read_asset_file(self, asset: ReferenceAsset) -> bytes:
        root = self.assets_dir.resolve()
        path = (self.assets_dir / asset.path).resolve()
        if not path.is_relative_to(root):
            raise ValueError("path leaves registry/assets/")
        with path.open("rb") as f:
            data = f.read(self.settings.max_image_bytes + 1)
        if len(data) > self.settings.max_image_bytes:
            raise ValueError("file exceeds media.max_image_bytes")
        return data

    async def _asset(self, asset: ReferenceAsset, report: CollectReport) -> Source | None:
        entry = {"id": asset.id, "brand": asset.brand, "kind": asset.kind}
        if asset.status != "confirmed":
            report.assets.append({**entry, "result": "skipped", "why": f"status {asset.status}"})
            return None
        prov = {"asset_id": asset.id, "registry_provenance": [
            p.model_dump(mode="json") for p in asset.provenance
        ]}  # fmt: skip
        if asset.path is not None:
            try:
                data = self._read_asset_file(asset)
            except (OSError, ValueError) as e:
                report.assets.append({**entry, "result": "refused", "why": str(e)[:200]})
                return None
            source, tls, trusted = f"registry/assets/{asset.path}", None, True
        else:
            r = await self._fetch_image(asset.url, asset.brand)
            if why := self._usable(r):
                report.assets.append({**entry, "result": "refused", "why": why})
                return None
            data, source, tls, trusted = r.body.data, asset.url, r.mode, True
            prov["fetch"] = _fetch_summary(r)
        digest = hashlib.sha256(data).hexdigest()
        if digest != asset.sha256:
            report.assets.append(
                {**entry, "result": "refused", "why": f"content sha256 {digest} differs from pin"}
            )
            self._observe(report, asset.brand, None, "asset_changed", asset.id, {"sha256": digest})
            return None
        report.assets.append({**entry, "result": "hashed"})
        return Source(
            asset.brand, asset.kind, "registry_asset", source, data, tls, trusted, prov, asset.id
        )

    async def _page(
        self, page: ReferencePage, report: CollectReport
    ) -> tuple[list[Source], bool] | None:
        """(sources found on a reference page, whether every in-scope image was
        fetched); None when the page could not be examined. Earlier corpus
        entries of a page are kept unless it was examined completely."""
        entry = {"url": page.url, "brand": page.brand}
        if page.status != "confirmed":
            report.pages.append({**entry, "result": "skipped", "why": f"status {page.status}"})
            return None
        r = await self.fetcher.fetch(
            page.url,
            mode="verified",
            purpose="reference",
            accept=PAGE_TYPES,
            host_allowed=self._official(page.brand),
        )
        why = self._usable(r)
        if why:
            self._snapshot(page, r, {})
            report.pages.append({**entry, "result": "refused", "why": why})
            return None
        results = {
            x.extractor.name: x.value or {}
            for x in run_extractors(
                r.body.data, r.body.content_type, r.body.charset, r.final_url, self.context
            )
        }
        self._snapshot(page, r, results.get("page_content", {}))
        imgs = results.get("images", {})
        wanted: list[tuple[str, str]] = [
            (i["url"], "favicon") for i in imgs.get("icons", [])[:MAX_ICONS]
        ]
        wanted += [(u, "og_image") for u in imgs.get("og_images", [])[:MAX_OG]]
        wanted += [(i["url"], "logo") for i in imgs.get("images", []) if i.get("logo_hints")][
            :MAX_LOGOS
        ]
        sources: list[Source] = []
        complete = True
        seen: set[str] = set()
        for url, kind in wanted:
            if url in seen:
                continue
            seen.add(url)
            host = host_of(url)
            if not (
                url.startswith("https://")
                and self.registry.on_confirmed_official_domain(page.brand, host)
            ):
                self._observe(report, page.brand, page.url, "offsite_image", url, {"kind": kind})
                continue
            ir = await self._fetch_image(url, page.brand)
            if why := self._usable(ir):
                report.images.append({"url": url, "kind": kind, "result": "refused", "why": why})
                complete = False
                continue
            sources.append(
                Source(
                    page.brand,
                    kind,
                    "collected",
                    url,
                    ir.body.data,
                    ir.mode,
                    ir.trusted_reference,
                    {"page_fetch": _fetch_summary(r), "image_fetch": _fetch_summary(ir)},
                    reference_page=page.url,
                )
            )
        if self.browser is not None:
            shot = await self._screenshot(page, report)
            if shot is None:
                complete = False
            else:
                sources.append(shot)
        own = set(self.registry.confirmed_official_domains(page.brand))
        for d in results.get("page_content", {}).get("links", {}).get("external_domains", []):
            if not any(d == o or d.endswith("." + o) for o in own):
                self._observe(report, page.brand, page.url, "third_party_domain", d, {})
        for o in results.get("payment", {}).get("observations", []):
            value = o.get("payee_identifier") or registrable_of(host_of(o.get("destination")))
            if value:
                detail = {k: o.get(k) for k in ("kind", "provider", "payee_name", "source")}
                self._observe(report, page.brand, page.url, "payment_destination", value, detail)
        report.pages.append({**entry, "result": "collected", "images": len(sources)})
        return sources, complete

    async def _screenshot(self, page: ReferencePage, report: CollectReport) -> Source | None:
        """The reference page's screenshot, rendered with verified TLS, or None
        (reported) when it cannot serve as a reference."""
        job = f"ref-{secrets.token_hex(6)}"
        try:
            r = await self.browser.render(page.url, job=job, verify_tls=True)
        except SandboxError as e:
            r = None
            why = f"browser sandbox unavailable: {e}"[:200]
        else:
            why = self._render_unusable(page, r)
        if why:
            report.images.append(
                {"url": page.url, "kind": "screenshot", "result": "refused", "why": why}
            )
            return None
        summary = {
            k: r.doc.get(k)
            for k in ("final_url", "main_status", "redirect_chain", "navigations", "verify_tls")
        }
        return Source(
            page.brand,
            "screenshot",
            "collected",
            r.doc["final_url"],
            r.screenshot,
            "verified",
            True,
            {"render": summary, "runs": r.runs},
            reference_page=page.url,
        )

    def _render_unusable(self, page: ReferencePage, r) -> str | None:
        if r.status != "ok":
            return f"render {r.status}: {r.reason or ''}".strip()[:200]
        if not r.doc.get("verify_tls"):
            return "not rendered with verified TLS"
        if r.doc.get("navigation_error") or not r.screenshot:
            return f"no page: {r.doc.get('navigation_error') or 'no screenshot'}"[:200]
        if len(r.screenshot) > self.settings.max_image_bytes:
            return "screenshot over media.max_image_bytes"
        urls = [r.doc.get("final_url") or "", *(r.doc.get("navigations") or [])]
        urls += [h.get("url") or "" for h in r.doc.get("redirect_chain") or []]
        for url in urls:
            if not (
                url.startswith("https://")
                and self.registry.on_confirmed_official_domain(page.brand, host_of(url))
            ):
                return f"navigated off the official https site: {url[:200]}"
        return None

    # --- hashing and writing ------------------------------------------------------------

    async def _hash(self, sources: list[Source], report: CollectReport) -> dict[int, dict]:
        """Media results by index into `sources`, from the sandbox only."""
        out: dict[int, dict] = {}
        batches: list[list[int]] = [[]]
        size = 0
        for i, s in enumerate(sources):
            if batches[-1] and (
                len(batches[-1]) >= MAX_ITEMS or size + len(s.data) > self.settings.max_batch_bytes
            ):
                batches.append([])
                size = 0
            batches[-1].append(i)
            size += len(s.data)
        for batch in filter(None, batches):
            items = [MediaItem(f"c{i}", sources[i].data, ocr=False, qr=False) for i in batch]
            job = f"corpus-{int(self.clock())}-{secrets.token_hex(3)}"
            result = await self.media.analyze(items, job=job)
            for i in batch:
                item = result.items.get(f"c{i}", {})
                if item.get("status") == "ok":
                    out[i] = item
                else:
                    report.images.append(
                        {
                            "url": sources[i].source,
                            "kind": sources[i].kind,
                            "result": "rejected",
                            "why": f"{item.get('reason')}: {item.get('detail', '')}"[:200],
                        }
                    )
        return out

    def _snapshot(self, page: ReferencePage, r: FetchResult, content: dict) -> None:
        title = sanitize_fact(content.get("title") or "", 300) or None
        excerpt = sanitize_fact(content.get("text_excerpt") or "", 2000) or None
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO reference_page_snapshots (brand, url, final_url, outcome,"
                " trusted_reference, title, text_excerpt, body_sha256, fetch_json, collected_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    page.brand,
                    page.url,
                    r.final_url,
                    r.outcome,
                    int(r.trusted_reference),
                    title,
                    excerpt,
                    r.body.sha256 if r.body else None,
                    json.dumps(_fetch_summary(r), sort_keys=True),
                    self.clock(),
                ),
            )

    def _observe(self, report, brand, page, kind, value, detail) -> None:
        value = sanitize_fact(str(value), 500)
        report.observations.append({"brand": brand, "page": page, "kind": kind, "value": value})
        now = self.clock()
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO reference_observations (brand, reference_page, kind, value,"
                " detail_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (brand, kind, value) DO UPDATE SET last_seen = excluded.last_seen,"
                " reference_page = excluded.reference_page, detail_json = excluded.detail_json",
                (
                    brand,
                    page,
                    kind,
                    value,
                    json.dumps(detail, sort_keys=True, default=str),
                    now,
                    now,
                ),
            )

    def _write(
        self,
        sources: list[Source],
        hashed: dict[int, dict],
        examined_assets: set[str],
        examined_pages: set[str],
        report: CollectReport,
    ) -> None:
        now = self.clock()
        keep: set[tuple[str, str, str]] = set()
        with transaction(self.conn):
            for i, s in enumerate(sources):
                item = hashed.get(i)
                if item is None:
                    continue
                key = (s.origin, s.source, item["sha256"], s.asset_id or "", s.reference_page or "")
                keep.add(key)
                exists = self.conn.execute(
                    "SELECT 1 FROM reference_corpus WHERE active = 1 AND origin = ? AND source = ?"
                    " AND sha256 = ? AND COALESCE(asset_id, '') = ?"
                    " AND COALESCE(reference_page, '') = ?",
                    key,
                ).fetchone()
                if exists:
                    report.unchanged += 1
                    continue
                self.conn.execute(
                    "INSERT INTO reference_corpus (brand, kind, origin, asset_id, reference_page,"
                    " source, sha256, phash, dhash, favicon_mmh3, width, height, format,"
                    " luma_stddev, tls_mode, trusted_reference, provenance_json,"
                    " collector_version, worker_version, collected_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        s.brand,
                        s.kind,
                        s.origin,
                        s.asset_id,
                        s.reference_page,
                        s.source,
                        item["sha256"],
                        item["phash"],
                        item["dhash"],
                        item.get("favicon_mmh3"),
                        item["width"],
                        item["height"],
                        item["format"],
                        item["luma_stddev"],
                        s.tls_mode,
                        int(s.trusted_reference),
                        json.dumps(s.provenance, sort_keys=True, default=str),
                        COLLECTOR_VERSION,
                        WORKER_VERSION,
                        now,
                    ),
                )
                report.added += 1
            # Retire what a successfully examined source no longer yields.
            rows = self.conn.execute(
                "SELECT id, origin, source, sha256, asset_id, reference_page FROM reference_corpus"
                " WHERE active = 1"
            ).fetchall()
            for rid, origin, source, sha, asset_id, page in rows:
                examined = (origin == "registry_asset" and asset_id in examined_assets) or (
                    origin == "collected" and page in examined_pages
                )
                if examined and (origin, source, sha, asset_id or "", page or "") not in keep:
                    self.conn.execute(
                        "UPDATE reference_corpus SET active = 0, retired_at = ? WHERE id = ?",
                        (now, rid),
                    )
                    report.retired += 1

    # --- entry point -------------------------------------------------------------------

    async def collect(self, brands: Iterable[str] | None = None) -> CollectReport:
        wanted = set(brands) if brands else {b.id for b in self.registry.brands}
        report = CollectReport()
        sources: list[Source] = []
        asset_index: dict[int, str] = {}
        for asset in self.registry.reference_assets:
            if asset.brand in wanted:
                s = await self._asset(asset, report)
                if s is not None:
                    asset_index[len(sources)] = asset.id
                    sources.append(s)
        page_sources: dict[str, list[int]] = {}
        for page in self.registry.reference_pages:
            if page.brand not in wanted:
                continue
            result = await self._page(page, report)
            if result is not None:
                found, complete = result
                if complete:
                    page_sources[page.url] = list(range(len(sources), len(sources) + len(found)))
                sources.extend(found)
        try:
            hashed = await self._hash(sources, report)
        except SandboxError as e:
            log.error("reference images could not be hashed", extra={"fields": {"error": str(e)}})
            raise
        # A source counts as examined only if all of its images were hashed.
        examined_assets = {asset_index[i] for i in asset_index if i in hashed}
        # Confirmed assets that are no longer confirmed, or whose pin changed, are
        # examined by definition: their rows go.
        confirmed = {
            (a.id, a.sha256) for a in self.registry.reference_assets if a.status == "confirmed"
        }
        stale = {
            r[0]
            for r in self.conn.execute(
                "SELECT asset_id, sha256 FROM reference_corpus"
                " WHERE active = 1 AND origin = 'registry_asset'"
            )
            if (r[0], r[1]) not in confirmed
        }
        examined_pages = {url for url, idx in page_sources.items() if all(i in hashed for i in idx)}
        self._write(sources, hashed, examined_assets | stale, examined_pages, report)
        return report


def _fetch_summary(r: FetchResult) -> dict:
    return {
        "requested_url": r.requested_url,
        "final_url": r.final_url,
        "outcome": r.outcome,
        "status": r.status,
        "mode": r.mode,
        "purpose": r.purpose,
        "trusted_reference": r.trusted_reference,
        "hops": [
            {
                "url": h.url,
                "address": h.address,
                "status": h.status,
                "tls": h.tls.mode if h.tls else None,
            }
            for h in r.hops
        ],
        "body_sha256": r.body.sha256 if r.body else None,
        "error": r.error,
    }
