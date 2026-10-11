"""Conditional image collection and media analysis for a case (U16, U17).

After a final static fetch, `decide` records whether the case's images are
worth examining and which ones (`media_decision` fact):

- never on a confirmed official domain, or without a fetched HTML page;
- triggered when the page is image-only, shows QR-code candidates, or is
  brand-related (the domain name matches a brand, or the page presents,
  mentions or claims one, or asks for donations);
- at most `media.max_images_per_case` images, in order: QR candidates, logo
  candidates, icons, og:image, then (image-only pages) the page images, and
  inline `data:` images.

The `media` stage (registered only when the sandbox runtime passed its checks)
then fetches each selected image through the hardened fetcher in evidence mode
(netguard, per-hop validation, image types only, size and time caps; in lab mode
only through the lab proxy), stores accepted bytes in the blob store under the
artifact quotas, and has them decoded, hashed, QR-decoded and OCR'd by the media
sandbox. It records one `media_analysis` fact, a `visual_matches` feature (the
corpus version and matcher settings included) and a `media_text` feature, all
in one transaction with the stage marker, and re-scores the case.

What could not be observed stays visible: an image that was not fetched, was
rejected by the worker or stopped by the sandbox limits is recorded with its
reason (`media_rejected`), and a case whose media job has not run shows
`pending`. None of it is read as benign.
"""

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import time

from brandsentinel.analysis import Page
from brandsentinel.analysis.images import inline_images
from brandsentinel.analysis.media_text import VERSION as MEDIA_TEXT_VERSION
from brandsentinel.analysis.media_text import media_text
from brandsentinel.evidence.bundle import EvidenceBundle
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage
from brandsentinel.policy.rules import presented_brands
from brandsentinel.sandbox.media_client import MediaClient, MediaItem
from brandsentinel.sandbox.runner import SandboxError
from brandsentinel.store.blobs import QuotaExceeded
from brandsentinel.store.db import transaction
from brandsentinel.store.jobs import Job
from brandsentinel.store.records import add_feature
from brandsentinel.visual.compare import HashMatcher, ImageHashes, VisualMatcher
from brandsentinel.visual.corpus import load_corpus

log = logging.getLogger(__name__)

MEDIA = "media"
DECISION_VERSION = "media_decision/1"
STAGE_VERSION = "media_stage/1"
MAX_LOGOS = 4
MAX_ICONS = 2


class TransientMediaFailure(Exception):
    """The sandbox could not start a container; the queue retries the job."""


def _candidates(b: EvidenceBundle, images: dict, reasons: list[str], cap: int) -> list[dict]:
    out: list[dict] = []

    def add(ref: str | None, role: str, why: list[str], *, ocr: bool, qr: bool) -> None:
        if ref and len(out) < cap and all(c["ref"] != ref for c in out):
            out.append({"ref": ref, "role": role, "why": why, "ocr": ocr, "qr": qr})

    imgs = images.get("images") or []
    for url in b.payment.qr_images:
        add(url, "qr", ["qr_hint"], ocr=False, qr=True)
    for i in imgs:
        if i.get("qr_hint"):
            add(i["url"], "qr", ["qr_hint"], ocr=False, qr=True)
    looks = "brand_related" in reasons or "image_only" in reasons
    if looks:
        logos = [i for i in imgs if i.get("logo_hints")]
        logos.sort(key=lambda i: (-len(i["logo_hints"]), i.get("index", 0)))
        for i in logos[:MAX_LOGOS]:
            add(i["url"], "logo", i["logo_hints"], ocr=True, qr=False)
        for icon in (images.get("icons") or [])[:MAX_ICONS]:
            add(icon["url"], "favicon", [icon.get("rel") or "icon"], ocr=False, qr=False)
        for url in (images.get("og_images") or [])[:1]:
            add(url, "og_image", ["og:image"], ocr=True, qr=True)
    if "image_only" in reasons:
        for i in imgs:
            add(i["url"], "page_image", ["image_only_page"], ocr=True, qr=True)
    if looks:
        for n in range(int(images.get("inline_images") or 0)):
            add(f"inline:{n}", "inline", ["data_uri"], ocr=True, qr=True)
    return out


def decide(b: EvidenceBundle, images: dict | None, *, enabled: bool, cap: int) -> dict:
    """The media decision for a freshly fetched case (see the module doc)."""
    base = {"analysis_round": b.http.analysis_round, "media_enabled": enabled}
    if b.registry.official_domain:
        return {**base, "triggered": False, "skipped": "official_domain", "reasons": []}
    if not (b.http.fetched and b.http.outcome == "ok" and b.page.available):
        return {**base, "triggered": False, "skipped": "no_page", "reasons": []}
    reasons = []
    if b.page.image_only:
        reasons.append("image_only")
    imgs = (images or {}).get("images") or []
    if b.payment.qr_images or any(i.get("qr_hint") for i in imgs):
        reasons.append("qr_candidates")
    if (
        b.discovery.domain_match in ("strong", "weak")
        or b.association.strong_mention
        or presented_brands(b)
        or b.association.claims
        or (b.payment.donation_cues and b.association.brands)
    ):
        reasons.append("brand_related")
    if not reasons:
        return {**base, "triggered": False, "skipped": "not_brand_related", "reasons": []}
    found = _candidates(b, images or {}, reasons, cap)
    if not found:
        return {**base, "triggered": False, "skipped": "no_images", "reasons": reasons}
    return {**base, "triggered": True, "skipped": None, "reasons": reasons, "candidates": found}


class MediaStage:
    def __init__(
        self,
        analysis,  # pipeline.stages.AnalysisStages
        client: MediaClient,
        *,
        matcher: VisualMatcher | None = None,
    ) -> None:
        self.a = analysis
        self.store = analysis.store
        self.config = analysis.config
        self.settings = self.config.media
        self.client = client
        self.matcher = matcher or HashMatcher(self.settings.matching)

    def register(self, orch: Orchestrator) -> None:
        c = self.config
        orch.register_stage(
            Stage(
                MEDIA,
                self.run,
                concurrency=c.stages.media,
                per_domain=True,
                per_group_limit=1,
                lease_seconds=c.jobs.lease_for(MEDIA),
                retry_delay_seconds=60.0,
            )
        )

    # --- collection -------------------------------------------------------------------

    async def _collect(self, decision: dict, page: tuple | None) -> list[dict]:
        """Fetch (or decode inline) every candidate within the time budget."""
        deadline = time.monotonic() + self.settings.collect_timeout_seconds
        inline: list[dict] | None = None
        out = []
        for c in decision.get("candidates") or []:
            rec = {
                "ref": c["ref"],
                "role": c["role"],
                "why": c["why"],
                "ocr": c["ocr"],
                "qr": c["qr"],
            }
            if time.monotonic() > deadline:
                out.append(
                    {**rec, "status": "not_fetched", "reason": "collection_budget_exhausted"}
                )
                continue
            if c["ref"].startswith("inline:"):
                if inline is None:
                    inline = await asyncio.to_thread(self._inline, page)
                data = self._inline_bytes(inline, int(c["ref"].split(":", 1)[1]))
                if data is None:
                    out.append({**rec, "status": "not_fetched", "reason": "inline_unreadable"})
                else:
                    out.append({**rec, "data": data})
                continue
            try:
                async with asyncio.timeout(max(0.1, deadline - time.monotonic())):
                    r = await self.a.fetcher.fetch(
                        c["ref"],
                        mode="evidence",
                        accept=self.settings.accept_types,
                        max_bytes=self.settings.max_image_bytes,
                    )
            except TimeoutError:
                out.append(
                    {**rec, "status": "not_fetched", "reason": "collection_budget_exhausted"}
                )
                continue
            fetch = {
                "outcome": r.outcome,
                "status": r.status,
                "final_url": r.final_url,
                "content_type": r.body.content_type if r.body else None,
                "bytes": r.body.decoded_bytes if r.body else 0,
                "truncated": r.body.truncated if r.body else None,
                "tls_verification_failed": r.tls_verification_failed,
                "error": r.error,
                "hops": len(r.hops),
            }
            rec["fetch"] = fetch
            if r.outcome == "ok" and r.status in (404, 410):
                # The image does not exist: nothing is hidden from us.
                out.append({**rec, "status": "absent", "reason": f"http_{r.status}"})
            elif r.outcome != "ok":
                out.append({**rec, "status": "not_fetched", "reason": f"fetch_{r.outcome}"})
            elif r.body is None or not r.body.data:
                # Not an accepted image type (an HTML page, for instance), or empty.
                # Unknown, unless it was only our guess at a default favicon.
                status = "absent" if "default" in c["why"] else "not_fetched"
                out.append({**rec, "status": status, "reason": f"not_an_image_response_{r.status}"})
            elif r.body.truncated:
                out.append(
                    {**rec, "status": "not_fetched", "reason": f"too_large_{r.body.truncated}"}
                )
            else:
                out.append({**rec, "data": r.body.data})
        return out

    def _inline(self, page: tuple | None) -> list[dict]:
        if page is None:
            return []
        data, url = page
        return inline_images(Page(data.decode("utf-8", "replace"), url))

    def _inline_bytes(self, found: list[dict], n: int) -> bytes | None:
        if n >= len(found):
            return None
        b64 = found[n]["data"]
        if len(b64) > (self.settings.max_image_bytes * 4) // 3 + 4:
            return None
        try:
            return base64.b64decode(b64, validate=False)
        except (binascii.Error, ValueError):
            return None

    # --- the stage --------------------------------------------------------------------

    async def run(self, job: Job) -> None:
        a = self.a
        case_id, rnd = int(job.payload["case_id"]), int(job.payload.get("round", 0))
        case = a._case(case_id)
        if case is None or case.status != "open" or a._done(case_id, MEDIA, rnd):
            return
        decision_row = self.store.conn.execute(
            "SELECT id, value_json FROM facts WHERE case_id = ? AND name = 'media_decision'"
            " AND json_extract(value_json, '$.analysis_round') = ? ORDER BY id DESC LIMIT 1",
            (case_id, rnd),
        ).fetchone()
        decision = json.loads(decision_row[1]) if decision_row else {}
        if not decision.get("triggered"):
            with transaction(self.store.conn):
                a._finish(case_id, MEDIA, rnd, "skipped")
            return
        collected = await self._collect(decision, self._page(case_id, rnd))
        items, by_sha = [], {}
        total = 0
        for i, rec in enumerate(collected):
            data = rec.get("data")
            if data is None:
                continue
            if total + len(data) > self.settings.max_batch_bytes:
                rec.update(status="not_fetched", reason="batch_budget_exhausted")
                rec.pop("data")
                continue
            sha = hashlib.sha256(data).hexdigest()
            rec["sha256"] = sha
            if sha not in by_sha:
                by_sha[sha] = f"m{i}"
                items.append(
                    MediaItem(
                        f"m{i}", data, ocr=rec["ocr"], qr=rec["qr"] or rec["role"] != "favicon"
                    )
                )
                total += len(data)
            else:  # the same bytes under another reference: analyze once, OCR if any asks
                prev = next(x for x in items if x.id == by_sha[sha])
                if rec["ocr"] and not prev.ocr:
                    items[items.index(prev)] = MediaItem(prev.id, prev.data, ocr=True, qr=prev.qr)
        try:
            batch = await self.client.analyze(
                items, job=f"media-{case_id}-r{rnd}", attempt=job.attempts
            )
        except SandboxError as e:
            if job.attempts < job.max_attempts:
                raise TransientMediaFailure(str(e)) from e
            batch = None
            error = f"sandbox unavailable: {e}"[:300]
        else:
            error = batch.error
        await self._record(case, rnd, decision_row[0], collected, by_sha, batch, error)
        a.score(case_id)

    def _page(self, case_id: int, rnd: int) -> tuple | None:
        """The stored page of the round's final fetch (for inline images)."""
        row = self.store.conn.execute(
            "SELECT value_json, artifact_refs FROM facts WHERE case_id = ? AND name = 'http_fetch'"
            " AND json_extract(value_json, '$.final')"
            " AND json_extract(value_json, '$.analysis_round') = ? ORDER BY id DESC LIMIT 1",
            (case_id, rnd),
        ).fetchone()
        if row is None:
            return None
        value, refs = json.loads(row[0]), json.loads(row[1])
        sha = (value.get("body") or {}).get("sha256")
        if not sha or sha not in refs or not value.get("final_url"):
            return None
        try:
            return self.store.blobs.read(sha), value["final_url"]
        except OSError:
            return None

    async def _record(self, case, rnd, decision_id, collected, by_sha, batch, error) -> None:
        a = self.a
        results = batch.items if batch is not None else {}
        images = []
        blobs: dict[str, bytes] = {}
        for rec in collected:
            data = rec.pop("data", None)
            entry = {k: rec[k] for k in ("ref", "role", "why") if k in rec}
            entry["fetch"] = rec.get("fetch")
            if "sha256" not in rec:
                images.append({**entry, "status": rec["status"], "reason": rec["reason"]})
                continue
            sha = rec["sha256"]
            item = results.get(by_sha[sha])
            if item is None:
                images.append(
                    {**entry, "sha256": sha, "status": "failed", "reason": "sandbox_unavailable"}
                )
                continue
            entry.update(sha256=sha, status=item["status"], reason=item.get("reason"))
            if item["status"] == "ok":
                entry["result"] = {k: v for k, v in item.items() if k != "id"}
                entry["low_information"] = (
                    item["luma_stddev"] < self.settings.matching.min_luma_stddev
                )
            images.append(entry)
            if data is not None:
                blobs.setdefault(sha, data)
        ok = [i for i in images if i["status"] == "ok"]
        expected = [i for i in images if i["status"] != "absent"]
        status = "complete" if len(ok) == len(expected) else ("partial" if ok else "failed")
        corpus = load_corpus(self.store.conn, a.registry)
        matches = []
        for img in ok:
            for m in self.matcher.match(ImageHashes.from_media(img["result"]), corpus):
                matches.append({"image": img["sha256"], **m.to_dict()})
        seen_sha: set[str] = set()
        texts = []
        for img in ok:
            if img["sha256"] in seen_sha:
                continue
            seen_sha.add(img["sha256"])
            r = img["result"]
            texts.append(
                {
                    "sha256": img["sha256"],
                    "role": img["role"],
                    "ocr_text": (r.get("ocr") or {}).get("text") or "",
                    "qr": [c["text"] for c in (r.get("qr") or {}).get("codes") or []],
                }
            )
        bundle = a.scorer.bundle(case.case_id)
        html_presented = list(bundle.association.presented) if bundle else []
        derived = media_text(texts, a.analysis_context.lexicon, html_presented)
        value = {
            "status": status,
            "decision_fact": decision_id,
            "batch": batch.to_fact() if batch is not None else {"status": "failed", "error": error},
            "images": images,
        }
        # Blobs, fact, features and the marker in one transaction: a crash leaves
        # all of them or none (an orphan file is swept).
        with transaction(self.store.conn):
            if a._done(case.case_id, MEDIA, rnd):  # a redelivery finished first
                return
            stored = [sha for sha, data in blobs.items() if self._store(case, data, sha)]
            fact_id = a._fact(
                case.case_id, "media", "media_analysis", value, STAGE_VERSION, rnd, stored
            )
            now = a.clock()
            add_feature(
                self.store.conn,
                case.case_id,
                name="visual_matches",
                value={
                    "analysis_round": rnd,
                    "matcher": self.matcher.describe(),
                    "corpus_version": corpus.version,
                    "corpus_entries": len(corpus.entries),
                    "corpus_rejected": len(corpus.rejected),
                    "compared": len(ok),
                    "matches": matches,
                },
                extractor_version=self.matcher.version,
                fact_refs=[fact_id],
                now=now,
            )
            add_feature(
                self.store.conn,
                case.case_id,
                name="media_text",
                value={**derived, "analysis_round": rnd},
                extractor_version=MEDIA_TEXT_VERSION,
                fact_refs=[fact_id],
                now=now,
            )
            a._finish(case.case_id, MEDIA, rnd, status)

    def _store(self, case, data: bytes, sha: str) -> bool:
        try:
            got = self.store.blobs.put(
                data,
                case_id=case.case_id,
                registrable_domain=case.group_key,
                content_type="application/octet-stream",  # inert: never served or opened
                role="image",
                privileged=case.match_strength == "strong",
            )
        except QuotaExceeded:
            return False
        return got == sha
