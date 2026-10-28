"""The render stage (U19): isolated browser rendering of triggered or sampled cases.

After the final static fetch, `AnalysisStages.decide_render` records why a case
is rendered (or why not) and queues this stage. It is registered only when the
sandbox runtime, the account gate, the orphan sweep and the network check with
its direct-egress probe all passed; the browser client repeats the network check
(without the probe) before every launch. Otherwise render jobs wait and cases
show `render pending`.

For one case and round the stage:

- renders the static fetch's requested URL in the browser sandbox (the browser
  follows redirects itself, each one through the validating proxy);
- stores the rendered HTML and the screenshot inert in the blob store, under the
  artifact quotas;
- runs the U12 extractors over the rendered HTML: `rendered` features that
  reference the `browser_render` fact;
- sends the screenshot to the media sandbox (hashes, OCR, QR) and matches it
  against the reference corpus (`screenshot_matches`, `screenshot_text`);
- compares the static and rendered views (`cloaking`).

Facts, features, blobs and the stage marker go in one transaction, and the case
is re-scored. A render that failed, was rejected or refused is recorded as such:
the case keeps its static evidence and the gap stays visible.
"""

import asyncio
import hashlib
import json
import logging
from urllib.parse import urlsplit

from brandsentinel.analysis import run_extractors
from brandsentinel.analysis.media_text import VERSION as MEDIA_TEXT_VERSION
from brandsentinel.analysis.media_text import media_text
from brandsentinel.pipeline.orchestrator import Orchestrator, Stage
from brandsentinel.pipeline.stages import RENDER, write_features
from brandsentinel.sandbox import cloaking
from brandsentinel.sandbox.browser_client import BrowserClient, Render
from brandsentinel.sandbox.media_client import MediaClient, MediaItem
from brandsentinel.sandbox.runner import SandboxError
from brandsentinel.store.blobs import QuotaExceeded
from brandsentinel.store.db import transaction
from brandsentinel.store.jobs import Job
from brandsentinel.store.records import add_feature
from brandsentinel.visual.compare import HashMatcher, ImageHashes, VisualMatcher
from brandsentinel.visual.corpus import load_corpus

log = logging.getLogger(__name__)

STAGE_VERSION = "render_stage/1"
MAX_STORED_URL = 500  # per request URL kept in the fact
COMPARED = ("page_content", "page_basics", "brand_references", "payment")


class TransientRenderFailure(Exception):
    """No browser could start (or the network check failed); the queue retries."""


class RenderStage:
    def __init__(
        self,
        analysis,  # pipeline.stages.AnalysisStages
        client: BrowserClient,
        media: MediaClient | None,
        *,
        matcher: VisualMatcher | None = None,
    ) -> None:
        self.a = analysis
        self.store = analysis.store
        self.config = analysis.config
        self.client = client
        self.media = media
        self.matcher = matcher or HashMatcher(self.config.media.matching)

    def register(self, orch: Orchestrator) -> None:
        c = self.config
        orch.register_stage(
            Stage(
                RENDER,
                self.run,
                concurrency=c.stages.render,
                per_domain=True,
                per_group_limit=1,
                lease_seconds=c.jobs.lease_for(RENDER),
                retry_delay_seconds=60.0,
            )
        )

    async def run(self, job: Job) -> None:
        a = self.a
        case_id, rnd = int(job.payload["case_id"]), int(job.payload.get("round", 0))
        case = a._case(case_id)
        if case is None or case.status != "open":
            return
        if a._done(case_id, RENDER, rnd):
            a.score(case_id)  # redelivered after the result was recorded
            return
        row = self.store.conn.execute(
            "SELECT id, value_json FROM facts WHERE case_id = ? AND name = 'render_decision'"
            " AND json_extract(value_json, '$.analysis_round') = ? ORDER BY id DESC LIMIT 1",
            (case_id, rnd),
        ).fetchone()
        decision = json.loads(row[1]) if row else {}
        if not (decision.get("triggered") and decision.get("browser_enabled")):
            with transaction(self.store.conn):
                a._finish(case_id, RENDER, rnd, "skipped")
            return
        url = decision["url"]
        last = job.attempts >= job.max_attempts
        try:
            render = await self.client.render(
                url, job=f"render-{case_id}-r{rnd}", attempt=job.attempts
            )
        except SandboxError as e:
            if not last:
                raise TransientRenderFailure(str(e)) from e
            render = Render("failed", url, f"sandbox unavailable: {e}"[:300])
        if render.status == "refused" and render.reason == "network_check_failed" and not last:
            raise TransientRenderFailure("network check failed: " + "; ".join(render.network_check))
        extracted, shot = [], None
        if render.status == "ok":
            final = render.doc.get("final_url") or ""
            page_url = final if urlsplit(final).scheme in ("http", "https") else url
            extracted = await asyncio.to_thread(
                run_extractors, render.html, "text/html", "utf-8", page_url, a.analysis_context
            )
            if render.screenshot:
                shot = await self._screenshot(render.screenshot, case_id, rnd, job.attempts)
        self._record(case, rnd, row[0], render, extracted, shot)
        a.score(case_id)

    async def _screenshot(self, data: bytes, case_id: int, rnd: int, attempt: int) -> dict:
        """The media sandbox's result for the screenshot, or why there is none."""
        if self.media is None:
            return {"status": "not_analyzed", "reason": "media_disabled"}
        if len(data) > self.config.media.max_image_bytes:
            return {"status": "not_analyzed", "reason": "too_large"}
        try:
            batch = await self.media.analyze(
                [MediaItem("s0", data, ocr=True, qr=True)],
                job=f"shot-{case_id}-r{rnd}",
                attempt=attempt,
            )
        except SandboxError as e:
            return {"status": "failed", "reason": f"sandbox unavailable: {e}"[:200]}
        return batch.items.get("s0") or {"status": "failed", "reason": batch.error}

    def _record(self, case, rnd, decision_id, render: Render, extracted, shot) -> None:
        a = self.a
        value = render.to_fact()
        value["decision_fact"] = decision_id
        value.pop("text", None)  # the extractors read the stored HTML
        value["requests"] = [
            {**q, "url": (q.get("url") or "")[:MAX_STORED_URL]} for q in value.get("requests", [])
        ]
        blobs: dict[str, tuple[bytes, str]] = {}
        if render.html is not None:
            sha = self._sha(render.html)
            value["html"] = {"sha256": sha, "bytes": len(render.html),
                             "truncated": bool(render.doc.get("html_truncated"))}  # fmt: skip
            blobs[sha] = (render.html, "rendered_page")
        shot_sha = None
        if render.screenshot is not None:
            shot_sha = self._sha(render.screenshot)
            media = _media_summary(shot, self.config.media.max_ocr_chars)
            value["screenshot"] = {**(value.get("screenshot") or {}), "sha256": shot_sha,
                                   "media": media}  # fmt: skip
            blobs[shot_sha] = (render.screenshot, "screenshot")
        with transaction(self.store.conn):
            if a._done(case.case_id, RENDER, rnd):  # a redelivery finished first
                return
            stored = [s for s, (d, role) in blobs.items() if self._store(case, d, s, role)]
            fact_id = a._fact(
                case.case_id, "browser", "browser_render", value, STAGE_VERSION, rnd, stored
            )
            now = a.clock()
            if extracted:
                write_features(
                    self.store.conn, case.case_id, extracted, fact_id=fact_id, rnd=rnd, now=now
                )
                self._compare(case.case_id, rnd, fact_id, render, extracted, now)
            if shot and shot.get("status") == "ok":
                self._screenshot_features(case, rnd, fact_id, shot_sha, shot, extracted, now)
            a._finish(case.case_id, RENDER, rnd, render.status)

    def _compare(self, case_id, rnd, fact_id, render: Render, extracted, now) -> None:
        static = self.store.conn.execute(
            "SELECT id, value_json FROM facts WHERE case_id = ? AND name = 'http_fetch'"
            " AND json_extract(value_json, '$.final')"
            " AND json_extract(value_json, '$.analysis_round') = ? ORDER BY id DESC LIMIT 1",
            (case_id, rnd),
        ).fetchone()
        if static is None:
            return
        fetch = json.loads(static[1])
        static_values = {
            name: json.loads(v)
            for name, v in self.store.conn.execute(
                "SELECT name, value_json FROM features f WHERE case_id = ?"
                " AND EXISTS (SELECT 1 FROM json_each(f.fact_refs) WHERE value = ?)"
                " ORDER BY id",
                (case_id, static[0]),
            )
            if name in COMPARED
        }
        rendered_values = {
            r.extractor.name: r.value for r in extracted if r.value and r.extractor.name in COMPARED
        }
        result = cloaking.compare(
            cloaking.summary(static_values, fetch.get("final_url"), fetch.get("status")),
            cloaking.summary(
                rendered_values, render.doc.get("final_url"), render.doc.get("main_status")
            ),
        )
        add_feature(
            self.store.conn,
            case_id,
            name="cloaking",
            value={**result, "analysis_round": rnd},
            extractor_version=cloaking.VERSION,
            fact_refs=[static[0], fact_id],
            now=now,
        )

    def _screenshot_features(self, case, rnd, fact_id, sha, shot, extracted, now) -> None:
        a = self.a
        corpus = load_corpus(self.store.conn, a.registry)
        item = {**shot, "sha256": sha}
        matches = [
            {"image": sha, **m.to_dict()}
            for m in self.matcher.match(ImageHashes.from_media(item), corpus)
        ]
        add_feature(
            self.store.conn,
            case.case_id,
            name="screenshot_matches",
            value={
                "analysis_round": rnd,
                "matcher": self.matcher.describe(),
                "corpus_version": corpus.version,
                "corpus_entries": len(corpus.entries),
                "matches": matches,
            },
            extractor_version=self.matcher.version,
            fact_refs=[fact_id],
            now=now,
        )
        refs = next((r.value for r in extracted if r.extractor.name == "brand_references"), None)
        derived = media_text(
            [
                {
                    "sha256": sha,
                    "role": "screenshot",
                    "ocr_text": (shot.get("ocr") or {}).get("text") or "",
                    "qr": [c["text"] for c in (shot.get("qr") or {}).get("codes") or []],
                }
            ],
            a.analysis_context.lexicon,
            list((refs or {}).get("presented") or []),
        )
        add_feature(
            self.store.conn,
            case.case_id,
            name="screenshot_text",
            value={**derived, "analysis_round": rnd},
            extractor_version=MEDIA_TEXT_VERSION,
            fact_refs=[fact_id],
            now=now,
        )

    @staticmethod
    def _sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _store(self, case, data: bytes, sha: str, role: str) -> bool:
        try:
            got = self.store.blobs.put(
                data,
                case_id=case.case_id,
                registrable_domain=case.group_key,
                content_type="application/octet-stream",  # inert: never served or opened
                role=role,
                privileged=case.match_strength == "strong",
            )
        except QuotaExceeded:
            return False
        return got == sha


def _media_summary(shot: dict | None, max_ocr_chars: int) -> dict:
    """What the media sandbox said about the screenshot, bounded for the fact."""
    if not shot:
        return {"status": "not_analyzed"}
    if shot.get("status") != "ok":
        return {"status": shot.get("status") or "failed", "reason": shot.get("reason")}
    ocr = shot.get("ocr") or {}
    return {
        "status": "ok",
        "phash": shot.get("phash"),
        "dhash": shot.get("dhash"),
        "ocr_status": ocr.get("status"),
        "ocr_chars": int(ocr.get("chars") or 0),
        "ocr_text": (ocr.get("text") or "")[:max_ocr_chars],
        "qr_codes": len((shot.get("qr") or {}).get("codes") or []),
    }
