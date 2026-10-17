"""The media client (U16, KTD11): runs the media worker in a sandbox container
and validates what comes back.

Every job runs through the U23 runner as role `media` with `--network none`
(fixed here; no caller can choose a network), the media limits from
configuration (memory without swap, CPU, PIDs, wall time, output caps) and a
read-only root. The images go in on stdin as one JSON document; nothing is
mounted or written to the host.

The worker's output is untrusted: it is parsed against a strict schema (no
unknown keys, bounded strings and lists, hex digests), its item ids must be
exactly the ones sent, and each reported sha256 must equal the hash of the bytes
sent. Anything else fails the batch as `invalid_output`.

When a batch fails as a whole (killed by a limit, crashed, invalid output),
each image of a multi-image batch is retried alone once, so one decompression
bomb cannot hide the evidence in the other images; an image that fails alone is
recorded with the reason (`sandbox_oom`, `sandbox_timeout`, ...), which the case
reports as `media_rejected` (AE12).

This module never imports an image library.
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from brandsentinel.config import MediaSettings
from brandsentinel.sandbox.runner import SandboxResult, SandboxRunner, SandboxSpec

log = logging.getLogger(__name__)

WORKER_VERSION = "media_worker/1"
CLIENT_VERSION = "media_client/1"
MAX_ITEMS = 32  # the worker's own cap
MODULE = "brandsentinel.sandbox.media_worker"
THREAD_POOL_ENV = (
    "OMP_THREAD_LIMIT",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
)
# Reasons the worker gives for an image it refuses.
REJECT_REASONS = (
    "too_large",
    "not_an_image",
    "decompression_bomb",
    "too_many_pixels",
    "too_large_dimension",
    "too_many_frames",
    "too_many_ico_images",
    "decode_error",
    "internal_error",
    "bad_input",
)

Hex16 = Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Short = Annotated[str, Field(max_length=200)]


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OcrOut(_Out):
    status: Literal["ok", "skipped", "unavailable", "timeout", "error"]
    text: Annotated[str, Field(max_length=100_000)] = ""
    chars: int = Field(0, ge=0)
    truncated: bool = False
    error: Short | None = None


class QrCode(_Out):
    format: Literal["qr"]
    text: Annotated[str, Field(max_length=16_384)]
    truncated: bool = False


class QrOut(_Out):
    status: Literal["ok", "skipped", "error"]
    codes: list[QrCode] = Field(default_factory=list, max_length=64)
    error: Short | None = None


class ItemOut(_Out):
    id: Annotated[str, Field(max_length=40)]
    status: Literal["ok", "rejected"]
    sha256: Hex64
    bytes: int = Field(ge=0)
    reason: Literal[REJECT_REASONS] | None = None  # type: ignore[valid-type]
    detail: Short | None = None
    format: Literal["PNG", "JPEG", "GIF", "WEBP", "ICO"] | None = None
    width: int | None = Field(None, ge=1, le=65535)
    height: int | None = Field(None, ge=1, le=65535)
    frames: int | None = Field(None, ge=1, le=1000)
    ico_images: int | None = Field(None, ge=0, le=65535)
    mode: Annotated[str, Field(max_length=10)] | None = None
    phash: Hex16 | None = None
    dhash: Hex16 | None = None
    favicon_mmh3: int | None = Field(None, ge=-(2**31), le=2**31 - 1)
    luma_mean: float | None = Field(None, ge=0, le=255)
    luma_stddev: float | None = Field(None, ge=0, le=255)
    qr: QrOut | None = None
    ocr: OcrOut | None = None


class WorkerOut(_Out):
    worker: Literal["media_worker/1"]
    tools: dict[Annotated[str, Field(max_length=40)], Short | None] = Field(
        default_factory=dict, max_length=16
    )
    items: list[ItemOut] = Field(default_factory=list, max_length=MAX_ITEMS)
    error: Short | None = None
    network_probe: dict[Short, Short] | None = None


@dataclass(frozen=True)
class MediaItem:
    id: str  # unique within a batch: [a-z0-9]{1,16}
    data: bytes
    ocr: bool = True
    qr: bool = True

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class MediaBatch:
    """The validated outcome. `items` maps each submitted id to the worker's
    result (`ok`/`rejected`) or to a `failed` record when the sandbox killed the
    job or its output was unusable."""

    status: Literal["ok", "partial", "failed"]
    items: dict[str, dict]
    tools: dict = field(default_factory=dict)
    runs: list[dict] = field(default_factory=list)  # sandbox summaries
    error: str | None = None
    network_probe: dict | None = None

    def to_fact(self) -> dict:
        return {
            "status": self.status,
            "worker": WORKER_VERSION,
            "client": CLIENT_VERSION,
            "tools": self.tools,
            "runs": self.runs,
            "error": self.error,
        }


class MediaOutputError(Exception):
    pass


def max_input_bytes(settings: MediaSettings) -> int:
    """stdin cap: the batch in base64 plus room for the JSON around it."""
    return (settings.max_batch_bytes * 4) // 3 + 4 * MAX_ITEMS + 256 * 1024


def worker_options(settings: MediaSettings) -> dict:
    return {
        "max_image_bytes": settings.max_image_bytes,
        "max_pixels": settings.max_pixels,
        "max_dimension": settings.max_dimension,
        "max_frames": settings.max_frames,
        "max_ico_images": settings.max_ico_images,
        "ocr": settings.ocr,
        "max_ocr_pixels": settings.max_ocr_pixels,
        "ocr_timeout_seconds": settings.ocr_timeout_seconds,
        "max_ocr_chars": settings.max_ocr_chars,
        "max_qr_codes": settings.max_qr_codes,
        "max_qr_chars": settings.max_qr_chars,
    }


def job_document(items: list[MediaItem], settings: MediaSettings, *, selftest=None) -> bytes:
    doc = {
        "version": 1,
        "options": worker_options(settings),
        "items": [
            {"id": i.id, "data": base64.b64encode(i.data).decode("ascii"), "ocr": i.ocr, "qr": i.qr}
            for i in items
        ],
    }
    if selftest:
        doc["selftest"] = selftest
    return json.dumps(doc, separators=(",", ":")).encode("ascii")


def media_spec(settings: MediaSettings) -> SandboxSpec:
    return SandboxSpec(
        role="media",
        command=("python3", "-m", MODULE, "--max-input-bytes", str(max_input_bytes(settings))),
        network="none",
        limits=settings.limits,
        # One thread per pool (Tesseract's OpenMP, numpy's OpenBLAS). Unpinned,
        # OpenBLAS starts a thread per host CPU at import and exhausts the PID
        # limit (EAGAIN) on a many-core host; the limit stays as it is.
        env=tuple((k, "1") for k in THREAD_POOL_ENV),
    )


def validate_output(doc: dict | None, items: list[MediaItem], settings: MediaSettings) -> WorkerOut:
    """Parse the worker's document and check it describes exactly `items`."""
    if doc is None:
        raise MediaOutputError("no JSON document")
    try:
        out = WorkerOut.model_validate(doc)
    except ValidationError as e:
        raise MediaOutputError(f"schema: {e.errors()[0]['loc']}: {e.errors()[0]['msg']}") from e
    if out.error:
        raise MediaOutputError(f"worker error: {out.error}")
    if [i.id for i in out.items] != [i.id for i in items]:
        raise MediaOutputError("item ids differ from the job")
    for sent, got in zip(items, out.items, strict=True):
        if got.sha256 != sent.sha256 or got.bytes != len(sent.data):
            raise MediaOutputError(f"item {got.id}: hash or size differs from what was sent")
        required = ("phash", "dhash", "format", "width", "height", "luma_mean", "luma_stddev")
        if got.status == "ok" and any(getattr(got, f) is None for f in required):
            raise MediaOutputError(f"item {got.id}: ok without hashes or dimensions")
        if got.status == "rejected" and got.reason is None:
            raise MediaOutputError(f"item {got.id}: rejected without a reason")
        if got.ocr and len(got.ocr.text) > settings.max_ocr_chars:
            raise MediaOutputError(f"item {got.id}: OCR text over the cap")
        if got.qr and (
            len(got.qr.codes) > settings.max_qr_codes
            or any(len(c.text) > settings.max_qr_chars for c in got.qr.codes)
        ):
            raise MediaOutputError(f"item {got.id}: QR output over the cap")
    return out


class MediaClient:
    def __init__(self, runner: SandboxRunner, settings: MediaSettings) -> None:
        self.runner = runner
        self.settings = settings

    async def analyze(self, items: list[MediaItem], *, job: str, attempt: int = 0) -> MediaBatch:
        """Analyze up to MAX_ITEMS images. Raises SandboxError only when no
        container could be started at all (the caller retries later)."""
        if not items:
            return MediaBatch("ok", {})
        if len(items) > MAX_ITEMS or len({i.id for i in items}) != len(items):
            raise ValueError("at most 32 items with unique ids")
        if sum(len(i.data) for i in items) > self.settings.max_batch_bytes:
            raise ValueError("batch exceeds media.max_batch_bytes")
        runs: list[dict] = []
        result, out, error = await self._run(items, job, attempt, runs)
        if out is not None:
            return MediaBatch("ok", _items(out), out.tools, runs)
        if len(items) == 1:
            return MediaBatch(
                "failed", {items[0].id: _failed(items[0], result, error)}, runs=runs, error=error
            )
        # One image may have brought the batch down: try each alone, once.
        results: dict[str, dict] = {}
        tools: dict = {}
        for n, item in enumerate(items):
            r, o, e = await self._run([item], f"{job}-i{n}"[:40], attempt, runs)
            if o is not None:
                results.update(_items(o))
                tools = tools or o.tools
            else:
                results[item.id] = _failed(item, r, e)
        status = "partial" if any(v["status"] != "failed" for v in results.values()) else "failed"
        return MediaBatch(status, results, tools, runs, error)

    async def selftest(
        self, items: list[MediaItem], *, job: str
    ) -> tuple[MediaBatch, SandboxResult]:
        stdin = job_document(items, self.settings, selftest={"network_probe": True})
        result = await self.runner.run(media_spec(self.settings), job=job, attempt=0, stdin=stdin)
        try:
            out = validate_output(result.output, items, self.settings)
        except MediaOutputError as e:
            return MediaBatch("failed", {}, error=str(e), runs=[result.summary()]), result
        return (
            MediaBatch("ok", _items(out), out.tools, [result.summary()], None, out.network_probe),
            result,
        )

    async def _run(self, items, job, attempt, runs):
        stdin = job_document(items, self.settings)
        result = await self.runner.run(
            media_spec(self.settings), job=job, attempt=attempt, stdin=stdin
        )
        runs.append(result.summary())
        if result.status != "ok":
            return result, None, f"sandbox {result.status}: {result.error or ''}".strip()[:300]
        try:
            return result, validate_output(result.output, items, self.settings), None
        except MediaOutputError as e:
            log.warning("invalid media worker output", extra={"fields": {"error": str(e)[:300]}})
            result.status = "invalid_output"
            return result, None, f"invalid_output: {e}"[:300]


def _items(out: WorkerOut) -> dict[str, dict]:
    return {i.id: i.model_dump(mode="json", exclude_none=True) for i in out.items}


def _failed(item: MediaItem, result: SandboxResult | None, error: str | None) -> dict:
    status = result.status if result is not None else "start_error"
    if status == "exit_error" and result.exit_code == 137 and not result.killed:
        # SIGKILL that the runner did not send: in practice the kernel's OOM
        # killer, which Docker does not flag as OOMKilled when it kills the
        # worker rather than the container's init process.
        status = "killed"
        error = "SIGKILL inside the container (memory limit; not flagged by Docker)"
    return {
        "id": item.id,
        "status": "failed",
        "reason": f"sandbox_{status}",
        "detail": (error or "")[:200],
        "sha256": item.sha256,
        "bytes": len(item.data),
    }
