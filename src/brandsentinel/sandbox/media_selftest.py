"""`brandsentinel sandbox selftest media` (U16 verification).

Runs the real media worker in a real sandbox container on synthetic fixtures and
checks the image-processing gate: a valid image is hashed, OCR reads brand text,
a UPI QR code decodes, a decompression bomb, an HTML body named `.png`, an
animation over the frame cap and an icon file over the entry cap are rejected,
the container has no network (the worker tries and must fail), and the
container is removed afterwards. Fixtures are built without an image library.
"""

import secrets
import time

from brandsentinel.config import MediaSettings
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox.media_client import MediaClient, MediaItem, media_spec
from brandsentinel.sandbox.preflight import Check
from brandsentinel.sandbox.runner import SandboxRunner


def fixtures(settings: MediaSettings) -> list[MediaItem]:
    return [
        MediaItem("valid", F.png_gray(64, 64), ocr=False, qr=False),
        MediaItem("ocr", F.packaged("ocr-donate.png"), ocr=True, qr=False),
        MediaItem("qr", F.packaged("upi-qr.png"), ocr=False, qr=True),
        MediaItem("bomb", F.bomb_png(30000)),
        MediaItem("html", F.html_named_png()),
        MediaItem("frames", F.gif_frames(settings.max_frames + 8)),
        MediaItem("ico", F.ico_entries(settings.max_ico_images + 4)),
    ]


EXPECT_REJECTED = {
    "bomb": "decompression_bomb",
    "html": "not_an_image",
    "frames": "too_many_frames",
    "ico": "too_many_ico_images",
}


async def selftest(runner: SandboxRunner, settings: MediaSettings) -> list[Check]:
    checks: list[Check] = []
    spec = media_spec(settings)
    checks.append(Check("network_none", spec.network == "none", f"spec network {spec.network}"))
    client = MediaClient(runner, settings)
    job = f"selftest-{int(time.time())}-{secrets.token_hex(3)}"
    batch, result = await client.selftest(fixtures(settings), job=job)
    run = result.summary()
    checks.append(
        Check(
            "container_ran",
            result.status == "ok" and batch.status == "ok",
            f"status {result.status}; {batch.error or ''}".strip(),
        )
    )
    checks.append(Check("container_removed", result.removed, f"{run['name']} removed"))
    if batch.status != "ok":
        return checks
    items = batch.items
    valid = items.get("valid", {})
    checks.append(
        Check(
            "valid_image_hashed",
            valid.get("status") == "ok" and bool(valid.get("phash")),
            f"phash {valid.get('phash')}",
        )
    )
    ocr = items.get("ocr", {}).get("ocr", {})
    checks.append(
        Check(
            "ocr_reads_text",
            ocr.get("status") == "ok" and "lumina" in ocr.get("text", "").lower(),
            f"ocr {ocr.get('status')}: {ocr.get('text', '')[:60]!r}",
        )
    )
    codes = items.get("qr", {}).get("qr", {}).get("codes", [])
    checks.append(
        Check(
            "qr_decodes",
            any(c["text"].startswith("upi://pay?pa=") for c in codes),
            f"{len(codes)} code(s)",
        )
    )
    for ident, reason in EXPECT_REJECTED.items():
        got = items.get(ident, {})
        checks.append(
            Check(
                f"rejects_{ident}",
                got.get("status") == "rejected" and got.get("reason") == reason,
                f"{got.get('status')} {got.get('reason')}",
            )
        )
    probe = batch.network_probe or {}
    leaks = [k for k, v in probe.items() if v in ("connected", "resolved")]
    checks.append(
        Check(
            "no_network_inside",
            bool(probe) and not leaks,
            ", ".join(f"{k}: {v}" for k, v in sorted(probe.items())) or "no probe result",
        )
    )
    tess = batch.tools.get("tesseract")
    checks.append(
        Check("tools", bool(tess), f"tesseract {tess}, pillow {batch.tools.get('pillow')}")
    )
    return checks
