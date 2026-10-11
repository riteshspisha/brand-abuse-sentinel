"""The media worker (U16, R21, R42): untrusted image decoding, hashing, QR
decoding and OCR, run only inside a sandbox container.

    python3 -m brandsentinel.sandbox.media_worker --max-input-bytes N

The container has no network, a read-only root, a small noexec /tmp and memory,
CPU, PID and wall-time limits (see media_client and the runner). This module is
imported only there and by unit tests: the application never decodes an image
itself (tests/security/test_media_limits.py checks that it never imports
Pillow).

Input (stdin): one JSON document written by the trusted client, read in memory
under `--max-input-bytes` and never written to disk:

    {"version": 1, "options": {...limits...},
     "items": [{"id": "i0", "data": "<base64>", "ocr": true, "qr": true}]}

Each image is checked before its pixels are decoded: its magic bytes must be
PNG, JPEG, GIF, WebP or ICO (the name and the server's content type are never
trusted), Pillow opens it with that one format only, `MAX_IMAGE_PIXELS` is
explicit and decompression-bomb warnings are errors, the declared size and
dimensions are checked, and animated images and icon files are capped in frames
and entries. Only the first frame (an icon's largest entry) is decoded. One
image's failure rejects that image, not the batch.

Output (stdout): one JSON document, `{"worker": ..., "tools": ..., "items": [...]}`
with, per item, either `status: "ok"` and the format, dimensions, sha256, pHash,
dHash, favicon MurmurHash, luminance statistics, QR payloads and OCR text, or
`status: "rejected"` and a reason. The client validates it before anything is
stored.
"""

import argparse
import base64
import binascii
import contextlib
import hashlib
import io
import json
import socket
import struct
import sys
import warnings

import imagehash
import PIL
from PIL import Image, ImageFile, ImageStat

WORKER_VERSION = "media_worker/1"
MAX_ITEMS = 32
# Stricter than any configuration can ask for, so a client bug cannot lift them.
HARD_MAX_PIXELS = 100_000_000
HARD_MAX_FRAMES = 1000

# Magic bytes -> the only Pillow plugin allowed to open the data.
_FORMATS = (
    (b"\x89PNG\r\n\x1a\n", 0, "PNG"),
    (b"\xff\xd8\xff", 0, "JPEG"),
    (b"GIF87a", 0, "GIF"),
    (b"GIF89a", 0, "GIF"),
    (b"\x00\x00\x01\x00", 0, "ICO"),
)


class Rejected(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail[:200]


def sniff(data: bytes) -> str | None:
    """The image format named by the magic bytes, or None."""
    for magic, offset, fmt in _FORMATS:
        if data[offset : offset + len(magic)] == magic:
            return fmt
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    return None


def _configure(max_pixels: int) -> None:
    Image.MAX_IMAGE_PIXELS = min(max_pixels, HARD_MAX_PIXELS)
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    warnings.simplefilter("error", Image.DecompressionBombWarning)


def _frames_over(img: Image.Image, cap: int) -> bool:
    """True when the image has more than `cap` frames. Seeks only as far as
    the cap, so a file claiming a million frames costs no more than cap + 1."""
    if not getattr(img, "is_animated", False):
        return False
    try:
        img.seek(cap)
    except EOFError:
        return False
    finally:
        with contextlib.suppress(EOFError):
            img.seek(0)
    return True


def decode(data: bytes, opts: dict) -> tuple[Image.Image, dict]:
    """Open, check and decode the first frame. Raises Rejected."""
    if len(data) > opts["max_image_bytes"]:
        raise Rejected("too_large", f"{len(data)} bytes")
    fmt = sniff(data)
    if fmt is None:
        raise Rejected("not_an_image", "magic bytes match no allowed format")
    info: dict = {"format": fmt}
    try:
        img = Image.open(io.BytesIO(data), formats=[fmt])
        if fmt == "ICO":
            entries = len(getattr(img, "ico", None).entry) if getattr(img, "ico", None) else 0
            info["ico_images"] = entries
            if entries > opts["max_ico_images"]:
                raise Rejected("too_many_ico_images", f"{entries} entries")
        width, height = img.size
        if width < 1 or height < 1:
            raise Rejected("decode_error", "empty image")
        if max(width, height) > opts["max_dimension"]:
            raise Rejected("too_large_dimension", f"{width}x{height}")
        if width * height > opts["max_pixels"]:
            raise Rejected("too_many_pixels", f"{width}x{height}")
        if _frames_over(img, min(opts["max_frames"], HARD_MAX_FRAMES)):
            raise Rejected("too_many_frames", f"more than {opts['max_frames']} frames")
        # Bounded by the check above: at most max_frames seeks.
        info["frames"] = int(getattr(img, "n_frames", 1))
        img.seek(0)
        img.load()
    except Rejected:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
        raise Rejected("decompression_bomb", str(e)) from None
    except MemoryError:
        raise Rejected("decode_error", "out of memory while decoding") from None
    except Exception as e:  # malformed or truncated data from a hostile server
        raise Rejected("decode_error", f"{type(e).__name__}: {e}") from None
    info["width"], info["height"] = img.size
    info["mode"] = img.mode
    return img, info


def to_rgb(img: Image.Image) -> Image.Image:
    """RGB with any transparency composited on white, so a logo hashes the same
    whether it is served with an alpha channel or flattened."""
    if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        canvas = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        canvas.alpha_composite(rgba)
        return canvas.convert("RGB")
    return img.convert("RGB")


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed (as the `mmh3` package returns it)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    n = len(data) // 4
    for (k,) in struct.iter_unpack("<I", data[: n * 4]):
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[n * 4 :]
    k = 0
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def favicon_hash(data: bytes) -> int:
    """The favicon hash search engines index: MurmurHash3 of the base64 text
    with a newline every 76 characters."""
    return murmur3_32(base64.encodebytes(data))


def _bounded(img: Image.Image, max_pixels: int) -> Image.Image:
    w, h = img.size
    if w * h <= max_pixels:
        return img
    scale = (max_pixels / (w * h)) ** 0.5
    return img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.Resampling.BILINEAR)


def read_qr(rgb: Image.Image, opts: dict) -> dict:
    if not opts["max_qr_codes"]:
        return {"status": "skipped", "codes": []}
    try:
        import zxingcpp

        found = zxingcpp.read_barcodes(
            _bounded(rgb, opts["max_ocr_pixels"]), formats=zxingcpp.BarcodeFormat.QRCode
        )
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"[:200], "codes": []}
    codes = []
    for r in found:
        if not r.valid or len(codes) >= opts["max_qr_codes"]:
            continue
        text = r.text or ""
        codes.append(
            {
                "format": "qr",
                "text": text[: opts["max_qr_chars"]],
                "truncated": len(text) > opts["max_qr_chars"],
            }
        )
    return {"status": "ok", "codes": codes}


def read_text(rgb: Image.Image, opts: dict) -> dict:
    try:
        import pytesseract
    except ImportError:
        return {"status": "unavailable", "text": "", "chars": 0}
    gray = _bounded(rgb.convert("L"), opts["max_ocr_pixels"])
    w, h = gray.size
    if max(w, h) < 400 and w * h * 4 <= opts["max_ocr_pixels"]:
        # Tesseract reads small text poorly; logos and buttons are small.
        gray = gray.resize((w * 2, h * 2), Image.Resampling.BICUBIC)
    try:
        text = pytesseract.image_to_string(
            gray, lang="eng", config="--psm 3", timeout=opts["ocr_timeout_seconds"]
        )
    except pytesseract.TesseractNotFoundError:
        return {"status": "unavailable", "text": "", "chars": 0}
    except RuntimeError as e:  # pytesseract reports its timeout this way
        status = "timeout" if "timeout" in str(e).lower() else "error"
        return {"status": status, "error": str(e)[:200], "text": "", "chars": 0}
    except Exception as e:
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}"[:200],
            "text": "",
            "chars": 0,
        }
    text = " ".join(text.split())
    cap = opts["max_ocr_chars"]
    return {"status": "ok", "text": text[:cap], "chars": len(text), "truncated": len(text) > cap}


def analyze(data: bytes, opts: dict, *, ocr: bool, qr: bool) -> dict:
    out: dict = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    try:
        img, info = decode(data, opts)
    except Rejected as r:
        return {**out, "status": "rejected", "reason": r.reason, "detail": r.detail}
    try:
        rgb = to_rgb(img)
        luma = ImageStat.Stat(_bounded(rgb.convert("L"), 65536))
        out.update(
            status="ok",
            **info,
            phash=str(imagehash.phash(rgb)),
            dhash=str(imagehash.dhash(rgb)),
            favicon_mmh3=favicon_hash(data),
            luma_mean=round(luma.mean[0], 2),
            luma_stddev=round(luma.stddev[0], 2),
        )
        out["qr"] = read_qr(rgb, opts) if qr else {"status": "skipped", "codes": []}
        if ocr and opts["ocr"]:
            out["ocr"] = read_text(rgb, opts)
        else:
            out["ocr"] = {"status": "skipped", "text": "", "chars": 0}
    except MemoryError:
        return {**out, "status": "rejected", "reason": "decode_error", "detail": "out of memory"}
    except Exception as e:
        detail = f"{type(e).__name__}: {e}"[:200]
        return {**out, "status": "rejected", "reason": "internal_error", "detail": detail}
    return out


def tools() -> dict:
    versions = {"python": sys.version.split()[0], "pillow": PIL.__version__}
    versions["imagehash"] = getattr(imagehash, "__version__", "unknown")
    try:
        import zxingcpp

        versions["zxing_cpp"] = getattr(zxingcpp, "__version__", "present")
    except ImportError:
        versions["zxing_cpp"] = None
    try:
        import pytesseract

        versions["tesseract"] = str(pytesseract.get_tesseract_version())
    except Exception:
        versions["tesseract"] = None
    return versions


_OPTION_KEYS = (
    "max_image_bytes",
    "max_pixels",
    "max_dimension",
    "max_frames",
    "max_ico_images",
    "ocr",
    "max_ocr_pixels",
    "ocr_timeout_seconds",
    "max_ocr_chars",
    "max_qr_codes",
    "max_qr_chars",
)


def network_probe() -> dict:
    """Selftest only: every attempt must fail inside a `--network none` container."""
    res = {}
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("1.1.1.1", 443))
        res["tcp 1.1.1.1:443"] = "connected"
    except OSError as e:
        res["tcp 1.1.1.1:443"] = type(e).__name__
    finally:
        s.close()
    try:
        socket.getaddrinfo("example.com", 443)
        res["dns example.com"] = "resolved"
    except OSError as e:
        res["dns example.com"] = type(e).__name__
    return res


def process(doc: dict) -> dict:
    """Process one job document (already parsed). Never raises for image data."""
    if not isinstance(doc, dict) or doc.get("version") != 1:
        return {"worker": WORKER_VERSION, "error": "unsupported job version"}
    opts = doc.get("options")
    items = doc.get("items")
    if not isinstance(opts, dict) or set(_OPTION_KEYS) - set(opts) or not isinstance(items, list):
        return {"worker": WORKER_VERSION, "error": "malformed job"}
    if len(items) > MAX_ITEMS:
        return {"worker": WORKER_VERSION, "error": f"more than {MAX_ITEMS} items"}
    _configure(int(opts["max_pixels"]))
    results = []
    for item in items:
        ident = str(item.get("id", ""))[:40] if isinstance(item, dict) else ""
        try:
            data = base64.b64decode(item["data"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error):
            results.append({"id": ident, "status": "rejected", "reason": "bad_input", "detail": ""})
            continue
        result = analyze(data, opts, ocr=bool(item.get("ocr")), qr=bool(item.get("qr")))
        results.append({"id": ident, **result})
    out = {"worker": WORKER_VERSION, "tools": tools(), "items": results}
    if doc.get("selftest", {}).get("network_probe"):
        out["network_probe"] = network_probe()
    return out


def main(argv: list[str] | None = None, stdin=None, stdout=None) -> int:
    parser = argparse.ArgumentParser(prog="media_worker")
    parser.add_argument("--max-input-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    raw = stdin.read(args.max_input_bytes + 1)
    if len(raw) > args.max_input_bytes:
        out = {"worker": WORKER_VERSION, "error": "input_too_large"}
    else:
        try:
            out = process(json.loads(raw))
        except (ValueError, RecursionError):
            out = {"worker": WORKER_VERSION, "error": "input is not JSON"}
    stdout.write(json.dumps(out, ensure_ascii=True, separators=(",", ":")))
    stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
