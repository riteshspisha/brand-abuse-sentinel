"""The media worker run in process (U16). The same code runs in the sandbox
container (tests/integration/test_media_sandbox.py); limits enforced by the
runtime are tested there and in tests/security/test_media_limits.py."""

import base64
import io
import json
import shutil
import time

import pytest
from tests import media_support as M

from brandsentinel.analysis.payment import parse_upi
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox import media_worker as W


def run(items: dict[str, bytes], *, ocr=False, qr=True, **opts) -> dict:
    doc = {
        "version": 1,
        "options": M.worker_opts(**opts),
        "items": [
            {"id": k, "data": base64.b64encode(v).decode(), "ocr": ocr, "qr": qr}
            for k, v in items.items()
        ],
    }
    out = W.process(doc)
    return {i["id"]: i for i in out["items"]}


def test_valid_png_is_hashed():
    item = run({"a": M.lab_logo()})["a"]
    assert item["status"] == "ok" and item["format"] == "PNG"
    assert (item["width"], item["height"], item["frames"]) == (256, 256, 1)
    assert len(item["phash"]) == len(item["dhash"]) == 16
    assert isinstance(item["favicon_mmh3"], int) and item["luma_stddev"] > 12


def test_same_image_gives_the_same_hashes_across_runs():
    a = run({"a": M.lab_logo()})["a"]
    b = run({"b": M.lab_logo()})["b"]
    for key in ("sha256", "phash", "dhash", "favicon_mmh3", "luma_stddev"):
        assert a[key] == b[key]


def test_ae12_decompression_bomb_is_rejected_quickly():
    """Covers AE12 (worker side): rejected from the header, before decoding."""
    start = time.monotonic()
    item = run({"bomb": F.bomb_png(30000)})["bomb"]
    assert item["status"] == "rejected" and item["reason"] == "decompression_bomb"
    assert time.monotonic() - start < 2


def test_a_lying_header_is_rejected_without_decoding():
    item = run({"x": F.lying_header_png()})["x"]
    assert item["status"] == "rejected" and item["reason"] == "decompression_bomb"


def test_pixel_cap_applies_below_pillows_bomb_threshold():
    big = M.encode(M.Image.new("L", (2000, 1000)))  # 2 MP
    item = run({"x": big}, max_pixels=1_000_000)["x"]
    assert item["status"] == "rejected" and item["reason"] in ("decompression_bomb",)


def test_dimension_cap():
    wide = F.png_gray(3000, 2)
    item = run({"x": wide}, max_dimension=2048)["x"]
    assert item["status"] == "rejected" and item["reason"] == "too_large_dimension"


def test_png_name_with_html_content_is_rejected_by_magic_bytes():
    item = run({"x": F.html_named_png()})["x"]
    assert item["status"] == "rejected" and item["reason"] == "not_an_image"


@pytest.mark.parametrize(
    "data",
    [b"", b"BM" + b"\0" * 64, b"<svg xmlns='http://www.w3.org/2000/svg'/>", b"%PDF-1.7\n"],
    ids=["empty", "bmp", "svg", "pdf"],
)
def test_formats_outside_the_allowlist_are_rejected(data):
    assert run({"x": data})["x"]["reason"] == "not_an_image"


def test_animated_gif_over_the_frame_cap_is_rejected():
    ok = run({"g": F.gif_frames(5)})["g"]
    assert ok["status"] == "ok" and ok["frames"] == 5
    over = run({"g": F.gif_frames(40)}, max_frames=32)["g"]
    assert over["status"] == "rejected" and over["reason"] == "too_many_frames"


def test_ico_with_too_many_entries_is_rejected():
    assert run({"i": F.ico_entries(3)})["i"]["status"] == "ok"
    over = run({"i": F.ico_entries(40)}, max_ico_images=16)["i"]
    assert over["status"] == "rejected" and over["reason"] == "too_many_ico_images"


def test_truncated_image_is_rejected():
    item = run({"t": F.truncated(M.lab_logo())})["t"]
    assert item["status"] == "rejected" and item["reason"] == "decode_error"


def test_oversized_item_is_rejected_before_parsing():
    item = run({"x": M.lab_logo()}, max_image_bytes=1000)["x"]
    assert item["status"] == "rejected" and item["reason"] == "too_large"


def test_one_bad_image_does_not_reject_the_others():
    out = run({"a": M.lab_logo(), "b": F.bomb_png(20000), "c": F.html_named_png()})
    assert [out[k]["status"] for k in "abc"] == ["ok", "rejected", "rejected"]


def test_transparency_is_flattened_on_white():
    assert run({"a": M.with_alpha()})["a"]["phash"] == run({"b": M.lab_logo()})["b"]["phash"]


def test_upi_qr_decodes_to_its_payload_and_payee():
    item = run({"q": M.LAB_QR.read_bytes()})["q"]
    (code,) = item["qr"]["codes"]
    assert code["text"].startswith("upi://pay?pa=rivers.relief.fund@quickpaybank")
    upi = parse_upi(code["text"])
    assert upi["pa"] == "rivers.relief.fund@quickpaybank" and upi["pn"] == "Lumina Relief"


def test_qr_codes_are_capped_and_skippable():
    assert run({"q": M.LAB_QR.read_bytes()}, max_qr_codes=0)["q"]["qr"]["codes"] == []
    assert run({"q": M.LAB_QR.read_bytes()}, qr=False)["q"]["qr"]["status"] == "skipped"
    item = run({"q": M.LAB_QR.read_bytes()}, max_qr_chars=10)["q"]
    assert item["qr"]["codes"][0] == {"format": "qr", "text": "upi://pay?", "truncated": True}


def test_screenshot_with_payment_details_yields_its_qr_payload():
    item = run({"s": M.payment_screenshot()})["s"]
    assert item["status"] == "ok"
    assert [c["text"][:44] for c in item["qr"]["codes"]] == [
        "upi://pay?pa=rivers.relief.fund@quickpaybank"
    ]


@pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract not installed")
def test_ocr_reads_brand_text():
    item = run({"o": M.text_image("Donate to Lumina Foundation")}, ocr=True)["o"]
    assert item["ocr"]["status"] == "ok" and "Lumina" in item["ocr"]["text"]


def test_ocr_reports_unavailable_without_tesseract(monkeypatch):
    import pytesseract

    def missing(*a, **k):
        raise pytesseract.TesseractNotFoundError()

    monkeypatch.setattr(pytesseract, "image_to_string", missing)
    item = run({"o": M.text_image("Lumina")}, ocr=True)["o"]
    assert item["status"] == "ok" and item["ocr"]["status"] == "unavailable"


def test_ocr_timeout_is_reported_not_raised(monkeypatch):
    import pytesseract

    def slow(*a, **k):
        raise RuntimeError("Tesseract process timeout")

    monkeypatch.setattr(pytesseract, "image_to_string", slow)
    item = run({"o": M.text_image("Lumina")}, ocr=True)["o"]
    assert item["ocr"]["status"] == "timeout" and item["phash"]


def test_favicon_hash_matches_the_reference_murmur3():
    # Published MurmurHash3 x86_32 vectors (seed 0) and the signed convention.
    assert W.murmur3_32(b"") == 0
    assert W.murmur3_32(b"hello") == 613153351
    assert W.murmur3_32(b"The quick brown fox jumps over the lazy dog") == 776992547
    assert -(2**31) <= W.favicon_hash(M.lab_logo()) < 2**31


def test_input_over_the_cap_is_refused_before_parsing():
    out = io.StringIO()
    W.main(["--max-input-bytes", "100"], io.BytesIO(b"{" + b" " * 200 + b"}"), out)
    assert json.loads(out.getvalue()) == {"worker": W.WORKER_VERSION, "error": "input_too_large"}


@pytest.mark.parametrize(
    "stdin",
    [b"not json", b"[]", b'{"version": 2}', b'{"version": 1, "options": {}, "items": []}',
     b"[" * 100_000],
    ids=["text", "list", "version", "options", "nesting"],
)  # fmt: skip
def test_malformed_jobs_give_an_error_document(stdin):
    out = io.StringIO()
    assert W.main(["--max-input-bytes", "1000000"], io.BytesIO(stdin), out) == 0
    assert "error" in json.loads(out.getvalue())


def test_bad_base64_rejects_only_that_item():
    doc = {
        "version": 1,
        "options": M.worker_opts(),
        "items": [
            {"id": "a", "data": "!!!"},
            {"id": "b", "data": base64.b64encode(M.lab_logo()).decode()},
        ],
    }
    a, b = W.process(doc)["items"]
    assert a["reason"] == "bad_input" and b["status"] == "ok"


def test_magic_sniffing():
    assert W.sniff(M.lab_logo()) == "PNG"
    assert W.sniff(M.resized_jpeg()) == "JPEG"
    assert W.sniff(M.as_gif()) == "GIF"
    assert W.sniff(M.as_ico()) == "ICO"
    assert W.sniff(M.encode(M.Image.new("RGB", (8, 8)), "WEBP")) == "WEBP"
    assert W.sniff(b"RIFF\0\0\0\0WAVE") is None
