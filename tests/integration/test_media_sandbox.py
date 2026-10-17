"""The media worker in real sandbox containers (U16, R42, AE12; marker docker).

Needs the rootless runtime and a sandbox image built from this tree
(scripts/build-sandbox-image.sh); skipped, and reported as skipped, otherwise.
"""

import asyncio
import json
import time

import pytest
from tests import media_support as M
from tests.docker_support import REPO, job_id, labelled, make_runner, runtime_or_skip

from brandsentinel.config import MediaSettings, SandboxLimits
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox.media_client import MediaClient, MediaItem, media_spec
from brandsentinel.sandbox.media_selftest import selftest

pytestmark = pytest.mark.docker
LAB = REPO / "labsites"


@pytest.fixture(scope="module")
def docker():
    return runtime_or_skip()


def analyze(docker, items, settings=None):
    settings = settings or MediaSettings()
    client = MediaClient(make_runner(docker), settings)
    return asyncio.run(client.analyze(items, job=job_id("media")))


def test_selftest_passes_in_a_real_container(docker):
    checks = asyncio.run(selftest(make_runner(docker), MediaSettings()))
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]


def test_client_processes_a_lab_image_batch_like_the_in_process_worker(docker):
    images = {
        "logo": (LAB / "official/static/lumina-logo.png").read_bytes(),
        "copy": (LAB / "copied-assets/static/logo.png").read_bytes(),
        "appeal": (LAB / "image-only/static/appeal.png").read_bytes(),
        "qr": (LAB / "image-only/static/upi-qr.png").read_bytes(),
    }
    batch = analyze(docker, [MediaItem(k, v) for k, v in images.items()])
    assert batch.status == "ok", batch.error
    for key, data in images.items():
        got, local = batch.items[key], M.hashes(data)
        assert got["status"] == "ok", got
        # Same image, same versions: the container agrees with the in-process worker.
        for field in ("sha256", "phash", "dhash", "favicon_mmh3", "width", "height"):
            assert got[field] == local[field], (key, field)
    assert "Lumina Foundation" in batch.items["appeal"]["ocr"]["text"]
    assert "rivers.relief.fund@quickpaybank" in batch.items["appeal"]["ocr"]["text"]
    (code,) = batch.items["qr"]["qr"]["codes"]
    assert code["text"].startswith("upi://pay?pa=rivers.relief.fund@quickpaybank")
    assert labelled(docker) == []  # every container removed


def test_screenshot_with_payment_details_is_read_by_ocr_and_qr(docker):
    batch = analyze(docker, [MediaItem("s", M.payment_screenshot())])
    item = batch.items["s"]
    assert "rivers.relief.fund@quickpaybank" in item["ocr"]["text"]
    assert "000123456789" in item["ocr"]["text"]
    assert item["qr"]["codes"][0]["text"].startswith("upi://pay?pa=rivers.relief.fund")


def test_ae12_bomb_that_passes_the_header_check_is_killed_by_the_memory_limit(docker):
    """Covers AE12 in the container: with the pixel cap raised so the worker
    really decodes an 81-megapixel bomb, the memory limit ends it; the image is
    recorded as failed or rejected, the other image survives (retried alone),
    and this process is unaffected."""
    settings = MediaSettings(
        max_pixels=100_000_000,
        max_dimension=10000,
        max_image_bytes=4 * 1024 * 1024,
        limits=SandboxLimits(memory_mb=160, pids=64, wall_seconds=60),
    )
    bomb = F.bomb_png(9000)
    start = time.monotonic()
    batch = analyze(docker, [MediaItem("bomb", bomb), MediaItem("logo", M.lab_logo())], settings)
    item = batch.items["bomb"]
    assert (item["status"], item["reason"]) in (
        ("failed", "sandbox_oom"),
        ("failed", "sandbox_killed"),  # kernel OOM kill of the worker, not flagged
        ("rejected", "decode_error"),  # MemoryError caught by the worker
    ), item
    assert batch.items["logo"]["status"] == "ok"
    assert time.monotonic() - start < 120
    assert labelled(docker) == []


def test_wall_time_limit_ends_a_slow_job(docker):
    # A page of dense text: OCR alone takes about three seconds here.
    settings = MediaSettings(limits=SandboxLimits(wall_seconds=1, pids=64), ocr_timeout_seconds=120)
    img = M.Image.new("RGB", (1900, 1900), M.WHITE)
    draw = M.ImageDraw.Draw(img)
    for y in range(0, 1900, 22):
        draw.text(
            (5, y),
            "Lumina Foundation relief appeal 0123456789 " * 4,
            fill=(0, 0, 0),
            font=M.font(16),
        )
    start = time.monotonic()
    batch = analyze(docker, [MediaItem("n", M.encode(img), ocr=True)], settings)
    assert (batch.items["n"]["status"], batch.items["n"]["reason"]) == ("failed", "sandbox_timeout")
    assert time.monotonic() - start < 30
    assert labelled(docker) == []


def test_media_container_has_no_network_and_runs_unprivileged(docker):
    runner = make_runner(docker)
    spec = media_spec(MediaSettings())
    probe = (
        "import json, os, socket\n"
        "out = {'uid': os.getuid(), 'ifaces': sorted(os.listdir('/sys/class/net'))}\n"
        "s = socket.socket(); s.settimeout(2)\n"
        "try:\n    s.connect(('1.1.1.1', 443)); out['tcp'] = 'connected'\n"
        "except OSError as e:\n    out['tcp'] = type(e).__name__\n"
        "print(json.dumps(out))\n"
    )
    from dataclasses import replace

    result = asyncio.run(
        runner.run(replace(spec, command=("python3", "-c", probe)), job=job_id("netp"), attempt=0)
    )
    assert result.status == "ok", result.summary()
    assert result.output["uid"] != 0 and result.output["ifaces"] == ["lo"]
    assert result.output["tcp"] != "connected"
    assert json.dumps(result.summary())  # serializable for facts
