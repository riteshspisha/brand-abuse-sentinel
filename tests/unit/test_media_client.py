"""The media client (U16): job documents, output validation and the per-image
retry after a batch is killed. The worker runs in process (InProcessRunner)."""

import asyncio

import pytest
from tests import media_support as M

from brandsentinel.config import MediaSettings
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox.media_client import (
    MediaClient,
    MediaItem,
    MediaOutputError,
    max_input_bytes,
    media_spec,
    validate_output,
)


def analyze(items, runner=None, settings=None, job="j1"):
    client = MediaClient(runner or M.InProcessRunner(), settings or MediaSettings())
    return asyncio.run(client.analyze(items, job=job))


def test_spec_has_no_network_and_the_media_limits():
    s = MediaSettings()
    spec = media_spec(s)
    assert spec.role == "media" and spec.network == "none"
    assert spec.limits == s.limits and spec.limits.pids == 64
    assert spec.command[:3] == ("python3", "-m", "brandsentinel.sandbox.media_worker")
    assert spec.command[-2:] == ("--max-input-bytes", str(max_input_bytes(s)))
    assert ("OMP_THREAD_LIMIT", "1") in spec.env
    assert spec.user is None and spec.image is None  # the image's non-root user


def test_a_batch_is_analyzed_and_mapped_by_id():
    batch = analyze([MediaItem("a", M.lab_logo()), MediaItem("b", F.html_named_png())])
    assert batch.status == "ok" and set(batch.items) == {"a", "b"}
    assert batch.items["a"]["status"] == "ok" and batch.items["a"]["phash"]
    assert batch.items["b"] == {
        "id": "b",
        "status": "rejected",
        "reason": "not_an_image",
        "detail": "magic bytes match no allowed format",
        "sha256": MediaItem("b", F.html_named_png()).sha256,
        "bytes": len(F.html_named_png()),
    }
    assert batch.tools["pillow"]


def test_ae12_a_killed_batch_is_retried_one_image_at_a_time():
    """Covers AE12 (client side): a job killed by its limits records the image
    as failed with the reason, and the other images are still analyzed."""
    runner = M.InProcessRunner(fail={"j1": "oom", "j1-i1": "oom"})
    items = [
        MediaItem("a", M.lab_logo()),
        MediaItem("b", b"bomb"),
        MediaItem("c", M.LAB_QR.read_bytes()),
    ]
    batch = analyze(items, runner)
    assert batch.status == "partial"
    assert batch.items["a"]["status"] == batch.items["c"]["status"] == "ok"
    assert batch.items["b"]["status"] == "failed" and batch.items["b"]["reason"] == "sandbox_oom"
    assert [c[1] for c in runner.calls] == ["j1", "j1-i0", "j1-i1", "j1-i2"]
    assert [r["status"] for r in batch.runs] == ["oom", "ok", "oom", "ok"]


def test_a_single_image_killed_by_a_limit_fails_without_retry():
    runner = M.InProcessRunner(fail={"j1": "timeout"})
    batch = analyze([MediaItem("a", M.lab_logo())], runner)
    assert batch.status == "failed" and batch.items["a"]["reason"] == "sandbox_timeout"
    assert len(runner.calls) == 1


def _tampered(fn):
    return M.InProcessRunner(tamper=fn, fail={})


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: {**d, "extra": 1},
        lambda d: {**d, "items": [{**d["items"][0], "id": "zz"}]},
        lambda d: {**d, "items": [{**d["items"][0], "sha256": "0" * 64}]},
        lambda d: {**d, "items": [{**d["items"][0], "phash": "not-hex"}]},
        lambda d: {**d, "items": [{**d["items"][0], "unexpected": True}]},
        lambda d: {**d, "items": d["items"] * 2},
        lambda d: {**d, "items": [{**d["items"][0], "ocr": {"status": "ok", "text": "x" * 5000}}]},
        lambda d: {**d, "items": [{**d["items"][0], "status": "ok", "phash": None}]},
        lambda d: {**d, "worker": "evil/9"},
        lambda d: {**d, "error": "worker crashed"},
    ],
    ids=["extra-key", "wrong-id", "wrong-hash", "bad-hex", "item-key", "duplicated",
         "ocr-over-cap", "ok-without-hash", "worker-version", "error"],
)  # fmt: skip
def test_untrusted_output_that_does_not_validate_fails_the_image(tamper):
    batch = analyze([MediaItem("a", M.lab_logo())], _tampered(tamper))
    assert batch.status == "failed"
    assert batch.items["a"]["status"] == "failed"
    assert batch.items["a"]["reason"] == "sandbox_invalid_output"


def test_validate_output_rejects_none():
    with pytest.raises(MediaOutputError):
        validate_output(None, [MediaItem("a", b"x")], MediaSettings())


def test_batch_limits_are_enforced_before_any_container_starts():
    runner = M.InProcessRunner()
    s = MediaSettings(max_image_bytes=1000, max_batch_bytes=2000)
    with pytest.raises(ValueError, match="max_batch_bytes"):
        analyze([MediaItem(str(i), b"x" * 900) for i in range(3)], runner, s)
    with pytest.raises(ValueError, match="unique"):
        analyze([MediaItem("a", b"x"), MediaItem("a", b"y")], runner)
    with pytest.raises(ValueError):
        analyze([MediaItem(str(i), b"x") for i in range(33)], runner)
    assert runner.calls == []


def test_empty_batch_runs_nothing():
    runner = M.InProcessRunner()
    assert analyze([], runner).status == "ok" and runner.calls == []
