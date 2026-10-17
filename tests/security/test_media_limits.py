"""The image-processing gate (U16, R42, R43): untrusted images are decoded only
in the network-less, limited media container, never in the application.

Argument-level and import-level properties run everywhere; the container checks
carry the `docker` marker (and are also in tests/integration/test_media_sandbox.py)."""

import asyncio
import subprocess
import sys
import warnings

import pytest
from tests.docker_support import make_runner, runtime_or_skip

from brandsentinel.config import Config, MediaSettings
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox.media_client import media_spec
from brandsentinel.sandbox.runner import DockerCli, SandboxRunner

pytestmark = pytest.mark.security

IMAGE_LIBRARIES = ("PIL", "imagehash", "zxingcpp", "pytesseract", "numpy", "scipy")
# Every module of the application that runs outside the sandbox.
APPLICATION_MODULES = (
    "brandsentinel.cli",
    "brandsentinel.pipeline.orchestrator",
    "brandsentinel.pipeline.stages",
    "brandsentinel.pipeline.media",
    "brandsentinel.analysis.media_text",
    "brandsentinel.sandbox.media_client",
    "brandsentinel.sandbox.media_selftest",
    "brandsentinel.visual.collector",
    "brandsentinel.visual.corpus",
    "brandsentinel.visual.compare",
    "brandsentinel.analysis.images",
    "brandsentinel.evidence.bundle",
    "brandsentinel.policy.scorer",
    "brandsentinel.triage.report",
)


def test_the_application_never_imports_an_image_decoder():
    code = (
        "import importlib, sys\n"
        f"for m in {APPLICATION_MODULES!r}:\n"
        "    importlib.import_module(m)\n"
        f"print(sorted(m for m in {IMAGE_LIBRARIES!r} if m in sys.modules))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]", out.stdout + out.stderr


def _args(spec) -> list[str]:
    runner = SandboxRunner(Config().sandbox, DockerCli("unix:///fake.sock"))
    runner.validate(spec)
    return runner.create_args(spec, "bs-main-media-1-0", "1", 0)


def _opt(args, flag):
    return [args[i + 1] for i, a in enumerate(args) if a == flag]


def test_media_container_is_network_less_read_only_and_limited():
    settings = MediaSettings()
    args = _args(media_spec(settings))
    head = args[: args.index("--")]
    lim = settings.limits
    assert _opt(head, "--network") == ["none"]
    assert "--read-only" in head and _opt(head, "--cap-drop") == ["ALL"]
    assert _opt(head, "--security-opt") == ["no-new-privileges=true"]
    assert _opt(head, "--memory") == _opt(head, "--memory-swap") == [f"{lim.memory_mb}m"]
    assert _opt(head, "--pids-limit") == [str(lim.pids)]
    assert _opt(head, "--cpus") == [f"{lim.cpus:g}"]
    assert _opt(head, "--tmpfs") == [f"/tmp:rw,nosuid,nodev,noexec,size={lim.tmpfs_mb}m"]
    assert not {"-v", "--volume", "--mount", "--device", "--privileged"} & set(head)
    tail = args[args.index("--") + 1 :]
    assert tail[1:4] == ["timeout", "--signal=KILL", f"{int(lim.wall_seconds + 10) + 1}s"]


def test_media_jobs_take_no_network_lease_and_inspect_no_network(
    fake_docker, tmp_path, monkeypatch
):
    from dataclasses import replace

    from brandsentinel.config import SandboxLimits, SandboxSettings

    runtime = tmp_path / "run"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    settings = SandboxSettings(limits=SandboxLimits(wall_seconds=10), kill_grace_seconds=5)
    r = SandboxRunner(settings, DockerCli("unix:///fake.sock", str(fake_docker.binary)))
    spec = replace(media_spec(MediaSettings()), image="fake/echo")
    result = asyncio.run(r.run(spec, job="m1", attempt=0, stdin=b"{}"))
    assert result.status == "ok"
    assert not (runtime / "brandsentinel").exists()  # no lease file was ever opened
    calls = [c[c.index("unix:///fake.sock") + 1 :] for c in fake_docker.calls()]
    assert not any(c[:2] == ["network", "inspect"] for c in calls)
    (create,) = [c for c in calls if c[0] == "create"]
    assert create[create.index("--network") + 1] == "none"


@pytest.mark.parametrize("bad", [["text/html"], ["image/svg+xml"], ["text/plain", "image/png"]])
def test_image_fetch_never_accepts_markup(bad):
    with pytest.raises(ValueError):
        MediaSettings(accept_types=bad)


def test_configuration_cannot_lift_the_workers_hard_caps():
    from brandsentinel.sandbox import media_worker as W

    W._configure(10**12)
    try:
        from PIL import Image

        assert Image.MAX_IMAGE_PIXELS == W.HARD_MAX_PIXELS
        with warnings.catch_warnings():
            W._configure(10**12)
            assert any(
                f[0] == "error" and f[2] is Image.DecompressionBombWarning for f in warnings.filters
            )
    finally:
        W._configure(MediaSettings().max_pixels)
    with pytest.raises(ValueError):
        MediaSettings(max_pixels=10**9)
    with pytest.raises(ValueError):
        MediaSettings(max_batch_bytes=1024, max_image_bytes=4096)


def test_a_bomb_is_rejected_from_its_header_in_process():
    from tests.media_support import worker_opts

    from brandsentinel.sandbox import media_worker as W

    item = W.analyze(F.bomb_png(30000), worker_opts(), ocr=False, qr=False)
    assert (item["status"], item["reason"]) == ("rejected", "decompression_bomb")


@pytest.mark.docker
def test_selftest_passes_on_the_rootless_runtime():
    from brandsentinel.sandbox.media_selftest import selftest

    checks = asyncio.run(selftest(make_runner(runtime_or_skip()), MediaSettings()))
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
