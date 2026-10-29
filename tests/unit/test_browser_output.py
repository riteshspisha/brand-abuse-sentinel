"""The browser client (U19): job documents, the container spec, the network check
before launch, and strict validation of the worker's untrusted document. The
runner is faked; the real container is in tests/integration/test_browser_client.py."""

import asyncio
import base64
import copy
import struct
import zlib

import pytest

from brandsentinel.config import BrowserSettings, SandboxSettings
from brandsentinel.sandbox import browser_worker as W
from brandsentinel.sandbox.browser_client import (
    SECCOMP_PROFILE,
    BrowserClient,
    BrowserOutputError,
    browser_spec,
    job_document,
    validate_output,
)
from brandsentinel.sandbox.runner import SandboxResult

URL = "http://login-luminafoundation.test/"


def png(width: int = 4, height: int = 3) -> bytes:
    raw = b"".join(b"\0" + b"\0\0\0" * width for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def doc(**changes) -> dict:
    shot = png()
    base = {
        "worker": "browser_worker/1",
        "status": "ok",
        "requested_url": URL,
        "error": None,
        "network_idle": True,
        "main_status": 200,
        "redirect_chain": [{"url": URL, "status": 200, "location": None}],
        "final_url": URL,
        "title": "Lumina Foundation - Member Sign In",
        "html": "<form><input type=password></form>",
        "html_truncated": False,
        "text": "Sign in",
        "text_truncated": False,
        "screenshot": {
            "status": "ok",
            "png": base64.b64encode(shot).decode(),
            "bytes": len(shot),
            "width": 4,
            "height": 3,
        },
        "navigations": [URL],
        "requests": [
            {
                "url": URL,
                "host": "login-luminafoundation.test",
                "method": "GET",
                "resource_type": "document",
                "navigation": True,
                "status": 200,
                "failure": None,
                "proxy_refusal": None,
            }
        ],
        "requests_dropped": 0,
        "attempts": {"blocked_requests": [], "dialogs": [], "popups": [], "downloads": []},
        "attempt_counts": {"blocked_requests": 0, "dialogs": 0, "popups": 0, "downloads": 0},
        "elapsed_ms": 900,
    }
    base.update(changes)
    return base


class FakeRunner:
    def __init__(self, output=None, status="ok", **result) -> None:
        self.output, self.status, self.result = output, status, result
        self.calls: list = []
        self.docker = None

    async def run(self, spec, *, job, attempt, stdin=b""):
        self.calls.append((spec, job, attempt, stdin))
        return SandboxResult(name="bs-test-browser", status=self.status, output=self.output,
                             **self.result)  # fmt: skip


async def passed() -> list[str]:
    return []


def client(runner, *, lab_hosts=None, check=passed, settings=None) -> BrowserClient:
    return BrowserClient(
        runner,
        settings or BrowserSettings(),
        SandboxSettings(),
        lab_hosts=lab_hosts,
        network_check=check,
    )


def render(c: BrowserClient, url: str = URL):
    return asyncio.run(c.render(url, job="r1"))


def test_spec_runs_the_worker_on_the_sandbox_network_with_chromiums_profile():
    settings, sandbox = BrowserSettings(), SandboxSettings()
    spec = browser_spec(sandbox, settings)
    assert spec.role == "browser" and spec.network == sandbox.network == "bs_sandbox"
    assert spec.command[:3] == ("python3", "-m", "brandsentinel.sandbox.browser_worker")
    assert spec.user == "pwuser" and spec.limits == settings.limits
    assert spec.seccomp_profile == str(SECCOMP_PROFILE.resolve()) and SECCOMP_PROFILE.is_file()
    assert ("HOME", "/tmp") in spec.env and spec.image is None


def test_lab_spec_uses_the_lab_sandbox_network():
    lab = SandboxSettings(network="bs_lab_sandbox", proxy_container="bs-lab-sandbox-proxy",
                          proxy_url="http://172.31.254.2:3128")  # fmt: skip
    assert browser_spec(lab, BrowserSettings()).network == "bs_lab_sandbox"


def test_job_document_names_the_proxy_and_the_caps():
    job = W.parse_job(job_document(URL, "http://172.31.251.2:3128", BrowserSettings()))
    assert job["proxy"] == "http://172.31.251.2:3128" and job["url"] == URL
    assert job["options"]["max_html_bytes"] == BrowserSettings().max_html_bytes
    assert "selftest" not in job


def test_a_valid_document_is_used_and_the_screenshot_decoded():
    r = render(client(FakeRunner(doc())))
    assert r.status == "ok" and r.reason is None
    assert r.html == b"<form><input type=password></form>" and r.screenshot == png()
    assert "png" not in r.doc["screenshot"] and "html" not in r.doc and r.doc["text"] == "Sign in"
    assert r.to_fact()["worker"] == "browser_worker/1"


def test_the_network_check_must_pass_before_any_container_starts():
    async def failing() -> list[str]:
        return ["network_internal: bs_sandbox is not internal"]

    runner = FakeRunner(doc())
    r = render(client(runner, check=failing))
    assert r.status == "refused" and r.reason == "network_check_failed"
    assert r.network_check == ["network_internal: bs_sandbox is not internal"]
    assert runner.calls == []


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("file:///etc/passwd", "invalid_url"),
        ("javascript:alert(1)", "invalid_url"),
        ("http://", "invalid_url"),
        ("http://example.com/" + "a" * 3000, "invalid_url"),
        ("http://example.com/", "not_lab_host"),
    ],
)
def test_unrenderable_urls_are_refused_without_a_container(url, reason):
    runner = FakeRunner(doc())
    r = render(client(runner, lab_hosts=frozenset({"login-luminafoundation.test"})), url)
    assert (r.status, r.reason) == ("refused", reason) and runner.calls == []


def test_a_sandbox_failure_is_recorded_with_its_reason():
    r = render(client(FakeRunner(None, status="timeout", killed=True)))
    assert (r.status, r.reason) == ("failed", "sandbox_timeout")
    r = render(client(FakeRunner(None, status="exit_error", exit_code=137)))
    assert (r.status, r.reason) == ("failed", "sandbox_killed")


def test_a_worker_error_is_a_failure_not_a_rejection():
    out = {"worker": "browser_worker/1", "status": "error", "error": "TimeoutError: x"}
    r = render(client(FakeRunner(out)))
    assert r.status == "failed" and r.reason.startswith("worker_error")


def _tamper(d: dict, path: str, value) -> dict:
    d = copy.deepcopy(d)
    keys = path.split(".")
    target = d
    for k in keys[:-1]:
        target = target[int(k)] if isinstance(target, list) else target[k]
    target[keys[-1]] = value
    return d


SHOT_9x9 = base64.b64encode(png(9, 9)).decode()
TAMPERED = {
    "unknown key": ("cookies", ["sid=1"]),
    "other worker": ("worker", "browser_worker/9"),
    "other url": ("requested_url", "http://elsewhere.test/"),
    "html over the cap": ("html", "x" * (2 * 1024 * 1024 + 1)),
    "text over the cap": ("text", "x" * 50_001),
    "no html": ("html", None),
    "long request url": ("requests.0.url", "http://x/" + "a" * 3000),
    "request extra key": ("requests.0.cookie", "x"),
    "bad status": ("main_status", 7),
    "not base64": ("screenshot.png", "@@@@"),
    "not a png": ("screenshot.png", base64.b64encode(b"GIF89a" + b"\0" * 40).decode()),
    "size lies": ("screenshot.width", 40),
    "bytes lie": ("screenshot.bytes", 3),
    "data without ok": ("screenshot.status", "too_large"),
    "long title": ("title", "t" * 501),
    "attempts flood": ("attempts.dialogs", [{"type": "alert", "message": "x"}] * 51),
}


@pytest.mark.parametrize("case", sorted(TAMPERED))
def test_a_tampered_document_is_rejected_and_nothing_of_it_is_used(case):
    path, value = TAMPERED[case]
    r = render(client(FakeRunner(_tamper(doc(), path, value))))
    assert r.status == "render_rejected" and r.reason.startswith("invalid_output")
    assert r.html is None and r.screenshot is None and r.doc == {}


def test_a_screenshot_larger_than_the_viewport_is_rejected():
    settings = BrowserSettings(viewport_width=320, viewport_height=240)
    big = png(400, 10)
    d = doc(screenshot={"status": "ok", "png": base64.b64encode(big).decode(),
                        "bytes": len(big), "width": 400, "height": 10})  # fmt: skip
    with pytest.raises(BrowserOutputError, match="viewport"):
        validate_output(d, URL, settings)


def test_too_many_requests_are_rejected():
    settings = BrowserSettings(max_requests=1)
    d = doc(requests=doc()["requests"] * 2)
    with pytest.raises(BrowserOutputError, match="requests"):
        validate_output(d, URL, settings)


def test_a_document_without_a_screenshot_is_still_valid():
    out = validate_output(doc(screenshot={"status": "too_large", "bytes": 9_000_000}), URL,
                          BrowserSettings())  # fmt: skip
    assert out.screenshot.status == "too_large" and out.screenshot.png is None
