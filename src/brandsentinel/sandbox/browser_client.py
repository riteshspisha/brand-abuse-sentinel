"""The browser client (U19, KTD9): renders one page in the browser sandbox and
validates what comes back.

Before every launch the client runs the sandbox network check (`check_network`
without the direct-egress probe, which runs at startup): the network must be
internal with no gateway into the rootless namespace, its proxy must be the
hardened, attached egress proxy (lab mode: the lab sandbox proxy), and no other
untrusted container may be on it. A failed check means no browser starts
(`network_check_failed`). In lab mode only lab hostnames are rendered.

Every job runs through the U23 runner as role `browser` on the configured
sandbox network, as the image's `pwuser`, with Chromium's seccomp profile
(`chromium-seccomp.json`: Docker's default plus what Chromium's own namespace
sandbox needs), all capabilities dropped, `no-new-privileges`, a read-only root,
private IPC with a shared-memory size, and the browser limits (memory without
swap, CPU, PIDs, wall time, output caps). Nothing is mounted. Never
`--privileged`, never an added capability.

The worker's document is untrusted. It is parsed against a strict schema (no
unknown keys, bounded strings and lists), its requested URL must be the one
sent, the rendered HTML and text must fit their caps, and the screenshot must be
strict base64 of a PNG whose header size fits the viewport and whose length is
the one reported. Anything else is `render_rejected`; nothing from such a
document is used. This module never decodes an image.
"""

import base64
import binascii
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from brandsentinel.config import BrowserSettings, SandboxSettings
from brandsentinel.logging import exception_fields
from brandsentinel.sandbox.browser_worker import MAX_ATTEMPTS, MAX_URL_CHARS, png_size
from brandsentinel.sandbox.runner import SandboxResult, SandboxRunner, SandboxSpec

log = logging.getLogger(__name__)

WORKER_VERSION = "browser_worker/1"
CLIENT_VERSION = "browser_client/1"
MODULE = "brandsentinel.sandbox.browser_worker"
SECCOMP_PROFILE = Path(__file__).with_name("chromium-seccomp.json")
MAX_INPUT_BYTES = 64 * 1024

Url = Annotated[str, Field(max_length=MAX_URL_CHARS)]
Short = Annotated[str, Field(max_length=300)]


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RequestOut(_Out):
    url: Url
    host: Annotated[str, Field(max_length=255)] | None
    method: Annotated[str, Field(max_length=10)]
    resource_type: Annotated[str, Field(max_length=20)]
    navigation: bool
    status: int | None = Field(None, ge=100, le=999)
    failure: Annotated[str, Field(max_length=120)] | None = None
    proxy_refusal: Annotated[str, Field(max_length=64)] | None = None
    blocked: bool = False  # a non-GET request the worker stopped; never sent


class HopOut(_Out):
    url: Url
    status: int | None = Field(None, ge=100, le=999)
    location: Url | None = None


class ScreenshotOut(_Out):
    status: Literal["ok", "too_large", "error"]
    png: str | None = None
    bytes: int | None = Field(None, ge=0)
    width: int | None = Field(None, ge=1, le=16384)
    height: int | None = Field(None, ge=1, le=16384)
    error: Short | None = None


class BlockedRequest(_Out):
    method: Annotated[str, Field(max_length=10)]
    url: Url


class DialogOut(_Out):
    type: Annotated[str, Field(max_length=20)]
    message: Annotated[str, Field(max_length=200)]


class UrlOut(_Out):
    url: Url


class AttemptsOut(_Out):
    blocked_requests: list[BlockedRequest] = Field(default_factory=list, max_length=MAX_ATTEMPTS)
    dialogs: list[DialogOut] = Field(default_factory=list, max_length=MAX_ATTEMPTS)
    popups: list[UrlOut] = Field(default_factory=list, max_length=MAX_ATTEMPTS)
    downloads: list[UrlOut] = Field(default_factory=list, max_length=MAX_ATTEMPTS)
    websockets: list[UrlOut] = Field(default_factory=list, max_length=MAX_ATTEMPTS)


class AttemptCounts(_Out):
    blocked_requests: int = Field(0, ge=0)
    dialogs: int = Field(0, ge=0)
    popups: int = Field(0, ge=0)
    downloads: int = Field(0, ge=0)
    websockets: int = Field(0, ge=0)


class SandboxFacts(_Out):
    """Self-test only: Chromium's processes, and the worker's own identity."""

    processes: int = Field(ge=0, le=10_000)
    in_own_user_namespace: int = Field(ge=0, le=10_000)
    no_sandbox_flag: int = Field(ge=0, le=10_000)
    uid: int = Field(ge=0)
    cap_eff: Annotated[str, Field(max_length=16)]
    no_new_privs: Annotated[str, Field(max_length=2)]
    seccomp: Annotated[str, Field(max_length=2)]


class WorkerOut(_Out):
    worker: Literal["browser_worker/1"]
    status: Literal["ok", "error"]
    requested_url: Url | None = None
    error: Short | None = None
    navigation_error: Short | None = None
    network_idle: bool = False
    main_status: int | None = Field(None, ge=100, le=999)
    redirect_chain: list[HopOut] = Field(default_factory=list, max_length=20)
    final_url: Url | None = None
    title: Annotated[str, Field(max_length=500)] | None = None
    html: str | None = None  # capped in validate_output (bytes)
    html_truncated: bool = False
    text: str | None = None  # capped in validate_output
    text_truncated: bool = False
    screenshot: ScreenshotOut | None = None
    sandbox: SandboxFacts | None = None
    navigations: list[Url] = Field(default_factory=list, max_length=20)
    requests: list[RequestOut] = Field(default_factory=list, max_length=5000)
    requests_dropped: int = Field(0, ge=0)
    attempts: AttemptsOut = AttemptsOut()
    attempt_counts: AttemptCounts = AttemptCounts()
    elapsed_ms: int = Field(0, ge=0)


class BrowserOutputError(Exception):
    pass


@dataclass
class Render:
    """The validated outcome of one render.

    `status`: `ok` (a page was observed; `doc` describes it), `failed` (the
    sandbox stopped or the worker could not render), `render_rejected` (the
    document failed validation and nothing of it is used) or `refused` (not
    started: network check failed, or not a renderable URL)."""

    status: Literal["ok", "failed", "render_rejected", "refused"]
    url: str
    reason: str | None = None
    doc: dict = field(default_factory=dict)  # WorkerOut without html and png
    html: bytes | None = None
    screenshot: bytes | None = None
    runs: list[dict] = field(default_factory=list)
    network_check: list[str] = field(default_factory=list)

    def to_fact(self) -> dict:
        return {
            "status": self.status,
            "url": self.url,
            "reason": self.reason,
            "worker": WORKER_VERSION,
            "client": CLIENT_VERSION,
            "runs": self.runs,
            "network_check": self.network_check,
            **self.doc,
        }


def worker_options(settings: BrowserSettings, *, verify_tls: bool = False) -> dict:
    return {
        "verify_tls": verify_tls,
        "viewport_width": settings.viewport_width,
        "viewport_height": settings.viewport_height,
        "navigation_timeout_seconds": settings.navigation_timeout_seconds,
        "settle_seconds": settings.settle_seconds,
        "max_html_bytes": settings.max_html_bytes,
        "max_text_chars": settings.max_text_chars,
        "max_requests": settings.max_requests,
        "max_screenshot_bytes": settings.max_screenshot_bytes,
        "user_agent": settings.user_agent,
    }


def job_document(
    url: str, proxy: str, settings: BrowserSettings, *, selftest=None, verify_tls: bool = False
) -> bytes:
    options = worker_options(settings, verify_tls=verify_tls)
    doc = {"version": 1, "url": url, "proxy": proxy, "options": options}
    if selftest:
        doc["selftest"] = selftest
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def browser_spec(sandbox: SandboxSettings, settings: BrowserSettings) -> SandboxSpec:
    return SandboxSpec(
        role="browser",
        command=("python3", "-m", MODULE, "--max-input-bytes", str(MAX_INPUT_BYTES)),
        network=sandbox.network,
        limits=settings.limits,
        user="pwuser",
        env=(("HOME", "/tmp"),),  # noqa: S108 - container path (read-only root)
        seccomp_profile=str((settings.seccomp_profile or SECCOMP_PROFILE).resolve()),
    )


def validate_output(doc: dict | None, url: str, settings: BrowserSettings) -> WorkerOut:
    """Parse the worker's document and check it against the job and the caps."""
    if doc is None:
        raise BrowserOutputError("no JSON document")
    try:
        out = WorkerOut.model_validate(doc)
    except ValidationError as e:
        first = e.errors()[0]
        raise BrowserOutputError(f"schema: {first['loc']}: {first['msg']}") from e
    if out.status == "error":
        return out
    if out.requested_url != url:
        raise BrowserOutputError("requested_url differs from the job")
    if out.html is None or len(out.html.encode("utf-8", "replace")) > settings.max_html_bytes:
        raise BrowserOutputError("rendered HTML missing or over the cap")
    if out.text is None or len(out.text) > settings.max_text_chars:
        raise BrowserOutputError("rendered text missing or over the cap")
    if len(out.requests) > settings.max_requests:
        raise BrowserOutputError("more requests than the cap")
    shot = out.screenshot
    if shot is not None and shot.status == "ok":
        if shot.png is None or shot.bytes is None:
            raise BrowserOutputError("screenshot without data")
        if len(shot.png) > (settings.max_screenshot_bytes * 4) // 3 + 4:
            raise BrowserOutputError("screenshot over the cap")
        try:
            data = base64.b64decode(shot.png, validate=True)
        except (binascii.Error, ValueError) as e:
            raise BrowserOutputError("screenshot is not base64") from e
        size = png_size(data)
        if len(data) != shot.bytes or len(data) > settings.max_screenshot_bytes:
            raise BrowserOutputError("screenshot length differs or is over the cap")
        if size is None or size != (shot.width, shot.height):
            raise BrowserOutputError("screenshot is not the PNG it claims to be")
        if size[0] > settings.viewport_width or size[1] > settings.viewport_height:
            raise BrowserOutputError("screenshot larger than the viewport")
    elif shot is not None and shot.png is not None:
        raise BrowserOutputError("screenshot data without status ok")
    return out


NetworkCheck = Callable[[], Awaitable[list[str]]]


class BrowserClient:
    def __init__(
        self,
        runner: SandboxRunner,
        settings: BrowserSettings,
        sandbox: SandboxSettings,
        *,
        lab_hosts: frozenset[str] | None = None,
        network_check: NetworkCheck | None = None,
    ) -> None:
        """`lab_hosts`: in lab mode, the only hostnames that may be rendered.
        `network_check` returns the failed checks (empty: passed); by default the
        sandbox network check without the direct-egress probe."""
        self.runner = runner
        self.settings = settings
        self.sandbox = sandbox
        self.lab_hosts = lab_hosts
        self.network_check = network_check or self._check_network

    async def _check_network(self) -> list[str]:
        from brandsentinel.sandbox.preflight import check_network

        report = await check_network(self.runner.docker, self.sandbox, self.runner, probe=False)
        return report.reasons()

    def refusal(self, url: str) -> str | None:
        """Why `url` may not be rendered, or None."""
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            return "invalid_url"
        if len(url) > MAX_URL_CHARS or parts.scheme not in ("http", "https") or not host:
            return "invalid_url"
        if self.lab_hosts is not None and host not in self.lab_hosts:
            return "not_lab_host"
        return None

    async def render(
        self,
        url: str,
        *,
        job: str,
        attempt: int = 0,
        selftest: dict | None = None,
        verify_tls: bool = False,
    ) -> Render:
        """Render `url` once. `verify_tls`: Chromium refuses certificate errors
        (reference pages); otherwise they are recorded, not stops. Raises
        SandboxError only when no container could be started (the caller retries)."""
        reason = self.refusal(url)
        if reason is not None:
            return Render("refused", url, reason)
        failed = await self.network_check()
        if failed:
            log.warning("browser not started", extra={"fields": {"network_check": failed}})
            return Render("refused", url, "network_check_failed", network_check=failed[:20])
        stdin = job_document(
            url, self.sandbox.proxy_url, self.settings, selftest=selftest, verify_tls=verify_tls
        )
        result = await self.runner.run(
            browser_spec(self.sandbox, self.settings), job=job, attempt=attempt, stdin=stdin
        )
        runs = [result.summary()]
        if result.status != "ok":
            return Render("failed", url, _sandbox_reason(result), runs=runs)
        try:
            out = validate_output(result.output, url, self.settings)
        except BrowserOutputError as e:
            # Not the message: validation errors quote the page-influenced output.
            log.warning("invalid browser worker output", extra={"fields": exception_fields(e)})
            return Render("render_rejected", url, f"invalid_output: {e}"[:300], runs=runs)
        if out.status == "error":
            return Render("failed", url, f"worker_error: {out.error}"[:300], runs=runs)
        doc = out.model_dump(mode="json", exclude={"html", "text"})
        doc["verify_tls"] = verify_tls
        shot = doc.get("screenshot") or {}
        png = shot.pop("png", None)
        doc["text"] = out.text
        return Render(
            "ok",
            url,
            doc=doc,
            html=out.html.encode("utf-8", "replace"),
            screenshot=base64.b64decode(png) if png else None,
            runs=runs,
        )


async def build_browser_client(runner: SandboxRunner, config) -> tuple[BrowserClient | None, list]:
    """The browser client for the service and `registry collect`, only once the
    sandbox network check with its direct-egress probe passes; otherwise None and
    the failed checks. In lab mode it renders lab hostnames only."""
    from brandsentinel.sandbox.preflight import check_network

    report = await check_network(runner.docker, config.sandbox, runner)
    if not report.ok:
        return None, report.reasons()
    lab = config.net.lab
    hosts = frozenset(lab.hosts) if lab.enabled else None
    return BrowserClient(runner, config.browser, config.sandbox, lab_hosts=hosts), []


def _sandbox_reason(result: SandboxResult) -> str:
    if result.status == "exit_error" and result.exit_code == 137 and not result.killed:
        return "sandbox_killed"  # SIGKILL the runner did not send: the memory limit
    return f"sandbox_{result.status}"
