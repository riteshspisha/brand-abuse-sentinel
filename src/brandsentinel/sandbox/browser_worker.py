"""The browser worker (U19, KTD9): renders one page in Chromium inside the browser
sandbox container and prints one JSON document.

It runs only in the sandbox image (`python3 -m brandsentinel.sandbox.browser_worker`),
started by the browser client through the U23 runner on the sandbox network,
whose only reachable peer is the validating egress proxy. Nothing here is the
isolation boundary: a page that ignores the proxy settings finds no route out.

Chromium keeps its own sandbox (`chromium_sandbox=True`, never `--no-sandbox`):
renderers run in their own user, PID and network namespaces, which the
container's seccomp profile (`chromium-seccomp.json`) permits without any added
capability.

The page is only observed. The worker loads the URL, waits for the load event and
then for network idle within its budget, and reads the result: it never clicks,
types, fills, presses, hovers, submits, uploads, downloads or grants a
permission. What the page tries on its own is contained and recorded:

- every request other than GET or HEAD is stopped in the browser (a form that
  submits itself, a beacon, a script POST), so no data leaves even through a
  CONNECT tunnel; a blocked navigation is answered locally with 204 No Content,
  which keeps the page in place;
- downloads are refused, service workers blocked, dialogs dismissed, popups
  closed, no permission is granted;
- QUIC is off and WebRTC may use only proxied TCP.

The document holds the final URL, the redirect chain and later main-frame
navigations, the rendered HTML and visible text (capped), the network requests
(host, method, type, status or failure, and the proxy's refusal reason), what
the page attempted, and a viewport PNG screenshot (capped). The client treats
all of it as untrusted and validates it before use.
"""

import argparse
import base64
import json
import os
import sys
import time
from urllib.parse import urlsplit

WORKER_VERSION = "browser_worker/1"
MAX_INPUT_BYTES = 64 * 1024
MAX_URL_CHARS = 2048
MAX_NAVIGATIONS = 20
MAX_REDIRECTS = 20
MAX_ATTEMPTS = 50  # per kind of contained page action
PROXY_HEADER = "x-brandsentinel-proxy"
# Steps after the page settles, each bounded (BrowserSettings budgets for them).
TEXT_TIMEOUT_MS = 5000
SCREENSHOT_TIMEOUT_MS = 10000
POST_SETTLE_SECONDS = 30  # text + screenshot + reading the page + launch and close
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
# Chromium flags beside Playwright's own. None of them is a boundary (the network
# is); they keep the browser from wandering. Never --no-sandbox.
CHROMIUM_ARGS = (
    "--disable-quic",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
    "--no-pings",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--no-first-run",
)


class JobError(Exception):
    pass


def parse_job(raw: bytes) -> dict:
    """The job document: {version, url, proxy, options, selftest?}."""
    try:
        job = json.loads(raw)
    except ValueError as e:
        raise JobError("job is not JSON") from e
    if not isinstance(job, dict) or job.get("version") != 1:
        raise JobError("unsupported job version")
    url, proxy, opts = job.get("url"), job.get("proxy"), job.get("options")
    if not isinstance(url, str) or len(url) > MAX_URL_CHARS:
        raise JobError("url must be a string")
    if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
        raise JobError("url must be http or https")
    selftest = job.get("selftest") or {}
    if not isinstance(selftest, dict):
        raise JobError("selftest must be an object")
    # Only the self-test may run without the proxy, to show that the network, not
    # a browser setting, stops a page that goes direct.
    if not (isinstance(proxy, str) and urlsplit(proxy).scheme == "http") and not selftest.get(
        "no_proxy"
    ):
        raise JobError("proxy must be an http:// URL")
    if not isinstance(opts, dict):
        raise JobError("options must be an object")
    return job


def cap(text: str | None, limit: int) -> str | None:
    return None if text is None else text[:limit]


def host_of(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


# C0 controls (but tab, newline, carriage return) and DEL: JSON escapes each as six
# bytes, so a page made of them could blow the output cap and deny rendering.
_CONTROLS = dict.fromkeys([*range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F])


def clean(text: str) -> str:
    return text.translate(_CONTROLS)


def cap_bytes(text: str, limit: int) -> tuple[str, bool]:
    """`text` cut to at most `limit` UTF-8 bytes, and whether it was cut."""
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode("utf-8", "ignore"), True


def png_size(data: bytes) -> tuple[int, int] | None:
    """Width and height from a PNG's IHDR, without decoding it."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


class Recorder:
    """Network requests and contained page actions, bounded."""

    def __init__(self, opts: dict) -> None:
        self.max_requests = int(opts["max_requests"])
        self.requests: list[dict] = []
        self.by_request: dict[int, dict] = {}
        self.dropped = 0
        self.navigations: list[str] = []
        self.attempts: dict[str, list[dict]] = {
            "blocked_requests": [],
            "dialogs": [],
            "popups": [],
            "downloads": [],
        }
        self.counts = dict.fromkeys(self.attempts, 0)

    def attempt(self, kind: str, entry: dict) -> None:
        self.counts[kind] += 1
        if len(self.attempts[kind]) < MAX_ATTEMPTS:
            self.attempts[kind].append(entry)

    def block(self, request) -> None:
        entry = self.by_request.get(id(request))
        if entry is not None:
            entry["blocked"] = True

    def on_request(self, request) -> None:
        if len(self.requests) >= self.max_requests:
            self.dropped += 1
            return
        entry = {
            "url": cap(request.url, MAX_URL_CHARS),
            "host": cap(host_of(request.url), 255),
            "method": cap(request.method, 10),
            "resource_type": cap(request.resource_type, 20),
            "navigation": request.is_navigation_request(),
            "status": None,
            "failure": None,
            "proxy_refusal": None,
            "blocked": False,  # stopped in the browser, never sent
        }
        self.requests.append(entry)
        self.by_request[id(request)] = entry

    def on_response(self, response) -> None:
        entry = self.by_request.get(id(response.request))
        if entry is None:
            return
        entry["status"] = response.status
        try:
            refusal = response.headers.get(PROXY_HEADER)
        except Exception:  # a page's response headers are untrusted
            refusal = None
        entry["proxy_refusal"] = cap(refusal, 64)

    def on_failed(self, request) -> None:
        entry = self.by_request.get(id(request))
        if entry is not None:
            entry["failure"] = cap(request.failure or "failed", 120)


def redirect_chain(response) -> list[dict]:
    """The main navigation's HTTP redirects, first request first."""
    chain = []
    request = response.request if response is not None else None
    while request is not None and len(chain) < MAX_REDIRECTS:
        r = request.response() if request is not response.request else response
        chain.append(
            {
                "url": cap(request.url, MAX_URL_CHARS),
                "status": r.status if r is not None else None,
                "location": cap((r.headers.get("location") if r is not None else None), 2048),
            }
        )
        request = request.redirected_from
    return chain[::-1]


def _sandbox_facts() -> dict:
    """Which processes run in Chromium's own namespaces (self-test only)."""
    own = os.readlink("/proc/self/ns/user")
    status = dict(
        line.split(":\t", 1)
        for line in open("/proc/self/status").read().splitlines()  # noqa: SIM115
        if ":\t" in line
    )
    seen = {
        "processes": 0,
        "in_own_user_namespace": 0,
        "no_sandbox_flag": 0,
        "uid": os.getuid(),
        "cap_eff": status.get("CapEff", "").strip()[:16],
        "no_new_privs": status.get("NoNewPrivs", "").strip()[:2],
        "seccomp": status.get("Seccomp", "").strip()[:2],
    }
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read()  # noqa: SIM115
            if b"chrome" not in cmd:
                continue
            seen["processes"] += 1
            if os.readlink(f"/proc/{pid}/ns/user") != own:
                seen["in_own_user_namespace"] += 1
            if b"--no-sandbox" in cmd:
                seen["no_sandbox_flag"] += 1
        except OSError:
            continue
    return seen


def render(job: dict) -> dict:
    """Render the job's URL. Imports Playwright here: only the image has it."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright

    opts = job["options"]
    selftest = job.get("selftest") or {}
    rec = Recorder(opts)
    started = time.monotonic()
    out: dict = {
        "worker": WORKER_VERSION,
        "status": "ok",
        "requested_url": job["url"],
        "error": None,
    }
    launch = {"chromium_sandbox": True, "args": list(CHROMIUM_ARGS), "headless": True}
    if not selftest.get("no_proxy"):
        # <-loopback>: even loopback goes to the proxy (which refuses it).
        launch["proxy"] = {"server": job["proxy"], "bypass": "<-loopback>"}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch)
        try:
            context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
                # Evidence: a certificate problem is a fact, not a stop. Reference
                # pages (`registry collect`) are rendered only with verified TLS.
                ignore_https_errors=not opts.get("verify_tls", False),
                java_script_enabled=True,
                permissions=[],
                viewport={"width": opts["viewport_width"], "height": opts["viewport_height"]},
                user_agent=opts.get("user_agent") or None,
                locale="en-US",
                timezone_id="UTC",
            )
            context.set_default_timeout(5000)

            def gate(route) -> None:
                request = route.request
                if request.method.upper() in ALLOWED_METHODS:
                    route.continue_()
                    return
                rec.attempt(
                    "blocked_requests",
                    {"method": cap(request.method, 10), "url": cap(request.url, MAX_URL_CHARS)},
                )
                rec.block(request)
                if request.is_navigation_request():
                    # Answered here, never sent: a 204 leaves the page where it is,
                    # so a form that submits itself cannot blank the evidence.
                    route.fulfill(status=204, body="")
                else:
                    route.abort("blockedbyclient")

            def popup(page) -> None:
                rec.attempt("popups", {"url": cap(page.url, MAX_URL_CHARS)})
                page.close()

            def dialog(d) -> None:
                rec.attempt("dialogs", {"type": cap(d.type, 20), "message": cap(d.message, 200)})
                d.dismiss()

            context.route("**/*", gate)
            context.on("request", rec.on_request)
            context.on("response", rec.on_response)
            context.on("requestfailed", rec.on_failed)
            page = context.new_page()
            context.on("page", popup)
            page.on("dialog", dialog)
            page.on(
                "download",
                lambda d: rec.attempt("downloads", {"url": cap(d.url, MAX_URL_CHARS)}),
            )

            def navigated(frame) -> None:
                if frame == page.main_frame and len(rec.navigations) < MAX_NAVIGATIONS:
                    rec.navigations.append(cap(frame.url, MAX_URL_CHARS))

            page.on("framenavigated", navigated)
            response = None
            try:
                response = page.goto(
                    job["url"],
                    wait_until="load",
                    timeout=opts["navigation_timeout_seconds"] * 1000,
                )
            except PlaywrightTimeout:
                out["navigation_error"] = "timeout"
            except PlaywrightError as e:
                out["navigation_error"] = cap(str(e).splitlines()[0], 300)
            idle = False
            if opts["settle_seconds"] > 0:
                try:
                    page.wait_for_load_state("networkidle", timeout=opts["settle_seconds"] * 1000)
                    idle = True
                except PlaywrightError:
                    idle = False
            out["network_idle"] = idle
            out["main_status"] = response.status if response is not None else None
            out["redirect_chain"] = redirect_chain(response) if response is not None else []
            out["final_url"] = cap(page.url, MAX_URL_CHARS)
            try:
                out["title"] = cap(page.title(), 500)
            except PlaywrightError:
                out["title"] = None
            html, truncated = cap_bytes(clean(page.content()), opts["max_html_bytes"])
            out["html"], out["html_truncated"] = html, truncated
            try:
                text = clean(page.inner_text("body", timeout=TEXT_TIMEOUT_MS))
            except PlaywrightError:
                text = ""
            out["text"] = cap(text, opts["max_text_chars"])
            out["text_truncated"] = len(text) > opts["max_text_chars"]
            out["screenshot"] = _screenshot(page, opts, PlaywrightError)
            if selftest.get("sandbox_probe"):
                out["sandbox"] = _sandbox_facts()
        finally:
            browser.close()
    out["navigations"] = rec.navigations
    out["requests"] = rec.requests
    out["requests_dropped"] = rec.dropped
    out["attempts"] = rec.attempts
    out["attempt_counts"] = rec.counts
    out["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return out


def _screenshot(page, opts: dict, error) -> dict:
    try:
        data = page.screenshot(
            type="png", full_page=False, animations="disabled", timeout=SCREENSHOT_TIMEOUT_MS
        )
    except error as e:
        return {"status": "error", "error": cap(str(e).splitlines()[0], 200)}
    size = png_size(data)
    if size is None:
        return {"status": "error", "error": "not a PNG"}
    if len(data) > opts["max_screenshot_bytes"]:
        return {"status": "too_large", "bytes": len(data)}
    return {
        "status": "ok",
        "png": base64.b64encode(data).decode("ascii"),
        "bytes": len(data),
        "width": size[0],
        "height": size[1],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="browser_worker")
    parser.add_argument("--max-input-bytes", type=int, default=MAX_INPUT_BYTES)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(args.max_input_bytes + 1)
    try:
        if len(raw) > args.max_input_bytes:
            raise JobError("job too large")
        out = render(parse_job(raw))
    except JobError as e:
        out = {"worker": WORKER_VERSION, "status": "error", "error": cap(str(e), 200)}
    except Exception as e:  # one bounded error document, never a traceback
        out = {
            "worker": WORKER_VERSION,
            "status": "error",
            "error": cap(f"{type(e).__name__}: {e}".splitlines()[0], 200),
        }
    # UTF-8, not \u escapes: a non-ASCII page costs its own bytes, at most.
    doc = json.dumps(out, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.buffer.write(doc.encode("utf-8", "replace"))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
