"""The browser worker in its real container on the lab sandbox network (U19, R39,
R41, R49, AE11): Chromium's own sandbox is on in an unprivileged container, a page
reaches nothing but lab hostnames through the lab sandbox proxy, a browser told
to go direct finds no route at all, page-initiated actions are contained, and a
page that never settles is killed at the wall-time limit.

Needs the sandbox image and the lab project (brought up if needed)."""

import asyncio
import json
import time

import pytest
from tests.docker_support import (
    INSTANCE,
    LAB_SANDBOX_NET,
    LAB_WEB_IP,
    REPO,
    compose,
    labelled,
    make_runner,
    net_settings,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import BrowserSettings, SandboxLimits, load_config
from brandsentinel.sandbox.browser_client import BrowserClient

pytestmark = [pytest.mark.docker, pytest.mark.lab, pytest.mark.security]

LAB = "http://go-luminafoundation.test"


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    for name in ("bs-lab-web", LAB_SANDBOX_NET.proxy_container):
        wait_running(d, name)
    yield d
    assert labelled(d) == []  # no browser container outlives its run


def client(docker, *, lab=True, **browser) -> BrowserClient:
    hosts = frozenset(load_config(REPO / "config" / "lab.yaml").net.lab.hosts) if lab else None
    settings = BrowserSettings(**browser)
    return BrowserClient(
        make_runner(docker, net=LAB_SANDBOX_NET),
        settings,
        net_settings(LAB_SANDBOX_NET),
        lab_hosts=hosts,
    )


def render(c: BrowserClient, url: str, selftest=None):
    return asyncio.run(c.render(url, job=f"b-{abs(hash(url)) % 10**8}", selftest=selftest))


def test_js_login_renders_in_chromiums_own_sandbox_in_an_unprivileged_container(docker):
    r = render(client(docker), "http://login-luminafoundation.test/", {"sandbox_probe": True})
    assert r.status == "ok", (r.reason, r.runs)
    assert b'type="password"' in r.html and "Member Sign In" in r.doc["title"]
    assert r.screenshot and r.screenshot.startswith(b"\x89PNG")
    box = r.doc["sandbox"]
    # Renderers live in Chromium's own user namespace; nothing runs --no-sandbox.
    assert box["in_own_user_namespace"] >= 1 and box["no_sandbox_flag"] == 0
    # The worker itself: not root, no capabilities, no-new-privileges, seccomp filter.
    assert box["uid"] != 0 and int(box["cap_eff"], 16) == 0
    assert box["no_new_privs"] == "1" and box["seccomp"] == "2"
    hosts = {q["host"] for q in r.doc["requests"]}
    assert hosts == {"login-luminafoundation.test"}
    assert r.doc["attempt_counts"] == {
        "blocked_requests": 0, "dialogs": 0, "popups": 0, "downloads": 0, "websockets": 0,
    }  # fmt: skip


def test_every_escape_a_page_tries_is_refused_at_the_proxy_or_has_no_route(docker):
    # Covers AE11 from inside Chromium: metadata, loopback, public IPs, a lab
    # address by IP, the reserved gateway, a public name, a WebSocket, STUN.
    r = render(client(docker), f"{LAB}/escape.html")
    assert r.status == "ok" and "done" in r.doc["text"]
    escaped = [
        q for q in r.doc["requests"]
        if q["host"] != "go-luminafoundation.test" and (q["status"] or 0) < 400
        and not q["failure"]
    ]  # fmt: skip
    assert escaped == [], escaped
    refused = {q["host"] for q in r.doc["requests"] if q["proxy_refusal"] == "not_lab_host"}
    assert {"169.254.169.254", "127.0.0.1", "1.1.1.1", LAB_WEB_IP, "example.com"} <= refused


def test_a_browser_that_ignores_the_proxy_has_no_route_anywhere(docker):
    # The self-test launches Chromium without any proxy setting: the network alone
    # must stop it, from public addresses to the lab web server by IP.
    c = client(docker, lab=False)
    # Positive control: the same proxy-less browser does reach the one peer its
    # network has (the proxy answers a direct origin-form GET with 400), so the
    # failures below are the network's, not a browser that cannot connect at all.
    peer = render(c, f"http://{LAB_SANDBOX_NET.proxy_ip}:3128/", {"no_proxy": True})
    assert peer.status == "ok" and peer.doc["main_status"] == 400, peer.doc
    for url in ("http://1.1.1.1/", f"http://{LAB_WEB_IP}/", "http://172.31.250.2:3128/",
                "http://example.com/", "http://169.254.169.254/latest/meta-data/"):  # fmt: skip
        r = render(c, url, {"no_proxy": True})
        assert r.status == "ok", (url, r.reason)
        assert r.doc["main_status"] is None and r.doc.get("navigation_error"), (url, r.doc)
        assert all(q["status"] is None for q in r.doc["requests"]), (url, r.doc["requests"])


@pytest.mark.parametrize("path", ["/to-metadata", "/js-to-metadata.html"])
def test_redirects_to_metadata_are_refused_at_the_proxy_and_recorded(docker, path):
    r = render(client(docker), f"{LAB}{path}")
    assert r.status == "ok"
    last = r.doc["requests"][-1]
    assert last["host"] == "169.254.169.254" and last["status"] == 403
    assert last["proxy_refusal"] == "not_lab_host"


def _proxy_methods(docker, since: str) -> set[str]:
    logs = docker.call_sync("logs", "--since", since, LAB_SANDBOX_NET.proxy_container)
    records = [json.loads(x) for x in logs.stderr.splitlines() if x.startswith("{")]
    # Connections closed before a request line carry no method; they sent nothing.
    return {str(r["method"]) for r in records if r.get("method")}


def test_page_initiated_actions_are_contained_and_the_page_kept(docker):
    # R39: dialogs dismissed, the popup closed, the download refused and the
    # self-submitting form stopped in the browser; nothing but GET reaches the proxy.
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))  # this test only
    r = render(client(docker), f"{LAB}/pushy.html")
    assert r.status == "ok"
    counts = r.doc["attempt_counts"]
    assert counts["dialogs"] == 2 and counts["popups"] == 1 and counts["downloads"] == 1
    assert r.doc["attempts"]["blocked_requests"] == [{"method": "POST", "url": f"{LAB}/collect"}]
    assert r.doc["final_url"] == f"{LAB}/pushy.html" and b"Lumina Foundation" in r.html
    sent = [q for q in r.doc["requests"] if q["method"] != "GET" and not q["blocked"]]
    assert sent == [] and any(q["blocked"] for q in r.doc["requests"])
    methods = _proxy_methods(docker, since)
    assert "GET" in methods and methods <= {"GET", "CONNECT"}, methods  # logged, never POST


def test_a_page_that_never_settles_is_killed_at_the_wall_time_limit(docker):
    limits = SandboxLimits(**{**BrowserSettings().limits.model_dump(), "wall_seconds": 35})
    c = client(docker, navigation_timeout_seconds=3, settle_seconds=1, limits=limits)
    r = render(c, f"{LAB}/stall.html")
    assert (r.status, r.reason) == ("failed", "sandbox_timeout"), (r.reason, r.runs)
    assert r.runs[0]["killed"] and r.runs[0]["removed"]
    assert r.runs[0]["elapsed_ms"] < 55_000
    assert labelled(docker, INSTANCE) == []
