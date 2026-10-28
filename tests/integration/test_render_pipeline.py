"""The render stage through the queue (U19, AE10, AE17, R19, R48): decision ->
render -> rendered extractor features -> screenshot media analysis -> cloaking
comparison -> bundle -> policy, with the store, extractors, media worker (in
process), corpus and scorer all real. The browser is scripted: its container is
covered by tests/integration/test_browser_client.py and the lab demo."""

import json

import pytest
from tests import media_support as M
from tests.detection_support import LAB, lab_registry, lab_site, seed_case
from tests.integration.test_orchestrator import drain

from brandsentinel.config import Config, MediaSettings
from brandsentinel.evidence.bundle import VisualMatch
from brandsentinel.pipeline.orchestrator import Orchestrator
from brandsentinel.pipeline.render import RenderStage
from brandsentinel.pipeline.stages import AnalysisStages, build_network
from brandsentinel.sandbox.browser_client import Render
from brandsentinel.sandbox.media_client import MediaClient
from brandsentinel.sandbox.runner import SandboxError
from brandsentinel.store import open_store
from brandsentinel.triage import load_case

LOGIN = "http://login-luminafoundation.test/"
GIFT = "http://luminafoundation-gift.test/"
LOGIN_RENDERED = (
    "<html><head><title>Lumina Foundation - Member Sign In</title></head><body>"
    "<h1>Lumina Foundation Members</h1><p>Sign in to access your program recordings.</p>"
    '<form id="login" action="/session" method="post"><label>Email <input type="email"'
    ' name="email" autocomplete="username"></label><label>Password <input type="password"'
    ' name="password" autocomplete="current-password"></label><button>Sign in</button></form>'
    "</body></html>"
)


def doc(url: str, *, final: str | None = None, requests=None) -> dict:
    final = final or url
    return {
        "worker": "browser_worker/1",
        "status": "ok",
        "requested_url": url,
        "final_url": final,
        "main_status": 200,
        "network_idle": True,
        "title": "t",
        "redirect_chain": [{"url": url, "status": 200, "location": None}],
        "navigations": [final],
        "requests": requests
        or [
            {
                "url": url,
                "host": url.split("/")[2],
                "method": "GET",
                "resource_type": "document",
                "navigation": True,
                "status": 200,
                "failure": None,
                "proxy_refusal": None,
                "blocked": False,
            },
        ],
        "requests_dropped": 0,
        "attempts": {"blocked_requests": [], "dialogs": [], "popups": [], "downloads": []},
        "attempt_counts": {"blocked_requests": 0, "dialogs": 0, "popups": 0, "downloads": 0},
        "screenshot": {"status": "ok", "bytes": 1, "width": 1, "height": 1, "error": None},
        "html_truncated": False,
        "text": "",
        "elapsed_ms": 10,
    }


class ScriptedBrowser:
    """Stands in for BrowserClient: one scripted outcome per URL."""

    def __init__(self, outcomes: dict) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, int]] = []

    async def render(self, url, *, job, attempt=0, selftest=None):
        self.calls.append((url, attempt))
        out = self.outcomes[url]
        if isinstance(out, Exception):
            raise out
        if callable(out):
            return out(attempt)
        return out


def ok(url: str, html: str, screenshot: bytes | None = None, **kw) -> Render:
    return Render("ok", url, doc=doc(url, **kw), html=html.encode(), screenshot=screenshot)


@pytest.fixture
def env(tmp_path):
    config = Config(
        data_dir=tmp_path / "data",
        media={"ocr": False},
        browser={"sample_rate": 0.0},
        jobs={"max_attempts": 2},
    )
    store = open_store(config)
    registry = lab_registry()
    guard, fetcher = build_network(config)
    stages = AnalysisStages(store, registry, guard=guard, fetcher=fetcher)
    yield store, stages
    store.close()


def run(store, stages, browser, until, *, media=True):
    orch = Orchestrator(store)
    client = MediaClient(M.InProcessRunner(), MediaSettings(ocr=False)) if media else None
    RenderStage(stages, browser, client).register(orch)
    for s in orch.stages.values():
        s.poll_seconds = 0.01
        s.retry_delay_seconds = 0.0
    drain(orch, until, timeout=30)


def seed(store, stages, html, url) -> int:
    case_id = seed_case(store, html, url)
    stages.decide_render(stages._case(case_id), 0)
    stages.score(case_id)
    return case_id


def rendered(store, case_id):
    return lambda: store.conn.execute(
        "SELECT 1 FROM stage_runs WHERE case_id = ? AND stage = 'render'", (case_id,)
    ).fetchone()


def facts(store, case_id, name):
    return [
        json.loads(r[0])
        for r in store.conn.execute(
            "SELECT value_json FROM facts WHERE case_id = ? AND name = ? ORDER BY id",
            (case_id, name),
        )
    ]


def test_ae10_js_login_is_rendered_and_scored_on_the_rendered_form(env):
    store, stages = env
    _, shell = lab_site("js-login")
    case_id = seed(store, stages, shell, LOGIN)
    before = load_case(store.conn, case_id)
    assert before.bundle.render.status == "pending" and "js_shell" in before.bundle.render.reasons
    assert "needs_render" in before.result.flags

    browser = ScriptedBrowser({LOGIN: ok(LOGIN, LOGIN_RENDERED, M.lab_logo())})
    run(store, stages, browser, rendered(store, case_id))
    r = load_case(store.conn, case_id)
    b = r.bundle
    assert b.schema_version == "bundle/4" and b.render.status == "complete"
    assert b.render.content_source == "rendered" and b.render_reason == "js_shell"
    assert b.credential.password_fields == 1 and not b.page.js_shell
    assert r.result.category == "credential_phishing" and r.result.priority == "P1"
    assert "needs_render" not in r.result.flags
    assert not (b.cloaking or {}).get("suspected")  # a shell completed: expected
    assert b.render.screenshot["stored"] and b.render.screenshot["media"]["status"] == "ok"
    assert any(ref.startswith("fact:") for ref in b.credential.refs)
    (fact,) = facts(store, case_id, "browser_render")
    assert "text" not in fact and fact["html"]["sha256"]
    roles = {
        row[0]
        for row in store.conn.execute(
            "SELECT role FROM case_artifacts WHERE case_id = ?", (case_id,)
        )
    }
    assert {"rendered_page", "screenshot"} <= roles


def test_ae17_cloaking_is_suspected_and_scored_on_the_rendered_donation_page(env):
    store, stages = env
    benign = (LAB / "cloaking" / "benign" / "index.html").read_text()
    fraud = (LAB / "cloaking" / "fraud" / "index.html").read_text()
    case_id = seed(store, stages, benign, GIFT)
    ((decision,),) = [facts(store, case_id, "render_decision")]
    assert decision["triggered"] and "decoy_page" in decision["reasons"]
    run(store, stages, ScriptedBrowser({GIFT: ok(GIFT, fraud)}), rendered(store, case_id))
    r = load_case(store.conn, case_id)
    assert r.bundle.cloaking["suspected"] and r.bundle.cloaking["score_on"] == "rendered"
    assert "cloaking_suspected" in r.result.labels
    assert r.result.category == "donation_fraud" and r.result.priority in ("P1", "P2")
    assert "cloaking_suspected" in {x.rule for x in r.result.reasons}


def test_abuse_hidden_from_the_browser_keeps_the_static_evidence(env):
    store, stages = env
    fraud = (LAB / "cloaking" / "fraud" / "index.html").read_text()
    benign = "<html><head><title>Notes</title></head><body><p>" + "Hello there. " * 30
    case_id = seed(store, stages, fraud, GIFT)
    stages.store.conn.execute("DELETE FROM jobs WHERE stage = 'render'")
    stages.store.conn.execute("DELETE FROM facts WHERE name = 'render_decision'")
    stages.config.browser.__dict__["sample_rate"] = 1.0  # render this complete page
    stages.decide_render(stages._case(case_id), 0)
    run(store, stages, ScriptedBrowser({GIFT: ok(GIFT, benign + "</p></body></html>")}),
        rendered(store, case_id))  # fmt: skip
    r = load_case(store.conn, case_id)
    assert r.bundle.cloaking["suspected"] and r.bundle.cloaking["score_on"] == "static"
    assert r.bundle.render.content_source == "static"
    assert r.result.category == "donation_fraud" and r.result.priority in ("P1", "P2")


def test_a_rejected_render_is_recorded_and_the_case_keeps_its_static_evidence(env):
    store, stages = env
    _, shell = lab_site("js-login")
    case_id = seed(store, stages, shell, LOGIN)
    rejected = Render("render_rejected", LOGIN, "invalid_output: schema: ('cookies',)")
    run(store, stages, ScriptedBrowser({LOGIN: rejected}), rendered(store, case_id))
    r = load_case(store.conn, case_id)
    assert r.bundle.render.status == "rejected" and r.bundle.render.content_source == "static"
    assert "render_rejected" in r.bundle.incomplete and r.bundle.page.js_shell
    assert "needs_render" in r.result.flags
    assert any("rendering rejected" in n for n in r.result.manual_review)
    assert store.conn.execute("SELECT COUNT(*) FROM features WHERE case_id = ? AND name ="
                              " 'cloaking'", (case_id,)).fetchone()[0] == 0  # fmt: skip


def test_no_browser_starts_after_a_failed_network_check_and_the_job_is_retried(env):
    store, stages = env
    _, shell = lab_site("js-login")
    case_id = seed(store, stages, shell, LOGIN)
    refused = Render("refused", LOGIN, "network_check_failed",
                     network_check=["network_internal: bs_sandbox is not internal"])  # fmt: skip
    browser = ScriptedBrowser({LOGIN: refused})
    run(store, stages, browser, rendered(store, case_id))
    assert [a for _, a in browser.calls] == [1, 2]  # retried, then recorded
    (fact,) = facts(store, case_id, "browser_render")
    assert fact["status"] == "refused" and fact["network_check"]
    assert load_case(store.conn, case_id).bundle.render.status == "refused"


def test_a_sandbox_that_cannot_start_is_retried_then_recorded_as_failed(env):
    store, stages = env
    _, shell = lab_site("js-login")
    case_id = seed(store, stages, shell, LOGIN)
    browser = ScriptedBrowser({LOGIN: SandboxError("docker unreachable")})
    run(store, stages, browser, rendered(store, case_id))
    assert len(browser.calls) == 2
    b = load_case(store.conn, case_id).bundle
    assert b.render.status == "failed" and "sandbox unavailable" in b.render.reason


def test_a_screenshot_qr_code_becomes_a_payee_from_the_screenshot(env):
    store, stages = env
    _, html = lab_site("js-payment")
    url = "http://pay-luminafoundation.test/"
    case_id = seed(store, stages, html, url)
    page = (
        "<html><head><title>Lumina Foundation - Inner Radiance Program Fee</title></head><body>"
        "<h2>Pay 2500 INR to Lumina Foundation Programs</h2><form id='card' action='/pay'"
        " method='post'><input name='cardnumber' autocomplete='cc-number'><input name='exp'"
        " autocomplete='cc-exp'><input name='cvc' autocomplete='cc-csc'></form></body></html>"
    )
    shot = (LAB / "js-payment" / "static" / "upi-qr.png").read_bytes()
    run(store, stages, ScriptedBrowser({url: ok(url, page, shot)}), rendered(store, case_id))
    r = load_case(store.conn, case_id)
    b = r.bundle
    assert b.payment.card_fields == 3
    shot_payees = [o for o in b.payment.observations if o.image_sha256
                   and o.image_sha256 == b.render.screenshot["sha256"]]  # fmt: skip
    assert shot_payees and shot_payees[0].source == "qr_code"
    assert r.result.category in ("payment_fraud", "donation_fraud")
    assert r.result.priority in ("P1", "P2")


def test_a_screenshot_never_corroborates_a_match_of_an_image_it_shows(env):
    # The M6 self-corroboration defect, for screenshots: a page whose only brand
    # signal is the matched logo must not be corroborated by the screenshot's QR
    # payee, since the screenshot contains that logo.
    from brandsentinel.policy.rules import visual_corroboration

    store, stages = env
    url = "http://sunrise-yoga-studio.test/"
    html = '<html><head><title>Studio</title></head><body><img src="/l.png" class="logo">' \
           + "<p>" + "Classes every morning. " * 20 + "</p></body></html>"  # fmt: skip
    case_id = seed(store, stages, html, url)
    stages.config.browser.__dict__["sample_rate"] = 1.0
    store.conn.execute("DELETE FROM facts WHERE name = 'render_decision'")
    stages.decide_render(stages._case(case_id), 0)
    shot = (LAB / "js-payment" / "static" / "upi-qr.png").read_bytes()
    run(store, stages, ScriptedBrowser({url: ok(url, html, shot)}), rendered(store, case_id))
    b = load_case(store.conn, case_id).bundle
    sha = b.render.screenshot["sha256"]
    logo = VisualMatch(image_sha256="a" * 64, image_ref="/l.png", role="logo",
                       method="sha256", phash_distance=0, dhash_distance=0,
                       reference={"brand": "lumina-foundation"})  # fmt: skip
    fake_match = b.visual.model_copy(update={"matches": [logo]})
    staged = b.model_copy(update={"visual": fake_match})
    support = visual_corroboration(staged, {"lumina-foundation"})
    assert not [what for what, _ in support if "payee" in what], support
    assert any(o.image_sha256 == sha for o in b.payment.observations)  # the payee exists


def test_reports_show_the_render_escaped_and_never_embed_the_screenshot(env):
    from brandsentinel.triage.report import render_case_html, render_case_text

    store, stages = env
    benign = (LAB / "cloaking" / "benign" / "index.html").read_text()
    fraud = (LAB / "cloaking" / "fraud" / "index.html").read_text()
    case_id = seed(store, stages, benign, GIFT)
    hostile = 'http://169.254.169.254/<script>alert(1)</script>"'
    requests = doc(GIFT)["requests"] + [
        {"url": hostile, "host": "169.254.169.254", "method": "GET", "resource_type": "image",
         "navigation": False, "status": 403, "failure": None, "proxy_refusal": "not_lab_host",
         "blocked": False},
    ]  # fmt: skip
    browser = ScriptedBrowser({GIFT: ok(GIFT, fraud, M.lab_logo(), requests=requests)})
    run(store, stages, browser, rendered(store, case_id))
    r = load_case(store.conn, case_id)
    page = render_case_html(r)
    assert "Isolated browser (render: complete)" in page and "cloaking suspected" in page
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert "data:image" not in page and "<img" not in page
    text = "\n".join(render_case_text(r))
    assert "cloaking suspected" in text and "refused by proxy" in text
