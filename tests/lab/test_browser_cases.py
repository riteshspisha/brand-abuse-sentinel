"""M7 demo on the controlled lab (U19, AE10, AE13, AE17, AE18; markers lab, docker).

The real service in lab mode: browser-relevant lab sites are submitted, fetched
statically through the lab proxy, rendered in the real browser container on
bs_lab_sandbox (whose only way out is the lab sandbox proxy), their screenshots
analyzed in the media container, compared with the static view, and scored.
Each site must reach the outcome its expected.yaml names. Then the application
is killed during a browser job: on restart the container is gone before any
lease is recovered, and the job runs again exactly once. Needs a sandbox image
built from this tree."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
import yaml
from tests.detection_support import lab_site
from tests.docker_support import (
    INSTANCE,
    LAB_SANDBOX_NET,
    REPO,
    compose,
    labelled,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.analysis.payment import ProviderCatalog
from brandsentinel.config import load_config
from brandsentinel.discovery.submit import submit
from brandsentinel.matching.matcher import Matcher
from brandsentinel.pipeline.orchestrator import run_service
from brandsentinel.pipeline.stages import build_network
from brandsentinel.registry.loader import load_registry
from brandsentinel.sandbox.media_client import MediaClient
from brandsentinel.sandbox.preflight import hostile_content_runtime
from brandsentinel.store import open_store
from brandsentinel.triage import load_case
from brandsentinel.visual.collector import Collector

pytestmark = [pytest.mark.lab, pytest.mark.docker]

SITES = ["js-login", "js-payment", "image-only", "redirects", "cloaking", "copied-assets"]


def lab_config(tmp, **browser):
    config = load_config(REPO / "config" / "lab.yaml")
    return config.model_copy(
        update={
            "data_dir": tmp,
            "sandbox": config.sandbox.model_copy(update={"instance": INSTANCE}),
            # Render every strong-strength case, so each site shows its rendered side.
            "browser": config.browser.model_copy(update={"sample_rate": 1.0, **browser}),
        }
    )


def settle(store, stop_after: float = 600) -> None:
    def settled() -> bool:
        busy = store.conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'running')"
        ).fetchone()[0]
        unscored = store.conn.execute(
            "SELECT COUNT(*) FROM cases WHERE score_id IS NULL"
        ).fetchone()[0]
        return not busy and not unscored

    async def main() -> None:
        stop = asyncio.Event()

        async def watch():
            deadline = time.monotonic() + stop_after
            while not settled() and time.monotonic() < deadline:
                await asyncio.sleep(0.5)
            stop.set()

        watcher = asyncio.create_task(watch())
        await run_service(
            store, store.registry, certstream_enabled=False, dnstwist_enabled=False, stop=stop
        )
        await watcher

    asyncio.run(main())
    assert settled(), "lab pipeline did not settle"


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    for name in ("bs-lab-web", "bs-lab-proxy", LAB_SANDBOX_NET.proxy_container):
        wait_running(d, name)
    yield d
    assert labelled(d) == []


@pytest.fixture(scope="module")
def demo(docker, tmp_path_factory):
    config = lab_config(tmp_path_factory.mktemp("browser-demo"))
    registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
    store = open_store(config)
    store.registry = registry
    runner, report = asyncio.run(hostile_content_runtime(config))
    assert runner is not None, report.reasons()
    _, fetcher = build_network(config)
    asyncio.run(
        Collector(
            store.conn, registry, fetcher, MediaClient(runner, config.media), config.media,
            config.registry_path.parent / "assets",
            providers=ProviderCatalog.load(config.analysis.payment_providers),
        ).collect()
    )  # fmt: skip
    matcher = Matcher(registry)
    cases = {s: submit(store, matcher, lab_site(s)[0]["url"]).case_id for s in SITES}
    settle(store)
    yield store, cases
    store.close()


@pytest.fixture(scope="module")
def requested(docker, tmp_path_factory):
    """M8: renders an analyst asked for, with no sample, on two lab stores: the
    lab budget (config/lab.yaml) and a copy with budget 0."""
    out = {}
    for budget in (None, 0):
        config = lab_config(tmp_path_factory.mktemp(f"requested-{budget}"), sample_rate=0.0)
        if budget is not None:
            config = config.model_copy(
                update={"browser": config.browser.model_copy(
                    update={"analyst_renders_per_day": budget})}
            )  # fmt: skip
        registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
        store = open_store(config)
        store.registry = registry
        matcher = Matcher(registry)
        url = lab_site("unrelated-yoga")[0]["url"]  # no brand match, no other trigger
        r = submit(store, matcher, url, render=True)
        assert r.render_request.status == "requested" and r.render_request.round == 0
        settle(store)
        out[budget] = (store, r.case_id)
    yield out
    for store, _ in out.values():
        store.close()


def test_a_requested_render_of_a_non_brand_lab_site_completes(requested):
    store, case_id = requested[None]
    assert store.config.browser.analyst_renders_per_day == 5  # from config/lab.yaml
    r = load_case(store.conn, case_id)
    b = r.bundle
    assert b.render.status == "complete" and b.render.reasons == ["analyst_request"]
    fact = render_fact(store, case_id)
    assert fact["status"] == "ok" and fact["attempt_counts"]["downloads"] == 0
    assert "sunrise-yoga-studio.test" in b.render.request_hosts
    # The page's https://js.stripe.com/v3/ is no lab host: the lab sandbox proxy
    # refuses the tunnel, so the request fails without a response.
    outside = [q for q in fact["requests"] if q["host"] != "sunrise-yoga-studio.test"]
    assert all(q["failure"] and q["status"] is None for q in outside), outside
    want = expected("unrelated-yoga")  # rendering does not change the outcome
    assert r.result.category == want["category"] and r.result.priority in want["priority"]


def test_with_budget_zero_the_request_is_refused_and_nothing_renders(requested):
    store, case_id = requested[0]
    b = load_case(store.conn, case_id).bundle
    assert b.render.status == "not_triggered"
    assert b.render.skipped == "analyst_budget_exhausted"
    jobs = store.conn.execute("SELECT COUNT(*) FROM jobs WHERE stage = 'render'").fetchone()[0]
    assert jobs == 0


def render_fact(store, case_id) -> dict:
    row = store.conn.execute(
        "SELECT value_json FROM facts WHERE case_id = ? AND name = 'browser_render'"
        " ORDER BY id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    assert row, f"case {case_id} was not rendered"
    return json.loads(row[0])


def expected(site: str) -> dict:
    return lab_site(site)[0]["expected"]


def outcome(store, cases, site):
    r = load_case(store.conn, cases[site])
    want = expected(site)
    assert r.result.category == want["category"], (site, r.result.category, r.result.reasons)
    assert r.result.priority in want["priority"], (site, r.result.priority)
    for label in want["labels"]:
        assert label in r.result.labels, (site, label, r.result.labels)
    return r


def test_ae10_js_login_renders_its_credential_form(demo):
    store, cases = demo
    r = outcome(store, cases, "js-login")
    b = r.bundle
    assert b.render.status == "complete" and "js_shell" in b.render.reasons
    assert b.render.content_source == "rendered" and b.credential.password_fields == 1
    assert "credential_form_brand" in {x.rule for x in r.result.reasons}


def test_js_payment_renders_card_fields_gateway_requests_and_the_upi_qr(demo):
    store, cases = demo
    r = outcome(store, cases, "js-payment")
    b = r.bundle
    assert b.payment.card_fields >= 3
    paths = {
        q["url"].rsplit("/", 1)[-1] for q in render_fact(store, cases["js-payment"])["requests"]
    }
    assert "paylumen-checkout.js" in paths  # the gateway-like script, in the network log
    assert "pay-luminafoundation.test" in b.render.request_hosts
    shot = b.render.screenshot["sha256"]
    upi = [o for o in b.payment.observations if o.kind == "upi" and o.image_sha256 == shot]
    assert upi and upi[0].source == "qr_code", b.payment.observations


def test_ae13_image_only_appeal_is_read_from_its_images(demo):
    store, cases = demo
    r = outcome(store, cases, "image-only")
    b = r.bundle
    assert any("Lumina" in t["text"] for t in b.visual.ocr_text)
    assert b.visual.qr_payloads


def test_copied_assets_clone_keeps_its_logo_match_when_rendered(demo):
    store, cases = demo
    r = outcome(store, cases, "copied-assets")
    assert any(m.role != "screenshot" for m in r.bundle.visual.matches)


def test_ae17_cloaking_site_is_rendered_and_scored_on_the_donation_page(demo):
    store, cases = demo
    r = outcome(store, cases, "cloaking")
    b = r.bundle
    assert b.cloaking["suspected"] and b.cloaking["score_on"] == "rendered"
    assert "Festival Gift" in (b.page.title or "")
    assert "cloaking_suspected" in {x.rule for x in r.result.reasons}


def test_the_malicious_redirect_site_reaches_its_outcome_when_rendered(demo):
    # Its JS redirect to the metadata address, refused at the proxy and recorded in
    # the network log, is proven on the real browser in
    # tests/integration/test_browser_client.py::test_redirects_to_metadata_...
    store, cases = demo
    r = outcome(store, cases, "redirects")
    assert r.bundle.render.status == "complete"


def test_no_lab_render_clicked_typed_submitted_or_downloaded(demo):
    store, cases = demo
    for site, case_id in cases.items():
        fact = render_fact(store, case_id)
        assert fact["status"] == "ok", (site, fact.get("reason"))
        assert fact["attempt_counts"] == {
            "blocked_requests": 0, "dialogs": 0, "popups": 0, "downloads": 0, "websockets": 0,
        }, site  # fmt: skip
        assert {q["method"] for q in fact["requests"]} <= {"GET"}, site


# --- AE18: the application killed during a browser job ------------------------------

CRASHING_SERVICE = """
import asyncio, sys
from pathlib import Path
from brandsentinel.config import load_config
from brandsentinel.discovery.submit import submit
from brandsentinel.matching.matcher import Matcher
from brandsentinel.pipeline.orchestrator import run_service
from brandsentinel.registry.loader import load_registry
from brandsentinel.store import open_store
config = load_config(Path(sys.argv[1]))
registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
store = open_store(config)
print(submit(store, Matcher(registry), sys.argv[2]).case_id, flush=True)
asyncio.run(run_service(store, registry, certstream_enabled=False, dnstwist_enabled=False,
                        stop=asyncio.Event()))
"""


def test_ae18_a_browser_container_orphaned_by_a_crash_is_removed_before_the_retry(docker, tmp_path):
    limits = {"wall_seconds": 35}
    config = lab_config(tmp_path / "data", navigation_timeout_seconds=3, settle_seconds=1)
    config = config.model_copy(
        update={
            "browser": config.browser.model_copy(
                update={"limits": config.browser.limits.model_copy(update=limits)}
            )
        }
    )
    path = tmp_path / "lab.yaml"
    path.write_text(yaml.safe_dump(json.loads(config.model_dump_json())))
    url = "http://go-luminafoundation.test/stall.html"  # never settles: only the wall ends it
    app = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", textwrap.dedent(CRASHING_SERVICE), str(path), url],
        cwd=REPO, stdout=subprocess.PIPE, text=True, start_new_session=True,
    )  # fmt: skip
    try:
        case_id = int(app.stdout.readline())
        name = f"bs-{INSTANCE}-browser-render-{case_id}-r0-1"
        wait_running(docker, name, timeout=120)
        os.killpg(app.pid, signal.SIGKILL)  # the app and its docker CLI die at once
        app.wait()
        assert name in labelled(docker)  # the browser container outlived the application
    finally:
        if app.poll() is None:
            os.killpg(app.pid, signal.SIGKILL)

    store = open_store(config)
    registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
    store.registry = registry
    store.jobs._clock = lambda: time.time() + 400  # past the render lease
    seen_at_recovery = []
    real_recover = store.jobs.recover_expired

    def recover():
        seen_at_recovery.append(labelled(docker))
        return real_recover()

    store.jobs.recover_expired = recover
    settle(store, stop_after=180)
    assert seen_at_recovery and seen_at_recovery[0] == []  # removed before leases recovered
    (attempts,) = store.conn.execute(
        "SELECT attempts FROM jobs WHERE dedupe_key = ?", (f"render:case:{case_id}:r0",)
    ).fetchone()
    assert attempts == 2  # the killed run, then exactly one retry
    fact = render_fact(store, case_id)
    assert (fact["status"], fact["reason"]) == ("failed", "sandbox_timeout")
    assert [r["name"] for r in fact["runs"]] == [f"bs-{INSTANCE}-browser-render-{case_id}-r0-2"]
    b = load_case(store.conn, case_id).bundle
    assert b.render.status == "failed" and b.http.fetched  # the static evidence stays
    store.close()
    assert labelled(docker) == []
