"""M6 demo on the controlled lab (U16, U17; markers lab, docker).

The real service in lab mode: the reference corpus is collected from the pinned
lab logo by `registry collect`'s collector with the real media container, every
lab site is submitted, fetched through the lab proxy, its selected images are
fetched the same way and analyzed in network-less media containers, and cases
are scored. The copied-assets clone must show a logo match with its reference
source; the image-only appeal must be found through OCR and its QR code; hard
negatives must not match. Needs a sandbox image built from this tree."""

import asyncio
import time

import pytest
from tests.detection_support import lab_site, lab_sites
from tests.docker_support import REPO, compose, labelled, runtime_or_skip, wait_running

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
from brandsentinel.triage.report import render_case_html
from brandsentinel.visual.collector import Collector

pytestmark = [pytest.mark.lab, pytest.mark.docker]


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    for name in ("bs-lab-web", "bs-lab-proxy"):
        wait_running(d, name)
    config = load_config(REPO / "config" / "lab.yaml")
    config = config.model_copy(update={"data_dir": tmp_path_factory.mktemp("media-demo")})
    assert config.sandbox.enabled and config.sandbox.network != "bs_sandbox"
    registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
    store = open_store(config)

    runner, report = asyncio.run(hostile_content_runtime(config))
    assert runner is not None, report.reasons()
    _, fetcher = build_network(config)
    collected = asyncio.run(
        Collector(
            store.conn,
            registry,
            fetcher,
            MediaClient(runner, config.media),
            config.media,
            config.registry_path.parent / "assets",
            providers=ProviderCatalog.load(config.analysis.payment_providers),
        ).collect()
    )
    assert collected.added + collected.unchanged == 1, collected

    matcher = Matcher(registry)
    sites = {}
    for site in lab_sites():
        expected, _ = lab_site(site)
        sites[site] = (expected, submit(store, matcher, expected["url"]).case_id)

    def settled() -> bool:
        pending = store.conn.execute(
            "SELECT COUNT(*) FROM cases WHERE score_id IS NULL"
        ).fetchone()[0]
        # Media and (M7) render jobs: lab mode renders sampled and triggered cases.
        sandbox_jobs = store.conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE stage IN ('media', 'render')"
            " AND status IN ('pending', 'running')"
        ).fetchone()[0]
        return not pending and not sandbox_jobs

    async def main() -> None:
        stop = asyncio.Event()

        async def watch() -> None:
            deadline = time.monotonic() + 300
            await asyncio.sleep(1)
            while time.monotonic() < deadline and not settled():
                await asyncio.sleep(0.5)
            stop.set()

        watcher = asyncio.create_task(watch())
        orch = await run_service(
            store, registry, certstream_enabled=False, dnstwist_enabled=False, stop=stop
        )
        await watcher
        assert orch.sandbox is not None, orch.sandbox_disabled
        assert "media" in orch.stages

    asyncio.run(main())
    yield store, sites, d
    store.close()


def report(demo, site):
    store, sites, _ = demo
    return load_case(store.conn, sites[site][1])


def test_every_triggered_media_job_ran_in_a_removed_container(demo):
    store, _, d = demo
    statuses = store.conn.execute("SELECT status FROM jobs WHERE stage = 'media'").fetchall()
    assert statuses and all(s[0] == "done" for s in statuses), statuses
    assert labelled(d, "lab") == []


def test_copied_assets_site_shows_a_logo_match_with_its_reference_source(demo):
    """M6 demo: the copied-assets lab site's report shows a logo match with its
    reference source."""
    r = report(demo, "copied-assets")
    want = lab_site("copied-assets")[0]["expected"]
    (m,) = [m for m in r.bundle.visual.matches if m.role == "logo"]
    assert m.method == "perceptual" and m.phash_distance <= 10
    assert m.reference["asset_id"] == "lumina-logo"
    assert m.reference["source"] == "registry/assets/lab/lumina-logo.png"
    assert "copied_asset_match" in {x.rule for x in r.result.reasons}
    assert r.result.priority in want["priority"] and r.result.category == want["category"]
    html = render_case_html(r)
    assert "registry/assets/lab/lumina-logo.png" in html and "copied_asset_match" in html


def test_image_only_appeal_is_found_through_ocr_and_its_qr_code(demo):
    """FA4 and AE13's media half: brand and appeal exist only inside images."""
    r = report(demo, "image-only")
    want = lab_site("image-only")[0]["expected"]
    v = r.bundle.visual
    assert "image_only" in v.reasons and v.status == "complete"
    assert "lumina-foundation" in v.ocr_presented
    assert any("Lumina Foundation" in t["text"] for t in v.ocr_text)
    qr = [o for o in r.bundle.payment.observations if o.source == "qr_code"]
    assert qr and qr[0].payee_identifier == "rivers.relief.fund@quickpaybank"
    assert r.result.category == want["category"] and r.result.priority in want["priority"]


def test_donation_fraud_qr_code_is_decoded(demo):
    r = report(demo, "donation-fraud")
    payloads = [q["text"] for q in r.bundle.visual.qr_payloads]
    assert any(p.startswith("upi://pay?pa=rivers.relief.fund@quickpaybank") for p in payloads)
    assert r.result.category == "donation_fraud"


@pytest.mark.parametrize("site", ["unrelated-tourism", "news-critical", "parody", "unrelated-yoga"])
def test_hard_negatives_do_not_match_and_keep_their_outcome(demo, site):
    r = report(demo, site)
    want = lab_site(site)[0]["expected"]
    assert r.bundle.visual.matches == []
    assert r.result.priority in want["priority"] and r.result.category == want["category"]


def test_tourism_sun_logo_was_examined_and_did_not_match(demo):
    v = report(demo, "unrelated-tourism").bundle.visual
    (sun,) = [i for i in v.images if i.ref.endswith("/static/valley-sun.png")]
    assert sun.status == "ok" and v.matches == []


def test_official_site_images_are_not_collected(demo):
    v = report(demo, "official").bundle.visual
    assert v.status == "not_triggered" and v.skipped == "official_domain"


STATIC = [s for s in lab_sites() if lab_site(s)[0]["detected_by"] == "static"]


@pytest.mark.parametrize("site", STATIC)
def test_static_sites_still_reach_their_expected_outcomes(demo, site):
    r = report(demo, site).result
    want = lab_site(site)[0]["expected"]
    assert r.priority in want["priority"] and r.category == want["category"], (site, r.summary)
