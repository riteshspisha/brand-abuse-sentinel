"""M5 demo on the controlled lab (U15): every lab site is submitted in lab mode,
fetched through the lab proxy by the real service, extracted, scored, reported
and exported. Static sites must reach their expected band, category and labels;
media and browser sites must be reported as not observable, never as benign."""

import asyncio
import csv
import io
import time

import pytest
from tests.detection_support import lab_site, lab_sites
from tests.docker_support import REPO, compose, runtime_or_skip, wait_running

from brandsentinel.config import load_config
from brandsentinel.discovery.submit import submit
from brandsentinel.matching.matcher import Matcher
from brandsentinel.pipeline.orchestrator import run_service
from brandsentinel.registry.loader import load_registry
from brandsentinel.store import open_store
from brandsentinel.triage import list_cases, load_case
from brandsentinel.triage.export import COLUMNS, to_csv
from brandsentinel.triage.report import render_case_html

pytestmark = [pytest.mark.lab, pytest.mark.docker]


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    for name in ("bs-lab-web", "bs-lab-proxy"):
        wait_running(d, name)
    config = load_config(REPO / "config" / "lab.yaml")
    config = config.model_copy(update={"data_dir": tmp_path_factory.mktemp("lab-demo")})
    registry, _ = load_registry(config.registry_path, config.net.lab.registry_overlay)
    store = open_store(config)
    matcher = Matcher(registry)
    sites = {}
    for site in lab_sites():
        expected, _ = lab_site(site)
        sites[site] = (expected, submit(store, matcher, expected["url"]).case_id)

    async def main() -> None:
        stop = asyncio.Event()

        async def watch() -> None:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                pending = store.conn.execute(
                    "SELECT COUNT(*) FROM cases WHERE score_id IS NULL"
                ).fetchone()[0]
                if not pending:
                    break
                await asyncio.sleep(0.2)
            stop.set()

        watcher = asyncio.create_task(watch())
        await run_service(
            store,
            registry,
            certstream_enabled=False,
            dnstwist_enabled=False,
            stop=stop,
            sandbox_enabled=False,
        )
        await watcher

    asyncio.run(main())
    yield store, sites
    store.close()


def test_every_case_was_fetched_through_the_lab_proxy_and_scored(demo):
    store, sites = demo
    for site, (_, case_id) in sites.items():
        r = load_case(store.conn, case_id)
        assert r.result is not None, site
        assert r.bundle.http.outcome == "ok" and r.bundle.http.status == 200, site
        assert r.bundle.http.redirect_chain[0].via == "http://127.0.0.1:3129", site


@pytest.mark.parametrize(
    "site", [s for s in lab_sites() if lab_site(s)[0]["detected_by"] == "static"]
)
def test_static_lab_sites_reach_expected_outcomes(demo, site):
    store, sites = demo
    expected, case_id = sites[site]
    r = load_case(store.conn, case_id).result
    want = expected["expected"]
    assert r.priority in want["priority"] and r.category == want["category"], (site, r.summary)
    for label in want["labels"]:
        assert label in r.labels, (site, label)


@pytest.mark.parametrize(
    "site", [s for s in lab_sites() if lab_site(s)[0]["detected_by"] != "static"]
)
def test_media_and_browser_sites_are_flagged_not_cleared(demo, site):
    store, sites = demo
    r = load_case(store.conn, sites[site][1]).result
    assert r.category not in ("benign_related", "unrelated") and r.priority != "no_action", site


def test_donation_fraud_demo_report_and_csv_row(demo):
    store, sites = demo
    report = load_case(store.conn, sites["donation-fraud"][1])
    p, b = report.result, report.bundle
    assert p.priority in ("P1", "P2") and p.category == "donation_fraud"
    (upi,) = [o for o in b.payment.observations if o.kind == "upi"]
    assert upi.payee_identifier == "rivers.relief.fund@quickpaybank"
    assert upi.attribution == "claims_brand_unconfirmed"
    html = render_case_html(report)
    for text in (
        "rivers.relief.fund@quickpaybank",
        "claims_brand_unconfirmed",
        p.priority,
        "payment_brand_unconfirmed_payee",
        "Content-Security-Policy",
    ):
        assert text in html
    reports = [load_case(store.conn, c.case_id) for c in list_cases(store.conn)]
    rows = list(csv.reader(io.StringIO(to_csv(reports))))
    assert tuple(rows[0]) == COLUMNS and len(rows) == len(sites) + 1
    row = next(
        dict(zip(COLUMNS, r, strict=True))
        for r in rows[1:]
        if r[0] == str(sites["donation-fraud"][1])
    )
    assert row["payee_attribution"] == (
        "rivers.relief.fund@quickpaybank=claims_brand_unconfirmed"
        " | 000123456789=claims_brand_unconfirmed"
    )
