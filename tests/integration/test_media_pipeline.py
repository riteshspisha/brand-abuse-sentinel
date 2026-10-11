"""Conditional image collection, media analysis and visual matching through the
queue (U16, U17): intake -> enrich -> fetch -> media decision -> media stage ->
bundle -> policy, against the local harness. Images are fetched by the hardened
fetcher and analyzed by the real worker code in process (InProcessRunner); the
container itself is covered by tests/integration/test_media_sandbox.py."""

import asyncio
import json

import pytest
from tests import media_support as M
from tests.detection_support import lab_registry
from tests.integration.test_orchestrator import drain
from tests.security.harness import harness_fetcher, harness_stages

from brandsentinel.config import Config, MediaSettings
from brandsentinel.discovery.submit import submit
from brandsentinel.matching.matcher import Matcher
from brandsentinel.pipeline.media import MediaStage
from brandsentinel.pipeline.orchestrator import Orchestrator
from brandsentinel.sandbox import media_fixtures as F
from brandsentinel.sandbox.media_client import MediaClient
from brandsentinel.store import open_store
from brandsentinel.triage import load_case
from brandsentinel.triage.report import render_case_html
from brandsentinel.visual.collector import Collector

ASSETS = M.REPO / "registry" / "assets"


@pytest.fixture
def env(tmp_path, harness, clock):
    config = Config(data_dir=tmp_path / "data", fetch={"retry_delay_seconds": 0})
    store = open_store(config)
    store.jobs._clock = clock
    registry = lab_registry()
    stages = harness_stages(harness, store, registry, clock=clock)
    stages.media_enabled = True
    # The corpus: the lab brand's confirmed, pinned logo.
    collector = Collector(
        store.conn, registry, harness_fetcher(harness),
        MediaClient(M.InProcessRunner(), MediaSettings()), MediaSettings(), ASSETS,
    )  # fmt: skip
    report = asyncio.run(collector.collect())
    assert report.added == 1
    yield store, stages, Matcher(registry), harness
    for k in list(harness.recorder.blobs):
        if k.startswith("mp-"):
            del harness.recorder.blobs[k]
    store.close()


def run(store, stages, until, *, media=True, runner=None, timeout=20):
    orch = Orchestrator(store)
    stages.register(orch)
    if media:
        MediaStage(stages, MediaClient(runner or M.InProcessRunner(), MediaSettings())).register(
            orch
        )
    for s in orch.stages.values():
        s.poll_seconds = 0.01
    drain(orch, until, timeout)
    return orch


def page(h, key: str, html: str) -> str:
    h.recorder.pages[key] = html.encode()
    return f"http://site.harness.test:{h.http.port}/mutable?k={key}"


def blob(h, key: str, data: bytes, ctype="image/png") -> str:
    h.recorder.blobs[key] = (data, ctype)
    return f"/blob?k={key}"


def logo_page(h, key: str, data: bytes, ctype="image/png") -> str:
    """A page presenting the brand in its title, with one logo-like image."""
    img = blob(h, key, data, ctype)
    return page(h, key, f'<title>Lumina Foundation</title><img src="{img}" class="logo">')


def scored(store, case_id):
    return lambda: store.conn.execute(
        "SELECT score_id FROM cases WHERE id = ?", (case_id,)
    ).fetchone()[0]


def media_done(store, case_id):
    return lambda: (
        store.conn.execute(
            "SELECT 1 FROM stage_runs WHERE case_id = ? AND stage = 'media'", (case_id,)
        ).fetchone()
        and store.conn.execute("SELECT score_id FROM cases WHERE id = ?", (case_id,)).fetchone()[0]
    )


def facts(store, case_id, name):
    return [
        (json.loads(r[0]), json.loads(r[1]))
        for r in store.conn.execute(
            "SELECT value_json, artifact_refs FROM facts WHERE case_id = ? AND name = ?"
            " ORDER BY id",
            (case_id, name),
        )
    ]


def hits(h, key):
    return h.recorder.hits.get(f"/blob?k={key}", 0)


def test_copied_logo_is_matched_with_provenance_and_corroborated(env):
    store, stages, matcher, h = env
    logo = blob(h, "mp-logo", M.resized_jpeg(), "image/jpeg")
    url = page(
        h,
        "mp-copy",
        f"""<title>Lumina Foundation - Donations</title>
<header><img src="{logo}" alt="Lumina Foundation" class="site-logo"></header>
<h1>Lumina Foundation</h1><p>Welcome to our programs.</p>""",
    )
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))

    ((decision, _),) = facts(store, case_id, "media_decision")
    assert decision["triggered"] and "brand_related" in decision["reasons"]
    ((analysis, refs),) = facts(store, case_id, "media_analysis")
    logo_img = next(i for i in analysis["images"] if i["role"] == "logo")
    assert logo_img["status"] == "ok" and logo_img["fetch"]["outcome"] == "ok"
    assert logo_img["sha256"] in refs  # stored, quota-checked, referenced
    role = store.conn.execute(
        "SELECT role FROM case_artifacts WHERE sha256 = ?", (logo_img["sha256"],)
    ).fetchone()[0]
    assert role == "image"

    r = load_case(store.conn, case_id)
    v = r.bundle.visual
    assert r.bundle.schema_version == "bundle/3" and v.status in ("complete", "partial")
    (m,) = v.matches
    assert m.method == "perceptual" and m.role == "logo"
    assert m.reference["asset_id"] == "lumina-logo" and m.reference["origin"] == "registry_asset"
    assert v.corpus_entries == 1 and v.corpus_version.startswith("corpus/1:1:")
    assert any(ref.startswith("artifact:") for ref in m.refs)
    reason = next(x for x in r.result.reasons if x.rule == "copied_asset_match")
    assert reason.kind == "abuse" and "the page presents Lumina Foundation" in reason.explanation
    assert any(e.startswith("feature:") for e in reason.evidence)
    assert "visual_match" in r.result.labels
    html = render_case_html(r)
    assert "registry/assets/lab/lumina-logo.png" in html and "perceptual" in html


def test_a_match_alone_is_not_impersonation(env):
    """Hard negative for the policy: the exact logo on an image-only page of an
    unrelated host, with nothing else tying it to the brand."""
    store, stages, matcher, h = env
    url = page(h, "mp-alone", f'<img src="{blob(h, "mp-alone", M.lab_logo())}" alt="">')
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    r = load_case(store.conn, case_id)
    assert [m.method for m in r.bundle.visual.matches] == ["sha256"]
    rules = {x.rule for x in r.result.reasons}
    assert "visual_match_uncorroborated" in rules and "copied_asset_match" not in rules
    assert r.result.priority not in ("P1", "P2")
    assert any(
        "visual match alone is not treated as impersonation" in m for m in r.result.manual_review
    )


def test_screenshot_with_payment_details_yields_an_unconfirmed_brand_payee(env):
    store, stages, matcher, h = env
    url = page(h, "mp-shot", f'<img src="{blob(h, "mp-shot", M.payment_screenshot())}">')
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    r = load_case(store.conn, case_id)
    (upi,) = [o for o in r.bundle.payment.observations if o.source == "qr_code"]
    assert upi.payee_identifier == "rivers.relief.fund@quickpaybank"
    assert upi.attribution == "claims_brand_unconfirmed"  # "Lumina Relief" names the brand
    assert upi.extractor_version == "media_text/1" and any(
        x.startswith("feature:") for x in upi.refs
    )
    assert r.bundle.visual.matches == []  # a screenshot is not the logo
    assert "payment_brand_unconfirmed_payee" in {x.rule for x in r.result.reasons}
    assert r.result.priority in ("P1", "P2")


def test_ae12_bomb_is_recorded_as_media_rejected_and_nothing_turns_benign(env):
    """Covers AE12 in the pipeline: the case records media_rejected and keeps
    its priority; the bomb never reaches this process's decoder."""
    store, stages, matcher, h = env
    bomb = blob(h, "mp-bomb", F.bomb_png(30000))
    url = page(
        h,
        "mp-bomb",
        f"""<title>Lumina Foundation</title>
<img src="{bomb}" alt="Lumina Foundation logo"><h1>Lumina Foundation relief</h1>""",
    )
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    r = load_case(store.conn, case_id)
    v = r.bundle.visual
    (rej,) = [x for x in v.rejected if x["role"] == "logo"]
    assert rej["reason"] == "decompression_bomb"
    assert "media_rejected" in r.bundle.incomplete and "media_rejected" in r.result.labels
    assert any("unknown, not benign" in m for m in r.result.manual_review)
    assert r.result.category != "unrelated"


def test_html_served_as_an_image_is_rejected_or_left_unknown(env):
    store, stages, matcher, h = env
    labelled = blob(h, "mp-html1", F.html_named_png(), "image/png")
    honest = blob(h, "mp-html2", F.html_named_png(), "text/html")
    url = page(
        h,
        "mp-html",
        f"""<title>Lumina Foundation</title>
<img src="{labelled}" class="logo"><img src="{honest}" class="logo">""",
    )
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    imgs = {
        i.ref.rsplit("=", 1)[-1]: i for i in load_case(store.conn, case_id).bundle.visual.images
    }
    assert (imgs["mp-html1"].status, imgs["mp-html1"].reason) == ("rejected", "not_an_image")
    assert imgs["mp-html2"].status == "not_fetched"  # the fetcher kept no body
    assert load_case(store.conn, case_id).bundle.visual.status in ("partial", "failed")


def test_media_pending_while_the_sandbox_is_unavailable_is_not_benign(env):
    store, stages, matcher, h = env
    url = page(h, "mp-pend", f'<img src="{blob(h, "mp-pend", M.payment_screenshot())}">')
    case_id = submit(store, matcher, url).case_id
    run(store, stages, scored(store, case_id), media=False)
    r = load_case(store.conn, case_id)
    assert r.bundle.visual.status == "pending" and "media_pending" in r.bundle.incomplete
    assert "needs_media" in r.result.flags
    assert r.result.priority != "no_action" and r.result.category == "insufficient_evidence"
    assert hits(h, "mp-pend") == 0  # nothing was fetched without the media stage


def test_unrelated_page_triggers_no_image_collection(env):
    store, stages, matcher, h = env
    url = page(
        h,
        "mp-unrel",
        f"""<title>Sunrise Bakery</title><h1>Fresh bread daily</h1>
<p>Open every morning from seven. Our sourdough is baked overnight.</p>
<img src="{blob(h, "mp-unrel", M.lab_logo())}" class="logo">""",
    )
    case_id = submit(store, matcher, url).case_id
    run(store, stages, scored(store, case_id))
    ((decision, _),) = facts(store, case_id, "media_decision")
    assert decision == {**decision, "triggered": False, "skipped": "not_brand_related"}
    assert hits(h, "mp-unrel") == 0
    assert load_case(store.conn, case_id).bundle.visual.status == "not_triggered"


def test_image_at_a_private_address_is_never_fetched(env):
    store, stages, matcher, h = env
    private = f"http://private.harness.test:{h.http.port}/blob?k=mp-x"
    url = page(h, "mp-priv", f'<title>Lumina Foundation</title><img src="{private}" class="logo">')
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    (img,) = [i for i in load_case(store.conn, case_id).bundle.visual.images if i.role == "logo"]
    assert (img.status, img.reason, img.fetch_outcome) == (
        "not_fetched",
        "fetch_blocked",
        "blocked",
    )


def test_redelivered_media_job_records_once(env):
    store, stages, matcher, h = env
    url = logo_page(h, "mp-twice", M.lab_logo())
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    from brandsentinel.store.jobs import Job

    stage = MediaStage(stages, MediaClient(M.InProcessRunner(), MediaSettings()))
    job = Job(
        id=0,
        stage="media",
        queue_class="strong",
        payload={"case_id": case_id, "round": 0},
        attempts=1,
        max_attempts=3,
        lease_owner="t",
        lease_token="t",  # noqa: S106 - not a secret
        lease_expires_at=0.0,
    )
    asyncio.run(stage.run(job))
    assert len(facts(store, case_id, "media_analysis")) == 1


def test_official_domain_is_not_collected():
    from brandsentinel.evidence.bundle import EvidenceBundle, RegistryContext, Subject
    from brandsentinel.pipeline.media import decide

    b = EvidenceBundle(
        subject=Subject(case_id=1, status="open", host="luminafoundation.test"),
        registry=RegistryContext(official_domain="luminafoundation.test"),
    )
    assert decide(b, {}, enabled=True, cap=8)["skipped"] == "official_domain"


def test_bundle_with_media_evidence_rebuilds_identically(env):
    """FA7 with M6 data: the bundle is a pure function of stored records."""
    from brandsentinel.evidence.bundle import bundle_json

    store, stages, matcher, h = env
    url = logo_page(h, "mp-fa7", M.resized_jpeg(), "image/jpeg")
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    first, second = stages.scorer.bundle(case_id), stages.scorer.bundle(case_id)
    assert first.visual.matches and bundle_json(first) == bundle_json(second)


def test_unchanged_recheck_carries_the_media_result_without_refetching(env):
    store, stages, matcher, h = env
    url = logo_page(h, "mp-carry", M.resized_jpeg(), "image/jpeg")
    case_id = submit(store, matcher, url).case_id
    run(store, stages, media_done(store, case_id))
    fetched = hits(h, "mp-carry")
    # Round 1: the same page again (a recheck with no material change).
    case = stages._case(case_id)
    final = facts(store, case_id, "http_fetch")[-1][0]
    from brandsentinel.store.db import transaction

    with transaction(store.conn):
        stages._fact(
            case_id, "fetcher", "http_fetch", {**final, "analysis_round": 1}, "fetcher/1", 1
        )
        stages._fact(case_id, "pipeline", "material_change",
                     {"previous_round": 0, "changed": False, "fields": [], "unknown_fields": []},
                     "fingerprint/1", 1)  # fmt: skip
    stages.decide_media(case, 1)
    decisions = [d for d, _ in facts(store, case_id, "media_decision")]
    assert decisions[-1]["analysis_round"] == 1 and decisions[-1]["carried_from_round"] == 0
    assert not store.conn.execute(
        "SELECT 1 FROM jobs WHERE stage = 'media' AND dedupe_key LIKE ?", (f"%:case:{case_id}:r1",)
    ).fetchone()
    b = stages.scorer.bundle(case_id)
    assert b.http.analysis_round == 1 and b.visual.matches and b.visual.analysis_round == 1
    assert hits(h, "mp-carry") == fetched
