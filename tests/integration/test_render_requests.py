"""Analyst render requests (M8): `submit --render` through the real chain
(submit -> enrich -> hardened static fetch through netguard -> render decision)
against the local harness. A request binds to exactly one round, never bypasses
the static fetch or the official-domain skip, and spends a daily budget that
concurrent deciders cannot overspend."""

import json
import threading
import time

import pytest
from tests.conftest import build_matcher, confirm_domain
from tests.detection_support import lab_registry, seed_case
from tests.integration.test_analysis_pipeline import run_until, runs
from tests.integration.test_render_pipeline import ScriptedBrowser, ok
from tests.integration.test_render_pipeline import run as run_render
from tests.security.harness import harness_stages

from brandsentinel.config import Config
from brandsentinel.discovery.submit import SubmissionError, request_render, submit
from brandsentinel.pipeline import scheduling
from brandsentinel.pipeline.stages import AnalysisStages, build_network
from brandsentinel.registry.model import Registry
from brandsentinel.sandbox import triggers
from brandsentinel.store import open_store
from brandsentinel.store.db import transaction
from brandsentinel.triage import load_case

SHELL = (
    b'<html><head><title>Loading</title></head><body><div id="app"></div>'
    b'<script src="/app.js"></script></body></html>'
)
RENDERED = (
    "<html><head><title>Garden notes</title></head><body><p>"
    + "Tomatoes and basil along the fence. " * 20
    + "</p></body></html>"
)


def make_env(tmp_path, harness, registry_data, clock, *, budget):
    config = Config(
        data_dir=tmp_path / "data",
        fetch={"retry_delay_seconds": 0},
        browser={"sample_rate": 0.0, "analyst_renders_per_day": budget},
    )
    store = open_store(config)
    store.jobs._clock = clock
    registry = Registry.model_validate(registry_data)
    stages = harness_stages(harness, store, registry, clock=clock)
    return store, stages, build_matcher(registry_data)


@pytest.fixture
def env(tmp_path, harness, registry_data, clock):
    store, stages, matcher = make_env(tmp_path, harness, registry_data, clock, budget=5)
    yield store, stages, matcher, clock
    store.close()


def shell_url(h, key="shell"):
    h.recorder.pages[key] = SHELL
    return f"http://site.harness.test:{h.http.port}/mutable?k={key}"


def decisions(store, case_id=None) -> dict[int, dict]:
    sql = "SELECT case_id, value_json FROM facts WHERE name = 'render_decision' ORDER BY id"
    out = {}
    for cid, v in store.conn.execute(sql):
        if case_id in (None, cid):
            d = json.loads(v)
            out[d["analysis_round"] if case_id else cid] = d
    return out


def render_jobs(store) -> list[str]:
    return [r[0] for r in store.conn.execute("SELECT dedupe_key FROM jobs WHERE stage = 'render'")]


def rechecks(store) -> list[tuple]:
    return [
        tuple(r)
        for r in store.conn.execute(
            "SELECT dedupe_key, not_before, payload_json, reason FROM deferred_jobs ORDER BY 1"
        )
    ]


def test_a_requested_non_brand_js_shell_gets_one_render_job_for_round_0(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, shell_url(harness), render=True)
    assert r.render_request.status == "requested" and r.render_request.round == 0
    run_until(store, stages, lambda: runs(store, "fetch"))
    d = decisions(store, r.case_id)[0]
    assert d["triggered"] and d["reasons"] == ["analyst_request"]
    assert d["analyst_budget_spent"] and d["analyst_renders_per_day"] == 5
    assert render_jobs(store) == [f"render:case:{r.case_id}:r0"]
    assert stages.analyst_renders(stages.clock()) == 1


def test_without_a_request_the_same_page_is_not_rendered_and_says_why(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, shell_url(harness))
    assert r.render_request is None
    run_until(store, stages, lambda: runs(store, "fetch"))
    d = decisions(store, r.case_id)[0]
    assert d["skipped"] == "no_trigger" and "analyst_request" not in d  # as before M8
    assert not render_jobs(store)
    res = load_case(store.conn, r.case_id).result
    assert {"needs_render", "render_not_scheduled"} <= set(res.flags)
    assert any("submit --render" in u for u in res.unknowns)


def test_budget_zero_records_the_refusal_and_schedules_nothing(
    tmp_path, harness, registry_data, clock
):
    store, stages, matcher = make_env(tmp_path, harness, registry_data, clock, budget=0)
    try:
        r = submit(store, matcher, shell_url(harness), render=True)
        run_until(store, stages, lambda: runs(store, "fetch"))
        d = decisions(store, r.case_id)[0]
        assert not d["triggered"] and d["skipped"] == "analyst_budget_exhausted"
        assert d["analyst_request"] and not d["analyst_budget_spent"]
        assert not render_jobs(store)
        res = load_case(store.conn, r.case_id).result
        assert "render_not_scheduled" in res.flags
        assert any("budget is used up (0 per 24 h" in u for u in res.unknowns)
    finally:
        store.close()


def test_a_decided_case_binds_the_request_to_the_next_recheck_without_moving_it(env, harness):
    store, stages, matcher, clock = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    run_until(store, stages, lambda: runs(store, "fetch"))
    assert decisions(store, first.case_id)[0]["skipped"] == "no_trigger"
    before = rechecks(store)

    again = submit(store, matcher, url, render=True)
    req = again.render_request
    assert again.case_id == first.case_id and not again.new_case
    assert req.status == "requested" and req.round == 1 and req.due == before[0][1]
    assert rechecks(store) == before  # no round created, no time moved
    dup = submit(store, matcher, url, render=True).render_request
    assert dup.status == "already_requested" and dup.round == 1
    n = store.conn.execute("SELECT COUNT(*) FROM facts WHERE name = 'render_request'")
    assert n.fetchone()[0] == 1
    assert not render_jobs(store)  # nothing renders before round 1 runs

    clock.advance(86400 + 1)
    scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
    run_until(store, stages, lambda: ("fetch", 1, "ok") in runs(store))
    d1 = decisions(store, first.case_id)[1]
    assert d1["reasons"] == ["analyst_request"] and d1["analyst_budget_spent"]
    assert render_jobs(store) == [f"render:case:{first.case_id}:r1"]

    clock.advance(6 * 86400)  # round 2: the request is not inherited
    scheduling.promote(store.conn, store.jobs, store.config.scheduling, now=clock())
    run_until(store, stages, lambda: ("fetch", 2, "ok") in runs(store))
    d2 = decisions(store, first.case_id)[2]
    assert d2["skipped"] == "no_trigger" and "analyst_request" not in d2
    assert render_jobs(store) == [f"render:case:{first.case_id}:r1"]
    # Every round decided: a further request is refused, not silently dropped.
    late = submit(store, matcher, url, render=True).render_request
    assert late.status == "refused" and "every analysis round" in late.reason


def test_a_pending_request_for_a_later_round_is_shown_on_the_case(env, harness):
    store, stages, matcher, _ = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    run_until(store, stages, lambda: runs(store, "fetch"))
    submit(store, matcher, url, render=True)
    stages.score(first.case_id)
    case = load_case(store.conn, first.case_id)
    assert case.bundle.render.requested_round == 1
    assert "an analyst render is requested for round 1" in case.result.unknowns


def test_a_request_racing_the_decision_binds_to_exactly_one_round(env, harness):
    """The fetch handler decides round 0 while `submit --render` writes: either
    order leaves one request consumed by one decision."""
    store, stages, matcher, _ = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    real = stages.decide_render

    def decide_then_request(case, rnd):
        # The analyst's request arrives just before this round decides.
        submit(store, matcher, url, render=True)
        real(case, rnd)

    stages.decide_render = decide_then_request
    run_until(store, stages, lambda: runs(store, "fetch"))
    stages.decide_render = real
    d = decisions(store, first.case_id)
    assert d[0]["reasons"] == ["analyst_request"]
    reqs = store.conn.execute(
        "SELECT json_extract(value_json, '$.round') FROM facts WHERE name = 'render_request'"
    ).fetchall()
    assert [r[0] for r in reqs] == [0]
    assert render_jobs(store) == [f"render:case:{first.case_id}:r0"]


def test_a_crash_inside_the_decision_leaves_nothing_and_the_retry_spends_once(env, harness):
    store, stages, matcher, _ = env
    r = submit(store, matcher, shell_url(harness), render=True)
    real = stages._schedule
    calls = {"n": 0}

    def crash_once(case, stage, rnd, **kw):
        if stage == "render" and calls["n"] == 0:
            calls["n"] += 1
            raise RuntimeError("power cut")
        return real(case, stage, rnd, **kw)

    stages._schedule = crash_once
    run_until(store, stages, lambda: ("fetch", 0, "ok") in runs(store) and render_jobs(store))
    d = decisions(store, r.case_id)
    assert list(d) == [0] and d[0]["analyst_budget_spent"]
    n = store.conn.execute("SELECT COUNT(*) FROM facts WHERE name = 'render_decision'")
    assert n.fetchone()[0] == 1
    assert render_jobs(store) == [f"render:case:{r.case_id}:r0"]
    assert stages.analyst_renders(stages.clock()) == 1


def test_a_request_never_renders_an_official_domain(env, harness, registry_data, clock):
    store, _, _, _ = env
    confirm_domain(registry_data, "isha.in")
    matcher = build_matcher(registry_data)
    stages = harness_stages(harness, store, Registry.model_validate(registry_data), clock=clock)
    case_id = seed_case(store, SHELL, "http://www.isha.in/", registry=stages.registry)
    with transaction(store.conn):
        request_render(store, case_id, rounds=2, now=clock())
    stages.decide_render(stages._case(case_id), 0)
    d = decisions(store, case_id)[0]
    assert d["skipped"] == "official_domain" and d["analyst_request"]
    assert not d["analyst_budget_spent"] and not render_jobs(store)
    assert matcher.match("www.isha.in").suppressed_by


@pytest.mark.security
@pytest.mark.parametrize(
    "target, stopped_at",
    [
        ("http://private.harness.test/", "fetch"),  # RFC 1918 answer
        ("http://metadata.harness.test/", "fetch"),  # 169.254.169.254
        ("http://loopback6.harness.test/", "fetch"),  # ::1
        ("http://mapped.harness.test/", "fetch"),  # ::ffff:127.0.0.1
        ("http://127.0.0.1/", "submit"),  # IP literals are no domain names
        ("http://[::1]/", "submit"),
        ("http://169.254.169.254/latest/meta-data/", "submit"),
        ("http://site.harness.test:8080/", "fetch"),  # a port outside net.allowed_ports
        ("REDIRECT:http://169.254.169.254/latest/meta-data/", "fetch"),
        ("REDIRECT:http://10.0.0.5/", "fetch"),
        ("REDIRECT:http://127.0.0.1:8080/", "fetch"),
    ],
)
def test_a_request_never_renders_what_the_static_fetch_refused(env, harness, target, stopped_at):
    """The browser renders only a URL the hardened fetcher reached through
    netguard: a request for a private, loopback, metadata or off-port target, or
    one that redirects there, gets no render job (positive control above)."""
    store, stages, matcher, _ = env
    if target.startswith("REDIRECT:"):
        target = f"http://site.harness.test:{harness.http.port}/redirect?to={target[9:]}"
    if stopped_at == "submit":
        with pytest.raises(SubmissionError):
            submit(store, matcher, target, render=True)
        assert not store.conn.execute("SELECT 1 FROM cases").fetchone()
        return
    r = submit(store, matcher, target, render=True)
    run_until(store, stages, lambda: runs(store, "fetch"))
    d = decisions(store, r.case_id)[0]
    assert d["skipped"] == "no_static_response" and not d["triggered"], d
    assert d["analyst_request"] and not d["analyst_budget_spent"]
    assert not render_jobs(store)
    assert stages.analyst_renders(stages.clock()) == 0


@pytest.mark.security
@pytest.mark.parametrize(
    "target",
    ["http://user:pw@site.harness.test/", "https://admin@x.test/", "javascript:alert(1)",
     "file:///etc/passwd", "http://*.example.test/"],
)  # fmt: skip
def test_submit_rejects_credential_urls_and_other_schemes_before_any_request(store, target):
    with pytest.raises(SubmissionError):
        submit(store, _lab_matcher(), target, render=True)
    assert store.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 0


def _lab_matcher():
    from brandsentinel.matching.matcher import Matcher

    return Matcher(lab_registry())


# --- the budget under concurrent deciders ------------------------------------------


def seed_requested(store, n, *, now):
    ids = []
    for i in range(n):
        case_id = seed_case(store, SHELL, f"http://c{i}.sunrise-yoga-studio.test/", now=now)
        with transaction(store.conn):
            assert request_render(store, case_id, rounds=2, now=now).round == 0
        ids.append(case_id)
    return ids


def spent(store) -> int:
    return sum(1 for d in decisions(store).values() if d.get("analyst_budget_spent"))


def test_concurrent_deciders_on_separate_connections_never_overspend(tmp_path, monkeypatch):
    """N+3 requested cases decided at once by 4 threads, each with its own
    connection (as separate processes would): exactly N renders, the rest
    `analyst_budget_exhausted`. A slow decision widens the race window: a count
    read outside the decision's write lock would overspend."""
    budget, workers = 4, 4
    config = Config(data_dir=tmp_path / "data",
                    browser={"sample_rate": 0.0, "analyst_renders_per_day": budget})  # fmt: skip
    main = open_store(config)
    ids = seed_requested(main, budget + 3, now=time.time())
    real = triggers.decide

    def slow_decide(*a, **kw):
        time.sleep(0.05)
        return real(*a, **kw)

    monkeypatch.setattr(triggers, "decide", slow_decide)
    barrier = threading.Barrier(workers)
    errors = []

    def worker(slice_):
        store = open_store(config)
        try:
            guard, fetcher = build_network(config)
            stages = AnalysisStages(store, lab_registry(), guard=guard, fetcher=fetcher)
            barrier.wait()
            for case_id in slice_:
                stages.decide_render(stages._case(case_id), 0)
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)
        finally:
            store.close()

    threads = [threading.Thread(target=worker, args=(ids[i::workers],)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    try:
        assert not errors
        d = decisions(main)
        assert len(d) == len(ids)
        assert spent(main) == budget
        exhausted = [c for c, v in d.items() if v["skipped"] == "analyst_budget_exhausted"]
        assert len(exhausted) == 3
        assert len(render_jobs(main)) == budget
    finally:
        main.close()


def test_the_budget_window_rolls_over_24_hours(tmp_path, clock):
    config = Config(data_dir=tmp_path / "data",
                    browser={"sample_rate": 0.0, "analyst_renders_per_day": 1})  # fmt: skip
    store = open_store(config)
    try:
        guard, fetcher = build_network(config)
        stages = AnalysisStages(store, lab_registry(), guard=guard, fetcher=fetcher, clock=clock)
        a, b, c = seed_requested(store, 3, now=clock())
        stages.decide_render(stages._case(a), 0)
        clock.advance(3600)
        stages.decide_render(stages._case(b), 0)
        clock.advance(23 * 3600 + 1)  # a's render is now more than 24 h old
        stages.decide_render(stages._case(c), 0)
        d = decisions(store)
        assert d[a]["analyst_budget_spent"] and d[c]["analyst_budget_spent"]
        assert d[b]["skipped"] == "analyst_budget_exhausted"
    finally:
        store.close()


def test_a_request_with_another_reason_renders_without_spending(tmp_path, clock):
    """A brand-domain JS shell renders for `js_shell` anyway; the request is
    recorded beside it and the budget (0 here) is not needed."""
    config = Config(data_dir=tmp_path / "data", browser={"sample_rate": 0.0})
    store = open_store(config)
    try:
        guard, fetcher = build_network(config)
        stages = AnalysisStages(store, lab_registry(), guard=guard, fetcher=fetcher, clock=clock)
        case_id = seed_case(store, SHELL, "http://login-luminafoundation.test/", now=clock())
        with transaction(store.conn):
            request_render(store, case_id, rounds=2, now=clock())
        stages.decide_render(stages._case(case_id), 0)
        d = decisions(store)[case_id]
        assert d["triggered"] and d["reasons"][0] == "js_shell"
        assert "analyst_request" in d["reasons"] and not d["analyst_budget_spent"]
        assert stages.analyst_renders(clock()) == 0
    finally:
        store.close()


def test_a_requested_render_completes_with_reason_analyst_request(tmp_path):
    config = Config(data_dir=tmp_path / "data", media={"ocr": False},
                    browser={"sample_rate": 0.0, "analyst_renders_per_day": 1})  # fmt: skip
    store = open_store(config)
    try:
        guard, fetcher = build_network(config)
        stages = AnalysisStages(store, lab_registry(), guard=guard, fetcher=fetcher)
        (case_id,) = seed_requested(store, 1, now=time.time())
        fetch = store.conn.execute("SELECT value_json FROM facts WHERE name = 'http_fetch'")
        url = json.loads(fetch.fetchone()[0])["final_url"]
        stages.decide_render(stages._case(case_id), 0)
        browser = ScriptedBrowser({url: ok(url, RENDERED)})
        run_render(store, stages, browser, lambda: store.conn.execute(
            "SELECT 1 FROM stage_runs WHERE stage = 'render'").fetchone())  # fmt: skip
        b = load_case(store.conn, case_id).bundle
        assert b.render.status == "complete" and b.render.reasons == ["analyst_request"]
        assert [u for u, _ in browser.calls] == [url]  # the URL the static fetch reached, once
    finally:
        store.close()


# --- rounds that can no longer decide (review follow-up) ---------------------------


def test_a_round_fetched_without_a_decision_is_skipped_not_stranded(env, harness):
    """A case analyzed before M7 has a recorded round-0 fetch and no render
    decision: the request goes to the next recheck, which will decide."""
    store, stages, matcher, _ = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    run_until(store, stages, lambda: runs(store, "fetch"))
    store.conn.execute("DELETE FROM facts WHERE name = 'render_decision'")  # as before M7
    req = submit(store, matcher, url, render=True).render_request
    assert req.status == "requested" and req.round == 1 and req.due == rechecks(store)[0][1]
    stages.score(first.case_id)
    assert load_case(store.conn, first.case_id).bundle.render.requested_round == 1


def test_rounds_whose_jobs_failed_for_good_are_refused_explicitly(env, harness):
    store, _, matcher, _ = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    # Round 0's enrichment failed for good, so no recheck was ever scheduled.
    store.conn.execute("UPDATE jobs SET status = 'failed' WHERE stage = 'enrich'")
    req = submit(store, matcher, url, render=True).render_request
    assert req.status == "refused" and "no remaining analysis round" in req.reason
    n = store.conn.execute("SELECT COUNT(*) FROM facts WHERE name = 'render_request'")
    assert n.fetchone()[0] == 0
    with transaction(store.conn):  # a case that does not exist has nothing scheduled
        missing = request_render(store, first.case_id + 99, rounds=2, now=time.time())
    assert missing.status == "refused"


def test_a_stale_request_for_a_dead_round_does_not_hide_a_later_one(env, harness):
    store, stages, matcher, _ = env
    url = shell_url(harness)
    first = submit(store, matcher, url)
    run_until(store, stages, lambda: runs(store, "fetch"))
    store.conn.execute("DELETE FROM facts WHERE name = 'render_decision'")
    with transaction(store.conn):  # a request left on round 0 by an older binding
        from brandsentinel.store.records import add_fact

        add_fact(store.conn, first.case_id, source="analyst", name="render_request",
                 value={"round": 0, "analysis_round": 0}, collector_version="t")  # fmt: skip
    assert submit(store, matcher, url, render=True).render_request.round == 1
    stages.score(first.case_id)
    assert load_case(store.conn, first.case_id).bundle.render.requested_round == 1


def test_the_render_stage_stays_at_one_browser_at_a_time(env):
    from brandsentinel.pipeline.orchestrator import Orchestrator
    from brandsentinel.pipeline.render import RenderStage

    store, stages, _, _ = env
    assert stages.config.stages.render == 1  # analyst requests add no browser concurrency
    orch = Orchestrator(store)
    RenderStage(stages, ScriptedBrowser({}), None).register(orch)
    assert orch.stages["render"].concurrency == 1
