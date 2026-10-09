"""dnstwist runner: safe subprocess, sized timeouts, schedule, history, failure isolation."""

import asyncio
import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from brandsentinel.config import DiscoverySettings, DnstwistSettings
from brandsentinel.discovery.dnstwist_runner import (
    FORBIDDEN_FLAGS,
    DnstwistRunner,
    SweepError,
    run_capped,
)
from brandsentinel.discovery.events import DISCOVERY_LOG
from brandsentinel.pipeline import health
from brandsentinel.registry.model import Registry
from brandsentinel.store.rawlog import read_segment

FIXTURE = Path(__file__).parent / "fixtures" / "dnstwist_output.json"


@pytest.fixture
def registry(registry_data):
    return Registry.model_validate(registry_data)


def with_dnstwist(config, **kw):
    settings = DnstwistSettings(**{"dictionary": None, **kw})
    return config.model_copy(
        update={
            "discovery": DiscoverySettings(
                certstream=config.discovery.certstream, dnstwist=settings
            )
        }
    )


class FakeDnstwist:
    """Stands in for run_capped: answers the count and scan calls per target."""

    def __init__(self, scans=None, count=100):
        self.scans = scans or {}
        self.count = count
        self.calls = []

    async def __call__(self, argv, *, timeout, max_bytes):
        self.calls.append((argv, timeout))
        target = argv[-1]
        if "list" in argv:
            return 0, ("\n".join([target] + ["x.com"] * self.count)).encode(), b""
        result = self.scans.get(target, [])
        if isinstance(result, Exception):
            raise result
        return 0, json.dumps(result).encode(), b""


def make_runner(store, matcher, registry, clock, fake, **settings):
    cfg = with_dnstwist(store.config, binary=sys.executable, **settings)
    return DnstwistRunner(store, matcher, registry, cfg, clock=clock, runner=fake)


def fixture_records():
    return json.loads(FIXTURE.read_text())


def runs(store):
    return store.conn.execute("SELECT * FROM discovery_runs ORDER BY id").fetchall()


def test_targets_are_every_confirmed_or_legacy_unverified_official_domain(
    store, matcher, registry, clock
):
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist())
    expected = sorted(
        d.name
        for d in registry.domains
        if d.kind == "official" and d.status in ("confirmed", "legacy-unverified")
    )
    assert runner.targets() == expected
    assert "savesoil.org" not in runner.targets()  # candidate status
    assert {"isha.in", "sadhguru.org", "ishafoundation.org"} <= set(runner.targets())


def test_sweep_wraps_records_with_provenance_and_skips_original(store, matcher, registry, clock):
    fake = FakeDnstwist({"sadhguru.org": fixture_records()})
    runner = make_runner(store, matcher, registry, clock, fake)
    result = asyncio.run(runner.sweep("sadhguru.org"))
    assert result.status == "ok"
    store.rawlog(DISCOVERY_LOG).flush()
    records = [r["record"] for s in store.rawlog(DISCOVERY_LOG).segments() for r in read_segment(s)]
    names = {r["name"] for r in records}
    assert "sadhguru.org" not in names  # *original excluded
    assert names == {"sadhgurru.org", "sadhguru.com", "sadhguru-login.org"}
    r = next(r for r in records if r["name"] == "sadhguru.com")
    assert r["source"] == "dnstwist"
    assert r["context"]["target"] == "sadhguru.org"
    assert r["context"]["fuzzer"] == "tld-swap"
    assert r["context"]["dns"]["dns_a"] == ["203.0.113.7"]
    assert r["observed_at"].endswith("Z")  # UTC
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 3


def test_command_line_is_safe(store, matcher, registry, clock, tmp_path):
    dictionary = tmp_path / "words.dict"
    dictionary.write_text("login\n")
    fake = FakeDnstwist({"isha.in": []})
    runner = make_runner(store, matcher, registry, clock, fake, dictionary=dictionary)
    asyncio.run(runner.sweep("isha.in"))
    for argv, _ in fake.calls:
        assert not FORBIDDEN_FLAGS.intersection(argv)
        assert argv[-2:] == ["--", "isha.in"]
        assert ["--dictionary", str(dictionary)] == argv[argv.index("--dictionary") :][:2]
    scan = fake.calls[1][0]
    assert "--registered" in scan and scan[scan.index("--format") + 1] == "json"


def test_forbidden_flags_are_refused_before_spawning():
    with pytest.raises(ValueError, match="refusing"):
        asyncio.run(run_capped(["dnstwist", "--lsh", "x.com"], timeout=1, max_bytes=10))


def test_timeout_grows_with_permutations_and_respects_floor_and_cap(
    store, matcher, registry, clock
):
    runner = make_runner(
        store,
        matcher,
        registry,
        clock,
        FakeDnstwist(),
        timeout_floor_seconds=100,
        resolution_rate_per_second=10,
        timeout_max_seconds=1000,
    )
    assert runner.timeout_for(0) == 100
    assert runner.timeout_for(500) == 150
    assert runner.timeout_for(10**6) == 1000


def test_one_target_failing_does_not_affect_others(store, matcher, registry, clock):
    fake = FakeDnstwist(
        {"isha.in": SweepError("timeout", "timed out after 9s"), "sadhguru.org": fixture_records()}
    )
    runner = make_runner(store, matcher, registry, clock, fake)
    bad = asyncio.run(runner.sweep("isha.in"))
    good = asyncio.run(runner.sweep("sadhguru.org"))
    assert (bad.status, good.status) == ("timeout", "ok")
    statuses = {r["target"]: r["status"] for r in runs(store)}
    assert statuses == {"isha.in": "timeout", "sadhguru.org": "ok"}
    assert json.loads(runs(store)[0]["detail_json"])["error"] == "timed out after 9s"


def test_two_consecutive_timeouts_mark_target_unhealthy(store, matcher, registry, clock):
    fake = FakeDnstwist({"isha.in": SweepError("timeout", "slow")})
    runner = make_runner(store, matcher, registry, clock, fake)
    asyncio.run(runner.sweep("isha.in"))
    assert health.collect(store, store.config, clock()).unhealthy_targets == []
    clock.advance(86400)
    asyncio.run(runner.sweep("isha.in"))
    assert health.collect(store, store.config, clock()).unhealthy_targets == ["isha.in"]


def test_too_many_permutations_refuses_the_scan(store, matcher, registry, clock):
    fake = FakeDnstwist(count=500)
    runner = make_runner(store, matcher, registry, clock, fake, max_permutations=100)
    assert asyncio.run(runner.sweep("isha.in")).status == "too_large"
    assert len(fake.calls) == 1  # only the count ran


def test_missing_binary_is_recorded_as_unavailable(store, matcher, registry, clock):
    cfg = with_dnstwist(store.config, binary="/nonexistent/dnstwist")
    runner = DnstwistRunner(store, matcher, registry, cfg, clock=clock, runner=FakeDnstwist())
    r = asyncio.run(runner.sweep("isha.in"))
    assert r.status == "unavailable" and "not found" in r.error


def test_second_run_reports_exactly_the_new_domains(store, matcher, registry, clock):
    records = fixture_records()
    fake = FakeDnstwist({"sadhguru.org": records})
    runner = make_runner(store, matcher, registry, clock, fake)
    first = asyncio.run(runner.sweep("sadhguru.org"))
    assert first.new == ()  # nothing to compare with yet
    clock.advance(86400)
    fake.scans["sadhguru.org"] = [*records, {"fuzzer": "hyphenation", "domain": "sadh-guru.org"}]
    second = asyncio.run(runner.sweep("sadhguru.org"))
    assert second.new == ("sadh-guru.org",)
    # Repeat sightings are observations of existing candidates, not new cases.
    assert store.conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 4
    obs = store.conn.execute(
        "SELECT observations FROM candidate_sources cs JOIN candidates c ON c.id = cs.candidate_id"
        " WHERE c.name = 'sadhguru.com'"
    ).fetchone()[0]
    assert obs == 2


def test_schedule_survives_restart_without_repeating_or_skipping(store, matcher, registry, clock):
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist())
    assert runner.next_due("isha.in") == 0  # never swept: due now
    asyncio.run(runner.sweep("isha.in"))
    restarted = make_runner(store, matcher, registry, clock, FakeDnstwist())
    clock.advance(3600)
    assert restarted.next_due("isha.in") > clock()
    clock.advance(23 * 3600)
    assert restarted.next_due("isha.in") <= clock()


def test_crashed_sweep_is_abandoned_and_retried_sooner(store, matcher, registry, clock):
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist())
    started = clock() - runner.max_wall_seconds() - 1
    store.conn.execute(
        "INSERT INTO discovery_runs (source, target, started_at, status) VALUES"
        " ('dnstwist', 'isha.in', ?, 'running')",
        (started,),
    )
    assert runner.recover_abandoned() == 1
    assert runner.next_due("isha.in") <= clock() + 3600


def test_live_sweep_from_another_process_is_not_abandoned_or_duplicated(
    store, matcher, registry, clock
):
    store.conn.execute(
        "INSERT INTO discovery_runs (source, target, started_at, status) VALUES"
        " ('dnstwist', 'isha.in', ?, 'running')",
        (clock() - 60,),
    )
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist())
    assert runner.recover_abandoned() == 0
    assert runner.next_due("isha.in") > clock()


def test_partial_sweep_waits_a_full_interval(store, matcher, registry, clock):
    store.conn.execute(
        "INSERT INTO discovery_runs (source, target, started_at, finished_at, status) VALUES"
        " ('dnstwist', 'isha.in', ?, ?, 'partial')",
        (clock(), clock()),
    )
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist())
    assert runner.next_due("isha.in") == clock() + 24 * 3600


def test_malformed_records_are_skipped_and_rest_persisted(store, matcher, registry, clock, caplog):
    records = [*fixture_records(), "junk", {"domain": 5}, {"domain": "bad..name", "fuzzer": "x"}]
    runner = make_runner(store, matcher, registry, clock, FakeDnstwist({"sadhguru.org": records}))
    assert asyncio.run(runner.sweep("sadhguru.org")).status == "ok"
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 3
    assert any("skipped malformed" in r.message for r in caplog.records)


def test_ingest_failure_on_one_record_keeps_the_batch(store, matcher, registry, clock, monkeypatch):
    import brandsentinel.discovery.dnstwist_runner as dr

    real = dr.ingest

    def flaky(store_, matcher_, ev, **kw):
        if ev.name == "sadhguru.com":
            raise RuntimeError("boom")
        return real(store_, matcher_, ev, **kw)

    monkeypatch.setattr(dr, "ingest", flaky)
    runner = make_runner(
        store, matcher, registry, clock, FakeDnstwist({"sadhguru.org": fixture_records()})
    )
    r = asyncio.run(runner.sweep("sadhguru.org"))
    assert r.status == "partial"
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 2


def test_unparseable_output_is_an_error(store, matcher, registry, clock):
    class Garbage(FakeDnstwist):
        async def __call__(self, argv, *, timeout, max_bytes):
            if "list" in argv:
                return 0, b"isha.in\n", b""
            return 0, b"{not json", b""

    runner = make_runner(store, matcher, registry, clock, Garbage())
    assert asyncio.run(runner.sweep("isha.in")).status == "error"


# --- real subprocess -------------------------------------------------------------


def fake_binary(tmp_path: Path, body: str) -> str:
    path = tmp_path / "fake-dnstwist"
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_run_capped_kills_the_process_group_on_timeout(tmp_path):
    marker = tmp_path / "child.pid"
    binary = fake_binary(
        tmp_path,
        f"""
        import subprocess, sys, time
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        open({str(marker)!r}, "w").write(str(child.pid))
        time.sleep(60)
    """,
    )
    with pytest.raises(SweepError) as e:
        asyncio.run(run_capped([binary, "--", "x.com"], timeout=1.0, max_bytes=1000))
    assert e.value.status == "timeout"
    pid = int(marker.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        asyncio.run(asyncio.sleep(0.05))
    else:
        pytest.fail("grandchild survived the timeout")


def test_run_capped_rejects_oversized_output(tmp_path):
    binary = fake_binary(tmp_path, "import sys; sys.stdout.write('x' * 100000)")
    with pytest.raises(SweepError, match="exceeded"):
        asyncio.run(run_capped([binary], timeout=10, max_bytes=1000))


def test_real_subprocess_sweep_end_to_end(store, matcher, registry, clock, tmp_path):
    out = json.dumps(fixture_records())
    binary = fake_binary(
        tmp_path,
        f"""
        import os, sys
        assert "--" in sys.argv and sys.stdin.read() == ""
        assert "AWS_SECRET_ACCESS_KEY" not in os.environ
        if "list" in sys.argv:
            print("sadhguru.org"); print("a.org"); print("b.org")
        else:
            sys.stdout.write({out!r})
    """,
    )
    os.environ["AWS_SECRET_ACCESS_KEY"] = "should-not-leak"  # noqa: S105
    try:
        cfg = with_dnstwist(store.config, binary=binary)
        runner = DnstwistRunner(store, matcher, registry, cfg, clock=clock)
        r = asyncio.run(runner.sweep("sadhguru.org"))
    finally:
        del os.environ["AWS_SECRET_ACCESS_KEY"]
    assert (r.status, r.permutations, r.registered) == ("ok", 2, 3), r.error


def test_nonzero_exit_records_stderr(store, matcher, registry, clock, tmp_path):
    binary = fake_binary(tmp_path, "import sys; sys.stderr.write('resolver exploded'); sys.exit(3)")
    cfg = with_dnstwist(store.config, binary=binary)
    r = asyncio.run(DnstwistRunner(store, matcher, registry, cfg, clock=clock).sweep("isha.in"))
    assert r.status == "error" and "resolver exploded" in r.error
