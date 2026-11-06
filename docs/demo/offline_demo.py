"""Deterministic offline demonstration: real pipeline, synthetic pages, no network, no Docker.

What it runs: the production code path for a manual submission (intake, the job queue,
enrichment, the hardened static fetcher with netguard, the extractors, the evidence
bundle and the deterministic policy) on five synthetic lab sites (`labsites/`, the
fictional "Lumina Foundation" brand). What is substituted: the network. Each site's
hostname resolves, through the test suite's local harness (`tests/security/harness.py`),
to a loopback HTTP server that serves the site's committed `index.html`; RDAP and DNS
answers also come from the harness. That substitution is test machinery: the
`brandsentinel` CLI itself cannot fetch from loopback (netguard blocks it) and has no
fixture mode; see docs/guide/demo.md, "Known gaps".

Not demonstrated: discovery (CertStream, dnstwist), media and browser sandboxes, and
anything about real-world detection accuracy. Five synthetic pages are a walkthrough,
not an evaluation.

    uv run python docs/demo/offline_demo.py OUTDIR

OUTDIR must not exist. It receives `data/` (a fresh store) and `demo.yaml` (a config
for the read-only CLI commands printed at the end). Linux only: the harness binds
127.77.0.0/24, which macOS does not route to loopback by default.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))  # tests/ is not installed; the demo reuses its harness

from tests.detection_support import lab_registry, lab_site  # noqa: E402
from tests.security.harness import harness_stages, start_harness  # noqa: E402

from brandsentinel.config import Config  # noqa: E402
from brandsentinel.discovery.submit import submit  # noqa: E402
from brandsentinel.matching.matcher import Matcher  # noqa: E402
from brandsentinel.pipeline.orchestrator import Orchestrator  # noqa: E402
from brandsentinel.store import open_store  # noqa: E402

# Sites whose outcome the static stage decides (labsites/*/expected.yaml `detected_by: static`).
SITES = ("donation-fraud", "false-association", "disguised-credential", "news-critical", "official")
PRODUCTION_DATA = Path("/var/lib/brandsentinel")
TIMEOUT_SECONDS = 60


def refuse(msg: str) -> None:
    print(f"offline_demo: {msg}", file=sys.stderr)
    raise SystemExit(2)


def check_target(out: Path) -> None:
    # Any BRANDSENTINEL_* variable, even empty: two of them redirect stores, and the CLI
    # refuses every other one, so the demo would succeed but its walkthrough would not.
    present = sorted(k for k in os.environ if k.startswith("BRANDSENTINEL_"))
    if present:
        refuse(
            f"{', '.join(present)} set; unset every BRANDSENTINEL_* variable so neither"
            " the demo nor the CLI can reach another store"
        )
    resolved = Path(os.path.abspath(out))
    if resolved == PRODUCTION_DATA or PRODUCTION_DATA in resolved.parents:
        refuse(f"{out} is under {PRODUCTION_DATA}, the production location")
    if out.exists():
        refuse(f"{out} exists; the demo only writes a new directory")


def cli_config(out: Path) -> dict:
    """Lab mode only so the CLI loads the same registry (brands.yaml + the Lumina overlay);
    every network-facing stage is off: these commands only read the demo store."""
    return {
        "data_dir": str(out / "data"),
        "discovery": {"certstream": {"enabled": False}, "dnstwist": {"enabled": False}},
        "net": {"lab": {"enabled": True}},
        "fetch": {"enabled": False},
        "enrich": {"enabled": False},
        "sandbox": {"enabled": False},
        "media": {"enabled": False},
        "browser": {"enabled": False},
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().split("\n\n")[3], file=sys.stderr)
        return 2
    out = Path(argv[0])
    check_target(out)
    out.mkdir(parents=True, mode=0o700)
    (out / "demo.yaml").write_text(
        "# Offline demo store (docs/demo/offline_demo.py). Read-only CLI use only.\n"
        + yaml.safe_dump(cli_config(out), sort_keys=False)
    )

    registry = lab_registry()
    with tempfile.TemporaryDirectory(prefix="bs-demo-harness-") as tmp:
        harness = start_harness(Path(tmp))
        try:
            config = Config(data_dir=out / "data", fetch={"retry_delay_seconds": 0})
            store = open_store(config)
            try:
                stages = harness_stages(harness, store, registry)
                matcher = Matcher(registry)
                cases = {}
                for site in SITES:
                    expected, html = lab_site(site)
                    host = expected["hostname"]
                    harness.dns.set(host, A=["127.77.0.1"])
                    harness.recorder.pages[site] = html
                    url = f"http://{host}:{harness.http.port}/mutable?k={site}"
                    cases[site] = (submit(store, matcher, url).case_id, expected)

                def all_scored() -> bool:
                    ids = [cid for cid, _ in cases.values()]
                    marks = ",".join("?" * len(ids))
                    sql = f"SELECT COUNT(*) FROM cases WHERE id IN ({marks})"  # noqa: S608
                    n = store.conn.execute(sql + " AND priority IS NOT NULL", ids).fetchone()[0]
                    return n == len(ids)

                orch = Orchestrator(store)
                stages.register(orch, enrich=True, fetch=True)

                async def run() -> None:
                    stop = asyncio.Event()

                    async def watch() -> None:
                        deadline = time.monotonic() + TIMEOUT_SECONDS
                        while not all_scored() and time.monotonic() < deadline:
                            await asyncio.sleep(0.05)
                        stop.set()

                    watcher = asyncio.create_task(watch())
                    await orch.run(stop)
                    await watcher

                asyncio.run(run())
                ok = all_scored()
                rows = []
                for site, (cid, expected) in cases.items():
                    prio, cat, score = store.conn.execute(
                        "SELECT c.priority, c.category, s.score FROM cases c LEFT JOIN scores s"
                        " ON s.id = c.score_id WHERE c.id = ?",
                        (cid,),
                    ).fetchone()
                    want = expected["expected"]
                    band = (
                        want["priority"]
                        if isinstance(want["priority"], list)
                        else [want["priority"]]
                    )
                    match = prio in band and cat == want["category"]
                    rows.append(
                        (cid, site, prio, cat, score, "/".join(band), want["category"], match)
                    )
            finally:
                store.close()
        finally:
            harness.close()

    head = ("case", "site", "priority", "category", "score")
    print("{:>4}  {:<22} {:<9} {:<22} {:>5}  expected (labsites)".format(*head))
    for cid, site, prio, cat, score, band, wcat, match in rows:
        mark = "ok" if match else "DIFFERS"
        shown = (cid, site, prio or "-", cat or "-", "-" if score is None else score)
        print("{:>4}  {:<22} {:<9} {:<22} {:>5}  ".format(*shown) + f"{band} {wcat}  [{mark}]")
    if not ok:
        print(f"offline_demo: not every case was scored within {TIMEOUT_SECONDS}s", file=sys.stderr)
        return 1
    cfg = out / "demo.yaml"
    print(f"\nStore: {out / 'data'}\nInspect it (read-only):")
    for cmd in (
        "status",
        "cases list",
        "cases show 1",
        "cases show --json 1",
        "report --index",
        "export csv",
    ):
        print(f"  uv run brandsentinel -c {cfg} {cmd}")
    return 0 if all(r[-1] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
