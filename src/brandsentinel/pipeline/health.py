"""Discovery health for `status`: source liveness, coverage gaps, sweeps, disk."""

import json
from dataclasses import dataclass, field

from brandsentinel.config import Config
from brandsentinel.discovery import certstream, dnstwist_runner
from brandsentinel.discovery.events import get_state
from brandsentinel.store import Store
from brandsentinel.store.retention import free_bytes


@dataclass
class SweepStatus:
    target: str
    status: str
    started_at: float
    registered: int | None
    new_count: int | None
    error: str | None


@dataclass
class DiscoveryHealth:
    certstream_enabled: bool
    certstream_last_message_at: float | None
    certstream_stale: bool
    certstream_counters: dict
    open_gaps_seconds_24h: float
    recent_gaps: list[dict] = field(default_factory=list)
    dnstwist_enabled: bool = False
    sweeps: list[SweepStatus] = field(default_factory=list)
    unhealthy_targets: list[str] = field(default_factory=list)
    candidates_by_source: dict[str, int] = field(default_factory=dict)
    candidates_total: int = 0
    free_disk_bytes: int = 0
    low_disk: bool = False


def collect(store: Store, config: Config, now: float) -> DiscoveryHealth:
    conn = store.conn
    cs = config.discovery.certstream
    state = get_state(conn, certstream.SOURCE)
    last = state.get("last_message_at")
    stale = cs.enabled and (last is None or now - last > cs.stale_after_seconds)

    gaps = [
        dict(r)
        for r in conn.execute(
            "SELECT started_at, ended_at, reason, detail_json FROM coverage_gaps"
            " WHERE source = ? ORDER BY started_at DESC LIMIT 5",
            (certstream.SOURCE,),
        )
    ]
    for g in gaps:
        g["detail"] = json.loads(g.pop("detail_json"))
    day_ago = now - 86400
    gap_seconds = conn.execute(
        "SELECT COALESCE(SUM(MIN(COALESCE(ended_at, ?), ?) - MAX(started_at, ?)), 0)"
        " FROM coverage_gaps WHERE source = ? AND COALESCE(ended_at, ?) > ?",
        (now, now, day_ago, certstream.SOURCE, now, day_ago),
    ).fetchone()[0]
    if stale and last is not None:  # currently down: the open interval counts too
        gap_seconds += now - max(last, day_ago)

    sweeps = []
    for r in conn.execute(
        "SELECT target, status, started_at, detail_json FROM discovery_runs d"
        " WHERE source = ? AND id = (SELECT MAX(id) FROM discovery_runs"
        " WHERE source = d.source AND target = d.target) ORDER BY target",
        (dnstwist_runner.SOURCE,),
    ):
        detail = json.loads(r["detail_json"])
        sweeps.append(
            SweepStatus(
                r["target"],
                r["status"],
                r["started_at"],
                detail.get("registered"),
                detail.get("new_count"),
                detail.get("error"),
            )
        )
    unhealthy = [
        r[0]
        for r in conn.execute(
            "SELECT target FROM discovery_runs d WHERE source = ? AND status = 'timeout'"
            " AND id IN (SELECT id FROM discovery_runs WHERE source = d.source"
            " AND target = d.target AND status != 'running' ORDER BY id DESC LIMIT 2)"
            " GROUP BY target HAVING COUNT(*) = 2",
            (dnstwist_runner.SOURCE,),
        )
    ]
    by_source = dict(
        conn.execute("SELECT source, COUNT(*) FROM candidate_sources GROUP BY source").fetchall()
    )
    free = free_bytes(config.data_dir)
    return DiscoveryHealth(
        certstream_enabled=cs.enabled,
        certstream_last_message_at=last,
        certstream_stale=stale,
        certstream_counters=state.get("counters", {}),
        open_gaps_seconds_24h=gap_seconds,
        recent_gaps=gaps,
        dnstwist_enabled=config.discovery.dnstwist.enabled,
        sweeps=sweeps,
        unhealthy_targets=unhealthy,
        candidates_by_source=by_source,
        candidates_total=conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0],
        free_disk_bytes=free,
        low_disk=free < config.rawlog.min_free_bytes,
    )
