-- Discovery intake (M2). One row per distinct discovery event, keyed by a
-- deterministic event id so replaying the raw log never duplicates anything.

CREATE TABLE discovery_events (
    event_id     TEXT PRIMARY KEY,  -- sha256 over source-specific identity
    source       TEXT NOT NULL,     -- certstream | dnstwist | manual
    name         TEXT NOT NULL,     -- canonical ASCII host
    observed_at  REAL NOT NULL,
    outcome      TEXT NOT NULL CHECK (outcome IN ('candidate', 'suppressed', 'no_match')),
    candidate_id INTEGER REFERENCES candidates (id),
    match_json   TEXT NOT NULL,     -- matcher result, including matcher_version
    context_json TEXT NOT NULL,     -- sanitized source metadata (certificate, fuzzer, ...)
    ingested_at  REAL NOT NULL
);
CREATE INDEX discovery_events_candidate ON discovery_events (candidate_id, observed_at);
CREATE INDEX discovery_events_observed ON discovery_events (observed_at);

-- Which sources have seen a candidate, and how often. One candidate seen by
-- both dnstwist and CertStream has one candidates row and two rows here.
CREATE TABLE candidate_sources (
    candidate_id INTEGER NOT NULL REFERENCES candidates (id),
    source       TEXT NOT NULL,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    observations INTEGER NOT NULL,
    PRIMARY KEY (candidate_id, source)
);

-- At most one open case per candidate.
CREATE UNIQUE INDEX cases_open_candidate ON cases (candidate_id) WHERE status = 'open';

-- Periods a live source was not receiving: events from them are not recoverable.
CREATE TABLE coverage_gaps (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    ended_at    REAL,
    reason      TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX coverage_gaps_source ON coverage_gaps (source, started_at);

-- Small per-source state that must survive restarts (liveness, replay marker).
CREATE TABLE source_state (
    source     TEXT PRIMARY KEY,
    state_json TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX discovery_runs_target ON discovery_runs (source, target, started_at);
