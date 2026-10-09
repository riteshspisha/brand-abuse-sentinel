-- Facts, features and judgments are kept in separate tables so any case can be
-- re-scored from stored facts. Timestamps are UTC epoch seconds (REAL).

CREATE TABLE candidates (
    id                 INTEGER PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,  -- normalized domain or URL host
    registrable_domain TEXT,
    match_strength     TEXT NOT NULL CHECK (match_strength IN ('strong', 'weak')),
    first_seen         REAL NOT NULL,
    last_seen          REAL NOT NULL
);

CREATE TABLE cases (
    id           INTEGER PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES candidates (id),
    subject_url  TEXT,
    status       TEXT NOT NULL DEFAULT 'open',
    priority     TEXT,
    category     TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX cases_candidate ON cases (candidate_id);

CREATE TABLE facts (
    id                INTEGER PRIMARY KEY,
    case_id           INTEGER NOT NULL REFERENCES cases (id),
    source            TEXT NOT NULL,
    name              TEXT NOT NULL,
    value_json        TEXT NOT NULL,
    artifact_refs     TEXT NOT NULL DEFAULT '[]',
    collector_version TEXT NOT NULL,
    observed_at       REAL NOT NULL
);
CREATE INDEX facts_case_name ON facts (case_id, name);

CREATE TABLE features (
    id                INTEGER PRIMARY KEY,
    case_id           INTEGER NOT NULL REFERENCES cases (id),
    name              TEXT NOT NULL,
    value_json        TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    fact_refs         TEXT NOT NULL DEFAULT '[]',
    computed_at       REAL NOT NULL
);
CREATE INDEX features_case_name ON features (case_id, name);

CREATE TABLE judgments (
    id               INTEGER PRIMARY KEY,
    case_id          INTEGER NOT NULL REFERENCES cases (id),
    provider         TEXT NOT NULL,
    model            TEXT NOT NULL,
    question_version TEXT NOT NULL,
    result_json      TEXT NOT NULL,
    latency_ms       REAL,
    truncated        INTEGER NOT NULL DEFAULT 0,
    created_at       REAL NOT NULL
);
CREATE INDEX judgments_case ON judgments (case_id);

CREATE TABLE jobs (
    id               INTEGER PRIMARY KEY,
    stage            TEXT NOT NULL,
    queue_class      TEXT NOT NULL CHECK (queue_class IN ('strong', 'weak')),
    dedupe_key       TEXT,
    payload_json     TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL,
    lease_token      TEXT,  -- unique per claim; required to renew/complete/fail
    lease_owner      TEXT,
    lease_expires_at REAL,
    available_at     REAL NOT NULL,
    last_error       TEXT,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
CREATE INDEX jobs_claim ON jobs (stage, status, queue_class, available_at, id);
-- A dedupe key blocks duplicates only while a job is live, so finished or failed
-- work can be enqueued again later (e.g. rechecks).
CREATE UNIQUE INDEX jobs_dedupe_live ON jobs (dedupe_key)
    WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'running');

CREATE TABLE artifacts (
    sha256       TEXT PRIMARY KEY,
    size         INTEGER NOT NULL,
    content_type TEXT,
    created_at   REAL NOT NULL
);

CREATE TABLE case_artifacts (
    case_id            INTEGER NOT NULL REFERENCES cases (id),
    sha256             TEXT NOT NULL REFERENCES artifacts (sha256),
    registrable_domain TEXT,
    role               TEXT,
    created_at         REAL NOT NULL,
    PRIMARY KEY (case_id, sha256)
);
CREATE INDEX case_artifacts_domain ON case_artifacts (registrable_domain);

CREATE TABLE labels (
    id          INTEGER PRIMARY KEY,
    case_id     INTEGER NOT NULL REFERENCES cases (id),
    question    TEXT NOT NULL,  -- a decision question, or 'overall' for the verdict
    value       TEXT NOT NULL,
    labelled_by TEXT,
    created_at  REAL NOT NULL,
    UNIQUE (case_id, question)
);

CREATE TABLE discovery_runs (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    target      TEXT,
    started_at  REAL NOT NULL,
    finished_at REAL,
    status      TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE health_samples (
    id         INTEGER PRIMARY KEY,
    sampled_at REAL NOT NULL,
    data_json  TEXT NOT NULL
);
