-- Guarded fetch and enrichment (M3): fair per-registrable-domain scheduling,
-- deferred work, per-stage completion markers and a small enrichment cache.

-- The registrable domain a job belongs to. Claims limit running jobs per group
-- and serve the least recently served group first.
ALTER TABLE jobs ADD COLUMN group_key TEXT;
-- Jobs queued before this migration get their group from the payload, so an
-- existing backlog is bounded like new work.
UPDATE jobs SET group_key = COALESCE(
    NULLIF(json_extract(payload_json, '$.registrable_domain'), ''),
    json_extract(payload_json, '$.name'))
WHERE group_key IS NULL;
CREATE INDEX jobs_group_live ON jobs (stage, group_key, status);

-- Set by a manual submission: all of the case's analysis work (fetch and
-- rechecks too, not just its first enrichment) bypasses domain allowances.
ALTER TABLE cases ADD COLUMN escalated INTEGER NOT NULL DEFAULT 0;
-- Lets a scheduler ask "was this unit of work ever queued?", whatever its status.
CREATE INDEX jobs_dedupe_any ON jobs (dedupe_key);

CREATE TABLE job_groups (
    stage           TEXT NOT NULL,
    group_key       TEXT NOT NULL,
    last_claimed_at REAL NOT NULL,
    PRIMARY KEY (stage, group_key)
);

-- Work held back because its registrable domain is over its queue allowance, or
-- not yet due (rechecks). Nothing is dropped: a promoter moves rows into the job
-- queue as the domain's jobs finish. Escalated rows bypass the allowance.
CREATE TABLE deferred_jobs (
    dedupe_key   TEXT PRIMARY KEY,
    stage        TEXT NOT NULL,
    group_key    TEXT NOT NULL,
    queue_class  TEXT NOT NULL CHECK (queue_class IN ('strong', 'weak')),
    escalated    INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    case_id      INTEGER REFERENCES cases (id),
    reason       TEXT NOT NULL,  -- domain_queue_full | recheck
    not_before   REAL NOT NULL,
    deferred_at  REAL NOT NULL
);
CREATE INDEX deferred_due ON deferred_jobs (stage, group_key, not_before);
CREATE INDEX deferred_case ON deferred_jobs (case_id);

-- One row per finished (case, stage, analysis round), written in the same
-- transaction as that run's facts, so a redelivered job writes nothing twice.
CREATE TABLE stage_runs (
    case_id     INTEGER NOT NULL REFERENCES cases (id),
    stage       TEXT NOT NULL,
    round       INTEGER NOT NULL,
    outcome     TEXT NOT NULL,
    finished_at REAL NOT NULL,
    PRIMARY KEY (case_id, stage, round)
);

-- Results shared across hosts, e.g. RDAP per registrable domain.
CREATE TABLE enrichment_cache (
    source      TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    observed_at REAL NOT NULL,
    PRIMARY KEY (source, key)
);
