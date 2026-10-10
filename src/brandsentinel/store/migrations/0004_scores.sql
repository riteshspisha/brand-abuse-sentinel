-- Static detection and triage (M5): one row per distinct policy result for a
-- case. The scored EvidenceBundle is kept beside the result, so a report shows
-- exactly what was decided on, with the policy version and bundle hash.

CREATE TABLE scores (
    id             INTEGER PRIMARY KEY,
    case_id        INTEGER NOT NULL REFERENCES cases (id),
    analysis_round INTEGER,
    policy_version TEXT NOT NULL,
    bundle_schema  TEXT NOT NULL,
    bundle_sha256  TEXT NOT NULL,
    bundle_json    TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    priority       TEXT NOT NULL,
    category       TEXT NOT NULL,
    score          INTEGER NOT NULL,
    created_at     REAL NOT NULL
);
CREATE INDEX scores_case ON scores (case_id, id);

-- The case's current score (cases.priority and cases.category mirror it).
ALTER TABLE cases ADD COLUMN score_id INTEGER REFERENCES scores (id);
CREATE INDEX cases_priority ON cases (priority, category);
