# Storage

All state lives under one directory, the configured `data_dir`. That directory is
created mode 0700, and the database file is mode 0600.

```text
<data_dir>/
├── brandsentinel.db            SQLite (WAL mode while open), schema v5
├── artifacts/
│   ├── sha256/<2 hex>/<sha256>  inert blobs: fetched pages, images, rendered HTML, screenshots
│   └── tmp/                     in-flight writes
├── raw/
│   └── discovery/*.jsonl.gz     append-only discovery log segments (rotated daily)
├── cache/                       RDAP bootstrap and response cache
└── reports/                     HTML written by `brandsentinel report`
```

## Database

Numbered migrations in `src/brandsentinel/store/migrations/` (`0001`–`0005`) define the
schema. `schema_migrations` records which have been applied. A store newer than the
code refuses to open (`SchemaTooNew`).

| Group | Tables |
|---|---|
| Discovery | `discovery_events`, `discovery_runs`, `candidate_sources`, `candidates`, `coverage_gaps`, `source_state` |
| Cases and evidence | `cases`, `facts`, `features`, `artifacts`, `case_artifacts`, `scores`, `judgments`, `labels` |
| Work | `jobs`, `job_groups`, `deferred_jobs`, `stage_runs` |
| Enrichment | `enrichment_cache` |
| Reference corpus | `reference_corpus`, `reference_page_snapshots`, `reference_observations` |
| Health | `health_samples` |

Key properties:

- **Facts** are generic records `(case_id, source, name, value_json, artifact_refs,
  collector_version, observed_at)`. New observations need no migration.
- **Scores** keep the bundle JSON and its sha256, the policy version and the bundle
  schema. `cases.priority`, `cases.category` and `cases.score_id` point at the current one,
  and old rows are never rewritten.
- **Transactions** use `BEGIN IMMEDIATE`, so writers serialize. A stage's facts and its
  `stage_runs` marker commit together.

## Artifacts

`store/blobs.py`:

- Artifacts are stored under their sha256, without extensions, mode 0600, and are never
  executed or opened by the host.
- Every write is checked against quotas: per artifact (10 MiB), per case (200 files,
  50 MiB), per registrable domain (200 MiB) and store-wide (2 GiB). A reserved 10% stays
  available for strong-strength and manual cases.
- A rejected write is recorded on the case as `artifact_quota_exceeded`.
- A file is placed only inside the committing transaction.

!!! warning "Opening a store deletes orphaned files"
    `open_store` calls `sweep_orphans`, which removes temporary files and stored files
    with no `artifacts` row that are older than one hour. Such files are left behind by
    a crash between placing a file and committing. This happens for **every** command that
    opens a store, including read-only ones (`status`, `cases`, `report`, `export`).
    Never open a store whose files must stay byte-identical, such as a backup or a
    forensic copy. Read a copy instead, or use SQLite's `immutable=1` read-only URI.

## Raw logs and retention

`store/rawlog.py`, `store/retention.py`:

- Discovery records are appended before ingestion and rotated by day.
- Segments and the matching discovery-event rows are pruned after
  `rawlog.discovery_max_age_days` (365). Candidates, cases and per-source summaries are
  kept.
- The optional CertStream firehose (unmatched certificates, off by default) has its own
  byte and age caps. It pauses below `rawlog.min_free_bytes` free disk.

## Backup and recovery

There is no built-in backup command. A consistent backup is a copy of the whole
`data_dir` taken while no BrandSentinel process has the store open. Verify it by content
hashes and metadata, not by opening it, because opening sweeps orphans. The procedure
used for production, a sealed recovery point, is owner-operated and described in
[Deployment and recovery](../operations/deployment.md#recovery).
