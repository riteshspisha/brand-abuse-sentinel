-- Media analysis and the reference corpus (M6: U16, U17).

-- The trusted reference corpus: images the registry vouches for, hashed in the
-- media sandbox. `registry_asset`: a confirmed registry asset whose bytes
-- matched its pinned sha256. `collected`: an image on a confirmed reference
-- page, fetched with verified TLS from a confirmed official domain of the brand.
-- The loader re-checks every row against the current registry before matching
-- uses it, so un-confirming an entry withdraws it at once.
CREATE TABLE reference_corpus (
    id                INTEGER PRIMARY KEY,
    brand             TEXT NOT NULL,
    kind              TEXT NOT NULL,
    origin            TEXT NOT NULL CHECK (origin IN ('registry_asset', 'collected')),
    asset_id          TEXT,
    reference_page    TEXT,
    source            TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    phash             TEXT NOT NULL,
    dhash             TEXT NOT NULL,
    favicon_mmh3      INTEGER,
    width             INTEGER NOT NULL,
    height            INTEGER NOT NULL,
    format            TEXT NOT NULL,
    luma_stddev       REAL NOT NULL,
    tls_mode          TEXT,
    trusted_reference INTEGER NOT NULL,
    provenance_json   TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    worker_version    TEXT NOT NULL,
    collected_at      REAL NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    retired_at        REAL
);
CREATE INDEX reference_corpus_active ON reference_corpus (active, brand);
-- One live row per image and owner: the same image on two reference pages (or
-- two assets) is two entries, so retiring one keeps the other.
CREATE UNIQUE INDEX reference_corpus_live
    ON reference_corpus (origin, source, sha256, COALESCE(asset_id, ''),
                         COALESCE(reference_page, '')) WHERE active = 1;

-- Reference pages as last collected: what the corpus was built from.
CREATE TABLE reference_page_snapshots (
    id                INTEGER PRIMARY KEY,
    brand             TEXT NOT NULL,
    url               TEXT NOT NULL,
    final_url         TEXT,
    outcome           TEXT NOT NULL,
    trusted_reference INTEGER NOT NULL,
    title             TEXT,
    text_excerpt      TEXT,
    body_sha256       TEXT,
    fetch_json        TEXT NOT NULL,
    collected_at      REAL NOT NULL
);
CREATE INDEX reference_page_snapshots_url ON reference_page_snapshots (url, id);

-- What collection saw on official pages but does not trust (R14): third-party
-- domains, payment destinations, images on other hosts, assets whose content no
-- longer matches their pin. Always `candidate`, for a maintainer to review in
-- the registry; never suppressing, never part of the corpus.
CREATE TABLE reference_observations (
    id             INTEGER PRIMARY KEY,
    brand          TEXT NOT NULL,
    reference_page TEXT,
    kind           TEXT NOT NULL,
    value          TEXT NOT NULL,
    detail_json    TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'candidate' CHECK (status = 'candidate'),
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    UNIQUE (brand, kind, value)
);
