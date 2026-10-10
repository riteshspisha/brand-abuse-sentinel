"""Stored evidence records: facts, features and judgments (U13, KTD15).

Facts are observations (source, observed value, artifact references, collector
version). Features are deterministic derivations (name, value, extractor
version, fact references). Judgments are advisory model outputs (M8) and are
never evidence for the policy. The writers live in `store.records`; these are
read models over the same tables.
"""

import json
import sqlite3
from typing import Any

from pydantic import BaseModel, ConfigDict


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FactRecord(_Record):
    id: int
    source: str
    name: str
    value: Any
    artifact_refs: list[str]
    collector_version: str
    observed_at: float

    @property
    def round(self) -> int | None:
        return self.value.get("analysis_round") if isinstance(self.value, dict) else None


class FeatureRecord(_Record):
    id: int
    name: str
    value: Any
    extractor_version: str
    fact_refs: list[int]
    computed_at: float


class JudgmentRecord(_Record):
    id: int
    provider: str
    model: str
    question_version: str
    result: Any
    latency_ms: float | None
    truncated: bool
    created_at: float


def load_facts(conn: sqlite3.Connection, case_id: int) -> list[FactRecord]:
    return [
        FactRecord(
            id=r[0],
            source=r[1],
            name=r[2],
            value=json.loads(r[3]),
            artifact_refs=json.loads(r[4]),
            collector_version=r[5],
            observed_at=r[6],
        )
        for r in conn.execute(
            "SELECT id, source, name, value_json, artifact_refs, collector_version, observed_at"
            " FROM facts WHERE case_id = ? ORDER BY id",
            (case_id,),
        )
    ]


def load_features(conn: sqlite3.Connection, case_id: int) -> list[FeatureRecord]:
    return [
        FeatureRecord(
            id=r[0],
            name=r[1],
            value=json.loads(r[2]),
            extractor_version=r[3],
            fact_refs=json.loads(r[4]),
            computed_at=r[5],
        )
        for r in conn.execute(
            "SELECT id, name, value_json, extractor_version, fact_refs, computed_at"
            " FROM features WHERE case_id = ? ORDER BY id",
            (case_id,),
        )
    ]


def load_judgments(conn: sqlite3.Connection, case_id: int) -> list[JudgmentRecord]:
    return [
        JudgmentRecord(
            id=r[0],
            provider=r[1],
            model=r[2],
            question_version=r[3],
            result=json.loads(r[4]),
            latency_ms=r[5],
            truncated=bool(r[6]),
            created_at=r[7],
        )
        for r in conn.execute(
            "SELECT id, provider, model, question_version, result_json, latency_ms, truncated,"
            " created_at FROM judgments WHERE case_id = ? ORDER BY id",
            (case_id,),
        )
    ]
