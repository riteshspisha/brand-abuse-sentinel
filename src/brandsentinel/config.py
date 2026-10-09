"""Configuration: one YAML file validated by pydantic.

Unknown keys are rejected so a typo never silently falls back to a default.
Environment variables may override paths only.
"""

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PositiveFloat, ValidationError, field_validator

ENV_CONFIG = "BRANDSENTINEL_CONFIG"
ENV_DATA_DIR = "BRANDSENTINEL_DATA_DIR"

STAGES = ("enrich", "fetch", "media", "render", "decision")

MiB = 1024 * 1024
GiB = 1024 * MiB


class ConfigError(Exception):
    """Configuration file missing, unreadable, or invalid."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StageLimits(_Section):
    """Maximum concurrent jobs per pipeline stage."""

    enrich: int = Field(8, ge=1)
    fetch: int = Field(4, ge=1)
    media: int = Field(2, ge=1)
    render: int = Field(1, ge=1)
    decision: int = Field(1, ge=1)
    per_domain_fetch: int = Field(1, ge=1)


class JobSettings(_Section):
    max_attempts: int = Field(3, ge=1)
    # A lease must outlive the stage's maximum wall time; long jobs renew it.
    lease_seconds: dict[str, PositiveFloat] = Field(
        default_factory=lambda: {
            "enrich": 120.0,
            "fetch": 120.0,
            "media": 180.0,
            "render": 300.0,
            "decision": 120.0,
        }
    )
    default_lease_seconds: float = Field(300.0, gt=0)

    @field_validator("lease_seconds")
    @classmethod
    def _known_stages(cls, value: dict[str, float]) -> dict[str, float]:
        unknown = sorted(set(value) - set(STAGES))
        if unknown:
            raise ValueError(f"unknown stage(s) {unknown}; expected some of {list(STAGES)}")
        return value

    def lease_for(self, stage: str) -> float:
        return self.lease_seconds.get(stage, self.default_lease_seconds)


class ArtifactQuotas(_Section):
    max_blob_bytes: int = Field(10 * MiB, gt=0)
    max_case_count: int = Field(200, gt=0)
    max_case_bytes: int = Field(50 * MiB, gt=0)
    max_domain_bytes: int = Field(200 * MiB, gt=0)
    max_store_bytes: int = Field(2 * GiB, gt=0)
    # Share of the store kept free for strong-strength and manual cases.
    reserve_fraction: float = Field(0.1, ge=0, lt=1)


class FirehoseSettings(_Section):
    """Optional storage of the unmatched CertStream feed. Off by default."""

    enabled: bool = False
    max_total_bytes: int = Field(2 * GiB, gt=0)
    max_age_days: int = Field(7, gt=0)


class RawLogSettings(_Section):
    flush_every_records: int = Field(100, ge=1)
    discovery_rotation: Literal["hour", "day"] = "day"
    # Discovery log segments and discovery event rows older than this are pruned.
    discovery_max_age_days: int = Field(365, gt=0)
    # Below this much free disk the firehose pauses; discovery logging continues.
    min_free_bytes: int = Field(1 * GiB, ge=0)
    firehose: FirehoseSettings = FirehoseSettings()


class CertStreamSettings(_Section):
    enabled: bool = True
    # certstream-server-go full stream (docker/compose.yaml, profile certstream).
    url: str = "ws://localhost:8080/full-stream"
    ping_interval_seconds: float = Field(30.0, gt=0)  # the server requires client pings
    open_timeout_seconds: float = Field(15.0, gt=0)
    max_message_bytes: int = Field(4 * MiB, gt=0)
    backoff_initial_seconds: float = Field(1.0, gt=0)
    backoff_max_seconds: float = Field(60.0, gt=0)
    # Recently seen certificate fingerprints kept in memory to skip duplicates
    # cheaply; persistence is idempotent regardless.
    dedupe_cache_size: int = Field(100_000, ge=1)
    max_names_per_cert: int = Field(1000, ge=1, le=1000)
    stale_after_seconds: float = Field(300.0, gt=0)

    @field_validator("url")
    @classmethod
    def _websocket_url(cls, v: str) -> str:
        if not v.startswith(("ws://", "wss://")):
            raise ValueError("must be a ws:// or wss:// URL")
        return v


class DnstwistSettings(_Section):
    enabled: bool = True
    # Executable name or path; a bare name is looked up next to the running
    # Python first, then on PATH.
    binary: str = "dnstwist"
    dictionary: Path | None = Path("registry/dictionaries/brand-words.dict")
    interval_hours: float = Field(24.0, gt=0)
    # Failed or abandoned sweeps retry after this, if shorter than the interval.
    retry_hours: float = Field(1.0, gt=0)
    threads: int = Field(8, ge=1, le=64)
    # The sweep timeout is floor + permutations / rate, capped at max.
    resolution_rate_per_second: float = Field(20.0, gt=0)
    timeout_floor_seconds: float = Field(120.0, gt=0)
    timeout_max_seconds: float = Field(4 * 3600.0, gt=0)
    count_timeout_seconds: float = Field(60.0, gt=0)
    max_permutations: int = Field(100_000, ge=1)
    max_output_bytes: int = Field(64 * MiB, gt=0)


class DiscoverySettings(_Section):
    certstream: CertStreamSettings = CertStreamSettings()
    dnstwist: DnstwistSettings = DnstwistSettings()


class TextSettings(_Section):
    max_fact_chars: int = Field(4096, gt=0)  # per string
    max_fact_bytes: int = Field(256 * 1024, gt=0)  # per serialized fact value


class Config(_Section):
    data_dir: Path = Path("data")
    registry_path: Path = Path("registry/brands.yaml")
    stages: StageLimits = StageLimits()
    jobs: JobSettings = JobSettings()
    artifacts: ArtifactQuotas = ArtifactQuotas()
    rawlog: RawLogSettings = RawLogSettings()
    text: TextSettings = TextSettings()
    discovery: DiscoverySettings = DiscoverySettings()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "brandsentinel.db"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"


def _format_errors(err: ValidationError) -> str:
    parts = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        parts.append(f"{loc}: {e['msg']}")
    return "; ".join(parts)


def load_config(path: Path | None = None) -> Config:
    """Load config from `path`, else $BRANDSENTINEL_CONFIG, else built-in defaults."""
    if path is None and os.environ.get(ENV_CONFIG):
        path = Path(os.environ[ENV_CONFIG])

    raw: dict = {}
    if path is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as e:
            raise ConfigError(f"cannot read config {path}: {e}") from e
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {path}: {e}") from e
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError(f"config {path} must be a mapping")
        raw = loaded or {}

    if os.environ.get(ENV_DATA_DIR):
        raw = {**raw, "data_dir": os.environ[ENV_DATA_DIR]}

    try:
        return Config.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"invalid config: {_format_errors(e)}") from e
