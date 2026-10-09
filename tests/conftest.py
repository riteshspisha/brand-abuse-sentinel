from pathlib import Path

import pytest

from brandsentinel.config import Config
from brandsentinel.store import Store, open_store


class FakeClock:
    def __init__(self, start: float = 1_760_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(data_dir=tmp_path / "data")


@pytest.fixture
def store(config: Config) -> Store:
    s = open_store(config)
    yield s
    s.close()


REPO = Path(__file__).parents[1]
REGISTRY_PATH = REPO / "registry" / "brands.yaml"


@pytest.fixture
def registry_data() -> dict:
    """The committed registry as plain data, for tests to modify."""
    import yaml

    return yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))


def confirm_domain(data: dict, name: str, *, suppresses: bool = True) -> None:
    """Mark a registry domain confirmed by a test maintainer."""
    for d in data["domains"]:
        if d["name"] == name:
            d["status"] = "confirmed"
            d["suppresses"] = suppresses
            d["provenance"].append(
                {
                    "source": "maintainer",
                    "recorded_by": "test",
                    "recorded_at": "2026-10-08",
                    "verified_by": "test-maintainer",
                    "verified_at": "2026-10-08",
                }
            )
            return
    raise KeyError(name)


def build_matcher(data: dict):
    """A Matcher over registry data (as loaded from YAML, possibly modified)."""
    from brandsentinel.matching.matcher import Matcher
    from brandsentinel.registry.loader import validate
    from brandsentinel.registry.model import Registry

    registry = Registry.model_validate(data)
    validate(registry)
    return Matcher(registry)


@pytest.fixture
def matcher(registry_data):
    return build_matcher(registry_data)


def cert_message(
    names: list[str],
    *,
    fingerprint: str = "AA:BB:CC",
    cert_index: int = 1000,
    log_url: str = "https://ct.example/log1/",
    issuer_o: str = "Let's Encrypt",
) -> str:
    """A certstream-server-go full-stream certificate_update message."""
    import json

    return json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "update_type": "X509LogEntry",
                "leaf_cert": {
                    "all_domains": names,
                    "fingerprint": fingerprint,
                    "issuer": {"C": "US", "CN": "R11", "O": issuer_o},
                    "not_before": 1760000000,
                    "not_after": 1767776000,
                    "serial_number": "04A1B2",
                },
                "cert_index": cert_index,
                "seen": 1760000000.5,
                "source": {"name": "Test Log", "url": log_url},
            },
        }
    )


@pytest.fixture(scope="session")
def harness(tmp_path_factory):
    """The local adversarial DNS/HTTP/TLS harness (tests/security/harness.py)."""
    from tests.security.harness import start_harness

    h = start_harness(tmp_path_factory.mktemp("harness"))
    yield h
    h.close()
