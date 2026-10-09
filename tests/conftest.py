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
