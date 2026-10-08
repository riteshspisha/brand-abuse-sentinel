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
