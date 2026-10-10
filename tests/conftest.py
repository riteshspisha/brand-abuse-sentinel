from pathlib import Path

import pytest

from brandsentinel.config import Config, SandboxSettings
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
    # No sandbox runtime: tests that need one build it explicitly (docker marker).
    return Config(data_dir=tmp_path / "data", sandbox=SandboxSettings(enabled=False))


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


class FakeDocker:
    """Handle on a fake `docker` binary (tests/fake_docker.py) and its state."""

    def __init__(self, root: Path) -> None:
        import json
        import sys

        self.state = root / "fake-docker"
        self.state.mkdir()
        (self.state / "networks").mkdir()
        (self.state / "containers").mkdir()
        self.binary = root / "docker"
        fake = Path(__file__).parent / "fake_docker.py"
        self.binary.write_text(f'#!/bin/sh\nexec {sys.executable} {fake} {self.state} "$@"\n')
        self.binary.chmod(0o755)
        self._json = json

    def calls(self) -> list[list[str]]:
        path = self.state / "calls.jsonl"
        if not path.exists():
            return []
        return [self._json.loads(line) for line in path.read_text().splitlines()]

    def containers(self) -> dict:
        path = self.state / "state.json"
        return self._json.loads(path.read_text()) if path.exists() else {}

    def set_info(self, info: dict) -> None:
        (self.state / "info.json").write_text(self._json.dumps(info))

    def set_network(self, name: str, doc: dict) -> None:
        (self.state / "networks" / f"{name}.json").write_text(self._json.dumps(doc))

    def set_container(self, name: str, doc: dict) -> None:
        (self.state / "containers" / f"{name}.json").write_text(self._json.dumps(doc))

    def add_container(self, name: str, labels: dict, status: str = "running") -> None:
        state = self.containers()
        state[name] = {
            "Id": f"id-{name}",
            "Image": "fake/sleep",
            "Labels": labels,
            "State": {"Status": status, "ExitCode": 0, "OOMKilled": False},
            "pid": None,
        }
        (self.state / "state.json").write_text(self._json.dumps(state))


@pytest.fixture
def fake_docker(tmp_path: Path) -> FakeDocker:
    return FakeDocker(tmp_path)
