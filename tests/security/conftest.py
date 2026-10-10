"""Security tests share the session harness fixture from tests/conftest.py."""

import logging

import pytest


class Decisions(logging.Handler):
    """Collects the egress proxy's structured decision records."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.fields)

    def last(self) -> dict:
        return self.records[-1]


@pytest.fixture
def decisions():
    handler = Decisions()
    logger = logging.getLogger("brandsentinel.proxy")
    logger.addHandler(handler)
    old = logger.level
    logger.setLevel(logging.INFO)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old)
