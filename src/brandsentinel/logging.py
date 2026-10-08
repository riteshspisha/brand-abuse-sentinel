"""Structured JSON-lines logging with timezone-aware UTC timestamps."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import IO


class JsonFormatter(logging.Formatter):
    """One JSON object per line. ASCII-only output keeps any untrusted text in
    messages from reaching a terminal as raw control or bidi characters."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True, default=str)


def configure_logging(level: str = "INFO", stream: IO[str] | None = None) -> None:
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("brandsentinel")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
