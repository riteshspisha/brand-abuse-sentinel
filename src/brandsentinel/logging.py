"""Structured JSON-lines logging with timezone-aware UTC timestamps.

Exceptions on the job path are logged with `exception_fields`: the exception
class and the code locations of its traceback, never its message or a
formatted traceback. Messages can carry URLs (queries included), credentials or
page text; the full message of a failed job stays in the store
(`jobs.last_error`).
"""

import json
import logging
import os
import sys
import traceback
from datetime import UTC, datetime
from typing import IO

MAX_ERROR_FRAMES = 8


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


def exception_fields(error: BaseException) -> dict:
    """What a log record may say about an exception: its class and where it was
    raised (innermost frames, `file.py:line`), never its message or arguments.
    Chained exceptions are not followed: their messages are no safer."""
    frames = traceback.extract_tb(error.__traceback__)[-MAX_ERROR_FRAMES:]
    return {
        "error_type": type(error).__name__,
        "error_at": [f"{os.path.basename(f.filename)}:{f.lineno}" for f in frames],
    }
