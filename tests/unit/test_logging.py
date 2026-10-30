import io
import json
import logging
from datetime import datetime

from brandsentinel.logging import configure_logging


def _emit(msg, **kwargs):
    buf = io.StringIO()
    configure_logging("DEBUG", stream=buf)
    logging.getLogger("brandsentinel.test").info(msg, **kwargs)
    return buf.getvalue()


def test_record_is_one_json_line_with_utc_timestamp():
    lines = _emit("hello").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["msg"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "brandsentinel.test"
    ts = datetime.fromisoformat(payload["ts"])
    assert ts.utcoffset() is not None and ts.utcoffset().total_seconds() == 0


def test_extra_fields_are_merged():
    payload = json.loads(_emit("job done", extra={"fields": {"job_id": 7, "stage": "fetch"}}))
    assert payload["job_id"] == 7
    assert payload["stage"] == "fetch"


def test_untrusted_control_and_bidi_characters_are_escaped():
    out = _emit("title: \x1b]0;pwned\x07 \u202eevil")
    assert "\x1b" not in out and "\u202e" not in out
    assert out.isascii()
    assert json.loads(out)["msg"] == "title: \x1b]0;pwned\x07 \u202eevil"


def test_exception_fields_carry_the_class_and_code_locations_never_the_message():
    from brandsentinel.logging import exception_fields

    def inner():
        raise ValueError("https://x.test/p?session=SECRET123 password=hunter2")

    try:
        try:
            inner()
        except ValueError as e:
            raise RuntimeError("wrapped https://x.test/?token=SECRET123") from e
    except RuntimeError as e:
        fields = exception_fields(e)
    assert fields["error_type"] == "RuntimeError"
    assert fields["error_at"] and all(":" in f and "/" not in f for f in fields["error_at"])
    assert "SECRET123" not in json.dumps(fields) and "hunter2" not in json.dumps(fields)
