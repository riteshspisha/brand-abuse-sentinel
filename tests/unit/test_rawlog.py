import gzip
import json
import stat

import pytest

from brandsentinel.store.rawlog import RawLog, read_segment


def _records(log):
    return [r["record"] for seg in log.segments() for r in read_segment(seg)]


def test_segment_is_gzip_readable_after_clean_shutdown(tmp_path, clock):
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        for i in range(5):
            log.write({"i": i})
    (seg,) = log.segments()
    # A standard gzip reader accepts the closed segment.
    lines = gzip.decompress(seg.read_bytes()).decode().splitlines()
    assert [json.loads(line)["record"]["i"] for line in lines] == [0, 1, 2, 3, 4]
    assert _records(log) == [{"i": i} for i in range(5)]


def test_interrupted_segment_is_readable_up_to_last_flush(tmp_path, clock):
    log = RawLog(tmp_path, "discovery", clock=clock, flush_every=1000)
    for i in range(3):
        log.write({"i": i})
    log.write({"i": 3}, durable=True)
    log.write({"i": 4})  # buffered, never flushed
    (seg,) = log.segments()
    crashed = tmp_path / "crashed.jsonl.gz"
    crashed.write_bytes(seg.read_bytes())  # file as a crash would leave it
    got = [r["record"]["i"] for r in read_segment(crashed)]
    assert got[:4] == [0, 1, 2, 3]
    log.close()


def test_corrupt_tail_stops_cleanly(tmp_path, clock):
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        log.write({"i": 0}, durable=True)
        log.write({"i": 1}, durable=True)
    (seg,) = log.segments()
    data = seg.read_bytes()
    damaged = tmp_path / "damaged.jsonl.gz"
    damaged.write_bytes(data[: len(data) - 12] + b"\xff" * 40)
    assert [r["record"]["i"] for r in read_segment(damaged)] == [0, 1]


def test_new_process_never_appends_to_an_existing_segment(tmp_path, clock):
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        log.write({"run": 1})
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        log.write({"run": 2})
    assert len(log.segments()) == 2
    assert sorted(r["run"] for r in _records(log)) == [1, 2]


def test_hourly_rotation_opens_new_segment(tmp_path, clock):
    with RawLog(tmp_path, "certstream-firehose", rotation="hour", clock=clock) as log:
        log.write({"n": 1})
        clock.advance(3600)
        log.write({"n": 2})
    assert len(log.segments()) == 2


def test_segments_are_private_files(tmp_path, clock):
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        log.write({"a": 1})
    (seg,) = log.segments()
    assert stat.S_IMODE(seg.stat().st_mode) == 0o600
    assert log.total_bytes() == seg.stat().st_size


def test_untrusted_strings_are_stored_ascii_escaped(tmp_path, clock):
    with RawLog(tmp_path, "discovery", clock=clock) as log:
        log.write({"san": "x\x1b]0;t\x07\u202e.example"})
    (seg,) = log.segments()
    raw = gzip.decompress(seg.read_bytes())
    assert raw.isascii() and b"\x1b" not in raw
    assert _records(log) == [{"san": "x\x1b]0;t\x07\u202e.example"}]


@pytest.mark.parametrize("bad", ["../escape", "Discovery", "", "a/b", "x" * 80])
def test_source_name_is_validated(tmp_path, bad):
    with pytest.raises(ValueError):
        RawLog(tmp_path, bad)


class _FailingFile:
    """Wraps a raw file; raises ENOSPC on write while `failing` is set."""

    def __init__(self, inner):
        self.inner = inner
        self.failing = False

    def write(self, data):
        if self.failing:
            raise OSError(28, "No space left on device")
        return self.inner.write(data)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def test_write_failure_abandons_segment_and_later_records_stay_correct(tmp_path, clock):
    import gzip as gz

    log = RawLog(tmp_path, "discovery", clock=clock, flush_every=1)
    log.write({"i": 0})
    failing = _FailingFile(log._raw)
    log._raw = failing
    log._gz = gz.GzipFile(fileobj=failing, mode="wb", mtime=0)  # continue same stream shape
    failing.failing = True
    with pytest.raises(OSError):
        log.write({"i": 1}, durable=True)
    assert log._gz is None  # segment abandoned
    for i in range(2, 200):
        log.write({"i": i})
    log.close()
    got = [r["i"] for r in _records(log)]
    assert got[0] == 0
    assert got[-198:] == list(range(2, 200))  # every later record intact, in order


def test_malformed_but_decodable_line_stops_cleanly(tmp_path):
    seg = tmp_path / "bad.jsonl.gz"
    seg.write_bytes(gzip.compress(b'{"record": 1}\n{not json}\n{"record": 3}\n'))
    assert list(read_segment(seg)) == [{"record": 1}]


def test_concatenated_members_and_large_segments_are_read(tmp_path):
    seg = tmp_path / "multi.jsonl.gz"
    lines_a = b"".join(json.dumps({"i": i, "pad": "x" * 200}).encode() + b"\n" for i in range(500))
    lines_b = b"".join(json.dumps({"i": i}).encode() + b"\n" for i in range(500, 600))
    seg.write_bytes(gzip.compress(lines_a) + gzip.compress(lines_b))
    assert seg.stat().st_size > 0
    assert [r["i"] for r in read_segment(seg)] == list(range(600))


def test_store_reuses_and_closes_raw_logs(config):
    from brandsentinel.store import open_store

    store = open_store(config)
    log = store.rawlog("discovery")
    assert store.rawlog("discovery") is log
    log.write({"a": 1})
    store.close()
    assert log._gz is None  # closed with its trailer by Store.close()
    (seg,) = log.segments()
    assert gzip.decompress(seg.read_bytes())
