import json

from brandsentinel.store.records import add_fact, create_case, upsert_candidate


def test_duplicate_candidate_updates_last_seen(store, clock):
    cid, created = upsert_candidate(store.conn, "save-soil.shop", match_strength="weak", now=100.0)
    again, created_again = upsert_candidate(
        store.conn, "save-soil.shop", match_strength="weak", now=200.0
    )
    assert created and not created_again and again == cid
    row = store.conn.execute("SELECT first_seen, last_seen FROM candidates").fetchone()
    assert tuple(row) == (100.0, 200.0)
    assert store.conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 1


def test_strong_sighting_upgrades_and_never_downgrades(store):
    upsert_candidate(store.conn, "x.test", match_strength="weak", now=1.0)
    upsert_candidate(store.conn, "x.test", match_strength="strong", now=2.0)
    upsert_candidate(store.conn, "x.test", match_strength="weak", now=3.0)
    assert store.conn.execute("SELECT match_strength FROM candidates").fetchone()[0] == "strong"


def test_out_of_order_sighting_keeps_latest_last_seen(store):
    upsert_candidate(store.conn, "x.test", match_strength="weak", now=50.0)
    upsert_candidate(store.conn, "x.test", match_strength="weak", now=10.0)
    assert store.conn.execute("SELECT last_seen FROM candidates").fetchone()[0] == 50.0


def test_fact_values_are_sanitized(store):
    cand, _ = upsert_candidate(store.conn, "x.test", match_strength="strong")
    case = create_case(store.conn, cand)
    add_fact(
        store.conn,
        case,
        source="static",
        name="title",
        value={"title": "Donate\x1b[31m now\u202e", "tags\u2066": ["a\x00b", 3]},
        collector_version="test/1",
        max_chars=100,
    )
    stored = json.loads(store.conn.execute("SELECT value_json FROM facts").fetchone()[0])
    assert stored == {"title": "Donate[31m now", "tags": ["ab", 3]}


def test_fact_length_is_capped(store):
    cand, _ = upsert_candidate(store.conn, "x.test", match_strength="strong")
    case = create_case(store.conn, cand)
    add_fact(
        store.conn, case, source="s", name="n", value="z" * 500, collector_version="v", max_chars=64
    )
    stored = json.loads(store.conn.execute("SELECT value_json FROM facts").fetchone()[0])
    assert stored == "z" * 64


def _stored(store):
    return json.loads(
        store.conn.execute("SELECT value_json FROM facts ORDER BY id DESC").fetchone()[0]
    )


def test_fact_nesting_and_collection_size_are_bounded(store):
    from brandsentinel.store.records import MAX_FACT_DEPTH, MAX_FACT_ITEMS

    cand, _ = upsert_candidate(store.conn, "x.test", match_strength="strong")
    case = create_case(store.conn, cand)
    deep: object = "leaf"
    for _ in range(MAX_FACT_DEPTH + 5):
        deep = [deep]
    add_fact(store.conn, case, source="s", name="deep", value=deep, collector_version="v")
    depth, node = 0, _stored(store)
    while isinstance(node, list):
        depth, node = depth + 1, node[0]
    assert depth == MAX_FACT_DEPTH and node == "[truncated]"

    add_fact(
        store.conn, case, source="s", name="wide", value=list(range(5000)), collector_version="v"
    )
    assert len(_stored(store)) == MAX_FACT_ITEMS


def test_oversized_fact_is_replaced_by_marker(store):
    cand, _ = upsert_candidate(store.conn, "x.test", match_strength="strong")
    case = create_case(store.conn, cand)
    add_fact(
        store.conn,
        case,
        source="s",
        name="big",
        value=["y" * 100] * 100,
        collector_version="v",
        max_bytes=1000,
    )
    stored = _stored(store)
    assert stored["truncated"] is True and stored["original_bytes"] > 1000


def test_non_json_values_are_stringified_and_sanitized(store):
    cand, _ = upsert_candidate(store.conn, "x.test", match_strength="strong")
    case = create_case(store.conn, cand)

    class Weird:
        def __str__(self):
            return "obj\x1b"

    add_fact(store.conn, case, source="s", name="w", value={"v": Weird()}, collector_version="v")
    assert _stored(store) == {"v": "obj"}
