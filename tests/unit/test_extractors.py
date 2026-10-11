"""Static page extractors: registry, isolation, page_basics."""

from tests.security.harness import PAGE

from brandsentinel.analysis import EXTRACTORS, Extractor, page_basics, parse_refresh, run_extractors


def test_page_basics_extracts_title_refresh_and_resources():
    v = page_basics(PAGE.decode(), "https://x.example/d/page")
    assert v["title"] == "Lumina Foundation Donate"
    assert v["meta_refresh"] == [{"delay": 5.0, "url": "https://x.example/next"}]
    assert v["resources"]["images"] == ["https://x.example/d/logo.png"]
    assert v["resources"]["frames"] == ["https://frame.example/x"]
    assert v["data_uri_count"] == 1
    assert all("javascript" not in u for urls in v["resources"].values() for u in urls)


def test_base_href_changes_resolution():
    html = '<base href="https://cdn.example/root/"><img src="a.png">'
    v = page_basics(html, "https://x.example/")
    assert v["base_href"] == "https://cdn.example/root/"
    assert v["resources"]["images"] == ["https://cdn.example/root/a.png"]


def test_refresh_parsing_variants():
    assert parse_refresh("0;URL='http://evil.example/'", "https://a/") == {
        "delay": 0.0,
        "url": "http://evil.example/",
    }
    assert parse_refresh("abc", "https://a/") == {"delay": None, "url": None}
    assert parse_refresh("3; url=javascript:alert(1)", "https://a/")["url"] is None


def test_resource_lists_are_capped():
    html = "".join(f'<img src="/i{i}.png">' for i in range(1000))
    assert page_basics(html, "https://x.example/")["resource_counts"]["images"] == 200


def test_malformed_html_and_unknown_charset_do_not_crash():
    out = run_extractors(b"<html><title>\xff\xfe broken <<<", "text/html", "x-bogus", "https://a/")
    assert out[0].value["title"].startswith("\ufffd")


def test_failing_extractor_is_recorded_not_fatal(monkeypatch):
    def boom(page):
        raise RuntimeError("bad parser day")

    monkeypatch.setitem(
        EXTRACTORS, "boom", Extractor("boom", "boom/1", frozenset({"text/html"}), boom)
    )
    results = {r.extractor.name: r for r in run_extractors(PAGE, "text/html", None, "https://a/")}
    assert results["boom"].value is None and "bad parser day" in results["boom"].error
    assert results["page_basics"].value["title"]


def test_non_html_bodies_are_not_parsed():
    assert run_extractors(b"plain", "text/plain", None, "https://a/") == []


def test_hostile_charset_labels_fall_back_to_utf8():
    from brandsentinel.analysis import decode_body

    for label in ["idna", "punycode", "rot13", "base64", "utf-8\x00", "zlib"]:
        assert decode_body(b"<title>ok \xff</title>", label).startswith("<title>ok")
    out = run_extractors(b"<title>x</title>", "text/html", "idna", "https://a/")
    assert out[0].value["title"] == "x"
