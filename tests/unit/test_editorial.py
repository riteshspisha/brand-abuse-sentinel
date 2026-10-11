"""U12 editorial and brand-reference extractors: page-provided context and claims."""

from pathlib import Path

from tests.detection_support import context, lab_site

from brandsentinel.analysis import Page
from brandsentinel.analysis.association import brand_references
from brandsentinel.analysis.editorial import editorial

FIXTURES = Path(__file__).parent / "fixtures" / "html"


def pg(html, url="http://site.test/"):
    return Page(html.decode() if isinstance(html, bytes) else html, url, context())


def lab(site):
    expected, html = lab_site(site)
    return pg(html, expected["url"])


def test_news_article_markup_and_byline_are_page_provided():
    v = editorial(lab("news-critical"))
    assert v["page_provided"] is True and v["editorial"] is True
    assert v["article_markup"]["schema_types"] == ["newsarticle"]
    assert v["article_markup"]["og_type"] == "article" and v["article_markup"]["article_element"]
    assert v["byline"].startswith("By A. Reporter")
    assert "critics" in v["critical_cues"]


def test_parody_page_sets_parody_cue():
    v = editorial(lab("parody"))
    assert {"parody", "satire"} <= set(v["parody_cues"]) and v["editorial"]
    assert "not affiliated" in v["disclaimer_cues"]


def test_plain_pages_are_not_editorial():
    assert editorial(lab("donation-fraud"))["editorial"] is False
    assert editorial(lab("official"))["editorial"] is False


def test_hostile_json_ld_does_not_crash():
    deep = "[" * 5000 + "]" * 5000
    html = (
        f'<script type="application/ld+json">{deep}</script>'
        '<script type="application/ld+json">{not json</script>'
        '<script type="application/ld+json">{"@type": ["Article", 5, {"x": 1}]}</script>'
    )
    v = editorial(pg(html))
    assert v["article_markup"]["schema_types"] == ["article"]


def test_brand_strength_weak_alias_and_excluded_word():
    tourism = brand_references(lab("unrelated-tourism"))
    assert [(b["brand"], b["strength"]) for b in tourism["brands"]] == [
        ("lumina-foundation", "weak")
    ]
    assert tourism["weak_only"] and not tourism["presented"]
    lounge = brand_references(lab("unrelated-lounge"))  # "Illumina" is not "Lumina"
    assert lounge["brands"] == [] and not lounge["strong_mention"]


def test_presented_brand_from_title_heading_or_logo_alt():
    v = brand_references(lab("copied-assets"))
    assert "lumina-foundation" in v["presented"]
    locs = next(b for b in v["brands"] if b["brand"] == "lumina-foundation")["locations"]
    assert {"title", "heading", "image_alt", "body"} <= set(locs)


def test_homoglyph_brand_in_page_text_is_matched():
    cyrillic_i = chr(0x0456)
    v = brand_references(pg(f"<title>Lum{cyrillic_i}na Foundation donations</title>"))
    assert v["presented"] == ["lumina-foundation"]


def test_association_claims_and_negated_disclaimers():
    claims = brand_references(lab("false-association"))["claims"]
    assert {c["kind"] for c in claims} >= {"partner", "authorized"}
    parody = brand_references(lab("parody"))
    assert parody["claims"] == []
    assert parody["disclaimers"][0]["kind"] == "affiliated"
    title = brand_references(lab("copied-assets"))["claims"]
    assert title and title[0]["kind"] == "official"


def test_news_references_are_not_association_claims():
    v = brand_references(pg((FIXTURES / "news_with_login.html").read_bytes()))
    # "the official Lumina Foundation statement" and "Lumina Foundation's official
    # website" refer to the brand; neither claims to be it or to partner with it.
    assert v["claims"] == []
    assert v["presented"] == ["lumina-foundation"]


def test_claim_patterns():
    for text, kind in [
        ("We are an authorised collection centre for Lumina Foundation donations.", "authorized"),
        ("Run in association with Lumina Foundation.", "association"),
        ("This is the official donation page of Lumina Foundation.", "official"),
        ("Endorsed by Master Orin.", "endorsed"),
    ]:
        claims = brand_references(pg(f"<p>{text}</p>"))["claims"]
        assert kind in {c["kind"] for c in claims}, text
    neg = brand_references(pg("<p>We are not affiliated with Lumina Foundation.</p>"))
    assert neg["claims"] == [] and neg["disclaimers"]
    unofficial = brand_references(pg("<p>An unofficial fan site about Lumina Foundation.</p>"))
    assert unofficial["claims"] == []


def test_without_registry_brand_references_are_unavailable():
    from brandsentinel.analysis import AnalysisContext

    assert brand_references(Page("<title>x</title>", "http://a/", AnalysisContext())) == {
        "available": False
    }
