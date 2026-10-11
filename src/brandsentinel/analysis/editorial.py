"""Editorial context: article markup, byline, dates, parody and critical cues (U12).

Everything here is *page-provided*: the page says it about itself, and an
attacker can say it too (AE15). These features set the `editorial_or_critical`
context label beside any abuse evidence and never reduce a score (KTD17, R47).
"""

import json
import re

from brandsentinel.analysis import HTML_TYPES, Extractor, Page, node_text, register, unique_matches
from brandsentinel.matching.normalize import skeleton_of

VERSION = "editorial/1"
MAX_LD_SCRIPTS = 5
MAX_LD_BYTES = 64 * 1024
MAX_TYPES = 20
MAX_CUES = 10
MAX_BYLINE_NODES = 2000

ARTICLE_TYPES = frozenset(
    {
        "article",
        "newsarticle",
        "reportagenewsarticle",
        "analysisnewsarticle",
        "opinionnewsarticle",
        "reviewnewsarticle",
        "blogposting",
        "socialmediaposting",
        "report",
        "scholarlyarticle",
    }
)
_PARODY = re.compile(
    r"(?<![a-z])(?:parody|parodies|satire|satirical|spoof|lampoon|humou?r\s+site|"
    r"for\s+entertainment\s+(?:purposes\s+)?only)(?![a-z])"
)
_DISCLAIMER = re.compile(
    r"(?<![a-z])(?:not\s+(?:affiliated|associated|connected|endorsed|sponsored)|no\s+affiliation|"
    r"unofficial|fan\s+(?:site|page)|independent\s+(?:of|from)|disclaimer)(?![a-z])"
)
_CRITICAL = re.compile(
    r"(?<![a-z])(?:critics?|criticism|criticised|criticized|allegations?|alleged(?:ly)?|"
    r"controvers(?:y|ial)|accused|lawsuit|investigation|complaints?|concerns?|"
    r"questions\s+over|did\s+not\s+respond|declined\s+to\s+comment|scam|fraud|exposed)(?![a-z])"
)
_BYLINE = re.compile(r"^\s*(?:by|written\s+by|posted\s+by|reported\s+by)\s+\S", re.IGNORECASE)


def ld_json_types(page: Page) -> list[str]:
    """Lowercased schema.org `@type` values from the page's JSON-LD (bounded)."""

    def compute() -> list[str]:
        types: list[str] = []

        def walk(obj, depth: int) -> None:
            if depth > 6 or len(types) >= MAX_TYPES:
                return
            if isinstance(obj, dict):
                t = obj.get("@type")
                for v in t if isinstance(t, list) else [t]:
                    if isinstance(v, str) and v.lower()[:60] not in types:
                        types.append(v.lower()[:60])
                for v in list(obj.values())[:50]:
                    walk(v, depth + 1)
            elif isinstance(obj, list):
                for v in obj[:50]:
                    walk(v, depth + 1)

        for node in page.tree.css('script[type="application/ld+json"]')[:MAX_LD_SCRIPTS]:
            raw = (node.text(deep=True) or "")[:MAX_LD_BYTES]
            try:
                walk(json.loads(raw), 0)
            except (ValueError, RecursionError):
                continue
        return types

    return page.cached("ld_types", compute)


def _meta(page: Page, prop: str) -> str | None:
    for n in page.tree.css("meta"):
        a = n.attributes
        if (a.get("property") or a.get("name") or "").lower() == prop:
            return (a.get("content") or "")[:200] or None
    return None


def _cues(rx: re.Pattern, text: str) -> list[str]:
    return unique_matches(rx, text, MAX_CUES)


def editorial(page: Page) -> dict:
    types = ld_json_types(page)
    og_type = (_meta(page, "og:type") or "").lower() or None
    article_types = sorted(t for t in types if t in ARTICLE_TYPES)
    article_element = page.tree.css_first("article") is not None
    byline = None
    for n in page.tree.css('[class*="byline"], [rel="author"], [itemprop="author"], address')[:50]:
        byline = node_text(n)[:200] or None
        if byline:
            break
    if byline is None:
        # Each element's own text only: deep text of every nested div is quadratic.
        for n in page.tree.css("p, span, div")[:MAX_BYLINE_NODES]:
            t = " ".join((n.text(deep=False) or "").split())
            if t and len(t) < 200 and _BYLINE.match(t):
                byline = t
                break
    published = _meta(page, "article:published_time")
    if published is None:
        node = page.tree.css_first("time[datetime]")
        published = (node.attributes.get("datetime") or "")[:60] or None if node else None
    text = skeleton_of(" ".join(page.sentences))
    parody = _cues(_PARODY, text)
    disclaimers = _cues(_DISCLAIMER, text)
    critical = _cues(_CRITICAL, text)
    markup = bool(article_types or og_type == "article" or article_element)
    return {
        "page_provided": True,
        "article_markup": {
            "schema_types": article_types,
            "og_type": og_type,
            "article_element": article_element,
            "present": markup,
        },
        "byline": byline,
        "published": published,
        "parody_cues": parody,
        "disclaimer_cues": disclaimers,
        "critical_cues": critical,
        # Article markup with a byline, or explicit parody/satire language.
        "editorial": bool((markup and (byline or published)) or parody),
    }


register(Extractor("editorial", VERSION, HTML_TYPES, editorial))
