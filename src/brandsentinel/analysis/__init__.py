"""Static evidence extractors over fetched bodies.

Extractors register by name with a version and the media types they read, and
each produces one feature value from a stored body. Later milestones add their
own extractors here (forms and credentials, payment and donation indicators,
association claims, commerce, editorial cues) without changing the fetch stage.

M3 ships only `page_basics`: title, meta-refresh targets, canonical and base
URLs, and the page's referenced resources (scripts, stylesheets, images, icons,
frames), resolved to absolute URLs and never fetched. Untrusted HTML is parsed
in-process with a size-capped input (accepted residual risk in the plan).
"""

import codecs
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

MAX_RESOURCES = 200
MAX_TEXT = 512
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})


@dataclass(frozen=True)
class Extractor:
    name: str
    version: str
    media_types: frozenset[str]
    fn: Callable[[str, str], dict]  # (decoded text, base URL) -> feature value


EXTRACTORS: dict[str, Extractor] = {}


def register(extractor: Extractor) -> Extractor:
    if extractor.name in EXTRACTORS:
        raise ValueError(f"extractor {extractor.name!r} already registered")
    EXTRACTORS[extractor.name] = extractor
    return extractor


# Codecs that are not plain text encodings, or reject errors="replace".
_BAD_CHARSETS = frozenset({"idna", "punycode", "raw_unicode_escape", "unicode_escape"})


def decode_body(data: bytes, charset: str | None) -> str:
    """Decode with the server's charset, falling back to UTF-8 for any label
    that is unknown, not a text encoding, or fails (the label is untrusted)."""
    label = (charset or "utf-8").strip().lower()
    try:
        info = codecs.lookup(label)
        if info.name in _BAD_CHARSETS or not getattr(info, "_is_text_encoding", True):
            raise LookupError(label)
        return data.decode(info.name, errors="replace")
    except (LookupError, UnicodeError, ValueError, TypeError):
        return data.decode("utf-8", errors="replace")


@dataclass
class ExtractorResult:
    extractor: Extractor
    value: dict | None
    error: str | None = None


def run_extractors(
    data: bytes, content_type: str | None, charset: str | None, base_url: str
) -> list[ExtractorResult]:
    text: str | None = None
    out = []
    for ex in EXTRACTORS.values():
        if content_type not in ex.media_types:
            continue
        if text is None:
            text = decode_body(data, charset)
        try:
            out.append(ExtractorResult(ex, ex.fn(text, base_url)))
        except Exception as e:  # one extractor's failure is recorded, not fatal
            out.append(ExtractorResult(ex, None, f"{type(e).__name__}: {e}"[:500]))
    return out


def _absolute(base: str, ref: str | None) -> str | None:
    if not ref:
        return None
    ref = ref.strip()
    scheme = urlsplit(ref).scheme.lower()
    if scheme and scheme not in ("http", "https"):
        return None  # data:, javascript:, blob: and the like are not resources
    try:
        return urljoin(base, ref)[:2048]
    except ValueError:
        return None


def parse_refresh(content: str | None, base: str) -> dict | None:
    """`5; url=/next` -> {"delay": 5.0, "url": "<absolute>"}."""
    if not content:
        return None
    delay_part, _, rest = content.partition(";")
    try:
        delay = float(delay_part.strip() or 0)
    except ValueError:
        delay = None
    rest = rest.strip()
    if rest.lower().startswith("url"):
        rest = rest[3:].lstrip(" =").strip("'\" ")
    return {"delay": delay, "url": _absolute(base, rest) if rest else None}


def page_basics(text: str, base_url: str) -> dict:
    tree = LexborHTMLParser(text)
    base = base_url
    base_tag = tree.css_first("base[href]")
    base_href = None
    if base_tag is not None:
        base_href = _absolute(base_url, base_tag.attributes.get("href"))
        base = base_href or base_url
    title_node = tree.css_first("title")
    title = title_node.text(strip=True)[:MAX_TEXT] if title_node else None
    refresh = [
        parse_refresh(m.attributes.get("content"), base)
        for m in tree.css("meta[http-equiv]")
        if (m.attributes.get("http-equiv") or "").lower() == "refresh"
    ]
    canonical = next(
        (
            _absolute(base, link.attributes.get("href"))
            for link in tree.css("link[rel][href]")
            if "canonical" in (link.attributes.get("rel") or "").lower().split()
        ),
        None,
    )

    resources: dict[str, list[str]] = {
        "scripts": [],
        "stylesheets": [],
        "images": [],
        "icons": [],
        "frames": [],
    }
    data_uris = 0

    def add(kind: str, ref: str | None) -> None:
        nonlocal data_uris
        if ref and ref.strip().lower().startswith("data:"):
            data_uris += 1
            return
        url = _absolute(base, ref)
        if url and len(resources[kind]) < MAX_RESOURCES and url not in resources[kind]:
            resources[kind].append(url)

    for n in tree.css("script[src]"):
        add("scripts", n.attributes.get("src"))
    for n in tree.css("link[rel][href]"):
        rel = (n.attributes.get("rel") or "").lower().split()
        if "stylesheet" in rel:
            add("stylesheets", n.attributes.get("href"))
        if "icon" in rel or "apple-touch-icon" in rel:
            add("icons", n.attributes.get("href"))
    for n in tree.css("img[src]"):
        add("images", n.attributes.get("src"))
    for n in tree.css("iframe[src], frame[src]"):
        add("frames", n.attributes.get("src"))
    return {
        "title": title,
        "meta_refresh": [r for r in refresh if r],
        "canonical": canonical,
        "base_href": base_href,
        "resources": resources,
        "resource_counts": {k: len(v) for k, v in resources.items()},
        "data_uri_count": data_uris,
        "text_chars": len(text),
    }


register(Extractor("page_basics", "page_basics/1", HTML_TYPES, page_basics))
