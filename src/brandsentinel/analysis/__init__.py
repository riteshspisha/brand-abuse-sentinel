"""Static evidence extractors over fetched bodies.

Extractors register by name with a version and the media types they read, and
each produces one feature value from a stored body. Each reads a `Page`: the
decoded text, the URL it came from, a once-parsed tree, and an optional
`AnalysisContext` (the registry's brand lexicon and the payment provider
catalog) for extractors that attribute what they see to a brand or payee.

- `page_basics` (M3): title, meta-refresh targets, canonical and base URLs, and
  the page's referenced resources, resolved to absolute URLs and never fetched.
- `page_content` (static.py): visible text, forms and credential fields, script
  redirects, outbound links, empty/JS-shell/parked cues, lure language.
- `payment` (payment.py): providers, UPI deep links and VPAs, bank details,
  card fields, donation vocabulary, and payee attribution.
- `brand_references` (association.py): brand mentions, presentation, and
  association claims and disclaimers.
- `commerce` (commerce.py) and `editorial` (editorial.py, page-provided context).

Extractors observe; they never decide. Nothing is ever submitted or fetched.
Untrusted HTML is parsed in-process with a size-capped input (accepted residual
risk in the plan), and every regular expression scans a bounded prefix.
"""

import codecs
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser, LexborNode

MAX_RESOURCES = 200
MAX_TEXT = 512
# Visible text and inline script scanned by the regular-expression extractors.
MAX_SCAN_CHARS = 200_000
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_INVISIBLE_TAGS = ["script", "style", "noscript", "template", "svg", "head"]
_WS = re.compile(r"\s+")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


@dataclass(frozen=True)
class AnalysisContext:
    """Registry-derived knowledge extractors may use (see association.BrandLexicon
    and payment.ProviderCatalog). Either may be None, e.g. in unit tests."""

    lexicon: Any = None
    providers: Any = None


@dataclass
class Page:
    text: str
    url: str
    context: AnalysisContext = field(default_factory=AnalysisContext)
    _cache: dict = field(default_factory=dict, repr=False)

    def cached(self, key: str, fn: Callable[[], Any]) -> Any:
        """Memoize a derived value shared by several extractors."""
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    @property
    def tree(self) -> LexborHTMLParser:
        return self.cached("tree", lambda: LexborHTMLParser(self.text))

    @property
    def base(self) -> str:
        """The URL relative references resolve against (honouring <base href>)."""

        def compute() -> str:
            tag = self.tree.css_first("base[href]")
            href = absolute(self.url, tag.attributes.get("href")) if tag is not None else None
            return href or self.url

        return self.cached("base", compute)

    @property
    def visible_tree(self) -> LexborHTMLParser:
        """A second parse without script, style, template, SVG and head content."""

        def compute() -> LexborHTMLParser:
            tree = LexborHTMLParser(self.text)  # a copy: stripping mutates the tree
            tree.strip_tags(_INVISIBLE_TAGS)
            return tree

        return self.cached("visible_tree", compute)

    @property
    def visible_text(self) -> str:
        """Body text a reader sees, whitespace-collapsed and capped."""

        def compute() -> str:
            root = self.visible_tree.body or self.visible_tree.root
            raw = root.text(separator=" ") if root is not None else ""
            return _WS.sub(" ", raw).strip()[:MAX_SCAN_CHARS]

        return self.cached("visible_text", compute)

    @property
    def headings_joined(self) -> list[str]:
        """Headings with inline elements joined without a separator."""

        def compute() -> list[str]:
            out = [joined_text(n)[:MAX_TEXT] for n in self.visible_tree.css("h1, h2")]
            return [h for h in out if h][:20]

        return self.cached("headings_joined", compute)

    @property
    def body_joined_chunks(self) -> list[str]:
        """Visible body text with inline elements joined, in sentence-sized chunks."""

        def compute() -> list[str]:
            root = self.visible_tree.body or self.visible_tree.root
            raw = joined_text(root)[:MAX_SCAN_CHARS] if root is not None else ""
            return [c for c in _SENTENCE_END.split(raw) if c][:5000]

        return self.cached("body_joined", compute)

    @property
    def title(self) -> str | None:
        def compute() -> str | None:
            node = self.tree.css_first("title")
            return node_text(node)[:MAX_TEXT] if node is not None else None

        return self.cached("title", compute)

    @property
    def headings(self) -> list[str]:
        def compute() -> list[str]:
            # From the stripped tree: CSS-in-JS often puts <style> inside headings.
            out = [node_text(n)[:MAX_TEXT] for n in self.visible_tree.css("h1, h2")]
            return [h for h in out if h][:20]

        return self.cached("headings", compute)

    @property
    def sentences(self) -> list[str]:
        """Title, headings and body text split into sentence-sized segments."""

        def compute() -> list[str]:
            parts = [*filter(None, [self.title]), *self.headings]
            parts += [s for s in _SENTENCE_END.split(self.visible_text) if s]
            return parts

        return self.cached("sentences", compute)

    @property
    def inline_scripts(self) -> str:
        def compute() -> str:
            chunks, total = [], 0
            for n in self.tree.css("script"):
                if n.attributes.get("src"):
                    continue
                t = n.text(deep=True) or ""
                chunks.append(t[: MAX_SCAN_CHARS - total])
                total += len(chunks[-1])
                if total >= MAX_SCAN_CHARS:
                    break
            return "\n".join(chunks)

        return self.cached("inline_scripts", compute)


def node_text(node: LexborNode | None) -> str:
    if node is None:
        return ""
    return _WS.sub(" ", node.text(deep=True, separator=" ") or "").strip()


def joined_text(node: LexborNode | None) -> str:
    """Text with adjacent text nodes joined directly, as inline markup renders."""
    if node is None:
        return ""
    return _WS.sub(" ", node.text(deep=True, separator="") or "").strip()


@dataclass(frozen=True)
class Extractor:
    name: str
    version: str
    media_types: frozenset[str]
    fn: Callable[[Page], dict]


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
    data: bytes,
    content_type: str | None,
    charset: str | None,
    base_url: str,
    context: AnalysisContext | None = None,
) -> list[ExtractorResult]:
    page: Page | None = None
    out = []
    for ex in EXTRACTORS.values():
        if content_type not in ex.media_types:
            continue
        if page is None:
            page = Page(decode_body(data, charset), base_url, context or AnalysisContext())
        try:
            out.append(ExtractorResult(ex, ex.fn(page)))
        except Exception as e:  # one extractor's failure is recorded, not fatal
            out.append(ExtractorResult(ex, None, f"{type(e).__name__}: {e}"[:500]))
    return out


def host_of(url: str | None) -> str | None:
    """Lowercase hostname of a URL, or None."""
    if not url:
        return None
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


def registrable_of(host: str | None) -> str | None:
    """Registrable domain of a host (the host itself when it has none)."""
    if not host:
        return None
    from brandsentinel.matching.normalize import registrable_domain

    try:
        return registrable_domain(host) or host
    except Exception:  # an odd host from a page is not worth failing an extractor
        return host


def unique_matches(rx: re.Pattern, text: str, limit: int) -> list[str]:
    """Distinct matched strings, in order of first appearance, at most `limit`."""
    out: list[str] = []
    for m in rx.finditer(text):
        v = m.group(0).strip()
        if v not in out:
            out.append(v)
            if len(out) >= limit:
                break
    return out


def absolute(base: str, ref: str | None) -> str | None:
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
    return {"delay": delay, "url": absolute(base, rest) if rest else None}


def page_basics(text: str, base_url: str, tree: LexborHTMLParser | None = None) -> dict:
    tree = tree or LexborHTMLParser(text)
    base = base_url
    base_tag = tree.css_first("base[href]")
    base_href = None
    if base_tag is not None:
        base_href = absolute(base_url, base_tag.attributes.get("href"))
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
            absolute(base, link.attributes.get("href"))
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
        url = absolute(base, ref)
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


register(
    Extractor(
        "page_basics", "page_basics/1", HTML_TYPES, lambda p: page_basics(p.text, p.url, p.tree)
    )
)

# The M5 extractors register themselves on import, after page_basics.
from brandsentinel.analysis import (  # noqa: E402
    association,  # noqa: F401
    commerce,  # noqa: F401
    editorial,  # noqa: F401
    payment,  # noqa: F401
    static,  # noqa: F401
)
