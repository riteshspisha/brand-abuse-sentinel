"""Brand references on a page: mentions, presentation, association claims (U12).

`BrandLexicon` turns the registry into phrase patterns. A brand's name, its
aliases and its high-tier keywords are *strong* terms; a low-tier keyword (and an
alias that is only that keyword, such as `Isha` or `Lumina`) is *weak*, because
the word on its own is common (a place, a person, a product). Text is matched on
its confusable skeleton (lowercase, diacritics stripped, Latin lookalikes
mapped), with letter/digit boundaries, so `Illumina` never matches `Lumina`.

The `brand_references` extractor records where each brand appears (title,
headings, body, image alt text), whether the page *presents* a brand (a strong
mention in the title, a heading or an image's alt text, as a logo would be), and
association claims ("official partner of", "authorised by", "in association
with") made in the same sentence as a brand mention. A negated claim ("not
affiliated with") is a page-provided disclaimer, not a claim; disclaimers are
context and never reduce a score (KTD17). A possessive reference ("the
foundation's official website", "Lumina Foundation's official site") is not a
claim to be that site.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from brandsentinel.analysis import HTML_TYPES, Extractor, Page, register
from brandsentinel.matching.normalize import skeleton_of
from brandsentinel.registry.model import Registry

VERSION = "brand_references/1"
MAX_SNIPPET = 300
MAX_CLAIMS = 20
MAX_ALTS = 100
MAX_MATCHES = 500  # per piece of text

_CLAIM_PATTERNS: list[tuple[str, str]] = [
    (
        "partner",
        r"(?:official|authori[sz]ed|exclusive|registered|certified)?\s*partners?\s+(?:of|with|to|for)\b",
    ),
    (
        "authorized",
        r"authori[sz]ed\s+(?:by|to|partner|dealer|agent|representative|reseller|distributor|seller|centre|center|organi[sz]er|collection)\b",
    ),
    (
        "official",
        r"official\s+(?:site|website|web\s+site|page|store|shop|portal|partner|representative|donation|donations|account|app|channel|branch|centre|center|organi[sz]er|merchandise|distributor|seller|fundraiser|campaign)\b",
    ),
    ("official", r"(?:we\s+are|we're|this\s+is)\s+(?:the\s+)?official\b"),
    ("association", r"in\s+(?:association|partnership|collaboration|affiliation)\s+with\b"),
    ("endorsed", r"(?:endorsed|approved|certified|recogni[sz]ed|sponsored|appointed)\s+by\b"),
    ("affiliated", r"affiliated\s+(?:with|to)\b"),
    ("on_behalf", r"on\s+behalf\s+of\b"),
]
_CLAIMS = [(kind, re.compile(r"(?<![a-z])" + p)) for kind, p in _CLAIM_PATTERNS]
# A negation directly before a claim (at most two words between, same clause)
# turns it into a disclaimer: "not affiliated with", "is not an official partner".
_NEGATED = re.compile(
    r"(?<![a-z])(?:not|no|never|neither|nor|isn't|aren't|without)\s+(?:[a-z']+\s+){0,2}$"
)
_CLAUSE_BREAK = re.compile(r"[,;:|.!?()\[\]-]|\bbut\b")
_NEGATION_WINDOW = 40
# "<Brand>'s official website": the possessive sits immediately before the claim.
_POSSESSIVE = re.compile(r"\s*(?:['\u2019]s|s['\u2019])\s+(?:the\s+|own\s+)*")
MAX_SENTENCE = 2000  # characters of one sentence examined for claims
# Uppercase Cyrillic and Greek letters that render like Latin capitals. Text is
# lowercased before the shared confusables table applies, and the lowercase forms
# of these do not look Latin, so page text maps them first. Domain names are
# lowercase, so the matcher (M1) does not need this.
_UPPER_CONFUSABLES = {
    0x0410: "a", 0x0412: "b", 0x0415: "e", 0x041A: "k", 0x041C: "m", 0x041D: "h",
    0x041E: "o", 0x0420: "p", 0x0421: "c", 0x0422: "t", 0x0425: "x", 0x0406: "i",
    0x0408: "j", 0x0405: "s", 0x0391: "a", 0x0392: "b", 0x0395: "e", 0x0396: "z",
    0x0397: "h", 0x0399: "i", 0x039A: "k", 0x039C: "m", 0x039D: "n", 0x039F: "o",
    0x03A1: "p", 0x03A4: "t", 0x03A5: "y", 0x03A7: "x",
}  # fmt: skip
_WS = re.compile(r"\s+")


def text_skeleton(text: str) -> str:
    """Skeleton of page text for brand matching: uppercase lookalikes mapped,
    then the shared confusables skeleton (lowercase, marks and zero-width
    characters removed), with whitespace runs collapsed."""
    return _WS.sub(" ", skeleton_of(text.translate(_UPPER_CONFUSABLES)))


@dataclass(frozen=True)
class BrandTerm:
    brand: str  # registry brand id
    brand_name: str
    phrase: str
    strength: str  # strong | weak
    pattern: re.Pattern = field(compare=False, hash=False)


def _pattern(phrase: str) -> re.Pattern | None:
    words = re.findall(r"[a-z0-9]+", skeleton_of(phrase))
    if not words:
        return None
    body = r"[\s\-_.]*".join(re.escape(w) for w in words)
    return re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])")


@dataclass(frozen=True)
class KnownPayee:
    payee_id: str
    name: str
    brand: str
    identifier_type: str


@dataclass
class BrandLexicon:
    terms: list[BrandTerm]
    official_domains: dict[str, str]  # confirmed official domain -> brand id
    payees: dict[tuple[str, str], KnownPayee]  # (identifier type, normalized value)
    relationships: list[tuple[str, str, str]]  # confirmed (from, to, type)
    brand_names: dict[str, str]

    @classmethod
    def from_registry(cls, registry: Registry) -> "BrandLexicon":
        low = {k.term for _, k in registry.keywords() if k.tier == "low"}
        seen: set[tuple[str, str]] = set()
        terms: list[BrandTerm] = []

        def add(brand, phrase: str, strength: str) -> None:
            key = (brand.id, " ".join(re.findall(r"[a-z0-9]+", skeleton_of(phrase))))
            pattern = _pattern(phrase)
            if pattern is None or key in seen:
                return
            seen.add(key)
            terms.append(BrandTerm(brand.id, brand.name, phrase, strength, pattern))

        for brand in (b for b in registry.brands if b.active):
            add(brand, brand.name, "strong")
            for alias in brand.aliases:
                compact = "".join(re.findall(r"[a-z0-9]+", skeleton_of(alias)))
                add(brand, alias, "weak" if compact in low else "strong")
            for kw in (k for k in brand.keywords if k.active):
                add(brand, kw.term, "strong" if kw.tier == "high" else "weak")
        # Longest phrases first, so "Lumina Foundation" wins over "Lumina".
        terms.sort(key=lambda t: (-len(t.phrase), t.brand, t.phrase))
        payees = {}
        for p in registry.confirmed_payees():
            for ident in p.identifiers:
                key = (ident.type, normalize_identifier(ident.value))
                payees[key] = KnownPayee(p.id, p.name, p.brand, ident.type)
        return cls(
            terms=terms,
            official_domains={
                d.name: d.brand
                for d in registry.domains
                if d.kind == "official" and d.status == "confirmed"
            },
            payees=payees,
            relationships=[
                (r.from_, r.to, r.type) for r in registry.relationships if r.status == "confirmed"
            ],
            brand_names={b.id: b.name for b in registry.brands},
        )

    def find(self, text: str) -> list[tuple[BrandTerm, int, int]]:
        """Non-overlapping term matches in the skeleton of `text`, in order (at most
        MAX_MATCHES; longer phrases claim their span first)."""
        skel = text_skeleton(text)
        taken = bytearray(len(skel))
        out = []
        for term in self.terms:
            for m in term.pattern.finditer(skel):
                a, b = m.span()
                if 1 in taken[a:b]:
                    continue
                taken[a:b] = b"\x01" * (b - a)
                out.append((term, a, b))
                if len(out) >= MAX_MATCHES:
                    break
        out.sort(key=lambda x: x[1])
        return out

    def official_domain(self, host: str | None) -> str | None:
        if not host:
            return None
        for name in self.official_domains:
            if host == name or host.endswith("." + name):
                return name
        return None

    def confirmed_relationships(self, *hosts: str | None) -> list[dict]:
        names = {f"domain:{h}" for h in hosts if h}
        return [
            {"from": f, "to": t, "type": ty}
            for f, t, ty in self.relationships
            if f in names or t in names
        ]

    def known_payee(self, identifier_type: str, value: str | None) -> KnownPayee | None:
        if not value:
            return None
        return self.payees.get((identifier_type, normalize_identifier(value)))


def normalize_identifier(value: str) -> str:
    return re.sub(r"\s+", "", value).lower()


def mentions(page: Page) -> dict:
    """Shared, memoized brand-mention summary of a page (see module doc)."""

    def compute() -> dict:
        lex: BrandLexicon | None = page.context.lexicon
        if lex is None:
            return {"available": False, "brands": [], "presented": [], "by_sentence": []}
        brands: dict[str, dict] = {}

        def record(location: str, text: str) -> list[tuple[BrandTerm, int, int]]:
            found = lex.find(text)
            for term, a, b in found:
                entry = brands.setdefault(
                    term.brand,
                    {
                        "brand": term.brand,
                        "name": term.brand_name,
                        "strength": "weak",
                        "count": 0,
                        "locations": set(),
                        "terms": set(),
                        "strong_locations": set(),
                        "snippet": None,
                    },
                )
                entry["count"] += 1
                entry["locations"].add(location)
                entry["terms"].add(term.phrase)
                if term.strength == "strong":
                    entry["strength"] = "strong"
                    entry["strong_locations"].add(location)
                if entry["snippet"] is None:
                    entry["snippet"] = _window(text_skeleton(text), a, b)
            return found

        def record_extra(location: str, text: str) -> None:
            """A second rendering of the same text (inline elements joined, as a
            browser shows them): recorded only if it adds a brand, or a strong
            mention of one, that this location has not seen."""
            for term, _, _ in lex.find(text[:MAX_SENTENCE]):
                e = brands.get(term.brand)
                where = "strong_locations" if term.strength == "strong" else "locations"
                if e is None or location not in e[where]:
                    record(location, text[:MAX_SENTENCE])
                    return

        by_sentence = []

        def scan(location: str, text: str) -> None:
            found = record(location, text)
            if found:
                by_sentence.append((text, found))

        if page.title:
            scan("title", page.title)
        for h in page.headings:
            scan("heading", h)
        alts = [n.attributes.get("alt") or "" for n in page.tree.css("img[alt]")][:MAX_ALTS]
        for alt in alts:
            record("image_alt", alt)
        for s in page.sentences[(1 if page.title else 0) + len(page.headings) :]:
            scan("body", s)
        # "Lum<span>ina</span>" reads as one word on screen but as two in the
        # spaced rendering above.
        for h in page.headings_joined:
            record_extra("heading", h)
        for chunk in page.body_joined_chunks:
            record_extra("body", chunk)
        presented = sorted(
            b["brand"]
            for b in brands.values()
            if b["strong_locations"] & {"title", "heading", "image_alt"}
        )
        ordered = sorted(brands.values(), key=lambda b: (-b["count"], b["brand"]))
        return {
            "available": True,
            "brands": [
                {
                    **b,
                    "locations": sorted(b["locations"]),
                    "terms": sorted(b["terms"]),
                    "strong_locations": sorted(b["strong_locations"]),
                }
                for b in ordered
            ],
            "presented": presented,
            # (sentence, matches) for title, headings and body, for claim detection
            "by_sentence": by_sentence,
        }

    return page.cached("brand_mentions", compute)


def brands_in(page: Page, text: str) -> list[dict]:
    """Brands mentioned in an arbitrary piece of page text (form context, payee name)."""
    lex: BrandLexicon | None = page.context.lexicon
    if lex is None or not text:
        return []
    out: dict[str, str] = {}
    for term, _, _ in lex.find(text):
        if out.get(term.brand) != "strong":
            out[term.brand] = term.strength
    return [{"brand": b, "strength": s} for b, s in sorted(out.items())]


def _window(text: str, a: int, b: int, width: int = 120) -> str:
    start, end = max(0, a - width), min(len(text), b + width)
    return text[start:end].strip()[:MAX_SNIPPET]


def find_claims(sentences: Iterable[tuple[str, list]]) -> tuple[list[dict], list[dict]]:
    """(claims, disclaimers) from sentences that mention a brand."""
    claims, disclaimers = [], []
    for sentence, found in sentences:
        skel = text_skeleton(sentence)[:MAX_SENTENCE]
        brands = sorted({t.brand for t, _, _ in found})
        hits = []
        for kind, rx in _CLAIMS:
            hits += [(kind, m.start(), m.end()) for m in rx.finditer(skel)]
        # "<Brand> Official" (a title such as "Lumina Foundation Official - ...").
        for term, _, b in found:
            m = re.match(r"\s*[-|:]?\s*official(?![a-z])", skel[b:])
            if m and term.strength == "strong":
                hits.append(("official", b, b + m.end()))
        for kind, a, _end in sorted(set(hits), key=lambda h: h[1]):
            before = skel[max(0, a - _NEGATION_WINDOW) : a]
            breaks = list(_CLAUSE_BREAK.finditer(before))
            clause = before[breaks[-1].end() :] if breaks else before
            item = {"kind": kind, "brands": brands, "snippet": skel.strip()[:MAX_SNIPPET]}
            if _NEGATED.search(clause):
                disclaimers.append(item)
                continue
            # "Lumina Foundation's official website" refers to the brand's own site.
            if any(tb <= a and _POSSESSIVE.fullmatch(skel[tb:a]) for _, _, tb in found):
                continue
            claims.append(item)
            if len(claims) >= MAX_CLAIMS:
                return _dedupe(claims), _dedupe(disclaimers)
    return _dedupe(claims), _dedupe(disclaimers)


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for i in items:
        key = (i["kind"], i["snippet"])
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out


def brand_references(page: Page) -> dict:
    m = mentions(page)
    if not m["available"]:
        return {"available": False}
    claims, disclaimers = find_claims(m["by_sentence"])
    strong = [b["brand"] for b in m["brands"] if b["strength"] == "strong"]
    return {
        "available": True,
        "brands": m["brands"],
        "presented": m["presented"],
        "strong_mention": bool(strong),
        "weak_only": bool(m["brands"]) and not strong,
        "claims": claims,
        "disclaimers": disclaimers,
        "page_provided_disclaimers": True,
    }


register(Extractor("brand_references", VERSION, HTML_TYPES, brand_references))
