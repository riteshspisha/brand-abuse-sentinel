"""Registry-driven, tiered domain matcher.

For one name it decides whether a confirmed registry domain suppresses it, which
brand hits it carries and why, and how strong the match is. Rules:

- Suppression: the host equals, or is a subdomain of, a confirmed official domain
  flagged `suppresses` (a confirmed third-party host suppresses only itself).
  Never a substring test, so `sadhguru.org.verify-login.xyz` is not suppressed by
  `sadhguru.org`.
- Registry domains that are not suppressing (legacy-unverified, candidate) yield
  a `registry_domain` hit and a label, so they are reported, not hidden.
- An official-domain lookalike (`isha.in.secure-donate.com`, `isha-in.com`,
  `sadhgurü.org`) is a strong hit.
- High-tier keywords match as substrings of the name, its hyphen-folded form and
  its skeleton; the reason records which form was needed.
- Low-tier keywords (`isha`) count as a whole token, or as an affix only when the
  name also carries a brand hit or an ecosystem context term. Otherwise the
  affix is recorded as a note and creates no candidate.
- An exclusion cancels only hits of its own keyword whose span lies inside the
  excluded word.
- Fuzzy keywords match name parts of 6+ characters within edit distance 2.

Results serialize deterministically; `matcher_version` changes whenever these
rules change, and `registry_digest` whenever the registry does.
"""

import hashlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from typing import Literal

from rapidfuzz.distance import Levenshtein

from brandsentinel.matching.normalize import NormalizedName, normalize
from brandsentinel.registry.model import Domain, Registry

MATCHER_VERSION = "2"
FUZZY_MIN_CHARS = 6
FUZZY_MAX_DISTANCE = 2

HitType = Literal["keyword", "token", "affix", "fuzzy", "official_lookalike", "registry_domain"]
Strength = Literal["strong", "weak"]

_STRONG_TYPES = {"keyword", "official_lookalike"}
_STATUS_LABELS = {
    "legacy-unverified": "legacy_whitelist_unverified",
    "candidate": "official_domain_candidate",
}


@dataclass(frozen=True)
class Hit:
    type: HitType
    keyword: str  # brand term, or registry domain for lookalike/registry hits
    brand: str
    tier: str | None = None
    reason: str | None = None  # substring | folded | homoglyph
    span: tuple[int, int] | None = None  # offsets in the form named by `reason`
    distance: int | None = None
    part: str | None = None  # name part a fuzzy hit matched
    context: tuple[str, ...] = ()
    status: str | None = None  # registry status for registry_domain hits

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, ())}


@dataclass(frozen=True)
class MatchResult:
    host: str
    unicode_host: str
    registrable_domain: str
    candidate: bool
    strength: Strength | None
    suppressed_by: str | None
    hits: tuple[Hit, ...]
    labels: tuple[str, ...]
    notes: tuple[str, ...]
    registry_digest: str
    matcher_version: str = MATCHER_VERSION

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hits"] = [h.to_dict() for h in self.hits]
        return d

    def to_json(self) -> str:
        # ASCII-only: names come from untrusted sources and may carry any code point.
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _find_all(text: str, term: str) -> Iterator[tuple[int, int]]:
    start = text.find(term)
    while start != -1:
        yield start, start + len(term)
        start = text.find(term, start + 1)


def _is_boundary(text: str, index: int) -> bool:
    return index < 0 or index >= len(text) or not text[index].isalnum()


def _is_token(text: str, span: tuple[int, int]) -> bool:
    # Digits also delimit a token here (isha2024), so test for letters only.
    a, b = span
    return (a == 0 or not text[a - 1].isalpha()) and (b == len(text) or not text[b].isalpha())


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


@dataclass
class _Keyword:
    term: str
    brand: str
    tier: str
    fuzzy: bool
    exclusions: list[str] = field(default_factory=list)


class Matcher:
    def __init__(self, registry: Registry) -> None:
        self.registry_digest = hashlib.sha256(
            registry.model_dump_json(by_alias=True).encode()
        ).hexdigest()[:16]
        self._keywords = [
            _Keyword(kw.term, brand.id, kw.tier, kw.fuzzy) for brand, kw in registry.keywords()
        ]
        by_term = {k.term: k for k in self._keywords}
        for ex in registry.exclusions:
            if ex.active and ex.scope in by_term:
                by_term[ex.scope].exclusions.append(ex.term)
        self._context = sorted({t.term for t in registry.context_terms if t.active})
        # Official domains suppress their subdomains too; a third-party domain
        # (a shared platform such as a blog host) suppresses only its exact host.
        self._suppressing = {d.name: d.kind == "official" for d in registry.suppressing_domains()}
        self._domains: dict[str, Domain] = {d.name: d for d in registry.domains if d.active}
        # Lookalike forms of every known domain, in skeleton space: as written,
        # with dots as hyphens, and with dots dropped.
        self._lookalikes: list[tuple[str, Domain]] = []
        for d in self._domains.values():
            skel = normalize(d.name).skeleton
            for form in sorted({skel, skel.replace(".", "-"), skel.replace(".", "")}):
                self._lookalikes.append((form, d))

    def match(self, name: str) -> MatchResult:
        """Match one name. Raises InvalidName for strings that are not DNS names."""
        n = normalize(name)
        notes: list[str] = []
        if n.wildcard:
            notes.append("wildcard")
        if n.idn:
            notes.append("idn")
        if n.idn_invalid:
            notes.append("idn_invalid")

        hits: list[Hit] = []
        hits += self._registry_hits(n)
        hits += self._lookalike_hits(n)
        hits += self._high_tier_hits(n, notes)
        hits += self._fuzzy_hits(n, hits)
        hits += self._low_tier_hits(n, hits, notes)

        suppressed_by = self._suppressor(n.host)
        hits.sort(key=lambda h: (h.type, h.keyword, h.span or (-1, -1), h.reason or ""))
        labels = sorted({_STATUS_LABELS[h.status] for h in hits if h.status in _STATUS_LABELS})
        if suppressed_by:
            notes.append("suppressed:official_domain")
            strength = None
        elif any(h.type in _STRONG_TYPES for h in hits):
            strength = "strong"
        else:
            strength = "weak" if hits else None
        return MatchResult(
            host=n.host,
            unicode_host=n.unicode_host,
            registrable_domain=n.registrable_domain,
            candidate=strength is not None,
            strength=strength,
            suppressed_by=suppressed_by,
            hits=tuple(hits),
            labels=tuple(labels),
            notes=tuple(sorted(set(notes))),
            registry_digest=self.registry_digest,
        )

    def _suppressor(self, host: str) -> str | None:
        # Most specific confirmed domain first, for a stable explanation.
        for d in sorted(self._suppressing, key=len, reverse=True):
            if host == d or (self._suppressing[d] and _under(host, d)):
                return d
        return None

    def _registry_hits(self, n: NormalizedName) -> list[Hit]:
        known = [d for d in self._domains.values() if _under(n.host, d.name)]
        if not known:
            return []
        d = max(known, key=lambda d: len(d.name))
        if self._suppressor(n.host) == d.name:
            return []
        return [Hit("registry_domain", d.name, d.brand, status=d.status)]

    def _lookalike_hits(self, n: NormalizedName) -> list[Hit]:
        hits = {}
        for form, d in self._lookalikes:
            if d.name in hits or _under(n.host, d.name):
                continue
            for text in (n.skeleton, n.residue):
                span = next(
                    (s for s in _find_all(text, form)
                     if _is_boundary(text, s[0] - 1) and _is_boundary(text, s[1])),
                    None,
                )  # fmt: skip
                if span:
                    reason = "substring" if form in n.plain else "homoglyph"
                    hits[d.name] = Hit(
                        "official_lookalike", d.name, d.brand, reason=reason, span=span
                    )
                    break
        return list(hits.values())

    def _high_tier_hits(self, n: NormalizedName, notes: list[str]) -> list[Hit]:
        # Spans are offsets in the form the reason names. `substring` and `folded`
        # need the brand literally in ASCII labels; anything that needed IDN
        # decoding, lookalike mapping or dropped characters is `homoglyph`.
        plain_folded = n.plain.replace("-", "")
        forms = (
            ("substring", n.plain),
            ("folded", plain_folded),
            ("folded", plain_folded.replace(".", "")),  # brand split by a dot
            ("homoglyph", n.skeleton),
            ("homoglyph", n.folded),
            ("homoglyph", n.folded.replace(".", "")),
            ("homoglyph", n.residue),
            ("homoglyph", n.residue.replace(".", "")),
        )
        hits = []
        for kw in self._keywords:
            if kw.tier != "high":
                continue
            for reason, text in forms:
                span = None
                for s in _find_all(text, kw.term):
                    excluded_by = self._excluded(kw, text, s)
                    if excluded_by:
                        notes.append(f"excluded:{excluded_by}")
                    else:
                        span = s
                        break
                if span:
                    hits.append(Hit("keyword", kw.term, kw.brand, kw.tier, reason, span))
                    break
        return hits

    def _fuzzy_hits(self, n: NormalizedName, found: list[Hit]) -> list[Hit]:
        parts = set()
        for label in n.skeleton.split("."):
            parts.add(label.replace("-", ""))
            parts.update(label.split("-"))
        parts = sorted(p for p in parts if len(p) >= FUZZY_MIN_CHARS)
        already = {h.keyword for h in found}
        hits = []
        for kw in self._keywords:
            if kw.term in already or not (kw.fuzzy or kw.tier == "high"):
                continue
            # Non-fuzzy high-tier keywords are still compared with parts that kept
            # a non-ASCII character, as a backstop for unmapped lookalikes.
            candidates = parts if kw.fuzzy else [p for p in parts if not p.isascii()]
            best = None
            for part in candidates:
                d = Levenshtein.distance(part, kw.term, score_cutoff=FUZZY_MAX_DISTANCE)
                if 0 < d <= FUZZY_MAX_DISTANCE and (best is None or (d, part) < best):
                    best = (d, part)
            if best:
                distance, part = best
                hits.append(Hit("fuzzy", kw.term, kw.brand, kw.tier, distance=distance, part=part))
        return hits

    def _low_tier_hits(self, n: NormalizedName, found: list[Hit], notes: list[str]) -> list[Hit]:
        brand_types = ("keyword", "fuzzy", "official_lookalike")
        brand_context = sorted(f"brand:{h.keyword}" for h in found if h.type in brand_types)
        hits = []
        for kw in self._keywords:
            if kw.tier != "low":
                continue
            context = tuple(
                brand_context + [t for t in self._context if t != kw.term and t in n.folded]
            )
            for span in _find_all(n.skeleton, kw.term):
                excluded_by = self._excluded(kw, n.skeleton, span)
                if excluded_by:
                    notes.append(f"excluded:{excluded_by}")
                    continue
                kind = "token" if _is_token(n.skeleton, span) else "affix"
                if kind == "affix" and not context:
                    notes.append(f"{kw.term}_affix_uncontexted")
                    continue
                hits.append(Hit(kind, kw.term, kw.brand, kw.tier, span=span, context=context))
        return hits

    @staticmethod
    def _excluded(kw: _Keyword, text: str, span: tuple[int, int]) -> str | None:
        """The exclusion word containing this hit's span, if any."""
        for term in kw.exclusions:
            for a, b in _find_all(text, term):
                if a <= span[0] and span[1] <= b:
                    return term
        return None
