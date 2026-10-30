"""EvidenceBundle: the compact, versioned evidence for one case (U13, R23, FA7).

The bundle is a pure function of a case's stored records (discovery events and
sources, facts, features) and the registry: rebuilding it from the same inputs
yields identical bytes. It is what the policy scores, what the report shows and,
in M8, what a model sees after rendering.

Blocks keep their provenance: each carries `refs` ("fact:<id>", "feature:<id>",
"artifact:<sha256>"), and every payment observation carries its own refs and
extractor version. Discovery similarity (how the *name* matched) is kept apart
from observed website behaviour (what the *page* did). Untrusted text is
re-sanitized and capped here even though the store already sanitized it.

Analysis rounds: the bundle describes the latest round that has a final static
fetch, with that round's enrichment (or the latest available) beside it.

Rendering (M7): when the round's browser render completed, the page, credential,
payment, association, commerce and editorial blocks describe the rendered page
(its extractor features reference the `browser_render` fact), unless the
static-versus-rendered comparison says the static page showed abuse indicators
the rendered one lacks. The `render` block says what the browser did and saw,
and the screenshot's matches, image text and QR payees join the visual and
payment blocks under the role `screenshot`.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from brandsentinel.analysis.association import BrandLexicon
from brandsentinel.evidence.models import FactRecord, FeatureRecord, load_facts, load_features
from brandsentinel.matching.normalize import InvalidName, normalize
from brandsentinel.registry.model import Registry
from brandsentinel.textsafe import sanitize_fact

# bundle/2 (M5 corrections): RegistryContext gained credential_destinations and
# vouching_brands. bundle/3 (M6): the `visual` block (media analysis, OCR, QR,
# visual matches) and payment observations read from images. Earlier versions
# are still accepted, only so stored scores made with them load with their
# original label; every block they lack has a default.
# bundle/4 (M7): the `render` block, `render_reason` and `cloaking`, content
# blocks from the rendered page, and screenshot evidence in `visual`.
# bundle/5 (M8): `render.requested_round` and `render.analyst_budget`.
SCHEMA_VERSION = "bundle/5"
SCHEMA_VERSIONS = ("bundle/1", "bundle/2", "bundle/3", "bundle/4", "bundle/5")
MAX_SNIPPETS = 20
MAX_SNIPPET_CHARS = 300
MAX_EXCERPT_CHARS = 1000
MAX_EVENTS = 20
MAX_HOPS = 10
MAX_LIST = 20
STRONG_HITS = frozenset({"keyword", "official_lookalike"})


class _Block(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _s(value: Any, limit: int = MAX_SNIPPET_CHARS) -> Any:
    """Sanitize every string in a JSON-like value (idempotent)."""
    if isinstance(value, str):
        return sanitize_fact(value, limit)
    if isinstance(value, dict):
        return {sanitize_fact(str(k), 100): _s(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_s(v, limit) for v in value[: MAX_LIST * 5]]
    return value


def iso(ts: float | None) -> str | None:
    """UTC ISO 8601 (seconds) for an epoch timestamp, or None."""
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds") if ts else None


_iso = iso


class Subject(_Block):
    case_id: int
    status: str
    host: str
    unicode_host: str | None = None
    registrable_domain: str | None = None
    subject_url: str | None = None
    case_created_at: str | None = None


class DiscoverySource(_Block):
    source: str
    first_seen: str | None
    last_seen: str | None
    observations: int


class DiscoveryEvent(_Block):
    source: str
    observed_at: str | None
    detail: dict[str, Any] = {}


class Discovery(_Block):
    """How the name was found and how it matched (discovery similarity)."""

    sources: list[DiscoverySource] = []
    recent_events: list[DiscoveryEvent] = []
    candidate_strength: str | None = None  # queue class; manual submissions are strong
    domain_match: Literal["strong", "weak", "none"] = "none"  # from the matcher's hits
    hits: list[dict[str, Any]] = []
    labels: list[str] = []
    notes: list[str] = []
    suppressed_by: str | None = None
    matcher_version: str | None = None
    refs: list[str] = []  # discovery_event:<event id>


class RegistryContext(_Block):
    official_domain: str | None = None  # host under a confirmed official domain
    final_url_official_domain: str | None = None
    confirmed_relationships: list[dict[str, str]] = []
    registry_domains: list[dict[str, str]] = []  # non-confirmed registry matches (context)
    # Brands the registry vouches for this host under: the brand of its confirmed
    # official domain (or of the official domain the fetch ended on), and the brand
    # side of its confirmed relationships.
    vouching_brands: list[str] = []
    # Off-site registrable domains that credential forms submit to. Approval is
    # per brand: `approved_for` lists the brands a confirmed registry domain or
    # brand relationship approves the destination for, with `approved_by` refs;
    # `ambiguous` holds confirmed relationships that name no brand, which approve
    # nothing. Confirming a host's affiliation does not approve its destinations.
    credential_destinations: list[dict[str, Any]] = []


class Infrastructure(_Block):
    analysis_round: int | None = None
    enrichment: Literal["ok", "partial", "not_run"] = "not_run"
    dns: dict[str, Any] | None = None
    rdap: dict[str, Any] | None = None
    tls: dict[str, Any] | None = None
    similarity: dict[str, Any] | None = None
    dns_mixed_private: bool = False
    domain_age_days: int | None = None
    errors: list[dict[str, Any]] = []
    refs: list[str] = []


class Hop(_Block):
    url: str | None = None
    status: int | None = None
    address: str | None = None
    location: str | None = None
    via: str | None = None
    error: str | None = None


class Http(_Block):
    fetched: bool = False
    analysis_round: int | None = None
    outcome: str | None = None
    requested_url: str | None = None
    final_url: str | None = None
    final_host: str | None = None
    status: int | None = None
    redirect_chain: list[Hop] = []
    content_type: str | None = None
    body_sha256: str | None = None
    body_bytes: int | None = None
    body_truncated: str | None = None
    body_stored: bool = False
    tls_verification_failed: bool = False
    error: dict[str, Any] | None = None
    attempts: list[dict[str, Any]] = []
    refs: list[str] = []


class PageBlock(_Block):
    available: bool = False
    title: str | None = None
    headings: list[str] = []
    meta_description: str | None = None
    lang: str | None = None
    text_excerpt: str | None = None
    text_chars: int = 0
    empty: bool = False
    js_shell: bool = False
    image_only: bool = False
    parked_cues: list[dict[str, Any]] = []
    lures: list[dict[str, Any]] = []
    script_redirects: list[dict[str, Any]] = []
    meta_refresh: list[dict[str, Any]] = []
    external_domains: list[str] = []
    messaging_links: list[dict[str, Any]] = []
    link_schemes: dict[str, int] = {}
    refs: list[str] = []


class CredentialBlock(_Block):
    password_fields: int = 0
    password_fields_outside_forms: int = 0
    otp_fields: int = 0
    forms: list[dict[str, Any]] = []  # forms with password or one-time-code fields
    cross_origin_forms: int = 0
    refs: list[str] = []


class PaymentObservation(_Block):
    kind: str
    source: str | None = None
    identifier_type: str | None = None
    payee_identifier: str | None = None
    payee_name: str | None = None
    provider: str | None = None
    destination: str | None = None
    amount: str | None = None
    currency: str | None = None
    ifsc: str | None = None
    attribution: str
    attribution_reason: str | None = None
    attributed_brands: list[str] = []
    registry_payee: dict[str, str] | None = None
    extractor_version: str
    # The image a QR code or image text was read from (sha256); None for page text.
    image_sha256: str | None = None
    refs: list[str] = []


class PaymentBlock(_Block):
    catalog_version: str | None = None
    providers: list[dict[str, Any]] = []
    observations: list[PaymentObservation] = []
    donation_cues: list[str] = []
    card_fields: int = 0
    card_forms: list[int] = []
    qr_images: list[str] = []
    refs: list[str] = []


class AssociationBlock(_Block):
    available: bool = False
    brands: list[dict[str, Any]] = []
    presented: list[str] = []
    strong_mention: bool = False
    weak_only: bool = False
    claims: list[dict[str, Any]] = []
    disclaimers: list[dict[str, Any]] = []
    refs: list[str] = []


class CommerceBlock(_Block):
    commerce: bool = False
    prices: list[str] = []
    calls_to_action: list[str] = []
    cart: bool = False
    product_markup: list[str] = []
    refs: list[str] = []


class EditorialBlock(_Block):
    page_provided: bool = True
    editorial: bool = False
    article_markup: dict[str, Any] = {}
    byline: str | None = None
    published: str | None = None
    parody_cues: list[str] = []
    disclaimer_cues: list[str] = []
    critical_cues: list[str] = []
    refs: list[str] = []


class VisualImage(_Block):
    """One image selected for media analysis, and what became of it."""

    ref: str  # its URL, or inline:<n> for a data: image in the page
    role: str  # qr | logo | favicon | og_image | page_image | inline
    why: list[str] = []
    fetch_outcome: str | None = None  # None for inline images
    status: str  # ok | rejected | failed | not_fetched
    reason: str | None = None
    sha256: str | None = None
    stored: bool = False
    format: str | None = None
    width: int | None = None
    height: int | None = None
    frames: int | None = None
    phash: str | None = None
    dhash: str | None = None
    favicon_mmh3: int | None = None
    low_information: bool = False
    ocr_status: str | None = None
    ocr_chars: int = 0
    qr_codes: int = 0
    gaps: list[str] = []  # requested OCR or QR decoding that did not finish
    refs: list[str] = []


class VisualMatch(_Block):
    image_sha256: str
    image_ref: str
    role: str
    method: str  # sha256 | perceptual
    phash_distance: int
    dhash_distance: int
    reference: dict[str, Any]  # corpus entry: brand, kind, origin, source, ...
    refs: list[str] = []


class VisualBlock(_Block):
    """Media analysis (M6): which images were examined and why, what the media
    sandbox reported, OCR and QR content, and matches against the reference
    corpus. `status` keeps what was not observed visible: `pending`, `failed`,
    `partial` and `disabled` are unknowns, never a clean result."""

    status: Literal[
        "not_run", "not_triggered", "disabled", "pending", "complete", "partial", "failed"
    ] = "not_run"
    analysis_round: int | None = None
    reasons: list[str] = []  # why media analysis was triggered
    skipped: str | None = None  # why it was not
    images: list[VisualImage] = []
    rejected: list[dict[str, Any]] = []  # media_rejected: {ref, role, reason}
    matches: list[VisualMatch] = []
    matcher: dict[str, Any] | None = None
    corpus_version: str | None = None
    corpus_entries: int = 0
    images_not_selected: int = 0  # wanted images left out by the per-case cap
    ocr_text: list[dict[str, Any]] = []  # {image, role, text}: bounded, sanitized
    ocr_brands: list[dict[str, Any]] = []
    ocr_presented: list[str] = []  # brands an image presents by a strong term
    donation_cues: list[str] = []
    qr_payloads: list[dict[str, Any]] = []
    refs: list[str] = []


class RenderBlock(_Block):
    """Isolated browser rendering (M7): whether the case was rendered and why,
    and what the browser saw. `status` keeps the unobserved visible: `pending`,
    `failed`, `rejected` (the worker's document failed validation), `refused`
    (not started, for example a failed network check) and `disabled` are
    unknowns, never a clean result."""

    status: Literal[
        "not_run", "not_triggered", "disabled", "pending", "complete", "failed", "rejected",
        "refused",
    ] = "not_run"  # fmt: skip
    analysis_round: int | None = None
    reasons: list[str] = []  # why it was rendered
    sampled: bool = False
    skipped: str | None = None  # why it was not
    reason: str | None = None  # why it failed
    # A render an analyst requested for a later round, not decided yet (M8).
    requested_round: int | None = None
    # browser.analyst_renders_per_day when this round decided a request (M8).
    analyst_budget: int | None = None
    requested_url: str | None = None
    final_url: str | None = None
    final_host: str | None = None
    main_status: int | None = None
    network_idle: bool = False
    redirect_chain: list[Hop] = []
    navigations: list[str] = []
    request_hosts: list[str] = []  # every host the page requested, through the proxy
    refused_requests: list[dict[str, Any]] = []  # {host, url, reason}: refused by the proxy
    page_actions: dict[str, int] = {}  # what the page tried on its own and was stopped
    screenshot: dict[str, Any] | None = None  # {sha256, stored, width, height, media}
    content_source: Literal["static", "rendered"] = "static"
    refs: list[str] = []


class Snippet(_Block):
    field: str
    text: str


class EvidenceBundle(_Block):
    schema_version: Literal[SCHEMA_VERSIONS] = SCHEMA_VERSION  # type: ignore[valid-type]
    subject: Subject
    discovery: Discovery = Discovery()
    registry: RegistryContext = RegistryContext()
    infrastructure: Infrastructure = Infrastructure()
    http: Http = Http()
    page: PageBlock = PageBlock()
    credential: CredentialBlock = CredentialBlock()
    payment: PaymentBlock = PaymentBlock()
    association: AssociationBlock = AssociationBlock()
    commerce: CommerceBlock = CommerceBlock()
    editorial: EditorialBlock = EditorialBlock()
    visual: VisualBlock = VisualBlock()
    render: RenderBlock = RenderBlock()
    # Never filled: superseded by visual.matches (bundle/3). Kept so bundle/1 and
    # bundle/2 documents keep loading.
    visual_matches: list[dict[str, Any]] = []
    render_reason: str | None = None  # the first of render.reasons
    # The static-versus-rendered comparison (cloaking/1), when the case was rendered.
    cloaking: dict[str, Any] | None = None
    snippets: list[Snippet] = Field(default_factory=list, max_length=MAX_SNIPPETS)
    extractor_errors: list[dict[str, str]] = []
    # What could not be observed, in plain words ("not_fetched", "js_shell", ...).
    incomplete: list[str] = []


def bundle_json(bundle: EvidenceBundle) -> str:
    """Canonical serialization: sorted keys, ASCII only, no whitespace."""
    return json.dumps(
        bundle.model_dump(mode="json"), sort_keys=True, ensure_ascii=True, separators=(",", ":")
    )


def bundle_sha256(bundle: EvidenceBundle) -> str:
    return hashlib.sha256(bundle_json(bundle).encode("ascii")).hexdigest()


def bundle_schema() -> dict:
    return EvidenceBundle.model_json_schema()


# --- inputs ------------------------------------------------------------------------


@dataclass
class CaseInputs:
    case_id: int
    status: str
    subject_url: str | None
    created_at: float
    host: str
    registrable_domain: str | None
    match_strength: str
    sources: list[dict]
    events: list[dict]
    facts: list[FactRecord]
    features: list[FeatureRecord]


def load_inputs(conn: sqlite3.Connection, case_id: int) -> CaseInputs | None:
    row = conn.execute(
        "SELECT c.id, c.status, c.subject_url, c.created_at, k.name, k.registrable_domain,"
        " k.match_strength, k.id FROM cases c JOIN candidates k ON k.id = c.candidate_id"
        " WHERE c.id = ?",
        (case_id,),
    ).fetchone()
    if row is None:
        return None
    sources = [
        {"source": r[0], "first_seen": r[1], "last_seen": r[2], "observations": r[3]}
        for r in conn.execute(
            "SELECT source, first_seen, last_seen, observations FROM candidate_sources"
            " WHERE candidate_id = ? ORDER BY source",
            (row[7],),
        )
    ]
    events = [
        {
            "source": r[0],
            "observed_at": r[1],
            "match": json.loads(r[2]),
            "context": json.loads(r[3]),
            "event_id": r[4],
        }
        for r in conn.execute(
            "SELECT source, observed_at, match_json, context_json, event_id FROM discovery_events"
            " WHERE candidate_id = ? ORDER BY observed_at DESC, event_id LIMIT ?",
            (row[7], MAX_EVENTS),
        )
    ]
    return CaseInputs(
        case_id=row[0],
        status=row[1],
        subject_url=row[2],
        created_at=row[3],
        host=row[4],
        registrable_domain=row[5],
        match_strength=row[6],
        sources=sources,
        events=events,
        facts=load_facts(conn, case_id),
        features=load_features(conn, case_id),
    )


# --- builder -----------------------------------------------------------------------


def _event_detail(source: str, context: dict) -> dict:
    keys = {
        "certstream": ("fingerprint", "issuer", "not_before", "not_after", "san_count", "log_name"),
        "dnstwist": ("target", "fuzzer", "run_id"),
        "manual": ("submitted", "url"),
    }.get(source, ())
    out = {k: context[k] for k in keys if context.get(k) not in (None, "", [], {})}
    for k in ("not_before", "not_after"):
        if isinstance(out.get(k), int | float):
            out[k] = _iso(out[k])
    return _s(out, 200)


def _discovery(inputs: CaseInputs) -> Discovery:
    match = next((e["match"] for e in inputs.events if e.get("match")), {}) or {}
    hits = match.get("hits") or []
    types = {h.get("type") for h in hits}
    domain_match = "strong" if types & STRONG_HITS else ("weak" if hits else "none")
    return Discovery(
        sources=[
            DiscoverySource(
                source=s["source"],
                first_seen=_iso(s["first_seen"]),
                last_seen=_iso(s["last_seen"]),
                observations=s["observations"],
            )
            for s in inputs.sources
        ],
        recent_events=[
            DiscoveryEvent(
                source=e["source"],
                observed_at=_iso(e["observed_at"]),
                detail=_event_detail(e["source"], e["context"] or {}),
            )
            for e in inputs.events
        ],
        candidate_strength=inputs.match_strength,
        domain_match=domain_match,
        hits=[_s(h, 200) for h in hits[:MAX_LIST]],
        labels=list(match.get("labels") or []),
        notes=list(match.get("notes") or [])[:MAX_LIST],
        suppressed_by=match.get("suppressed_by"),
        matcher_version=match.get("matcher_version"),
        refs=[f"discovery_event:{e['event_id']}" for e in inputs.events[:5]],
    )


def _registry_matches(registry: Registry | None, *hosts: str | None) -> list[dict]:
    if registry is None:
        return []
    out = []
    for d in registry.domains:
        for h in filter(None, hosts):
            if (h == d.name or h.endswith("." + d.name)) and d.status != "confirmed":
                item = {"domain": d.name, "status": d.status, "kind": d.kind, "host": h}
                if item not in out:
                    out.append(item)
    return out


def _brand_side(relationship: dict, own: str) -> str | None:
    """The brand id on the other side of a relationship from `own`, if it is one."""
    other = relationship["to"] if relationship["from"] == own else relationship["from"]
    return other.removeprefix("brand:") if other.startswith("brand:") else None


def _vouching_brands(lexicon: BrandLexicon, host_refs: list[str | None]) -> list[str]:
    brands = []
    for official in host_refs[:2]:
        if official and lexicon.official_domains.get(official):
            brands.append(lexicon.official_domains[official])
    for host in host_refs[2:]:
        for rel in lexicon.confirmed_relationships(host) if host else []:
            brand = _brand_side(rel, f"domain:{host}")
            if brand:
                brands.append(brand)
    return sorted(set(brands))


def _credential_destinations(
    forms: list[dict], lexicon: BrandLexicon, registry: Registry | None
) -> list[dict]:
    out: list[dict] = []
    for f in forms:
        d = f.get("action_registrable_domain")
        if not f.get("cross_origin") or not d or any(x["domain"] == d for x in out):
            continue
        approved_for, approved_by, ambiguous = set(), [], []
        for entry in registry.domains if registry is not None else []:
            if entry.status == "confirmed" and (d == entry.name or d.endswith("." + entry.name)):
                approved_for.add(entry.brand)
                approved_by.append(f"registry:domain:{entry.name}")
        official = lexicon.official_domain(d)
        if registry is None and official:
            approved_for.add(lexicon.official_domains[official])
            approved_by.append(f"registry:domain:{official}")
        for rel in lexicon.confirmed_relationships(d):
            ref = f"registry:relationship:{rel['from']}>{rel['to']}"
            brand = _brand_side(rel, f"domain:{d}")
            if brand:
                approved_for.add(brand)
                approved_by.append(ref)
            else:
                ambiguous.append(ref)
        out.append(
            {
                "domain": d,
                "approved_for": sorted(approved_for),
                "approved_by": approved_by,
                "ambiguous": ambiguous,
            }
        )
    return out


def _latest(facts: list[FactRecord], name: str, rnd: int | None) -> FactRecord | None:
    same = [f for f in facts if f.name == name and (rnd is None or f.round == rnd)]
    if same:
        return same[-1]
    any_round = [f for f in facts if f.name == name]
    return any_round[-1] if any_round else None


def _infrastructure(facts: list[FactRecord], rnd: int | None) -> Infrastructure:
    refs: list[str] = []
    errors = []
    dns = rdap = tls = similarity = None
    mixed = False
    age = None
    used_round = None
    names = ("dns_records", "rdap_registration", "tls_certificate", "similarity")
    picked = {n: _latest(facts, n, rnd) for n in names}
    for n in ("dns_error", "rdap_error", "tls_error", "similarity_error"):
        f = _latest(facts, n, rnd)
        if f is not None and (rnd is None or f.round == rnd):
            errors.append({"source": f.source, **_s(f.value, 200)})
            refs.append(f"fact:{f.id}")
    if (f := picked["dns_records"]) is not None:
        v = f.value
        records = v.get("records", {})
        dns = {
            "status": v.get("status"),
            "a": records.get("A", {}).get("values", []),
            "aaaa": records.get("AAAA", {}).get("values", []),
            "cname": records.get("CNAME", {}).get("values", []),
            "mx": records.get("MX", {}).get("values", [])[:5],
            "ns": records.get("NS", {}).get("values", [])[:5],
            "all_public": v.get("address_policy", {}).get("all_public"),
        }
        mixed = bool(v.get("address_policy", {}).get("dns_mixed_private"))
    if (f := picked["rdap_registration"]) is not None:
        v = f.value
        registrar = v.get("registrar") or {}
        rdap = {
            "domain": v.get("domain"),
            "cached": v.get("cached"),
            "registered_at": v.get("registered_at"),
            "expires_at": v.get("expires_at"),
            "registrar": registrar.get("name") if isinstance(registrar, dict) else registrar,
            "redacted": v.get("redacted"),
            "nameservers": (v.get("nameservers") or [])[:5],
        }
        age = v.get("domain_age_days")
    if (f := picked["tls_certificate"]) is not None:
        v = f.value
        cert = v.get("certificate") or {}
        tls = {
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "san_dns": (cert.get("san_dns") or [])[:10],
            "self_signed": cert.get("self_signed"),
            "verification_passes": v.get("verification_passes"),
            "verification_error": v.get("verification_error"),
        }
    if (f := picked["similarity"]) is not None:
        v = f.value
        close = sorted(
            (b for b in v.get("brands", []) if b.get("min_label_distance") is not None),
            key=lambda b: (b["min_label_distance"], b["keyword"]),
        )[:3]
        similarity = {
            "idn": v.get("idn"),
            "closest_official_domains": (v.get("closest_official_domains") or [])[:3],
            "closest_keywords": [
                {k: b.get(k) for k in ("brand", "keyword", "min_label_distance", "contains")}
                for b in close
            ],
        }
    for f in picked.values():
        if f is not None:
            refs.append(f"fact:{f.id}")
            used_round = f.round if used_round is None else used_round
    enrichment = "not_run"
    if any(picked.values()):
        enrichment = "partial" if errors or not all(picked.values()) else "ok"
    return Infrastructure(
        analysis_round=used_round,
        enrichment=enrichment,
        dns=_s(dns, 300),
        rdap=_s(rdap, 300),
        tls=_s(tls, 300),
        similarity=_s(similarity, 300),
        dns_mixed_private=mixed,
        domain_age_days=age if isinstance(age, int) else None,
        errors=errors,
        refs=sorted(set(refs), key=_ref_key),
    )


def _ref_key(ref: str) -> tuple:
    kind, _, value = ref.partition(":")
    return (kind, int(value) if value.isdigit() else 0, value)


def _http(facts: list[FactRecord]) -> tuple[Http, FactRecord | None]:
    finals = [f for f in facts if f.name == "http_fetch" and f.value.get("final")]
    if not finals:
        attempts = [f for f in facts if f.name == "http_fetch_attempt"]
        return Http(
            attempts=[
                _s(
                    {
                        "url": a.value.get("requested_url"),
                        "outcome": a.value.get("outcome"),
                        "error": (a.value.get("error") or {}).get("kind"),
                    }
                )
                for a in attempts[-5:]
            ],
            refs=[f"fact:{a.id}" for a in attempts[-5:]],
        ), None
    final = finals[-1]
    rnd = final.round
    v = final.value
    same_round = [f for f in facts if f.name == "http_fetch" and f.round == rnd]
    body = v.get("body") or {}
    hops = [
        Hop(
            url=h.get("url"),
            status=h.get("status"),
            address=h.get("address"),
            location=h.get("location"),
            via=h.get("via"),
            error=(h.get("error") or {}).get("kind") if isinstance(h.get("error"), dict) else None,
        )
        for h in (v.get("hops") or [])[:MAX_HOPS]
    ]
    final_host = None
    if v.get("final_url"):
        try:
            final_host = normalize(urlsplit(v["final_url"]).hostname or "").host
        except (InvalidName, ValueError):
            final_host = None
    refs = [f"fact:{f.id}" for f in same_round] + [f"artifact:{a}" for a in final.artifact_refs]
    return Http(
        fetched=True,
        analysis_round=rnd,
        outcome=v.get("outcome"),
        requested_url=v.get("requested_url"),
        final_url=v.get("final_url"),
        final_host=final_host,
        status=v.get("status"),
        redirect_chain=[Hop(**_s(h.model_dump(), 500)) for h in hops],
        content_type=body.get("content_type"),
        body_sha256=body.get("sha256"),
        body_bytes=body.get("decoded_bytes"),
        body_truncated=body.get("truncated"),
        body_stored=bool(v.get("body_stored")),
        tls_verification_failed=bool(v.get("tls_verification_failed")),
        error=_s(v.get("error"), 300),
        attempts=[
            _s({"url": f.value.get("requested_url"), "outcome": f.value.get("outcome")})
            for f in same_round
        ],
        refs=refs,
    ), final


def _features_for(features: list[FeatureRecord], fact: FactRecord | None) -> dict:
    if fact is None:
        return {}
    out: dict[str, FeatureRecord] = {}
    for f in features:
        if fact.id in f.fact_refs:
            out[f.name] = f
    return out


MAX_MEDIA_OBSERVATIONS = 10
MAX_OCR_SNIPPET = 500


def _round_fact(facts: list[FactRecord], name: str, rnd: int | None) -> FactRecord | None:
    same = [f for f in facts if f.name == name and f.round == rnd]
    return same[-1] if same else None


def _visual(
    facts: list[FactRecord], features: list[FeatureRecord], rnd: int | None
) -> tuple[VisualBlock, list[PaymentObservation]]:
    """The visual block for the round of the final static fetch, and payment
    observations read from its images."""
    decision = _round_fact(facts, "media_decision", rnd) if rnd is not None else None
    if decision is None:
        return VisualBlock(), []
    dv = decision.value
    base = {
        "analysis_round": rnd,
        "reasons": _s(list(dv.get("reasons") or [])[:MAX_LIST], 100),
        "skipped": _s(dv.get("skipped"), 100),
        "images_not_selected": int(dv.get("images_not_selected") or 0),
        "refs": [f"fact:{decision.id}"],
    }
    if not dv.get("triggered"):
        return VisualBlock(status="not_triggered", **base), []
    if not dv.get("media_enabled", True):
        return VisualBlock(status="disabled", **base), []
    # A recheck whose content did not change carries the earlier round's result.
    source = dv.get("carried_from_round", rnd)
    analysis = _round_fact(facts, "media_analysis", source)
    if analysis is None:
        return VisualBlock(status="pending", **base), []
    av = analysis.value
    status = av.get("status") if av.get("status") in ("complete", "partial", "failed") else "failed"
    if "images" not in av:  # dropped by the fact size cap: nothing is known about them
        status = "failed"
    afact = f"fact:{analysis.id}"
    stored = set(analysis.artifact_refs)

    def image_refs(sha: str | None) -> list[str]:
        return [afact] + ([f"artifact:{sha}"] if sha and sha in stored else [])

    images, rejected, ocr_text = [], [], []
    for im in (av.get("images") or [])[:MAX_LIST]:
        r = im.get("result") or {}
        ocr = r.get("ocr") or {}
        sha = im.get("sha256")
        vi = VisualImage(
            ref=_s(im.get("ref") or "?", 500),
            role=_s(im.get("role") or "?", 40),
            why=_s(list(im.get("why") or [])[:10], 60),
            fetch_outcome=(im.get("fetch") or {}).get("outcome"),
            status=im.get("status") or "failed",
            reason=_s(im.get("reason"), 200),
            sha256=sha,
            stored=bool(sha and sha in stored),
            format=r.get("format"),
            width=r.get("width"),
            height=r.get("height"),
            frames=r.get("frames"),
            phash=r.get("phash"),
            dhash=r.get("dhash"),
            favicon_mmh3=r.get("favicon_mmh3"),
            low_information=bool(im.get("low_information")),
            ocr_status=ocr.get("status"),
            gaps=_s(list(im.get("gaps") or [])[:5], 40),
            ocr_chars=int(ocr.get("chars") or 0),
            qr_codes=len((r.get("qr") or {}).get("codes") or []),
            refs=image_refs(sha),
        )
        images.append(vi)
        if im.get("status") in ("rejected", "failed"):  # media_rejected (AE12)
            rejected.append({"ref": vi.ref, "role": vi.role, "reason": vi.reason})
        if ocr.get("text"):
            ocr_text.append(
                {
                    "image": sha,
                    "role": vi.role,
                    "text": sanitize_fact(ocr["text"], MAX_OCR_SNIPPET),
                }
            )
    own = [f for f in features if analysis.id in f.fact_refs]
    feats = {f.name: f for f in own}
    vm, mt = feats.get("visual_matches"), feats.get("media_text")
    vmv = vm.value if vm and isinstance(vm.value, dict) else {}
    mtv = mt.value if mt and isinstance(mt.value, dict) and mt.value.get("available") else {}
    by_sha = {i.sha256: i for i in images if i.sha256}
    matches = []
    for m in (vmv.get("matches") or [])[:MAX_LIST]:
        img = by_sha.get(m.get("image"))
        matches.append(
            VisualMatch(
                image_sha256=m.get("image") or "",
                image_ref=img.ref if img else "?",
                role=img.role if img else "?",
                method=m.get("method") or "?",
                phash_distance=int(m.get("phash_distance") or 0),
                dhash_distance=int(m.get("dhash_distance") or 0),
                reference=_s(m.get("reference") or {}, 500),
                refs=[f"feature:{vm.id}", *image_refs(m.get("image"))],
            )
        )
    payments = []
    for o in (mtv.get("observations") or [])[:MAX_MEDIA_OBSERVATIONS]:
        payments.append(
            PaymentObservation(
                kind=o["kind"],
                source=o.get("source"),
                identifier_type=o.get("identifier_type"),
                payee_identifier=_s(o.get("payee_identifier")),
                payee_name=_s(o.get("payee_name")),
                destination=_s(o.get("destination"), 500),
                amount=_s(o.get("amount")),
                currency=_s(o.get("currency")),
                ifsc=_s(o.get("ifsc")),
                attribution=o.get("attribution", "unknown"),
                attribution_reason=_s(o.get("reason")),
                attributed_brands=o.get("brands", []),
                registry_payee=o.get("registry_payee"),
                extractor_version=mt.extractor_version,
                image_sha256=o.get("image"),
                refs=[f"feature:{mt.id}", *image_refs(o.get("image"))],
            )
        )
    refs = base.pop("refs") + [afact] + [f"feature:{f.id}" for f in (vm, mt) if f]
    return (
        VisualBlock(
            status=status,
            **base,
            images=images,
            rejected=rejected,
            matches=matches,
            matcher=_s(vmv.get("matcher"), 100),
            corpus_version=vmv.get("corpus_version"),
            corpus_entries=int(vmv.get("corpus_entries") or 0),
            ocr_text=ocr_text,
            ocr_brands=_s(list(mtv.get("brands") or [])[:MAX_LIST], 200),
            ocr_presented=list(mtv.get("presented") or []),
            donation_cues=_s(list(mtv.get("donation_cues") or [])[:MAX_LIST], 100),
            qr_payloads=_s(list(mtv.get("qr_payloads") or [])[:MAX_LIST], 500),
            refs=refs,
        ),
        payments,
    )  # fmt: skip


RENDER_STATUS = {"ok": "complete", "failed": "failed", "render_rejected": "rejected",
                 "refused": "refused"}  # fmt: skip


def _render(
    facts: list[FactRecord], features: list[FeatureRecord], rnd: int | None
) -> tuple[RenderBlock, FactRecord | None, dict | None]:
    """The render block for the round of the final static fetch, the completed
    `browser_render` fact (None unless the render completed) and the comparison."""
    decided = {f.round for f in facts if f.name == "render_decision"}
    # The next request still to decide after this round (one for an earlier,
    # dead round is ignored, never hiding a later one).
    pending = sorted(
        f.round
        for f in facts
        if f.name == "render_request"
        and isinstance(f.round, int)
        and f.round not in decided
        and (rnd is None or f.round > rnd)
    )
    requested_round = pending[0] if pending else None
    decision = _round_fact(facts, "render_decision", rnd) if rnd is not None else None
    if decision is None:
        return RenderBlock(requested_round=requested_round), None, None
    dv = decision.value
    budget = dv.get("analyst_renders_per_day") if dv.get("analyst_request") else None
    base = {
        "analysis_round": rnd,
        "reasons": _s(list(dv.get("reasons") or [])[:MAX_LIST], 100),
        "sampled": bool(dv.get("sampled")),
        "skipped": _s(dv.get("skipped"), 100),
        "requested_round": requested_round,
        "analyst_budget": budget if isinstance(budget, int) else None,
        "requested_url": _s(dv.get("url"), 2048),
    }
    refs = [f"fact:{decision.id}"]
    if not dv.get("triggered"):
        return RenderBlock(status="not_triggered", refs=refs, **base), None, None
    if not dv.get("browser_enabled", True):
        return RenderBlock(status="disabled", refs=refs, **base), None, None
    fact = _round_fact(facts, "browser_render", rnd)
    if fact is None:
        return RenderBlock(status="pending", refs=refs, **base), None, None
    v = fact.value
    refs += [f"fact:{fact.id}"] + [f"artifact:{a}" for a in fact.artifact_refs]
    status = RENDER_STATUS.get(v.get("status"), "failed")
    if status != "complete" or "requests" not in v:  # dropped by the fact size cap: unknown
        reason = v.get("reason") or ("render fact truncated" if status == "complete" else None)
        status = "failed" if status == "complete" else status
        return RenderBlock(status=status, reason=_s(reason, 300), refs=refs, **base), None, None
    requests = [q for q in v.get("requests") or [] if isinstance(q, dict)]
    final_host = None
    if v.get("final_url"):
        try:
            final_host = normalize(urlsplit(v["final_url"]).hostname or "").host
        except (InvalidName, ValueError):
            final_host = None
    shot = v.get("screenshot") or {}
    sha = shot.get("sha256")
    own = [f for f in features if fact.id in f.fact_refs]
    comparison = next((f for f in own if f.name == "cloaking"), None)
    cloaking = None
    if comparison is not None and isinstance(comparison.value, dict):
        cloaking = {**_s(comparison.value, 300), "refs": [f"feature:{comparison.id}"]}
    has_page = any(f.name == "page_content" for f in own)
    source = "rendered" if has_page and (cloaking or {}).get("score_on") != "static" else "static"
    block = RenderBlock(
        status="complete",
        **base,
        reason=_s(v.get("unusable"), 300),
        final_url=_s(v.get("final_url"), 2048),
        final_host=final_host,
        main_status=v.get("main_status"),
        network_idle=bool(v.get("network_idle")),
        redirect_chain=[
            Hop(
                **_s(
                    {"url": h.get("url"), "status": h.get("status"), "location": h.get("location")},
                    500,
                )
            )
            for h in (v.get("redirect_chain") or [])[:MAX_HOPS]
        ],
        navigations=_s(list(v.get("navigations") or [])[:MAX_HOPS], 500),
        request_hosts=_s(sorted({str(q["host"]) for q in requests if q.get("host")})[:50], 255),
        refused_requests=_s(
            [
                {"host": q.get("host"), "url": q.get("url"), "reason": q.get("proxy_refusal")}
                for q in requests
                if q.get("proxy_refusal")
            ][:MAX_LIST],
            500,
        ),
        page_actions={
            k: int(n) for k, n in (v.get("attempt_counts") or {}).items() if isinstance(n, int)
        },
        screenshot=_s(
            {k: shot.get(k) for k in ("status", "sha256", "width", "height", "bytes", "media")}
            | {"stored": bool(sha and sha in fact.artifact_refs)},
            300,
        )
        if shot
        else None,
        content_source=source,
        refs=refs,
    )
    return block, fact, cloaking


def _with_static_association(rendered: dict, static: FeatureRecord | None) -> dict:
    """The rendered page's brand references joined with the static page's."""
    sv = static.value if static and isinstance(static.value, dict) else {}
    if "error" in sv or not sv.get("available"):
        return rendered
    known = {b.get("brand") for b in rendered.get("brands", [])}
    return {
        **rendered,
        "available": True,
        "brands": rendered.get("brands", [])
        + [{**b, "locations": ["static_page"]} for b in sv.get("brands", [])
           if b.get("brand") not in known],
        "presented": sorted(set(rendered.get("presented", [])) | set(sv.get("presented", []))),
        "strong_mention": bool(rendered.get("strong_mention") or sv.get("strong_mention")),
        "weak_only": bool(rendered.get("weak_only") and sv.get("weak_only", True)),
        "claims": rendered.get("claims", []) + sv.get("claims", []),
    }  # fmt: skip


def _screenshot_evidence(
    visual: VisualBlock, fact: FactRecord, features: list[FeatureRecord]
) -> tuple[VisualBlock, list[PaymentObservation]]:
    """The screenshot's matches, image text and QR payees, joined to the visual
    block under the role `screenshot`."""
    shot = fact.value.get("screenshot") or {}
    sha = shot.get("sha256")
    if not sha:
        return visual, []
    image_refs = [f"fact:{fact.id}"] + ([f"artifact:{sha}"] if sha in fact.artifact_refs else [])
    own = {f.name: f for f in features if fact.id in f.fact_refs}
    vm, mt = own.get("screenshot_matches"), own.get("screenshot_text")
    vmv = vm.value if vm and isinstance(vm.value, dict) else {}
    mtv = mt.value if mt and isinstance(mt.value, dict) and mt.value.get("available") else {}
    matches = [
        VisualMatch(
            image_sha256=sha,
            image_ref="screenshot",
            role="screenshot",
            method=m.get("method") or "?",
            phash_distance=int(m.get("phash_distance") or 0),
            dhash_distance=int(m.get("dhash_distance") or 0),
            reference=_s(m.get("reference") or {}, 500),
            refs=[f"feature:{vm.id}", *image_refs],
        )
        for m in (vmv.get("matches") or [])[:MAX_LIST]
    ]
    text = ((shot.get("media") or {}).get("ocr_text")) or ""
    ocr_text = [{"image": sha, "role": "screenshot", "text": sanitize_fact(text, MAX_OCR_SNIPPET)}]
    payments = [
        PaymentObservation(
            kind=o["kind"],
            source=o.get("source"),
            identifier_type=o.get("identifier_type"),
            payee_identifier=_s(o.get("payee_identifier")),
            payee_name=_s(o.get("payee_name")),
            destination=_s(o.get("destination"), 500),
            amount=_s(o.get("amount")),
            currency=_s(o.get("currency")),
            ifsc=_s(o.get("ifsc")),
            attribution=o.get("attribution", "unknown"),
            attribution_reason=_s(o.get("reason")),
            attributed_brands=o.get("brands", []),
            registry_payee=o.get("registry_payee"),
            extractor_version=mt.extractor_version,
            image_sha256=sha,
            refs=[f"feature:{mt.id}", *image_refs],
        )
        for o in (mtv.get("observations") or [])[:MAX_MEDIA_OBSERVATIONS]
    ]
    merged = visual.model_copy(
        update={
            "matches": visual.matches + matches,
            "ocr_text": visual.ocr_text + (ocr_text if text else []),
            "ocr_brands": visual.ocr_brands + _s(list(mtv.get("brands") or [])[:MAX_LIST], 200),
            "ocr_presented": sorted(set(visual.ocr_presented) | set(mtv.get("presented") or [])),
            "donation_cues": list(
                dict.fromkeys(visual.donation_cues + _s(list(mtv.get("donation_cues") or []), 100))
            )[:MAX_LIST],
            "qr_payloads": visual.qr_payloads
            + _s(list(mtv.get("qr_payloads") or [])[:MAX_LIST], 500),
            "refs": visual.refs + [f"feature:{f.id}" for f in (vm, mt) if f],
        }
    )
    return merged, payments


def build_bundle(
    inputs: CaseInputs, lexicon: BrandLexicon | None, registry: Registry | None = None
) -> EvidenceBundle:
    try:
        unicode_host = normalize(inputs.host).unicode_host
    except InvalidName:
        unicode_host = None
    http, final = _http(inputs.facts)
    render, rendered, cloaking = _render(inputs.facts, inputs.features, http.analysis_round)
    infra = _infrastructure(inputs.facts, http.analysis_round)
    view = rendered if render.content_source == "rendered" else final
    feats = _features_for(inputs.features, view)
    base_refs = [f"fact:{view.id}"] + [f"artifact:{a}" for a in view.artifact_refs] if view else []

    def refs(name: str) -> list[str]:
        f = feats.get(name)
        return [f"feature:{f.id}", *base_refs] if f else []

    def value(name: str) -> dict:
        f = feats.get(name)
        return f.value if f and isinstance(f.value, dict) and "error" not in f.value else {}

    errors = [
        {"extractor": f.name, "version": f.extractor_version, "error": _s(f.value["error"])}
        for f in feats.values()
        if isinstance(f.value, dict) and "error" in f.value
    ]
    pc, basics = value("page_content"), value("page_basics")
    pay, assoc = value("payment"), value("brand_references")
    com, edit = value("commerce"), value("editorial")

    page = PageBlock(
        available=bool(pc),
        title=_s(pc.get("title")),
        headings=_s(pc.get("headings", [])[:10]),
        meta_description=_s(pc.get("meta_description")),
        lang=_s(pc.get("lang"), 20),
        text_excerpt=_s(pc.get("text_excerpt"), MAX_EXCERPT_CHARS) if pc else None,
        text_chars=pc.get("text_chars", 0),
        empty=bool(pc.get("empty")),
        js_shell=bool(pc.get("js_shell")),
        image_only=bool(pc.get("image_only")),
        parked_cues=_s(pc.get("parked_cues", [])),
        lures=_s(pc.get("lures", [])),
        script_redirects=_s(pc.get("script_redirects", []), 500),
        meta_refresh=_s(basics.get("meta_refresh", []), 500),
        external_domains=_s(pc.get("links", {}).get("external_domains", [])[:MAX_LIST]),
        messaging_links=_s(pc.get("links", {}).get("messaging", [])),
        link_schemes=pc.get("links", {}).get("schemes", {}),
        refs=sorted(set(refs("page_content") + refs("page_basics")), key=_ref_key),
    )
    cred = pc.get("credential", {})
    cred_forms = [
        _s(
            {
                k: f.get(k)
                for k in (
                    "index",
                    "method",
                    "action",
                    "action_registrable_domain",
                    "cross_origin",
                    "password_fields",
                    "otp_fields",
                    "identity_fields",
                    "submit_text",
                    "context_excerpt",
                    "brands_in_context",
                )
            }
        )
        for f in pc.get("forms", [])
        if f.get("password_fields") or f.get("otp_fields")
    ]
    credential = CredentialBlock(
        password_fields=cred.get("password_fields", 0),
        password_fields_outside_forms=cred.get("password_fields_outside_forms", 0),
        otp_fields=cred.get("otp_fields", 0),
        forms=cred_forms,
        cross_origin_forms=len(cred.get("cross_origin_credential_forms", [])),
        refs=refs("page_content"),
    )
    pay_feature = feats.get("payment")
    visual, media_payments = _visual(inputs.facts, inputs.features, http.analysis_round)
    if rendered is not None:
        visual, shot_payments = _screenshot_evidence(visual, rendered, inputs.features)
        media_payments += shot_payments
    pay_refs = refs("payment")
    payment = PaymentBlock(
        catalog_version=pay.get("catalog_version"),
        providers=_s(pay.get("providers", []), 500),
        observations=[
            PaymentObservation(
                kind=o["kind"],
                source=o.get("source"),
                identifier_type=o.get("identifier_type"),
                payee_identifier=_s(o.get("payee_identifier")),
                payee_name=_s(o.get("payee_name")),
                provider=o.get("provider"),
                destination=_s(o.get("destination"), 500),
                amount=_s(o.get("amount")),
                currency=_s(o.get("currency")),
                ifsc=_s(o.get("ifsc")),
                attribution=o.get("attribution", "unknown"),
                attribution_reason=_s(o.get("reason")),
                attributed_brands=o.get("brands", []),
                registry_payee=o.get("registry_payee"),
                extractor_version=pay_feature.extractor_version if pay_feature else "unknown",
                refs=pay_refs,
            )
            for o in pay.get("observations", [])[:MAX_LIST]
        ]
        + media_payments,
        donation_cues=_s(pay.get("donation_cues", [])),
        card_fields=pay.get("card_fields", 0),
        card_forms=pay.get("card_field_forms", []),
        qr_images=_s(pay.get("qr_images", []), 500),
        refs=pay_refs
        + list(dict.fromkeys(r for o in media_payments for r in o.refs if r not in pay_refs)),
    )
    if view is not final and final is not None:
        # The rendered page is scored, but what the static page presented was
        # served by the same site: a brand or claim shown only to the fetcher
        # still ties what the browser saw to the brand.
        assoc = _with_static_association(
            assoc, _features_for(inputs.features, final).get("brand_references")
        )
    association = AssociationBlock(
        available=bool(assoc.get("available")),
        brands=[
            _s(
                {
                    k: b.get(k)
                    for k in (
                        "brand",
                        "name",
                        "strength",
                        "count",
                        "locations",
                        "strong_locations",
                        "terms",
                        "snippet",
                    )
                }
            )
            for b in assoc.get("brands", [])[:MAX_LIST]
        ],
        presented=assoc.get("presented", []),
        strong_mention=bool(assoc.get("strong_mention")),
        weak_only=bool(assoc.get("weak_only")),
        claims=_s(assoc.get("claims", [])[:MAX_LIST]),
        disclaimers=_s(assoc.get("disclaimers", [])[:MAX_LIST]),
        refs=refs("brand_references"),
    )
    commerce = CommerceBlock(
        commerce=bool(com.get("commerce")),
        prices=_s(com.get("prices", [])),
        calls_to_action=_s(com.get("calls_to_action", [])),
        cart=bool(com.get("cart")),
        product_markup=com.get("product_markup", []),
        refs=refs("commerce"),
    )
    editorial = EditorialBlock(
        editorial=bool(edit.get("editorial")),
        article_markup=edit.get("article_markup", {}),
        byline=_s(edit.get("byline")),
        published=_s(edit.get("published")),
        parody_cues=_s(edit.get("parody_cues", [])),
        disclaimer_cues=_s(edit.get("disclaimer_cues", [])),
        critical_cues=_s(edit.get("critical_cues", [])),
        refs=refs("editorial"),
    )
    registry_ctx = RegistryContext()
    if lexicon is not None:
        hosts = [inputs.host, inputs.registrable_domain]
        registry_ctx = RegistryContext(
            official_domain=lexicon.official_domain(inputs.host),
            final_url_official_domain=lexicon.official_domain(http.final_host),
            confirmed_relationships=lexicon.confirmed_relationships(*hosts),
            registry_domains=_registry_matches(registry, inputs.host, http.final_host),
            vouching_brands=_vouching_brands(
                lexicon,
                [
                    lexicon.official_domain(inputs.host),
                    lexicon.official_domain(http.final_host),
                    inputs.host,
                    inputs.registrable_domain,
                ],
            ),
            credential_destinations=_credential_destinations(cred_forms, lexicon, registry),
        )
    return EvidenceBundle(
        subject=Subject(
            case_id=inputs.case_id,
            status=inputs.status,
            host=inputs.host,
            unicode_host=_s(unicode_host),
            registrable_domain=inputs.registrable_domain,
            subject_url=_s(inputs.subject_url, 2048),
            case_created_at=_iso(inputs.created_at),
        ),
        discovery=_discovery(inputs),
        registry=registry_ctx,
        infrastructure=infra,
        http=http,
        page=page,
        credential=credential,
        payment=payment,
        association=association,
        commerce=commerce,
        editorial=editorial,
        visual=visual,
        render=render,
        render_reason=render.reasons[0] if render.reasons else None,
        cloaking=cloaking,
        snippets=_snippets(page, credential, payment, association, visual),
        extractor_errors=errors,
        incomplete=_incomplete(http, page, infra, errors, visual, render),
    )


def _snippets(page, credential, payment, association, visual) -> list[Snippet]:
    out: list[Snippet] = []

    def add(field: str, text: str | None) -> None:
        if text and len(out) < MAX_SNIPPETS:
            item = Snippet(field=field, text=sanitize_fact(text, MAX_SNIPPET_CHARS))
            if item not in out:
                out.append(item)

    add("page.title", page.title)
    for c in association.claims:
        add("association.claim", c.get("snippet"))
    for f in credential.forms:
        add("credential.form_context", f.get("context_excerpt"))
    for o in payment.observations:
        add("payment.payee_name", o.payee_name)
    for lure in page.lures:
        add("page.lure", lure.get("snippet"))
    for d in association.disclaimers:
        add("association.disclaimer", d.get("snippet"))
    for t in visual.ocr_text:
        add("visual.ocr_text", t.get("text"))
    for q in visual.qr_payloads:
        add("visual.qr_payload", q.get("text"))
    add("page.text_excerpt", page.text_excerpt)
    return out


def _incomplete(
    http: Http,
    page: PageBlock,
    infra: Infrastructure,
    errors: list,
    visual: VisualBlock,
    render: RenderBlock,
) -> list[str]:
    out = []
    if not http.fetched:
        out.append("not_fetched" if not http.attempts else "fetch_pending_retry")
    elif http.outcome != "ok":
        out.append(f"fetch_{http.outcome}")
    elif not page.available:
        out.append("no_html_content")
    if http.body_truncated:
        out.append(f"body_truncated_{http.body_truncated}")
    if http.fetched and http.outcome == "ok" and not http.body_stored:
        out.append("body_not_stored")
    if page.js_shell:
        out.append("js_shell")
    if page.image_only:
        out.append("image_only")
    if page.empty:
        out.append("empty_page")
    if infra.enrichment == "not_run":
        out.append("enrichment_not_run")
    for e in infra.errors:
        out.append(f"enrichment_error_{e.get('source')}")
    for e in errors:
        out.append(f"extractor_error_{e['extractor']}")
    if visual.status in ("pending", "failed", "partial", "disabled"):
        out.append(f"media_{visual.status}")
    if visual.rejected:
        out.append("media_rejected")
    if visual.status in ("complete", "partial") and not visual.corpus_entries:
        out.append("reference_corpus_empty")
    if render.status in ("pending", "failed", "rejected", "refused", "disabled"):
        out.append(f"render_{render.status}")
    return out
