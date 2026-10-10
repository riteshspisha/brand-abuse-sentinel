"""Policy rules (U14, KTD17). Each reads only the EvidenceBundle.

Three kinds of rule add or subtract points; weights live in `config/policy.yaml`:

- `abuse`: independently observed abuse evidence. Only these can lift a case to
  P1 or P2. Each needs a protected brand tied to the behaviour (a credential
  form whose surrounding text names the brand, a payee claiming the brand) on a
  host that is not a confirmed official domain.
- `supporting`: signals that describe risk but cannot reach P1/P2 alone (domain
  similarity, recent registration, parking, lure language, redirects).
- `relief`: registry-derived facts only (confirmed official domain, confirmed
  payee, confirmed relationship). Page-provided signals (article markup,
  bylines, parody labels, disclaimers) are never relief (R29, AE15).

Context labels are computed separately in the scorer and never change points.
Nothing here asserts fraud: explanations say what was observed.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from brandsentinel.analysis import host_of, registrable_of
from brandsentinel.evidence.bundle import EvidenceBundle

Kind = Literal["abuse", "supporting", "relief"]
PAYEE_KINDS = frozenset({"upi", "bank_account", "merchant_key"})


@dataclass(frozen=True)
class Fired:
    explanation: str
    evidence: list[str]
    category: str | None = None
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    id: str
    kind: Kind
    category: str | None
    summary: str
    fn: Callable[[EvidenceBundle, dict], Fired | None]


RULES: dict[str, Rule] = {}


def rule(id: str, kind: Kind, summary: str, category: str | None = None):
    def deco(fn):
        if id in RULES:
            raise ValueError(f"rule {id!r} already defined")
        RULES[id] = Rule(id, kind, category, summary, fn)
        return fn

    return deco


# --- helpers -----------------------------------------------------------------------


def _names(b: EvidenceBundle, ids) -> str:
    known = {x["brand"]: x.get("name") or x["brand"] for x in b.association.brands}
    out = []
    for i in ids:
        name = known.get(i, i)
        if name not in out:
            out.append(name)
    return ", ".join(out) or "a protected brand"


def official(b: EvidenceBundle) -> bool:
    return bool(b.registry.official_domain)


def redirected_to_official(b: EvidenceBundle) -> bool:
    return bool(b.registry.final_url_official_domain) and not official(b)


def related(b: EvidenceBundle) -> bool:
    return bool(b.registry.confirmed_relationships)


def registry_cleared(b: EvidenceBundle) -> bool:
    """The registry vouches for this host or the page it served: a confirmed
    official domain (or the fetch ended on one), or a confirmed relationship."""
    return official(b) or redirected_to_official(b) or related(b)


def domain_uses_brand(b: EvidenceBundle) -> bool:
    return b.discovery.domain_match in ("strong", "weak")


def _uniq(*groups: list[str]) -> list[str]:
    out: list[str] = []
    for g in groups:
        for r in g:
            if r not in out:
                out.append(r)
    return out


def credential_tie(b: EvidenceBundle) -> tuple[list[str], str] | None:
    """The brands a credential request is tied to, and how, or None.

    Tied when a credential form's own text or enclosing block names a brand,
    when the domain name strongly matches a brand (or weakly, with a strong brand
    mention on the page: a common word such as a person's name is not enough),
    or when the page presents a brand and uses account-verification lure language."""
    c = b.credential
    if not (c.forms or c.password_fields_outside_forms):
        return None
    # A weak term alone (a common word such as a place or person's name) is no tie.
    near = sorted(
        {
            x["brand"]
            for f in c.forms
            for x in f.get("brands_in_context") or []
            if x.get("strength") == "strong"
        }
    )
    if near:
        return near, f"the form's surrounding text names {_names(b, near)}"
    m = b.discovery.domain_match
    if m == "strong" or (m == "weak" and b.association.strong_mention):
        brands = sorted({h.get("brand") for h in b.discovery.hits if h.get("brand")})
        return brands, f"the domain name matches {_names(b, brands)} ({m})"
    lure = any(lu.get("category") == "account_verification" for lu in b.page.lures)
    if b.association.presented and lure:
        return b.association.presented, (
            f"the page presents {_names(b, b.association.presented)} and asks the reader to"
            " verify or confirm an account"
        )
    return None


def unconfirmed_payees(b: EvidenceBundle, attributions=("claims_brand_unconfirmed",)):
    return [
        o
        for o in b.payment.observations
        if o.kind in PAYEE_KINDS and o.payee_identifier and o.attribution in attributions
    ]


def _payee_text(observations) -> str:
    parts = []
    for o in observations[:5]:
        name = f" ({o.payee_name!r})" if o.payee_name else ""
        parts.append(f"{o.kind} {o.payee_identifier}{name}")
    more = f" and {len(observations) - 5} more" if len(observations) > 5 else ""
    return "; ".join(parts) + more


def _registrable(url: str) -> str | None:
    return registrable_of(host_of(url))


def _brand_present(b: EvidenceBundle) -> bool:
    return b.association.strong_mention or bool(b.association.presented)


# --- abuse evidence ------------------------------------------------------------------


@rule(
    "credential_form_brand",
    "abuse",
    "Credential form tied to a protected brand on a non-official domain",
    "credential_phishing",
)
def _credential_form_brand(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b):
        return None
    tie = credential_tie(b)
    if tie is None:
        return None
    brands, how = tie
    c = b.credential
    actions = sorted({f.get("action") or "?" for f in c.forms})
    kinds = []
    if c.password_fields:
        kinds.append(f"{c.password_fields} password field(s)")
    if c.otp_fields:
        kinds.append(f"{c.otp_fields} one-time-code field(s)")
    where = f" posting to {', '.join(actions)}" if actions else " outside any form"
    return Fired(
        f"The page asks for credentials ({', '.join(kinds) or 'password'}){where}, and {how};"
        " the host is not a confirmed official domain.",
        _uniq(c.refs, b.association.refs, b.discovery.refs),
        details={"brands": brands, "actions": actions},
    )


@rule(
    "credential_cross_origin",
    "abuse",
    "Brand-tied credential form submits to a different registrable domain",
    "credential_phishing",
)
def _credential_cross_origin(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b) or credential_tie(b) is None or not b.credential.cross_origin_forms:
        return None
    domains = sorted(
        {f.get("action_registrable_domain") for f in b.credential.forms if f.get("cross_origin")}
    )
    return Fired(
        f"A credential form submits to another registrable domain ({', '.join(domains)}).",
        b.credential.refs,
    )


@rule(
    "payment_brand_unconfirmed_payee",
    "abuse",
    "Payment destination presented under a protected brand, payee not confirmed",
    "payment_fraud",
)
def _payment_unconfirmed(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b):
        return None
    payees = unconfirmed_payees(b)
    gateway_checkout = [
        o
        for o in b.payment.observations
        if o.kind == "gateway"
        and o.attribution == "claims_brand_unconfirmed"
        and (o.source in ("form_action", "link", "iframe") or b.payment.card_fields)
    ]
    if not payees and not gateway_checkout:
        return None
    category = "donation_fraud" if b.payment.donation_cues else "payment_fraud"
    if payees:
        brands = sorted({x for o in payees for x in o.attributed_brands})
        text = (
            f"Payment identifier(s) {_payee_text(payees)} are presented under"
            f" {_names(b, brands)} (payee name or page) and are not confirmed registry payees."
        )
    else:
        providers = sorted({o.provider or "?" for o in gateway_checkout})
        text = (
            f"A checkout through {', '.join(providers)} (card fields or checkout destination) is "
            "presented under a protected brand with no confirmed payee."
        )
    return Fired(
        text,
        _uniq(b.payment.refs, b.association.refs),
        category,
        {"payees": [o.payee_identifier for o in payees]},
    )


@rule(
    "donation_appeal_unconfirmed_payee",
    "abuse",
    "Donation appeal naming a protected brand with a payee that is not confirmed",
    "donation_fraud",
)
def _donation_unconfirmed(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b) or not b.payment.donation_cues:
        return None
    if not (_brand_present(b) or b.discovery.domain_match == "strong"):
        return None
    payees = unconfirmed_payees(b, ("claims_brand_unconfirmed", "unrelated"))
    if not payees:
        return None
    brands = b.association.presented or [
        x["brand"] for x in b.association.brands if x.get("strength") == "strong"
    ]
    return Fired(
        f"The page appeals for donations ({', '.join(b.payment.donation_cues[:5])}) in the name"
        f" of {_names(b, brands)} and directs them to {_payee_text(payees)}, which is not a"
        " confirmed registry payee.",
        _uniq(b.payment.refs, b.association.refs),
    )


@rule(
    "false_association_claim",
    "abuse",
    "Claims an official, partner or authorised relationship that the registry does not confirm",
    "false_association",
)
def _false_association(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b) or not b.association.claims:
        return None
    claims = b.association.claims
    kinds = sorted({c.get("kind") for c in claims})
    brands = sorted({x for c in claims for x in c.get("brands", [])})
    return Fired(
        f"The page claims a relationship ({', '.join(kinds)}) with {_names(b, brands)}:"
        f" {claims[0].get('snippet')!r}; no confirmed relationship exists in the registry.",
        b.association.refs,
    )


@rule(
    "lookalike_domain_brand_content",
    "abuse",
    "Brand-lookalike domain serves content presenting the brand",
    "impersonation",
)
def _lookalike(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b):
        return None
    if b.discovery.domain_match != "strong" or not b.association.presented:
        return None
    hits = [f"{h.get('type')}:{h.get('keyword')}" for h in b.discovery.hits[:5]]
    return Fired(
        f"The domain matches the brand strongly ({', '.join(hits)}) and the page presents"
        f" {_names(b, b.association.presented)} in its title, headings or image text.",
        _uniq(b.discovery.refs, b.association.refs),
    )


@rule(
    "unauthorized_commerce",
    "abuse",
    "Sells under a protected brand without a confirmed relationship",
    "unauthorized_commerce",
)
def _commerce(b: EvidenceBundle, p: dict) -> Fired | None:
    if registry_cleared(b) or not b.commerce.commerce:
        return None
    if not (b.association.presented or b.association.claims):
        return None
    brands = b.association.presented or sorted(
        {x for c in b.association.claims for x in c.get("brands", [])}
    )
    offer = ", ".join((b.commerce.prices + b.commerce.calls_to_action)[:4])
    return Fired(
        f"The page sells or books ({offer}) under {_names(b, brands)} with no confirmed"
        " relationship in the registry.",
        _uniq(b.commerce.refs, b.association.refs),
    )


# --- supporting signals ----------------------------------------------------------------


@rule("domain_similarity_strong", "supporting", "Domain name strongly matches a brand")
def _sim_strong(b: EvidenceBundle, p: dict) -> Fired | None:
    if b.discovery.domain_match != "strong" or official(b):
        return None
    hits = [f"{h.get('type')}:{h.get('keyword')}" for h in b.discovery.hits[:5]]
    return Fired(f"Discovery matched the name strongly ({', '.join(hits)}).", b.discovery.refs)


@rule("domain_similarity_weak", "supporting", "Domain name weakly matches a brand")
def _sim_weak(b: EvidenceBundle, p: dict) -> Fired | None:
    if b.discovery.domain_match != "weak" or official(b):
        return None
    hits = [f"{h.get('type')}:{h.get('keyword')}" for h in b.discovery.hits[:5]]
    return Fired(f"Discovery matched the name weakly ({', '.join(hits)}).", b.discovery.refs)


@rule("recent_registration", "supporting", "Registrable domain registered recently")
def _recent(b: EvidenceBundle, p: dict) -> Fired | None:
    age = b.infrastructure.domain_age_days
    limit = int(p.get("recent_registration_days", 90))
    if age is None or age > limit or not (domain_uses_brand(b) or _brand_present(b)):
        return None
    return Fired(
        f"RDAP shows the domain was registered {age} days ago (threshold {limit}).",
        b.infrastructure.refs,
    )


@rule("dns_mixed_private", "supporting", "DNS answers mix public and private addresses")
def _mixed(b: EvidenceBundle, p: dict) -> Fired | None:
    if not b.infrastructure.dns_mixed_private:
        return None
    return Fired("DNS returned both public and private/blocked addresses.", b.infrastructure.refs)


@rule(
    "parked_typosquat",
    "supporting",
    "Brand-matching domain serves a parking or placeholder page",
    "typosquat_parked",
)
def _parked(b: EvidenceBundle, p: dict) -> Fired | None:
    if official(b) or not b.page.parked_cues or not domain_uses_brand(b):
        return None
    cues = ", ".join(sorted({c.get("cue") for c in b.page.parked_cues})[:4])
    return Fired(
        f"The brand-matching domain serves a parking/placeholder page ({cues}).",
        _uniq(b.page.refs, b.discovery.refs),
    )


@rule("social_engineering_language", "supporting", "Lure language next to brand content")
def _lures(b: EvidenceBundle, p: dict) -> Fired | None:
    if official(b) or not b.page.lures or not (_brand_present(b) or domain_uses_brand(b)):
        return None
    cats = sorted({lu.get("category") for lu in b.page.lures})
    cues = ", ".join(repr(lu.get("cue")) for lu in b.page.lures[:3])
    return Fired(f"Lure language ({', '.join(cats)}): {cues}.", b.page.refs)


@rule("client_redirect_offsite", "supporting", "Page redirects the browser to another domain")
def _client_redirect(b: EvidenceBundle, p: dict) -> Fired | None:
    if official(b) or not (domain_uses_brand(b) or _brand_present(b)):
        return None
    targets = [r.get("url") for r in b.page.meta_refresh + b.page.script_redirects if r.get("url")]
    own = b.subject.registrable_domain
    offsite = [t for t in targets if own and _registrable(t) not in (own, None)]
    if not offsite:
        return None
    return Fired(
        f"Client-side redirect (meta refresh or script) to {', '.join(offsite[:3])}.", b.page.refs
    )


@rule("blocked_redirect", "supporting", "A redirect pointed at a blocked (internal) address")
def _blocked_redirect(b: EvidenceBundle, p: dict) -> Fired | None:
    if b.http.outcome != "blocked_redirect":
        return None
    reason = (b.http.error or {}).get("reason") or (b.http.error or {}).get("kind") or "blocked"
    return Fired(
        f"The site redirected toward an address the network policy blocks ({reason});"
        " the redirect was not followed.",
        b.http.refs,
    )


@rule(
    "unobserved_content_on_lookalike",
    "supporting",
    "Strong lookalike whose content static analysis could not see",
)
def _unobserved(b: EvidenceBundle, p: dict) -> Fired | None:
    if official(b) or b.discovery.domain_match != "strong":
        return None
    gaps = [
        g
        for g in b.incomplete
        if g in ("js_shell", "image_only", "empty_page", "not_fetched") or g.startswith("fetch_")
    ]
    if not gaps:
        return None
    return Fired(
        f"The domain strongly matches a brand but its content was not observable statically"
        f" ({', '.join(gaps)}).",
        _uniq(b.http.refs, b.page.refs, b.discovery.refs),
    )


# --- registry relief -------------------------------------------------------------------


@rule("official_domain", "relief", "Host is under a confirmed official domain")
def _official(b: EvidenceBundle, p: dict) -> Fired | None:
    if not official(b):
        return None
    d = b.registry.official_domain
    return Fired(f"The host is under the confirmed official domain {d}.", [f"registry:domain:{d}"])


@rule("redirects_to_official", "relief", "Final URL is under a confirmed official domain")
def _to_official(b: EvidenceBundle, p: dict) -> Fired | None:
    if not redirected_to_official(b):
        return None
    d = b.registry.final_url_official_domain
    return Fired(
        f"The fetch ended on the confirmed official domain {d} ({b.http.final_url}).",
        _uniq([f"registry:domain:{d}"], b.http.refs),
    )


@rule("confirmed_payee", "relief", "Payment goes to a confirmed registry payee")
def _confirmed_payee(b: EvidenceBundle, p: dict) -> Fired | None:
    known = [o for o in b.payment.observations if o.attribution == "registry_known_payee"]
    # Relief only when every payee on the page is confirmed: a hidden copy of the
    # real payee must not offset a scam payee beside it.
    if not known or unconfirmed_payees(b, ("claims_brand_unconfirmed", "unrelated")):
        return None
    ids = sorted({(o.registry_payee or {}).get("id", "?") for o in known})
    return Fired(
        f"Payment identifier(s) {_payee_text(known)} belong to confirmed registry payee(s)"
        f" {', '.join(ids)}.",
        _uniq([f"registry:payee:{i}" for i in ids], b.payment.refs),
    )


@rule("confirmed_relationship", "relief", "Registry confirms a relationship for this domain")
def _relationship(b: EvidenceBundle, p: dict) -> Fired | None:
    if not related(b):
        return None
    rels = b.registry.confirmed_relationships
    text = ", ".join(f"{r['from']} {r['type']} {r['to']}" for r in rels[:3])
    return Fired(
        f"The registry confirms: {text}.",
        [f"registry:relationship:{r['from']}>{r['to']}" for r in rels[:3]],
    )
