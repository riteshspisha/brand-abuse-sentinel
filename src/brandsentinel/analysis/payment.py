"""Payment and donation indicators with payee attribution (U12, R17, R18).

Three things are kept apart, as R18 requires:

- observed facts: the provider (from the catalog), the payee identifier (UPI
  VPA, bank account and IFSC, publishable merchant key), the payee display name,
  the destination (deep link, form action, checkout host), amount and currency;
- attribution: `registry_known_payee` when the identifier is a confirmed
  registry payee, `claims_brand_unconfirmed` when the payee name or the page
  presents a protected brand but the identifier is not a confirmed payee, and
  `unrelated` otherwise (`unknown` without a registry);
- evidence references, added when the bundle is built (fact, blob, version).

Donation vocabulary, card fields and candidate QR images are recorded as
supporting observations. QR images are decoded in the media sandbox (M6), never
here. Nothing is ever submitted or paid.
"""

import html
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml

from brandsentinel.analysis import HTML_TYPES, Extractor, Page, absolute, host_of, register
from brandsentinel.analysis.association import brands_in, mentions
from brandsentinel.analysis.static import forms
from brandsentinel.matching.normalize import skeleton_of

VERSION = "payment/1"
MAX_ITEMS = 20
MAX_NODES = 2000  # elements of one kind examined per page

_UPI_SCHEMES = ("upi", "tez", "phonepe", "paytmmp", "gpay", "bhim", "intent")
_VPA = re.compile(r"^[a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9]{1,63}$")
# A VPA in text: handle@psp, where the PSP part has no dot (an e-mail address does).
_VPA_IN_TEXT = re.compile(
    r"(?<![\w.@-])([a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9]{1,63})(?![\w@-])(?!\.[a-z0-9])"
)
_UPI_IN_TEXT = re.compile(r"(?:upi|tez|phonepe|paytmmp|gpay|bhim)://pay\?[^\s\"'<>]{1,1024}", re.I)
_IFSC = re.compile(r"(?<![a-z0-9])([a-z]{4}0[a-z0-9]{6})(?![a-z0-9])")
# Account numbers may be written in groups ("0001 2345 6789", "0001-2345-6789").
_ACCOUNT = re.compile(
    r"(?:account|a/c|acct|acc\.?)\s*(?:no\.?|number|#)?[^0-9]{0,20}(\d[\d -]{7,24}\d)(?!\d)"
)
MAX_RAW_SCAN = 1_000_000  # characters of raw markup scanned for UPI deep links
_DONATION = re.compile(
    r"(?<![a-z])(?:donat(?:e|es|ed|ing|ion|ions)|contribut(?:e|ion|ions)|seva|offering|dakshina|"
    r"relief\s+fund|fundrais(?:er|ing)|support\s+(?:our|the)\s+cause|give\s+now|charity|80g|"
    r"tax\s+exempt(?:ion)?|sponsor\s+a)(?![a-z])"
)
_QR_HINT = re.compile(r"(?<![a-z])(?:qr|scan|upi|bhim|gpay|paytm|phonepe)(?![a-z])")


class CatalogError(ValueError):
    """The payment provider catalog is missing or malformed."""


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    script_hosts: tuple[str, ...]
    checkout_hosts: tuple[str, ...]
    key_patterns: tuple[re.Pattern, ...]


@dataclass(frozen=True)
class ProviderCatalog:
    version: str
    providers: tuple[Provider, ...]

    @classmethod
    def load(cls, path: Path) -> "ProviderCatalog":
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("providers"), list):
                raise CatalogError("expected a mapping with a providers list")
            providers = tuple(
                Provider(
                    id=str(p["id"]),
                    name=str(p["name"]),
                    script_hosts=tuple(h.lower() for h in p.get("script_hosts", [])),
                    checkout_hosts=tuple(h.lower() for h in p.get("checkout_hosts", [])),
                    key_patterns=tuple(re.compile(k) for k in p.get("key_patterns", [])),
                )
                for p in data["providers"]
            )
        except (OSError, yaml.YAMLError, KeyError, TypeError, AttributeError, re.error) as e:
            raise CatalogError(f"invalid payment provider catalog {path}: {e}") from e
        except CatalogError as e:
            raise CatalogError(f"invalid payment provider catalog {path}: {e}") from e
        return cls(str(data.get("version", "unversioned")), providers)

    def by_host(self, host: str | None, kinds: tuple[str, ...]) -> Provider | None:
        if not host:
            return None
        host = host.lower()
        for p in self.providers:
            for kind in kinds:
                for h in getattr(p, kind):
                    if host == h or host.endswith("." + h):
                        return p
        return None


_host = host_of


def parse_upi(link: str) -> dict | None:
    """Fields of a UPI deep link (`upi://pay?pa=..&pn=..`); None if it has no payee."""
    try:
        parts = urlsplit(link.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in _UPI_SCHEMES:
        return None
    query = parse_qs(parts.query, keep_blank_values=False)

    def one(key: str, limit: int = 200) -> str | None:
        v = query.get(key)  # parse_qs has already percent-decoded the value
        return v[0].strip()[:limit] or None if v else None

    pa = (one("pa", 300) or "").lower() or None
    if not pa:
        return None
    return {
        "pa": pa,
        "pa_valid": bool(_VPA.match(pa)),
        "pn": one("pn"),
        "am": one("am", 20),
        "cu": one("cu", 10),
        "tn": one("tn"),
        "mc": one("mc", 10),
        "link": link.strip()[:500],
    }


def _attribute(page: Page, kind: str, identifier: str | None, payee_name: str | None) -> dict:
    lex = page.context.lexicon
    if lex is None:
        return {"attribution": "unknown", "reason": "no registry available"}
    if identifier:
        known = lex.known_payee(kind, identifier)
        if known is not None:
            return {
                "attribution": "registry_known_payee",
                "reason": f"identifier is confirmed registry payee {known.payee_id}",
                "registry_payee": {
                    "id": known.payee_id,
                    "name": known.name,
                    "brand": known.brand,
                },
            }
    named = brands_in(page, payee_name or "")
    if named:
        names = ", ".join(lex.brand_names.get(b["brand"], b["brand"]) for b in named)
        return {
            "attribution": "claims_brand_unconfirmed",
            "reason": f"payee name {payee_name!r} names {names}; not a confirmed registry payee",
            "brands": [b["brand"] for b in named],
        }
    presented = mentions(page)["presented"]
    if presented:
        names = ", ".join(lex.brand_names.get(b, b) for b in presented)
        return {
            "attribution": "claims_brand_unconfirmed",
            "reason": f"page presents {names} (title, heading or image text); not a confirmed"
            " registry payee",
            "brands": presented,
        }
    return {"attribution": "unrelated", "reason": "no protected brand claimed by payee or page"}


def payment(page: Page) -> dict:
    catalog: ProviderCatalog | None = page.context.providers
    tree = page.tree
    providers: list[dict] = []

    def add_provider(p: Provider, via: str, url: str | None) -> None:
        item = {"provider": p.id, "name": p.name, "via": via, "url": url}
        if item not in providers and len(providers) < MAX_ITEMS:
            providers.append(item)

    merchant_keys: list[dict] = []
    if catalog is not None:
        for n in tree.css("script[src]")[:MAX_NODES]:
            url = absolute(page.base, n.attributes.get("src"))
            p = catalog.by_host(_host(url), ("script_hosts", "checkout_hosts"))
            if p:
                add_provider(p, "script", url)
        for f in forms(page):
            p = catalog.by_host(f["action_host"], ("checkout_hosts",))
            if p:
                add_provider(p, "form_action", f["action"])
        for n in tree.css("a[href], iframe[src]")[:MAX_NODES]:
            ref = n.attributes.get("href") or n.attributes.get("src")
            url = absolute(page.base, ref)
            p = catalog.by_host(_host(url), ("checkout_hosts",))
            if p:
                add_provider(p, "iframe" if n.tag == "iframe" else "link", url)
        scripts = page.inline_scripts
        for p in catalog.providers:
            for rx in p.key_patterns:
                for m in rx.finditer(scripts):
                    item = {"provider": p.id, "key": m.group(0)[:120]}
                    if item not in merchant_keys and len(merchant_keys) < MAX_ITEMS:
                        merchant_keys.append(item)

    upi: list[dict] = []
    seen_links: set[str] = set()
    raw_links = [
        n.attributes.get("href") or "" for n in tree.css("a[href], area[href]")[:MAX_NODES]
    ]
    # Anywhere else in the markup too: onclick handlers, data attributes, form
    # actions, comments and text. Entities are decoded (&amp; separates fields).
    raw_links += [html.unescape(x) for x in _UPI_IN_TEXT.findall(page.text[:MAX_RAW_SCAN])]
    raw_links += _UPI_IN_TEXT.findall(page.visible_text)
    for link in raw_links:
        parsed = parse_upi(link) if ":" in link else None
        if parsed and parsed["link"] not in seen_links and len(upi) < MAX_ITEMS:
            seen_links.add(parsed["link"])
            upi.append(parsed)

    text = page.visible_text.lower()
    linked = {u["pa"] for u in upi}
    vpas = []
    for m in _VPA_IN_TEXT.finditer(text):
        v = m.group(1)
        if v not in linked and v not in vpas and len(vpas) < MAX_ITEMS:
            vpas.append(v)

    bank = []
    for s in page.sentences:
        low = s.lower()
        accounts = [re.sub(r"[ -]", "", a) for a in _ACCOUNT.findall(low)]
        accounts = [a for a in accounts if 9 <= len(a) <= 18]
        ifscs = [i.upper() for i in _IFSC.findall(low)]
        for acct in accounts:
            item = {"account": acct, "ifsc": ifscs[0] if ifscs else None}
            if item not in bank and len(bank) < MAX_ITEMS:
                bank.append(item)

    card_forms = [f["index"] for f in forms(page) if f["card_fields"]]
    donation = []
    for m in _DONATION.finditer(skeleton_of(" ".join(page.sentences))):
        if m.group(0) not in donation and len(donation) < MAX_ITEMS:
            donation.append(m.group(0))
    qr_images = []
    for n in tree.css("img")[:MAX_NODES]:
        hint = " ".join([n.attributes.get("alt") or "", n.attributes.get("src") or ""]).lower()
        if _QR_HINT.search(hint) and len(qr_images) < 10:
            qr_images.append(absolute(page.base, n.attributes.get("src")))

    observations: list[dict] = []
    for u in upi:
        observations.append(
            {
                "kind": "upi",
                "source": "deep_link",
                "identifier_type": "upi_vpa",
                "payee_identifier": u["pa"],
                "payee_name": u["pn"],
                "amount": u["am"],
                "currency": u["cu"],
                "destination": u["link"],
                **_attribute(page, "upi_vpa", u["pa"], u["pn"]),
            }
        )
    for v in vpas:
        observations.append(
            {
                "kind": "upi",
                "source": "page_text",
                "identifier_type": "upi_vpa",
                "payee_identifier": v,
                "payee_name": None,
                **_attribute(page, "upi_vpa", v, None),
            }
        )
    for b in bank:
        observations.append(
            {
                "kind": "bank_account",
                "source": "page_text",
                "identifier_type": "bank_account",
                "payee_identifier": b["account"],
                "ifsc": b["ifsc"],
                "payee_name": None,
                **_attribute(page, "bank_account", b["account"], None),
            }
        )
    for k in merchant_keys:
        observations.append(
            {
                "kind": "merchant_key",
                "source": "inline_script",
                "identifier_type": "merchant_id",
                "provider": k["provider"],
                "payee_identifier": k["key"],
                "payee_name": None,
                **_attribute(page, "merchant_id", k["key"], None),
            }
        )
    for p in providers:
        observations.append(
            {
                "kind": "gateway",
                "source": p["via"],
                "identifier_type": None,
                "provider": p["provider"],
                "payee_identifier": None,
                "payee_name": None,
                "destination": p["url"],
                **_attribute(page, "gateway", None, None),
            }
        )
    return {
        "catalog_version": catalog.version if catalog else None,
        "providers": providers,
        "upi_links": upi,
        "vpas_in_text": vpas,
        "bank_accounts": bank,
        "merchant_keys": merchant_keys,
        "card_field_forms": card_forms,
        "card_fields": sum(f["card_fields"] for f in forms(page)),
        "donation_cues": donation,
        "qr_images": [q for q in qr_images if q],
        "observations": observations,
        "payee_identifiers": sum(1 for o in observations if o["payee_identifier"]),
    }


register(Extractor("payment", VERSION, HTML_TYPES, payment))
