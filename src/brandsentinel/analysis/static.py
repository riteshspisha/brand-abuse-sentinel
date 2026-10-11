"""Page content: text, forms and credential fields, redirects, links, cues (U12).

`page_content` records what a reader and a browser would be asked to do:

- forms with method, resolved action, action domain, whether they post to a
  different registrable domain, their inputs (type, name, autocomplete hint),
  and the brands named in the form or its enclosing block;
- credential fields: password inputs (in or outside a form) and one-time-code
  inputs;
- script redirects (`location = ...`, `location.replace(...)`) in inline script;
- outbound link domains and messaging/payment link schemes;
- whether the page is empty, a JavaScript shell, image-only, or a parking or
  placeholder page;
- social-engineering lure phrases (account verification, urgency, rewards).

Facts only: nothing here decides whether a page is abusive.
"""

import re
from urllib.parse import urlsplit

from brandsentinel.analysis import (
    HTML_TYPES,
    Extractor,
    Page,
    absolute,
    host_of,
    joined_text,
    node_text,
    register,
    registrable_of,
)
from brandsentinel.analysis.association import brands_in
from brandsentinel.matching.normalize import skeleton_of

VERSION = "page_content/1"
MAX_FORMS = 20
MAX_FORMS_SCANNED = 200
MAX_BLOCK_CHARS = 1000  # an enclosing block larger than this is not form context
MAX_INPUTS = 40
MAX_INPUTS_SCANNED = 2000
MAX_LINKS_SCANNED = 2000
MAX_DOMAINS = 50
MAX_REDIRECTS = 10
MAX_EXCERPT = 1500
MAX_CONTEXT = 400
# Below this much visible text a page shows a reader (almost) nothing.
THIN_TEXT_CHARS = 50

_OTP = re.compile(
    r"(?:^|[^a-z])(?:otp|one.?time|verification.?code|2fa|mfa|totp|passcode|pin)(?:[^a-z]|$)"
)
_PASSWORD_NAME = re.compile(r"(?:^|[^a-z])(?:pass(?:word|wd)?|pwd|passphrase)(?:[^a-z]|$)")
_IDENTITY = re.compile(r"(?:e-?mail|user|login|phone|mobile|member|account|customer)")
_CARD = re.compile(
    r"(?:card.?num|ccnum|cc.?number|cvv|cvc|csc|security.?code|expir|exp.?date|cc.?exp)"
)
_REDIRECTS = [
    (
        "location_assign",
        re.compile(
            r"(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*[\"']([^\"'\s]{1,2048})[\"']"
        ),
    ),
    (
        "location_replace",
        re.compile(r"location\.(?:replace|assign)\(\s*[\"']([^\"'\s]{1,2048})[\"']\s*\)"),
    ),
    ("window_open", re.compile(r"window\.open\(\s*[\"']([^\"'\s]{1,2048})[\"']")),
]
_PARKED = [
    (
        "for_sale",
        re.compile(
            r"(?<![a-z])(?:domain\s+(?:name\s+)?(?:may\s+be|is)\s+for\s+sale|buy\s+this\s+domain|"
            r"make\s+an\s+offer|domain\s+for\s+sale)(?![a-z])"
        ),
    ),
    (
        "parking_service",
        re.compile(
            r"(?<![a-z])(?:related\s+searches|sponsored\s+listings|this\s+domain\s+is\s+parked|"
            r"parked\s+(?:free|domain)|domain\s+parking|sedo|parkingcrew|bodis|afternic|hugedomains)(?![a-z])"
        ),
    ),
    (
        "placeholder",
        re.compile(
            r"(?<![a-z])(?:coming\s+soon|under\s+construction|site\s+is\s+being\s+built|"
            r"default\s+web\s+page|welcome\s+to\s+nginx|it\s+works!|index\s+of\s+/)(?![a-z])"
        ),
    ),
]
_LURES = [
    (
        "account_verification",
        re.compile(
            r"(?<![a-z])(?:verify\s+your\s+(?:account|identity|details|email)|confirm\s+your\s+"
            r"(?:account|identity|details|membership|password)|update\s+your\s+(?:account|payment|billing|"
            r"bank|kyc)\s*(?:details|information)?|account\s+(?:will\s+be|has\s+been|is)\s+"
            r"(?:suspended|locked|closed|deactivated|blocked|moved|migrated)|moving\s+(?:member\s+)?accounts|"
            r"keep\s+access|re-?enter\s+your\s+password|sign\s+in\s+to\s+(?:continue|verify|keep)|kyc)(?![a-z])"
        ),
    ),
    (
        "urgency",
        re.compile(
            r"(?<![a-z])(?:act\s+now|immediately|urgent(?:ly)?|within\s+\d+\s+(?:hours|minutes|days)|"
            r"limited\s+(?:time|seats|offer|period)|seats\s+are\s+limited|last\s+chance|expires?\s+(?:today|soon)|"
            r"only\s+today|hurry)(?![a-z])"
        ),
    ),
    (
        "reward",
        re.compile(
            r"(?<![a-z])(?:blessed\s+gift|free\s+gift|receive\s+a\s+(?:blessed\s+)?gift|you\s+(?:have\s+)?won|"
            r"claim\s+your\s+(?:prize|reward|gift|refund)|cash\s?back|double\s+your|guaranteed\s+returns?|"
            r"lucky\s+draw|prasad(?:am)?\s+(?:delivered|free))(?![a-z])"
        ),
    ),
]
_MESSAGING_HOSTS = {
    "wa.me": "whatsapp",
    "api.whatsapp.com": "whatsapp",
    "chat.whatsapp.com": "whatsapp",
    "t.me": "telegram",
    "telegram.me": "telegram",
}
_LINK_SCHEMES = ("mailto", "tel", "sms", "upi", "intent", "whatsapp", "tg", "javascript")


_host, _rd = host_of, registrable_of


def _input(n) -> dict:
    a = n.attributes
    tag = n.tag
    return {
        "tag": tag,
        "type": (a.get("type") or ("text" if tag == "input" else tag)).lower()[:20],
        "name": (a.get("name") or "")[:64] or None,
        "id": (a.get("id") or "")[:64] or None,
        "autocomplete": (a.get("autocomplete") or "").lower()[:40] or None,
        "placeholder": (a.get("placeholder") or "")[:64] or None,
        # A text input styled to mask what is typed is a password field to a reader.
        "masked": "text-security" in (a.get("style") or "").lower(),
    }


def _inputs(form) -> list[dict]:
    return [_input(n) for n in form.css("input, select, textarea")[:MAX_INPUTS]]


def _probe(i: dict) -> str:
    return " ".join(filter(None, [i["name"], i["id"], i["placeholder"]])).lower()


def is_password(i: dict) -> bool:
    if i["type"] == "password" or i.get("masked"):
        return True
    if (i["autocomplete"] or "") in ("current-password", "new-password"):
        return True
    return i["type"] in ("text", "tel", "number") and bool(_PASSWORD_NAME.search(_probe(i)))


def is_otp(i: dict) -> bool:
    return (i["autocomplete"] or "") == "one-time-code" or bool(_OTP.search(_probe(i)))


def is_card(i: dict) -> bool:
    return (i["autocomplete"] or "").startswith("cc-") or bool(_CARD.search(_probe(i)))


def _form_context(form) -> tuple[str, str]:
    """(spaced, joined) text of a form and the block it sits in. A form directly
    under <body> (or in a very large block) gets its own text plus the few
    elements just before it, not the whole page."""
    parent = form.parent
    if parent is not None and parent.tag not in ("body", "html"):
        text = node_text(parent)
        if len(text) <= MAX_BLOCK_CHARS:
            return text, joined_text(parent)
    parts, joined, n, prev = [node_text(form)], [joined_text(form)], 0, form.prev
    while prev is not None and n < 3:
        if prev.tag != "-text":
            # The end of the element: the text closest to the form.
            parts.insert(0, node_text(prev)[-300:])
            joined.insert(0, joined_text(prev)[-300:])
            n += 1
        prev = prev.prev
    return " ".join(parts), " ".join(joined)


def _merge_brands(*groups: list[dict]) -> list[dict]:
    out: dict[str, str] = {}
    for g in groups:
        for x in g:
            if out.get(x["brand"]) != "strong":
                out[x["brand"]] = x["strength"]
    return [{"brand": b, "strength": st} for b, st in sorted(out.items())]


def forms(page: Page) -> list[dict]:
    """Forms with resolved actions and classified inputs (shared with payment)."""

    def compute() -> list[dict]:
        page_rd = _rd(_host(page.url))
        out = []
        candidates = page.tree.css("form")[:MAX_FORMS_SCANNED]
        # Padding a page with empty forms must not push its credential form out of
        # view: credential forms are always kept, then others in page order.
        creds = [
            i for i, f in enumerate(candidates)
            if any(is_password(x) or is_otp(x) for x in _inputs(f))
        ]  # fmt: skip
        keep = set(creds[:MAX_FORMS])
        for i in range(len(candidates)):
            if len(keep) >= MAX_FORMS:
                break
            keep.add(i)
        for index, f in enumerate(candidates):
            if index not in keep:
                continue
            raw_action = (f.attributes.get("action") or "").strip()
            scheme = urlsplit(raw_action).scheme.lower() if raw_action else ""
            action = page.url if not raw_action else absolute(page.base, raw_action)
            action_host = _host(action)
            action_rd = _rd(action_host)
            inputs = _inputs(f)
            submit = node_text(f.css_first("button, input[type=submit]"))
            if not submit:
                node = f.css_first("input[type=submit]")
                submit = (node.attributes.get("value") or "") if node is not None else ""
            context, joined = _form_context(f)
            out.append(
                {
                    "index": index,
                    "method": (f.attributes.get("method") or "get").upper()[:10],
                    "action": action,
                    "action_scheme": scheme or None,
                    "action_host": action_host,
                    "action_registrable_domain": action_rd,
                    "cross_origin": bool(action_rd and page_rd and action_rd != page_rd),
                    "inputs": inputs,
                    "password_fields": sum(is_password(i) for i in inputs),
                    "otp_fields": sum(is_otp(i) for i in inputs),
                    "identity_fields": sum(
                        i["type"] == "email" or bool(_IDENTITY.search(_probe(i))) for i in inputs
                    ),
                    "card_fields": sum(is_card(i) for i in inputs),
                    "submit_text": submit[:80] or None,
                    "context_excerpt": context[:MAX_CONTEXT] or None,
                    "brands_in_context": _merge_brands(
                        brands_in(page, context[:2000]), brands_in(page, joined[:2000])
                    ),
                }
            )
        return out

    return page.cached("forms", compute)


def _script_redirects(page: Page) -> list[dict]:
    out: list[dict] = []
    scripts = page.inline_scripts
    for kind, rx in _REDIRECTS:
        for m in rx.finditer(scripts):
            url = absolute(page.base, m.group(1))
            if url and {"kind": kind, "url": url} not in out:
                out.append({"kind": kind, "url": url})
            if len(out) >= MAX_REDIRECTS:
                return out
    return out


def _links(page: Page) -> dict:
    page_rd = _rd(_host(page.url))
    domains: list[str] = []
    schemes: dict[str, int] = {}
    messaging: list[dict] = []
    anchors = page.tree.css("a[href]")
    for n in anchors[:MAX_LINKS_SCANNED]:
        href = (n.attributes.get("href") or "").strip()
        scheme = urlsplit(href).scheme.lower() if ":" in href else ""
        if scheme in _LINK_SCHEMES:
            schemes[scheme] = schemes.get(scheme, 0) + 1
            continue
        url = absolute(page.base, href)
        host = _host(url)
        if not host:
            continue
        if host in _MESSAGING_HOSTS and len(messaging) < 10:
            messaging.append({"channel": _MESSAGING_HOSTS[host], "url": url})
        rd = _rd(host)
        if rd and rd != page_rd and rd not in domains and len(domains) < MAX_DOMAINS:
            domains.append(rd)
    return {
        "count": len(anchors),
        "external_domains": domains,
        "schemes": dict(sorted(schemes.items())),
        "messaging": messaging,
    }


def _cues(table, text: str, limit: int = 10) -> list[dict]:
    out: list[dict] = []
    for category, rx in table:
        for m in rx.finditer(text):
            cue = {"category": category, "cue": m.group(0)}
            if cue not in out:
                out.append(cue)
            if len(out) >= limit:
                return out
    return out


def page_content(page: Page) -> dict:
    tree = page.tree
    text = page.visible_text
    scan = skeleton_of(" ".join(page.sentences))
    all_forms = forms(page)
    in_forms = sum(f["password_fields"] for f in all_forms)
    page_passwords = sum(
        1 for n in tree.css("input")[:MAX_INPUTS_SCANNED] if is_password(_input(n))
    )
    scripts = len(tree.css("script"))
    images = len(tree.css("img"))
    thin = len(text) < THIN_TEXT_CHARS
    password_forms = [f["index"] for f in all_forms if f["password_fields"]]
    otp_forms = [f["index"] for f in all_forms if f["otp_fields"]]
    lures = []
    for cue in _cues(_LURES, scan):
        snippet = next((s for s in page.sentences if cue["cue"] in skeleton_of(s)), None)
        lures.append({**cue, "snippet": (snippet or "")[:300] or None})
    meta_description = None
    for n in tree.css("meta[name]"):
        if (n.attributes.get("name") or "").lower() == "description":
            meta_description = (n.attributes.get("content") or "")[:300] or None
            break
    html = tree.css_first("html")
    return {
        "title": page.title,
        "headings": page.headings[:10],
        "meta_description": meta_description,
        "lang": ((html.attributes.get("lang") or "")[:20] or None) if html is not None else None,
        "text_excerpt": text[:MAX_EXCERPT],
        "text_chars": len(text),
        "word_count": len(text.split()),
        "forms": all_forms,
        "credential": {
            "password_fields": page_passwords,
            "password_fields_outside_forms": max(0, page_passwords - in_forms),
            "otp_fields": sum(f["otp_fields"] for f in all_forms),
            "password_forms": password_forms,
            "otp_forms": otp_forms,
            "cross_origin_credential_forms": [
                f["index"]
                for f in all_forms
                if f["cross_origin"] and (f["password_fields"] or f["otp_fields"])
            ],
            "credential_action_domains": sorted(
                {
                    f["action_registrable_domain"]
                    for f in all_forms
                    if (f["password_fields"] or f["otp_fields"]) and f["action_registrable_domain"]
                }
            ),
        },
        "script_redirects": _script_redirects(page),
        "links": _links(page),
        "counts": {"scripts": scripts, "images": images, "forms": len(all_forms)},
        "empty": thin and not scripts and not images and not all_forms,
        "js_shell": thin and scripts > 0 and not all_forms,
        "image_only": thin and images > 0 and scripts == 0 and not all_forms,
        "parked_cues": _cues(_PARKED, scan),
        "lures": lures,
    }


register(Extractor("page_content", VERSION, HTML_TYPES, page_content))
