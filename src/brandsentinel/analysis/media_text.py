"""What image text says (U16, R21, R18): brand mentions, donation language and
payment identifiers in OCR text, and the payloads of QR codes.

Input is the media sandbox's validated output; this only reads strings. Every
observation keeps the image it came from (sha256) and its source:

- `qr_code`: a decoded QR payload, exact. A UPI link gives payee, name, amount.
- `image_text`: read by OCR, which can misread characters. An OCR identifier
  within two edits of a confirmed registry payee identifier (and not equal to
  it) is attributed `possible_ocr_misread_of_registry_payee`: it may be a
  misreading of the real payee or a deliberate lookalike, so it never earns
  relief, counts as an unconfirmed payee of that payee's brand, and asks for
  review.

Brands are "presented" by an image when its OCR text holds a strong term of the
brand (its name, not a common word such as `Lumina` alone). Attribution uses the
same rules as page payees (payment.attribute).
"""

import re

from rapidfuzz.distance import Levenshtein

from brandsentinel.analysis.association import BrandLexicon, normalize_identifier
from brandsentinel.analysis.payment import (
    _ACCOUNT,
    _DONATION,
    _IFSC,
    _VPA_IN_TEXT,
    attribute,
    parse_upi,
)
from brandsentinel.matching.normalize import skeleton_of

VERSION = "media_text/1"
MAX_ITEMS = 20
OCR_MISREAD = "possible_ocr_misread_of_registry_payee"


def _near_registry_payee(lex: BrandLexicon, kind: str, value: str):
    v = normalize_identifier(value)
    for (k, known), payee in lex.payees.items():
        if k == kind and known != v and Levenshtein.distance(known, v, score_cutoff=2) <= 2:
            return payee
    return None


def _brands(lex: BrandLexicon, text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for term, _, _ in lex.find(text):
        if out.get(term.brand) != "strong":
            out[term.brand] = term.strength
    return out


def media_text(images: list[dict], lex: BrandLexicon | None, html_presented: list[str]) -> dict:
    """`images`: [{"sha256", "role", "ocr_text", "qr": [payload, ...]}]."""
    if lex is None:
        return {"available": False}
    brands: dict[str, dict] = {}
    donation: list[str] = []
    for img in images:
        text = img.get("ocr_text") or ""
        if not text:
            continue
        for brand, strength in _brands(lex, text).items():
            entry = brands.setdefault(
                brand,
                {"brand": brand, "name": lex.brand_names.get(brand, brand), "strength": "weak",
                 "images": []},
            )  # fmt: skip
            if strength == "strong":
                entry["strength"] = "strong"
            if img["sha256"] not in entry["images"]:
                entry["images"].append(img["sha256"])
        for m in _DONATION.finditer(skeleton_of(text)):
            if m.group(0) not in donation and len(donation) < MAX_ITEMS:
                donation.append(m.group(0))
    presented = sorted(b for b, e in brands.items() if e["strength"] == "strong")
    page_presented = sorted(set(html_presented) | set(presented))

    observations: list[dict] = []
    payloads: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(obs: dict) -> None:
        key = (obs["kind"], normalize_identifier(obs["payee_identifier"]))
        if key not in seen and len(observations) < MAX_ITEMS:
            seen.add(key)
            observations.append(obs)

    def attributed(kind: str, ident: str, name: str | None, source: str) -> dict:
        if source == "image_text" and lex.known_payee(kind, ident) is None:
            near = _near_registry_payee(lex, kind, ident)
            if near:
                return {
                    "attribution": OCR_MISREAD,
                    "reason": f"read by OCR within two characters of confirmed registry payee"
                    f" {near.payee_id}: a misreading, or a lookalike payee; not confirmed",
                    "near_registry_payee": near.payee_id,
                    "brands": [near.brand],
                }
        named = [{"brand": b, "strength": s} for b, s in sorted(_brands(lex, name or "").items())]
        return attribute(
            lex, kind, ident, name, named=named, presented=page_presented,
            where="page title, headings, image alt text or image text",
        )  # fmt: skip

    for img in images:
        for payload in img.get("qr") or []:
            upi = parse_upi(payload) if ":" in payload else None
            kind = "upi" if upi else ("url" if re.match(r"(?i)https?://", payload) else "text")
            payloads.append({"image": img["sha256"], "kind": kind, "text": payload[:500]})
            if upi:
                add(
                    {
                        "kind": "upi",
                        "source": "qr_code",
                        "identifier_type": "upi_vpa",
                        "payee_identifier": upi["pa"],
                        "payee_name": upi["pn"],
                        "amount": upi["am"],
                        "currency": upi["cu"],
                        "destination": upi["link"],
                        "image": img["sha256"],
                        **attributed("upi_vpa", upi["pa"], upi["pn"], "qr_code"),
                    }
                )
    for img in images:
        text = (img.get("ocr_text") or "").lower()
        if not text:
            continue
        for m in _VPA_IN_TEXT.finditer(text):
            add(
                {
                    "kind": "upi",
                    "source": "image_text",
                    "identifier_type": "upi_vpa",
                    "payee_identifier": m.group(1),
                    "payee_name": None,
                    "image": img["sha256"],
                    **attributed("upi_vpa", m.group(1), None, "image_text"),
                }
            )
        ifscs = [i.upper() for i in _IFSC.findall(text)]
        for acct in (re.sub(r"[ -]", "", a) for a in _ACCOUNT.findall(text)):
            if 9 <= len(acct) <= 18:
                add(
                    {
                        "kind": "bank_account",
                        "source": "image_text",
                        "identifier_type": "bank_account",
                        "payee_identifier": acct,
                        "ifsc": ifscs[0] if ifscs else None,
                        "payee_name": None,
                        "image": img["sha256"],
                        **attributed("bank_account", acct, None, "image_text"),
                    }
                )
    return {
        "available": True,
        "brands": sorted(brands.values(), key=lambda b: b["brand"]),
        "presented": presented,
        "donation_cues": donation,
        "qr_payloads": payloads[:MAX_ITEMS],
        "observations": observations,
    }
