"""Commerce indicators: prices, calls to action, carts, product markup (U12).

Commerce is context (`commerce` label). It becomes abuse evidence only in the
policy, combined with a brand claim on a domain with no confirmed relationship.
"""

import re

from brandsentinel.analysis import HTML_TYPES, Extractor, Page, register, unique_matches
from brandsentinel.analysis.editorial import ld_json_types

VERSION = "commerce/1"
MAX_ITEMS = 20

_PRICE = re.compile(
    r"(?:(?<![a-z])(?:\u20b9|rs\.?|inr|\$|usd|us\$|\u20ac|eur|\u00a3|gbp)\s?\d[\d,]{0,12}(?:\.\d{1,2})?)"
    r"|(?:\d[\d,]{0,12}(?:\.\d{1,2})?\s?(?:inr|rupees|rs\.?|usd|dollars|eur|euros|gbp)(?![a-z]))"
)
_CTA = re.compile(
    r"(?<![a-z])(?:add\s+to\s+(?:cart|bag|basket)|buy\s+now|book\s+now|shop\s+now|order\s+now|"
    r"pay\s+now|checkout|check\s+out|proceed\s+to\s+pay(?:ment)?|purchase|enrol(?:l)?\s+now|"
    r"register\s+now|book\s+(?:a|your)\s+\w+|get\s+tickets?)(?![a-z])"
)
_CART = re.compile(r"(?<![a-z])(?:add\s+to\s+(?:cart|bag|basket)|view\s+cart|my\s+cart)(?![a-z])")
_CHECKOUT_ACTION = re.compile(r"(?:checkout|cart|order|payment|/pay\b|purchase|billing)")
PRODUCT_TYPES = frozenset({"product", "offer", "aggregateoffer", "productgroup", "event"})


def _found(rx: re.Pattern, text: str) -> list[str]:
    return unique_matches(rx, text, MAX_ITEMS)


def commerce(page: Page) -> dict:
    text = " ".join(page.sentences).lower()
    buttons = " ".join(
        (n.attributes.get("value") or n.text(deep=True) or "")
        for n in page.tree.css("button, input[type=submit], a")[:2000]
    )[:20000].lower()
    prices = _found(_PRICE, text)
    ctas = _found(_CTA, text + " " + buttons)
    cart = bool(_CART.search(text + " " + buttons))
    product_types = sorted(t for t in ld_json_types(page) if t in PRODUCT_TYPES)
    og_product = any(
        (n.attributes.get("property") or "").lower() == "og:type"
        and (n.attributes.get("content") or "").lower().startswith("product")
        for n in page.tree.css("meta[property]")
    )
    itemprop_price = page.tree.css_first('[itemprop="price"]') is not None
    checkout_forms = sum(
        1
        for f in page.tree.css("form")
        if _CHECKOUT_ACTION.search((f.attributes.get("action") or "").lower())
        or _CHECKOUT_ACTION.search((f.attributes.get("id") or "").lower())
    )
    return {
        "prices": prices,
        "calls_to_action": ctas,
        "cart": cart,
        "product_markup": product_types + (["og:product"] if og_product else []),
        "itemprop_price": itemprop_price,
        "checkout_forms": checkout_forms,
        "commerce": bool(
            (prices and ctas)
            or cart
            or product_types
            or og_product
            or itemprop_price
            or (checkout_forms and prices)
        ),
    }


register(Extractor("commerce", VERSION, HTML_TYPES, commerce))
