"""Image references on a page (U17): candidates for media analysis and visual
matching. Nothing is fetched or decoded here; this only reads markup.

- `icons`: `<link rel=icon|apple-touch-icon>` targets, else the site's default
  `/favicon.ico` (marked `default`);
- `og_images`: `og:image` and `twitter:image` targets;
- `images`: `<img>` elements in document order, with their alt text, declared
  size, and why one may be a logo (file name, alt text, class or id says so,
  the alt text names a protected brand, or it sits in the page header) or a
  payment QR code;
- `inline`: `data:image/...;base64` images (counted by position; the media
  stage reads their bytes from the stored page, never from this feature).
"""

import re
from urllib.parse import urlsplit

from brandsentinel.analysis import HTML_TYPES, MAX_TEXT, Extractor, Page, absolute, register
from brandsentinel.analysis.association import brands_in

VERSION = "images/1"
MAX_IMAGES = 60
MAX_INLINE = 10
MAX_NODES = 2000
_LOGO = re.compile(r"(?<![a-z])(?:logo|logotype|brand|emblem|crest|wordmark)(?![a-z])")
_QR = re.compile(r"(?<![a-z])(?:qr|scan|upi|bhim|gpay|paytm|phonepe)(?![a-z])")
_HEADERISH = re.compile(r"(?<![a-z])(?:header|masthead|navbar|topbar|site-?brand)(?![a-z])")
INLINE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon")
_DATA_URI = re.compile(r"^data:(image/[a-z0-9.+-]+);base64,", re.I)


def _int(value: str | None) -> int | None:
    try:
        n = int(str(value).strip().removesuffix("px"))
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 100_000 else None


def _in_header(node) -> bool:
    parent, depth = node.parent, 0
    while parent is not None and depth < 12:
        if parent.tag in ("header", "nav"):
            return True
        ident = " ".join(
            [parent.attributes.get("id") or "", parent.attributes.get("class") or ""]
        ).lower()
        if _HEADERISH.search(ident):
            return True
        parent, depth = parent.parent, depth + 1
    return False


def inline_images(page: Page) -> list[dict]:
    """`data:image/...;base64,` images, with their payload (used by the media
    stage on the stored page; not stored in the feature)."""
    out = []
    for index, n in enumerate(page.tree.css("img[src]")[:MAX_NODES]):
        src = (n.attributes.get("src") or "").strip()
        m = _DATA_URI.match(src)
        if m and m.group(1).lower() in INLINE_TYPES:
            out.append({"index": index, "mime": m.group(1).lower(), "data": src[m.end() :]})
            if len(out) >= MAX_INLINE:
                break
    return out


def images(page: Page) -> dict:
    tree = page.tree
    icons: list[dict] = []
    for n in tree.css("link[rel][href]")[:MAX_NODES]:
        rel = (n.attributes.get("rel") or "").lower().split()
        if not {"icon", "apple-touch-icon"} & set(rel):
            continue
        url = absolute(page.base, n.attributes.get("href"))
        if url and all(i["url"] != url for i in icons) and len(icons) < 10:
            icons.append(
                {
                    "url": url,
                    "rel": " ".join(rel)[:40],
                    "sizes": (n.attributes.get("sizes") or "")[:40] or None,
                    "type": (n.attributes.get("type") or "")[:40] or None,
                }
            )
    if not icons:
        try:
            parts = urlsplit(page.url)
            if parts.scheme in ("http", "https") and parts.netloc:
                icons.append(
                    {
                        "url": f"{parts.scheme}://{parts.netloc}/favicon.ico",
                        "rel": "default",
                        "sizes": None,
                        "type": None,
                    }
                )
        except ValueError:
            pass
    og: list[str] = []
    for n in tree.css("meta[content]")[:MAX_NODES]:
        key = (n.attributes.get("property") or n.attributes.get("name") or "").lower()
        if key in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image"):
            url = absolute(page.base, n.attributes.get("content"))
            if url and url not in og and len(og) < 5:
                og.append(url)
    found: list[dict] = []
    inline = 0
    for index, n in enumerate(tree.css("img")[:MAX_NODES]):
        src = (n.attributes.get("src") or "").strip()
        if _DATA_URI.match(src):
            inline += 1
            continue
        url = absolute(page.base, src)
        if not url or len(found) >= MAX_IMAGES:
            continue
        alt = (n.attributes.get("alt") or "")[:MAX_TEXT]
        ident = " ".join([n.attributes.get("id") or "", n.attributes.get("class") or ""]).lower()
        name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
        why = []
        if _LOGO.search(name.replace("_", " ").replace("-", " ")):
            why.append("file_name")
        if _LOGO.search(alt.lower()):
            why.append("alt_text")
        if _LOGO.search(ident.replace("_", " ").replace("-", " ")):
            why.append("class_or_id")
        brands = [b["brand"] for b in brands_in(page, alt) if b["strength"] == "strong"]
        if brands:
            why.append("alt_names_brand")
        header = _in_header(n)
        if header:
            why.append("in_header")
        found.append(
            {
                "url": url,
                "index": index,
                "alt": alt or None,
                "width": _int(n.attributes.get("width")),
                "height": _int(n.attributes.get("height")),
                "logo_hints": why,
                "alt_brands": brands,
                "qr_hint": bool(_QR.search(f"{alt} {name}".lower())),
            }
        )
    return {
        "icons": icons,
        "og_images": og,
        "images": found,
        "inline_images": inline,
        "image_count": len(found) + inline,
    }


register(Extractor("images", VERSION, HTML_TYPES, images))
