"""Domain-name normalization for matching.

A name is reduced to several aligned forms:

- `host`: canonical lowercase ASCII (IDN labels as punycode). Used for identity,
  storage and suppression.
- `unicode_host`: IDN labels decoded, NFKC-normalized, with invisible and
  control characters removed. Used for display (always escape before output).
- `skeleton`: `unicode_host` with diacritics stripped and Latin lookalikes from
  other scripts mapped to Latin. Hyphens and dots are kept, so token
  boundaries survive.
- `folded`: `skeleton` with hyphens removed (`save-soil` -> `savesoil`).
- `residue`: `folded` without any character the skeleton could not map, so a
  brand with an inserted foreign letter (`adiyo<X>gi`) is still visible.
- `plain`: `host` with IDN labels blanked, for telling a literal brand from a
  disguised one.

The registrable domain comes from the bundled public suffix list snapshot,
including private suffixes, so `x.github.io` and `y.github.io` are different
owners. Nothing here touches the network.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

import tldextract

MAX_NAME_CHARS = 253
_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")

# Small curated table of single characters that render like a Latin letter.
# Written as code points so the source stays free of lookalike characters.
_CONFUSABLES = {
    # Cyrillic
    0x0430: "a", 0x0435: "e", 0x0456: "i", 0x0458: "j", 0x043A: "k", 0x043E: "o",
    0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x", 0x0455: "s", 0x04BB: "h",
    0x04CF: "l", 0x0501: "d", 0x051B: "q", 0x051D: "w",
    # Greek
    0x03B1: "a", 0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p",
    0x03C5: "u", 0x03C7: "x", 0x03F2: "c", 0x03B3: "y",
    # Armenian
    0x0570: "h", 0x0578: "n", 0x057D: "u", 0x0585: "o",
    # Latin letters that NFKD does not decompose
    0x0131: "i", 0x0142: "l", 0x00F8: "o", 0x0111: "d", 0x0127: "h", 0x0140: "l",
    0x0261: "g", 0x00DF: "ss",
    # Latin extended and IPA lookalikes
    0x0251: "a", 0x1D00: "a", 0x0269: "i", 0x026A: "i", 0x0268: "i", 0x0275: "o",
    0x0257: "d", 0x0266: "h", 0x028B: "v", 0x04AF: "y", 0x0280: "r", 0x0274: "n",
    0x0237: "j", 0x0262: "g",
}  # fmt: skip

# `test` (RFC 6761, never delegated) is a suffix so lab sites under it have
# registrable domains like real ones; no Internet name can end in it.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True, extra_suffixes=("test",)
)


class InvalidName(ValueError):
    """The input is not a usable DNS name."""


@dataclass(frozen=True)
class NormalizedName:
    host: str
    unicode_host: str
    plain: str  # host with IDN labels blanked: what an ASCII reader sees literally
    skeleton: str
    folded: str
    residue: str  # folded with every remaining non-ASCII character dropped
    registrable_domain: str  # empty when the host is itself a public suffix
    wildcard: bool
    idn: bool
    idn_invalid: bool


def canonical_host(name: str) -> tuple[str, bool]:
    """Return (lowercase ASCII host, had_wildcard). Raises InvalidName."""
    if not isinstance(name, str) or len(name) > 4 * MAX_NAME_CHARS:
        raise InvalidName("not a string of plausible length")
    host = name.strip().lower().rstrip(".")
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
    if not host:
        raise InvalidName("empty name")
    labels = []
    for label in host.split("."):
        if not label.isascii():
            label = unicodedata.normalize("NFKC", label).lower()
        if not label.isascii():
            try:
                label = "xn--" + label.encode("punycode").decode("ascii")
            except UnicodeError as e:
                raise InvalidName("label cannot be encoded") from e
        if not _LABEL_RE.match(label):
            raise InvalidName("invalid label")
        labels.append(label)
    host = ".".join(labels)
    if len(host) > MAX_NAME_CHARS:
        raise InvalidName("name too long")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, wildcard
    raise InvalidName("IP address, not a domain name")


def _visible(text: str) -> str:
    # Drop control and format characters (zero-width, bidi), which an IDN can carry.
    return "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf"))


def _decode_label(label: str) -> str | None:
    """Decoded, display-safe text of an IDN label; None if it is not a sane IDN.

    Punycode can encode any code point, so a label could decode to nothing, to
    pure ASCII, or to text containing dots that would fake label boundaries.
    """
    if not label.startswith("xn--"):
        return label
    try:
        raw = label[4:].encode("ascii").decode("punycode")
    except UnicodeError:
        return None
    if raw.isascii():  # never needed punycode
        return None
    # Invisible and fullwidth characters can disguise an ASCII brand, so they are
    # removed or folded here and the result may legitimately be ASCII.
    text = _visible(unicodedata.normalize("NFKC", raw).lower())
    if not text or not all(c == "-" or unicodedata.category(c)[0] in "LMN" for c in text):
        return None
    return text


def skeleton_of(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    out = []
    for c in decomposed:
        if unicodedata.category(c) in ("Mn", "Mc", "Me", "Cc", "Cf"):
            continue
        out.append(_CONFUSABLES.get(ord(c), c))
    return "".join(out)


def registrable_domain(host: str) -> str:
    return _EXTRACT(host).top_domain_under_public_suffix


def normalize(name: str) -> NormalizedName:
    host, wildcard = canonical_host(name)
    decoded = []
    idn = idn_invalid = False
    for label in host.split("."):
        text = _decode_label(label)
        if text is None:
            idn_invalid = True
            text = label
        elif text != label:
            idn = True
        decoded.append(text)
    unicode_host = ".".join(decoded)
    skeleton = skeleton_of(unicode_host)
    folded = skeleton.replace("-", "")
    return NormalizedName(
        host=host,
        unicode_host=unicode_host,
        plain=".".join("" if label.startswith("xn--") else label for label in host.split(".")),
        skeleton=skeleton,
        folded=folded,
        residue="".join(c for c in folded if c.isascii()),
        registrable_domain=registrable_domain(host),
        wildcard=wildcard,
        idn=idn,
        idn_invalid=idn_invalid,
    )
