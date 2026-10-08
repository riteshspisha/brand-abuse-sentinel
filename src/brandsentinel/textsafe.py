"""Neutralize untrusted text before it is stored, printed, or exported.

Strings from candidate sites, headers, RDAP, TLS or DNS are attacker-controlled.
Three different sinks need three different treatments:

- facts in the store: strip control and bidi characters, cap length
- terminal output: make those characters visible instead of interpreting them
- CSV export: stop spreadsheets from evaluating a cell as a formula
"""

import unicodedata

# Bidirectional controls are listed explicitly as code points so no invisible
# character ever appears in this file. Most are also category Cf.
_BIDI = frozenset(
    chr(c)
    for c in (
        *(0x061C, 0x200E, 0x200F),
        *range(0x202A, 0x202F),  # LRE RLE PDF LRO RLO
        *range(0x2066, 0x206A),  # LRI RLI FSI PDI
    )
)
# Cc: C0/C1 controls incl. ESC and DEL. Cf: invisible format characters such as
# zero-width spaces, BOM and Unicode tag characters (used to smuggle hidden text
# to language models). Zl/Zp: line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_CSV_TRIGGERS = ("=", "+", "-", "@")
_CSV_LEADING_CONTROLS = ("\t", "\r", "\n")


def _is_unsafe(ch: str) -> bool:
    return ch in _BIDI or unicodedata.category(ch) in _UNSAFE_CATEGORIES


def sanitize_fact(text: str, max_chars: int = 4096) -> str:
    """Return text safe to persist: whitespace controls become spaces, other
    control, format and bidi characters are dropped, and the result is capped."""
    out = []
    for ch in text:
        if ch in "\t\n\r":
            out.append(" ")
        elif not _is_unsafe(ch):
            out.append(ch)
    return "".join(out)[:max_chars]


def escape_terminal(text: str) -> str:
    """Render control, format and bidi characters as visible escapes for terminal
    output. Backslashes are doubled so text cannot imitate an escape."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif _is_unsafe(ch):
            code = ord(ch)
            if code < 0x100:
                out.append(f"\\x{code:02x}")
            elif code < 0x10000:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def neutralize_csv(value: object) -> str:
    """Prefix a single quote when a spreadsheet would treat the cell as a formula."""
    text = "" if value is None else str(value)
    if text.startswith(_CSV_LEADING_CONTROLS):
        return "'" + text
    stripped = text.lstrip()
    if stripped and stripped[0] in _CSV_TRIGGERS:
        return "'" + text
    return text
