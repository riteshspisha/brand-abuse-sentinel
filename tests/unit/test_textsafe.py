import pytest

from brandsentinel.textsafe import escape_terminal, neutralize_csv, sanitize_fact


def test_terminal_escaping_makes_osc_and_bidi_visible():
    out = escape_terminal("title \x1b]0;x\x07 \u202eabc")
    assert out == "title \\x1b]0;x\\x07 \\u202eabc"
    assert "\x1b" not in out and "\u202e" not in out


def test_terminal_escaping_covers_newlines_and_c1():
    assert escape_terminal("a\nb\x9bc") == "a\\x0ab\\x9bc"


def test_terminal_escaping_leaves_normal_unicode():
    assert escape_terminal("Sadhguru सद्गुरु ✓") == "Sadhguru सद्गुरु ✓"


def test_fact_sanitizer_strips_controls_and_bidi():
    assert sanitize_fact("a\x1b[31mred\x1b[0m\u202eb\u2066c\x00d") == "a[31mred[0mbcd"


def test_fact_sanitizer_turns_whitespace_controls_into_spaces():
    assert sanitize_fact("line1\nline2\tx\ry") == "line1 line2 x y"


def test_fact_sanitizer_truncates():
    assert sanitize_fact("x" * 50, max_chars=10) == "x" * 10


@pytest.mark.parametrize(
    "cell",
    ['=HYPERLINK("http://x")', " =HYPERLINK(1)", "\t=cmd", "\r=cmd", "+1", "-1+2", "@SUM(A1)"],
)
def test_csv_formula_triggers_are_neutralized(cell):
    assert neutralize_csv(cell) == "'" + cell


@pytest.mark.parametrize("cell", ["plain", "a=b", "", "  ", "Isha Foundation"])
def test_csv_plain_cells_unchanged(cell):
    assert neutralize_csv(cell) == cell


def test_csv_non_string_values():
    assert neutralize_csv(None) == ""
    assert neutralize_csv(-5) == "'-5"
    assert neutralize_csv(42) == "42"


@pytest.mark.parametrize(
    "hidden",
    [
        "\u200b",  # zero-width space
        "\ufeff",  # byte-order mark
        "\u2028",  # line separator
        "\u2029",  # paragraph separator
        "\U000e0041",  # tag LATIN CAPITAL LETTER A ("ASCII smuggling")
        "\u2066",  # left-to-right isolate
    ],
)
def test_invisible_format_characters_are_removed_and_escaped(hidden):
    text = f"pay{hidden}here"
    assert sanitize_fact(text) == "payhere"
    escaped = escape_terminal(text)
    assert hidden not in escaped and escaped.startswith("pay\\") and escaped.endswith("here")


def test_terminal_escaping_doubles_backslashes():
    # A literal backslash sequence must not look like an escape the tool emitted.
    assert escape_terminal("a\\x1bb") == "a\\\\x1bb"


def test_csv_leading_newline_is_neutralized():
    assert neutralize_csv("\n=cmd") == "'\n=cmd"
