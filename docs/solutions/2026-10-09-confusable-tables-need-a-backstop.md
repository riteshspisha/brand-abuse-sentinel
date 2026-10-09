# Confusable tables need a backstop

**Context:** M1 matcher, IDN and lookalike domain names (`src/brandsentinel/matching/`).

A hand-curated confusables table (Cyrillic and Greek lookalikes plus NFKD diacritic
stripping) passed every planned test, but review found two cheap evasions that kept
non-fuzzy brand keywords from matching at all:

- an unmapped Latin-extended or IPA letter (`U+0251` in `adiyogi`), and
- one inserted foreign character (a Hangul filler, a Devanagari letter, or a spacing
  or enclosing mark) in the middle of the brand.

Punycode keeps the basic code points in the A-label (`xn--adiyogi-donate-u56c`), so
dropping every character the skeleton cannot map recovers the brand.

**Lesson:** never rely on the table alone. Match on three things:

1. the mapped skeleton;
2. a `residue` form with every unmapped non-ASCII character removed;
3. a fuzzy fallback that compares any non-ASCII name part with every high-tier keyword.

Strip all mark categories (`Mn`, `Mc`, `Me`) and format characters. Report anything
that needed decoding or mapping as `homoglyph`, never `substring`.

When testing, build lookalike names from code points (`chr(0x0251)`) so the source
stays free of lookalike characters (see `2026-10-08-invisible-unicode-in-source.md`).
