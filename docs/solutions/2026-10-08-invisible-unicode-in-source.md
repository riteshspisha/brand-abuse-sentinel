# Invisible Unicode can enter source through tool-written escapes

**Context:** M0 (`textsafe`, tests). Source and test files written by an agent tool
ended up containing literal bidi and format characters (for example U+202E) where
`\uXXXX` escapes were intended. Tool parameters are JSON, so `\uXXXX` is decoded
to the real character before the file is written; `\xNN` is not a JSON escape and
survives. One hidden character landed in the plan document the same way.

**Why it matters:** this project exists to neutralize hidden characters in
attacker content; the same characters in our own code are a Trojan Source risk
and make security tests silently test the wrong thing.

**What we do now:**
- Ruff rule `PLE2502` (bidirectional Unicode) is enabled; `RUF001` flags
  ambiguous characters.
- Security-relevant character sets are defined by code point (`chr(0x202E)`),
  not by escape literals.
- When writing files containing escapes through a tool, check the result with
  `od -c` or a Unicode-category scan before committing.
