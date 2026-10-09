# httpcore chains ssl errors as context, not cause

**Context.** The hardened fetcher (M3) must tell a certificate-verification failure
(retry without verification in evidence mode) apart from other connect failures.

**Problem.** httpcore wraps `ssl.SSLCertVerificationError` in `httpcore.ConnectError`
inside its `map_exceptions` context manager. The original exception is reachable
through `__context__`, and `__cause__` is not set in the anyio TLS path. A check of
`e.__cause__` alone classified every bad certificate as a plain `connect_error`, so
evidence mode never fell back and verified mode never reported `tls_error`.

**Fix.** Walk both links (`__cause__ or __context__`, bounded) to find the
`ssl.SSLError` (`net/fetcher.py:_ssl_cause`). The harness tests for self-signed,
expired and wrong-host certificates pin the behaviour.

**Also.** selectolax 1.0 removed the Modest backend: `selectolax.parser.HTMLParser`
raises ImportError on import. Use `selectolax.lexbor.LexborHTMLParser`.
