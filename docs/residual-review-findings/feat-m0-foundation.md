# Residual review findings: feat/m0-foundation (M0, U1-U2)

Code review run `20261008-155009-3cee99f0` (correctness, testing, maintainability,
security, reliability, adversarial). Actionable findings were fixed before commit;
the items below were accepted as known residuals for later milestones.

| Item | Why accepted now | Revisit in |
|---|---|---|
| Leases use wall-clock time; a suspend/resume or NTP step can expire every lease at once | Delivery is documented as at-least-once and completions are token-checked, so the effect is a re-run, not a lost or duplicated result; stage handlers must be idempotent | U7 (orchestrator) |
| Raw logs flush by record count only; a quiet source can hold unflushed records | Discovery events are written with `durable=True` (fsync per event) per the CertStream guarantee; only the optional firehose relies on batching | U5 |
| Store helpers each open their own transaction and cannot be nested | Sufficient for M0 callers; atomic multi-step writes will need a caller-owned transaction variant | U5/U7 when needed |
| `RawLog` is not thread-safe | The pipeline is a single asyncio process; one writer per source | U7 if threads are introduced |
| Candidate names and case URLs are stored unsanitized | They come from the matcher/normalizer (M1), not raw page text; every output path (CLI, report, CSV) must still escape | U4, U15 |
| Third-party library loggers are not routed through the JSON formatter | No third-party logging yet | U7 |
| Several config keys (stage limits, firehose caps) have no consumer yet | Declared now so the config surface is stable; wired by later units | U5, U7, U22 |
