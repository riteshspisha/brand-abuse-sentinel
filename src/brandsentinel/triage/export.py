"""CSV export of cases (U15, R32, KTD20).

One row per case, columns stable and in this order (times are UTC ISO 8601; list
cells are joined with " | "):

    case_id, priority, category, score, summary, host, registrable_domain,
    subject_url, status, discovery_sources, first_seen, last_seen, domain_match,
    final_url, http_status, fetch_outcome, credential_forms, payment_providers,
    payee_identifiers, payee_attribution, association_claims, labels, flags,
    reasons, manual_review, policy_version, bundle_sha256, scored_at,
    analyst_verdict

`reasons` lists `rule(+points)`; `payee_attribution` pairs each payee with its
attribution. Every cell goes through `neutralize_csv`: a cell whose first
non-whitespace character is `=`, `+`, `-` or `@`, or that starts with a tab,
carriage return or newline, is prefixed with a single quote so spreadsheets do
not evaluate it. Embedded line breaks are flattened to spaces.
"""

import csv
import io
from collections.abc import Iterable

from brandsentinel.textsafe import neutralize_csv
from brandsentinel.triage import CaseReport, iso

COLUMNS = (
    "case_id",
    "priority",
    "category",
    "score",
    "summary",
    "host",
    "registrable_domain",
    "subject_url",
    "status",
    "discovery_sources",
    "first_seen",
    "last_seen",
    "domain_match",
    "final_url",
    "http_status",
    "fetch_outcome",
    "credential_forms",
    "payment_providers",
    "payee_identifiers",
    "payee_attribution",
    "association_claims",
    "labels",
    "flags",
    "reasons",
    "manual_review",
    "policy_version",
    "bundle_sha256",
    "scored_at",
    "analyst_verdict",
)
SEP = " | "
MAX_CELL = 2000


def _cell(value: object) -> str:
    # Neutralize the raw value first, so a leading control character is judged
    # before line breaks are flattened; the quote prefix stays at position 0.
    text = neutralize_csv(value)
    return text.replace("\r", " ").replace("\n", " ")[:MAX_CELL]


def row(report: CaseReport) -> dict[str, object]:
    s, b, p = report.summary, report.bundle, report.result
    out: dict[str, object] = {
        "case_id": s.case_id,
        "priority": s.priority or "unscored",
        "category": s.category or "",
        "score": s.score if s.score is not None else "",
        "host": s.host,
        "registrable_domain": s.registrable_domain or "",
        "status": s.status,
        "discovery_sources": SEP.join(s.sources),
        "first_seen": iso(s.first_seen),
        "last_seen": iso(s.last_seen),
        "scored_at": iso(s.scored_at),
        "analyst_verdict": (report.analyst_labels.get("overall") or {}).get("value", ""),
    }
    if b is not None and p is not None:
        out |= {
            "summary": p.summary,
            "subject_url": b.subject.subject_url or "",
            "domain_match": b.discovery.domain_match,
            "final_url": b.http.final_url or "",
            "http_status": b.http.status if b.http.status is not None else "",
            "fetch_outcome": b.http.outcome or ("not_fetched" if not b.http.fetched else ""),
            "credential_forms": SEP.join(
                f"{f.get('method')} {f.get('action')}" for f in b.credential.forms
            ),
            "payment_providers": SEP.join(
                sorted({x.get("name") or x.get("provider") for x in b.payment.providers})
            ),
            "payee_identifiers": SEP.join(
                o.payee_identifier for o in b.payment.observations if o.payee_identifier
            ),
            "payee_attribution": SEP.join(
                f"{o.payee_identifier}={o.attribution}"
                for o in b.payment.observations
                if o.payee_identifier
            ),
            "association_claims": SEP.join(
                f"{c.get('kind')}: {c.get('snippet')}" for c in b.association.claims
            ),
            "labels": SEP.join(p.labels),
            "flags": SEP.join(p.flags),
            "reasons": SEP.join(f"{r.rule}({r.points:+d})" for r in p.reasons),
            "manual_review": SEP.join(p.manual_review),
            "policy_version": p.policy_version,
            "bundle_sha256": p.bundle_sha256,
        }
    return out


def write_csv(reports: Iterable[CaseReport], out: io.TextIOBase) -> int:
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    n = 0
    for report in reports:
        r = row(report)
        writer.writerow([_cell(r.get(c, "")) for c in COLUMNS])
        n += 1
    return n


def to_csv(reports: Iterable[CaseReport]) -> str:
    buf = io.StringIO()
    write_csv(reports, buf)
    return buf.getvalue()
