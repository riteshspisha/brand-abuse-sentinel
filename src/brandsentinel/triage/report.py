"""Analyst reports: terminal text and self-contained static HTML (U15, KTD20, R40).

The HTML report is rendered by Jinja2 with autoescaping on for every template,
declares `default-src 'none'` (images only from data URIs or the report itself,
inline styles only, no scripts, no forms, no base URI), and never links to a
candidate URL: every URL is printed as text. Analysts never load attacker HTML.

The text report is a list of plain lines; the CLI passes each through
`escape_terminal`, so control, bidi and escape sequences in page text show as
visible escapes instead of acting on the terminal.

A report ranks analyst attention. It is not a finding of fraud and it never
initiates a takedown.
"""

import os
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from brandsentinel.store.fsutil import ensure_private_dir
from brandsentinel.triage import CaseReport, CaseSummary, iso

CSP = (
    "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "
    "base-uri 'none'; form-action 'none'"
)
DISCLAIMER = (
    "Priority ranks analyst attention from observed evidence; it is not a finding of fraud."
    " BrandSentinel never initiates takedowns."
)


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("brandsentinel.triage", "templates"),
        autoescape=True,  # every template, whatever its extension
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["iso"] = iso
    return env


def render_case_html(report: CaseReport) -> str:
    return (
        _env()
        .get_template("case.html.j2")
        .render(
            r=report,
            s=report.summary,
            b=report.bundle,
            p=report.result,
            csp=CSP,
            disclaimer=DISCLAIMER,
        )
    )


def render_index_html(cases: list[CaseSummary], generated_at: float) -> str:
    return (
        _env()
        .get_template("index.html.j2")
        .render(cases=cases, generated_at=generated_at, csp=CSP, disclaimer=DISCLAIMER)
    )


def write_private(path: Path, text: str) -> Path:
    """Write a report readable only by its owner (reports quote untrusted text)."""
    ensure_private_dir(path.parent)
    # O_NOFOLLOW: never write through a symlink planted in a shared directory.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    path.chmod(0o600)
    return path


# --- terminal ----------------------------------------------------------------------


def _kv(label: str, value) -> str:
    return f"  {label + ':':<22} {'' if value is None else value}"


def render_case_text(report: CaseReport) -> list[str]:
    s, b, p = report.summary, report.bundle, report.result
    lines = [
        f"Case #{s.case_id}  {s.host}",
        f"  {DISCLAIMER}",
        "",
    ]
    if p is None or b is None:
        lines += [
            _kv("status", s.status),
            _kv("priority", "not scored yet (no static analysis result)"),
            _kv("discovered by", ", ".join(s.sources)),
        ]
        return lines
    lines += [
        _kv(
            "priority",
            f"{p.priority}  (score {p.score}: abuse {p.abuse_points}, supporting"
            f" {p.supporting_points}, relief {p.relief_points})",
        ),
        _kv("category", p.category),
        _kv("summary", p.summary),
        _kv("labels", ", ".join(p.labels) or "-"),
        _kv("flags", ", ".join(p.flags) or "-"),
        "",
        "Why (policy reasons):",
    ]
    if not p.reasons:
        lines.append("  no rule fired")
    for r in p.reasons:
        lines.append(f"  {r.points:+5}  {r.rule} [{r.kind}]")
        lines.append(f"         {r.explanation}")
        lines.append(f"         evidence: {', '.join(r.evidence) or '-'}")
    if p.context:
        lines += ["", "Context (never changes the score):"]
        lines += [f"  {c.label}: {c.explanation}" for c in p.context]
    if p.manual_review:
        lines += ["", "Manual review:"]
        lines += [f"  - {m}" for m in p.manual_review]
    if p.unknowns:
        lines += ["", "Unknowns: " + ", ".join(dict.fromkeys(p.unknowns))]

    d = b.discovery
    lines += ["", "Discovery (name similarity):"]
    for src in d.sources:
        lines.append(
            f"  {src.source:<10} first {src.first_seen}  last {src.last_seen}"
            f"  ({src.observations} observation(s))"
        )
    lines.append(_kv("domain match", d.domain_match))
    for h in d.hits[:8]:
        lines.append(
            f"    hit {h.get('type')}:{h.get('keyword')} brand {h.get('brand')}"
            f"{' (' + h['reason'] + ')' if h.get('reason') else ''}"
        )
    if d.labels:
        lines.append(_kv("matcher labels", ", ".join(d.labels)))

    h = b.http
    lines += ["", "HTTP (static fetch, evidence mode):"]
    if not h.fetched:
        lines.append("  not fetched" + (f" ({len(h.attempts)} attempt(s))" if h.attempts else ""))
    else:
        lines += [
            _kv("requested", h.requested_url),
            _kv("outcome", h.outcome),
            _kv("final URL", h.final_url),
            _kv("status", h.status),
            _kv("content", f"{h.content_type} {h.body_bytes} bytes sha256 {h.body_sha256}"),
        ]
        for hop in h.redirect_chain:
            lines.append(
                f"    hop {hop.status} {hop.url} via {hop.address}"
                f"{' -> ' + hop.location if hop.location else ''}"
                f"{' error ' + hop.error if hop.error else ''}"
            )
        if h.error:
            lines.append(_kv("error", h.error))

    pg = b.page
    lines += ["", "Page (observed):"]
    lines += [
        _kv("title", pg.title),
        _kv("headings", " | ".join(pg.headings[:5])),
        _kv(
            "brands",
            ", ".join(
                f"{x['name']} ({x['strength']}: {', '.join(x['locations'])})"
                for x in b.association.brands
            )
            or "-",
        ),
        _kv("presents", ", ".join(b.association.presented) or "-"),
    ]
    for c in b.association.claims:
        lines.append(f"    claim {c.get('kind')}: {c.get('snippet')}")
    for c in b.association.disclaimers:
        lines.append(f"    disclaimer (page-provided): {c.get('snippet')}")
    for f in b.credential.forms:
        lines.append(
            f"    credential form #{f.get('index')} {f.get('method')} -> {f.get('action')}"
            f" (cross-origin {f.get('cross_origin')}, password {f.get('password_fields')},"
            f" otp {f.get('otp_fields')})"
        )
    if b.payment.observations:
        lines += ["", "Payment (facts | attribution | evidence):"]
        for o in b.payment.observations:
            lines.append(
                f"  {o.kind} {o.payee_identifier or o.provider or ''}"
                f"{' name ' + repr(o.payee_name) if o.payee_name else ''}"
                f"{' amount ' + o.amount if o.amount else ''}"
            )
            lines.append(f"      attribution: {o.attribution} - {o.attribution_reason}")
            lines.append(f"      evidence: {', '.join(o.refs)} ({o.extractor_version})")
    if b.payment.donation_cues:
        lines.append(_kv("donation cues", ", ".join(b.payment.donation_cues)))
    if b.page.lures:
        lines.append(_kv("lures", ", ".join(f"{x['category']}: {x['cue']}" for x in b.page.lures)))
    redirects = b.page.meta_refresh + b.page.script_redirects
    for r in redirects:
        lines.append(f"    client redirect {r.get('kind', 'meta_refresh')} -> {r.get('url')}")

    inf = b.infrastructure
    lines += ["", f"Infrastructure (enrichment {inf.enrichment}):"]
    if inf.dns:
        lines.append(
            _kv("dns", f"{inf.dns.get('status')} A {inf.dns.get('a')} AAAA {inf.dns.get('aaaa')}")
        )
    if inf.rdap:
        lines.append(
            _kv(
                "rdap",
                f"registered {inf.rdap.get('registered_at')} registrar"
                f" {inf.rdap.get('registrar')} (age {inf.domain_age_days} days)",
            )
        )
    if inf.tls:
        lines.append(
            _kv(
                "tls",
                f"issuer {inf.tls.get('issuer')} verified {inf.tls.get('verification_passes')}",
            )
        )
    if inf.similarity:
        close = inf.similarity.get("closest_official_domains") or []
        lines.append(
            _kv(
                "closest official",
                ", ".join(f"{c.get('domain')} (distance {c.get('distance')})" for c in close)
                or "-",
            )
        )
    for e in inf.errors:
        lines.append(_kv("enrichment error", e))

    lines += [
        "",
        "Provenance:",
        _kv("policy", p.policy_version),
        _kv("bundle", f"{p.bundle_schema} sha256 {p.bundle_sha256}"),
        _kv("scored at", iso(s.scored_at)),
    ]
    if report.analyst_labels:
        lines += ["", "Analyst labels:"]
        for q, v in report.analyst_labels.items():
            lines.append(f"  {q}: {v['value']}" + (f" (by {v['by']})" if v.get("by") else ""))
    return lines
