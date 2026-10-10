"""Deterministic policy scorer: priority, category, labels and reasons (U14, R28, R29).

`evaluate` is a pure function of an EvidenceBundle, a Policy and (optionally)
advisory judgments. It returns every fired rule as a reason with its points, an
explanation and evidence references, so a decision can be audited without
reading code. Context labels describe a case and never change its score.
`CaseScorer` builds a case's bundle from the store, evaluates it and records
the result (policy version and bundle hash included) when anything changed.

Categories follow a fixed precedence among fired abuse rules; without abuse
evidence a case is `typosquat_parked`, `editorial_or_critical`,
`insufficient_evidence` (static analysis could not see the content),
`benign_related` (brand-related, no abuse indicator observed) or `unrelated`.
None of these is a finding of fraud; P1-P4 rank analyst attention.
"""

import json
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from brandsentinel.analysis.association import BrandLexicon
from brandsentinel.evidence.bundle import (
    EvidenceBundle,
    build_bundle,
    bundle_json,
    bundle_sha256,
    load_inputs,
)
from brandsentinel.evidence.models import load_judgments
from brandsentinel.policy.rules import RULES, credential_tie
from brandsentinel.registry.model import Registry
from brandsentinel.store.db import transaction

PRIORITIES = ("P1", "P2", "P3", "P4")
NO_ACTION = "no_action"
CATEGORY_PRECEDENCE = (
    "credential_phishing",
    "payment_fraud",
    "donation_fraud",
    "impersonation",
    "false_association",
    "unauthorized_commerce",
    "typosquat_parked",
)
CATEGORIES = (
    *CATEGORY_PRECEDENCE,
    "editorial_or_critical",
    "insufficient_evidence",
    "benign_related",
    "unrelated",
)
_UNOBSERVED = (
    "not_fetched",
    "fetch_pending_retry",
    "js_shell",
    "image_only",
    "empty_page",
    "no_html_content",
)


class PolicyError(Exception):
    pass


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    thresholds: dict[str, int]
    max_priority_without_abuse: str = "P3"
    min_priority_when_unobserved: str = "P4"
    model_review_threshold: float = Field(0.8, gt=0, le=1)
    params: dict[str, float] = {}
    points: dict[str, int]

    @model_validator(mode="after")
    def _check(self):
        if set(self.thresholds) != set(PRIORITIES):
            raise ValueError(f"thresholds must define exactly {list(PRIORITIES)}")
        values = [self.thresholds[p] for p in PRIORITIES]
        if values != sorted(values, reverse=True) or values[-1] < 1:
            raise ValueError("thresholds must decrease from P1 to P4, and P4 must be >= 1")
        for key in ("max_priority_without_abuse", "min_priority_when_unobserved"):
            if getattr(self, key) not in PRIORITIES:
                raise ValueError(f"{key} must be one of P1..P4")
        missing, unknown = set(RULES) - set(self.points), set(self.points) - set(RULES)
        if missing or unknown:
            raise ValueError(
                f"points must list every rule exactly: missing {sorted(missing)},"
                f" unknown {sorted(unknown)}"
            )
        if any(v < 0 for v in self.points.values()):
            raise ValueError("points must be >= 0 (relief rules subtract their points)")
        return self

    @classmethod
    def load(cls, path: Path) -> "Policy":
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return cls.model_validate(data)
        except (OSError, yaml.YAMLError, ValidationError) as e:
            raise PolicyError(f"invalid policy {path}: {e}") from e


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule: str
    kind: str
    points: int
    summary: str
    explanation: str
    evidence: list[str]
    category: str | None = None


class ContextNote(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    explanation: str
    evidence: list[str] = []


class PolicyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str
    bundle_schema: str
    bundle_sha256: str
    score: int
    abuse_points: int
    supporting_points: int
    relief_points: int
    priority: str
    category: str
    capped: bool  # priority lowered because no abuse-evidence rule fired
    labels: list[str]
    flags: list[str]
    reasons: list[Reason]
    context: list[ContextNote]
    manual_review: list[str]
    unknowns: list[str]
    summary: str


def _priority(score: int, policy: Policy) -> str:
    for p in PRIORITIES:
        if score >= policy.thresholds[p]:
            return p
    return NO_ACTION


def _rank(priority: str) -> int:
    return PRIORITIES.index(priority) if priority in PRIORITIES else len(PRIORITIES)


def _context(b: EvidenceBundle) -> list[ContextNote]:
    notes: list[ContextNote] = []

    def add(label: str, explanation: str, evidence: list[str] = ()) -> None:
        notes.append(ContextNote(label=label, explanation=explanation, evidence=list(evidence)))

    e = b.editorial
    cues = e.parody_cues + e.critical_cues
    if e.editorial or e.parody_cues or (e.article_markup.get("present") and e.critical_cues):
        what = []
        if e.article_markup.get("present"):
            what.append("article markup")
        if e.byline:
            what.append(f"byline {e.byline!r}")
        if cues:
            what.append("cues " + ", ".join(repr(c) for c in cues[:4]))
        add(
            "editorial_or_critical",
            "Page-provided editorial, critical or parody signals ("
            + "; ".join(what)
            + "). Context only: they never lower a score.",
            e.refs,
        )
    if b.association.disclaimers or e.disclaimer_cues:
        add(
            "disclaimer_present",
            "The page carries a self-declared disclaimer (page-provided; not relief).",
            _refs(b.association.refs, e.refs),
        )
    if b.page.parked_cues:
        add("parked", "Parking or placeholder page cues.", b.page.refs)
    if b.commerce.commerce:
        add("commerce", "Prices, calls to action, a cart or product markup.", b.commerce.refs)
    if b.payment.providers:
        names = sorted({p.get("name") or p.get("provider") for p in b.payment.providers})
        add(
            "payment_gateway_present",
            f"Payment provider(s) {', '.join(names)} referenced; a gateway alone scores zero.",
            b.payment.refs,
        )
    if b.registry.official_domain:
        add("official_domain", f"Confirmed official domain {b.registry.official_domain}.")
    if b.registry.final_url_official_domain and not b.registry.official_domain:
        add("redirects_to_official", f"Fetch ended on {b.registry.final_url_official_domain}.")
    for label in b.discovery.labels:
        add(label, "Discovery matcher label.", b.discovery.refs)
    if b.http.tls_verification_failed:
        add("tls_verification_failed", "TLS certificate did not verify.", b.http.refs)
    if b.page.messaging_links:
        add(
            "messaging_contact",
            "Links to messaging channels: "
            + ", ".join(sorted({m.get("channel") for m in b.page.messaging_links})),
            b.page.refs,
        )
    if any(g in b.incomplete for g in _UNOBSERVED) or any(
        g.startswith("fetch_") for g in b.incomplete
    ):
        add("incomplete_evidence", "Static content was missing or not observable.", b.http.refs)
    return notes


def _refs(*groups: Iterable[str]) -> list[str]:
    out: list[str] = []
    for g in groups:
        out += [r for r in g if r not in out]
    return out


def _unobserved(b: EvidenceBundle) -> list[str]:
    return [g for g in b.incomplete if g in _UNOBSERVED or g.startswith("fetch_")]


def _judgment_flag(judgments: Iterable[dict], policy: Policy) -> bool:
    for j in judgments:
        probs = j.get("probabilities", j) if isinstance(j, dict) else {}
        for v in probs.values() if isinstance(probs, dict) else []:
            if isinstance(v, int | float) and v > policy.model_review_threshold:
                return True
    return False


def evaluate(b: EvidenceBundle, policy: Policy, judgments: Iterable[dict] = ()) -> PolicyResult:
    reasons: list[Reason] = []
    for rule in RULES.values():
        fired = rule.fn(b, policy.params)
        if fired is None:
            continue
        reasons.append(
            Reason(
                rule=rule.id,
                kind=rule.kind,
                points=policy.points[rule.id] * (-1 if rule.kind == "relief" else 1),
                summary=rule.summary,
                explanation=fired.explanation,
                evidence=fired.evidence,
                category=fired.category or rule.category,
            )
        )
    abuse = sum(r.points for r in reasons if r.kind == "abuse")
    supporting = sum(r.points for r in reasons if r.kind == "supporting")
    relief = -sum(r.points for r in reasons if r.kind == "relief")
    score = max(0, abuse + supporting - relief)
    priority = _priority(score, policy)
    capped = False
    has_abuse = any(r.kind == "abuse" for r in reasons)
    if not has_abuse and _rank(priority) < _rank(policy.max_priority_without_abuse):
        priority, capped = policy.max_priority_without_abuse, True

    context = _context(b)
    labels = sorted({c.label for c in context})
    fired_categories = {r.category for r in reasons if r.category and r.points > 0}
    category = next((c for c in CATEGORY_PRECEDENCE if c in fired_categories), None)
    unobserved = _unobserved(b)
    brand_related = (
        b.association.strong_mention
        or bool(b.association.presented)
        or b.discovery.domain_match == "strong"
    )
    if category is None:
        if b.registry.official_domain:
            category = "benign_related"
        elif "editorial_or_critical" in labels and (
            b.association.strong_mention or b.association.presented
        ):
            category = "editorial_or_critical"
        elif unobserved:
            category = "insufficient_evidence"
        elif brand_related:
            category = "benign_related"
        else:
            category = "unrelated"
    floored = False
    cleared = bool(b.registry.official_domain)
    if (
        unobserved
        and not has_abuse
        and not cleared
        and _rank(priority) > _rank(policy.min_priority_when_unobserved)
    ):
        priority, floored = policy.min_priority_when_unobserved, True

    flags: list[str] = []
    manual: list[str] = []
    unknowns = list(b.incomplete)
    if unobserved and not b.registry.official_domain:
        manual.append(
            "Static content was not observable (" + ", ".join(unobserved) + "); the absence of"
            " abuse indicators here is not evidence of benign use."
        )
    if b.page.js_shell:
        flags.append("needs_render")
        unknowns.append("page builds its content with script: browser rendering (M7) needed")
    if b.page.image_only or b.payment.qr_images:
        flags.append("needs_media")
        unknowns.append("images and QR codes are not decoded until media analysis (M6)")
    if has_abuse and "editorial_or_critical" in labels:
        manual.append(
            "Abuse evidence appears alongside page-provided editorial/parody signals; those"
            " signals did not lower the priority (AE15)."
        )
    for d in b.registry.registry_domains:
        manual.append(
            f"{d['host']} is under registry domain {d['domain']} with status {d['status']};"
            " confirm or reject it in the registry (only confirmed entries give relief)."
        )
    if (b.credential.forms or b.credential.password_fields_outside_forms) and credential_tie(
        b
    ) is None:
        manual.append(
            "A credential form is present but not tied to a protected brand; check what account"
            " it collects."
        )
    if (
        not has_abuse
        and any(o.attribution == "unrelated" and o.payee_identifier for o in b.payment.observations)
        and brand_related
    ):
        manual.append("Payment identifiers on a brand-related page are not attributed to a brand.")
    if b.http.body_truncated:
        manual.append(f"Page body was truncated ({b.http.body_truncated}); findings are partial.")
    if manual:
        flags.append("manual_review")
    if _judgment_flag(judgments, policy) and priority in ("P3", "P4", NO_ACTION):
        flags.append("model_suggests_review")

    fired_abuse = [r.rule for r in reasons if r.kind == "abuse"]
    if fired_abuse:
        summary = f"{priority} {category}: abuse evidence from {', '.join(fired_abuse)}."
    elif reasons:
        summary = f"{priority} {category}: no abuse evidence; supporting or relief signals only."
    else:
        summary = f"{priority} {category}: no rule fired."
    if capped:
        summary += f" Capped at {priority} without abuse evidence."
    if floored:
        summary += f" Kept at {priority} because the content could not be observed."
    return PolicyResult(
        policy_version=policy.version,
        bundle_schema=b.schema_version,
        bundle_sha256=bundle_sha256(b),
        score=score,
        abuse_points=abuse,
        supporting_points=supporting,
        relief_points=relief,
        priority=priority,
        category=category,
        capped=capped,
        labels=labels,
        flags=sorted(set(flags)),
        reasons=reasons,
        context=context,
        manual_review=manual,
        unknowns=unknowns,
        summary=summary,
    )


@dataclass
class ScoreOutcome:
    score_id: int
    changed: bool
    bundle: EvidenceBundle
    result: PolicyResult


class CaseScorer:
    """Builds, evaluates and records a case's score from the store."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        registry: Registry,
        policy: Policy,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.conn = conn
        self.registry = registry
        self.lexicon = BrandLexicon.from_registry(registry)
        self.policy = policy
        self.clock = clock

    def bundle(self, case_id: int) -> EvidenceBundle | None:
        inputs = load_inputs(self.conn, case_id)
        return build_bundle(inputs, self.lexicon, self.registry) if inputs else None

    def score(self, case_id: int) -> ScoreOutcome | None:
        bundle = self.bundle(case_id)
        if bundle is None:
            return None
        judgments = [j.result for j in load_judgments(self.conn, case_id)]
        result = evaluate(bundle, self.policy, judgments)
        encoded = result.model_dump_json()
        with transaction(self.conn):
            last = self.conn.execute(
                "SELECT id, result_json FROM scores WHERE case_id = ? ORDER BY id DESC LIMIT 1",
                (case_id,),
            ).fetchone()
            if last and last[1] == encoded:
                return ScoreOutcome(last[0], False, bundle, result)
            now = self.clock()
            cur = self.conn.execute(
                "INSERT INTO scores (case_id, analysis_round, policy_version, bundle_schema,"
                " bundle_sha256, bundle_json, result_json, priority, category, score, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    bundle.http.analysis_round,
                    result.policy_version,
                    result.bundle_schema,
                    result.bundle_sha256,
                    bundle_json(bundle),
                    encoded,
                    result.priority,
                    result.category,
                    result.score,
                    now,
                ),
            )
            self.conn.execute(
                "UPDATE cases SET priority = ?, category = ?, score_id = ?, updated_at = ?"
                " WHERE id = ?",
                (result.priority, result.category, cur.lastrowid, now, case_id),
            )
            return ScoreOutcome(cur.lastrowid, True, bundle, result)


def latest_score(
    conn: sqlite3.Connection, case_id: int
) -> tuple[EvidenceBundle, PolicyResult, float] | None:
    row = conn.execute(
        "SELECT bundle_json, result_json, created_at FROM scores WHERE case_id = ?"
        " ORDER BY id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    if row is None:
        return None
    return (
        EvidenceBundle.model_validate(json.loads(row[0])),
        PolicyResult.model_validate_json(row[1]),
        row[2],
    )
