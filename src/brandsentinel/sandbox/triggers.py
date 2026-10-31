"""When a case is rendered in the isolated browser (U19, R19, KTD23).

`decide` runs after the final static fetch and records why a case is rendered,
or why not (`render_decision` fact). It reads only the static EvidenceBundle:

- never on a confirmed official domain, nor without a static HTTP response (a
  fetch refused by netguard is never retried through the browser);
- `js_shell`: a script-built page on a brand-matching domain (AE10);
- `static_error`: a strong-strength domain answering 4xx or 5xx;
- `decoy_page`: a strong-strength domain serving a parked, placeholder or empty
  page with no brand content;
- `script_redirect`: a strong-strength domain whose page redirects by script or
  meta refresh;
- `form_hints_without_forms`: a brand-related page with credential or payment
  hints (lures, payment providers, donation language) but no credential form,
  card field or payee to show for them;
- `little_text`: a brand-matching domain with less visible text than
  `browser.little_text_chars`;
- `no_static_images`: a brand-related page with no image to compare;
- `sample`: otherwise, a deterministic share (`browser.sample_rate`) of
  strong-strength cases, chosen by hashing case and round;
- `analyst_request` (M8): an analyst asked for this round to be rendered
  (`submit --render`). It never bypasses the skips above: the browser renders
  only a URL the hardened static fetcher reached through netguard. When no
  other reason applies the request spends the analyst budget
  (`browser.analyst_renders_per_day`), and with the budget used up the case is
  skipped as `analyst_budget_exhausted`; the request is never silently dropped.

Every reason found is recorded, so the case explains why it was rendered.
"""

import hashlib

from brandsentinel.evidence.bundle import EvidenceBundle
from brandsentinel.policy.rules import donation_cues, presented_brands

# render_decision/2 (M8): analyst_request, analyst_budget_spent and
# analyst_renders_per_day.
VERSION = "render_decision/2"


def sampled(case_id: int, rnd: int, rate: float) -> bool:
    """A stable choice: the same case and round always give the same answer."""
    if rate <= 0:
        return False
    digest = hashlib.sha256(f"render-sample:{case_id}:{rnd}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64 < rate


def decide(
    b: EvidenceBundle,
    images: dict | None,
    *,
    strength: str,
    sample_rate: float,
    little_text_chars: int,
    enabled: bool,
    analyst_request: bool = False,
    budget_left: bool = False,
    analyst_renders_per_day: int | None = None,
) -> dict:
    """`budget_left`: whether the analyst budget has a render left in the past 24
    hours (the caller counts it in the transaction that records the decision)."""
    base = {
        "analysis_round": b.http.analysis_round,
        "browser_enabled": enabled,
        "url": b.http.requested_url,
        "sampled": False,
    }
    if analyst_request:  # without a request the decision is as before M8
        base |= {
            "analyst_request": True,
            "analyst_budget_spent": False,
            "analyst_renders_per_day": analyst_renders_per_day,
        }
    if b.registry.official_domain:
        return {**base, "triggered": False, "skipped": "official_domain", "reasons": []}
    if not (b.http.fetched and b.http.outcome == "ok" and b.http.requested_url):
        return {**base, "triggered": False, "skipped": "no_static_response", "reasons": []}
    strong = strength == "strong"
    brand_domain = b.discovery.domain_match in ("strong", "weak")
    brand_page = bool(b.association.strong_mention or presented_brands(b))
    related = brand_domain or brand_page
    reasons = []
    if b.page.js_shell and brand_domain:
        reasons.append("js_shell")
    if strong and (b.http.status or 0) >= 400:
        reasons.append("static_error")
    if strong and (b.page.parked_cues or b.page.empty) and not b.association.brands:
        reasons.append("decoy_page")
    if strong and (b.page.script_redirects or b.page.meta_refresh):
        reasons.append("script_redirect")
    hints = b.page.lures or b.payment.providers or donation_cues(b)
    payees = any(o.payee_identifier for o in b.payment.observations)  # a gateway is no payee
    shown = b.credential.forms or b.payment.card_fields or payees
    if related and hints and not shown:
        reasons.append("form_hints_without_forms")
    if brand_domain and b.page.available and b.page.text_chars < little_text_chars:
        reasons.append("little_text")
    imgs = images or {}
    if related and not (imgs.get("images") or imgs.get("icons") or imgs.get("og_images")):
        reasons.append("no_static_images")
    if not reasons and strong and sampled(b.subject.case_id, b.http.analysis_round or 0,
                                          sample_rate):  # fmt: skip
        reasons.append("sample")
        base["sampled"] = True
    if analyst_request:
        # The budget pays only for a render the request alone causes; with
        # another reason, or no browser at all, nothing is spent.
        alone = not reasons and enabled
        if alone and not budget_left:
            return {**base, "triggered": False, "skipped": "analyst_budget_exhausted",
                    "reasons": []}  # fmt: skip
        base["analyst_budget_spent"] = alone
        reasons.append("analyst_request")
    if not reasons:
        return {**base, "triggered": False, "skipped": "no_trigger", "reasons": []}
    return {**base, "triggered": True, "skipped": None, "reasons": reasons}
