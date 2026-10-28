"""Static-versus-rendered comparison (U19, R48, KTD23, AE17).

When a case is rendered, `compare` sets `cloaking_suspected` on a material
difference between what the static fetcher and the browser were shown:

- `brands`: the browser saw a protected brand presented or strongly mentioned
  that the static page did not (or the reverse);
- `credential_form`: password or one-time-code fields on one side only;
- `payment`: card fields, payees or donation language on one side only;
- `final_site`: the two ended on different registrable domains, and the static
  page announced no redirect (script or meta refresh) that explains it;
- `status`: the static fetch got an error status where the browser got a page.

A difference is expected, not suspicious, when the static page is a
script-built shell: its scripts build the content, and the browser is how such
a page is seen at all. A page without scripts cannot change in a browser, so an
empty or placeholder page that renders as something else was served something
else. The comparison is always recorded.

`score_on` says which view the policy scores. Normally the rendered one, the
page as a visitor sees it. When the static page showed abuse indicators that
the rendered page lacks (cloaking aimed at browsers), the static view is scored,
so a page can never lose evidence by hiding it from the browser.
"""

from brandsentinel.analysis import host_of, registrable_of

VERSION = "cloaking/1"


def summary(values: dict, final_url: str | None, status: int | None) -> dict:
    """What one view showed, from its extractor feature values."""
    pc = values.get("page_content") or {}
    refs = values.get("brand_references") or {}
    pay = values.get("payment") or {}
    cred = pc.get("credential") or {}
    brands = sorted(
        {b["brand"] for b in refs.get("brands") or [] if b.get("strength") == "strong"}
        | set(refs.get("presented") or [])
    )
    return {
        "final_url": final_url,
        "final_site": registrable_of(_host(final_url)),
        "status": status,
        "title": (pc.get("title") or "")[:200] or None,
        "text_chars": int(pc.get("text_chars") or 0),
        "shell": bool(pc.get("js_shell")),
        "brands": brands,
        "credential_fields": int(cred.get("password_fields") or 0)
        + int(cred.get("otp_fields") or 0),
        "card_fields": int(pay.get("card_fields") or 0),
        "payees": sorted(
            {o.get("payee_identifier") for o in pay.get("observations") or []} - {None}
        )[:20],
        "donation_cues": sorted(set(pay.get("donation_cues") or []))[:20],
        "redirects": [
            r.get("url")
            for r in (values.get("page_basics") or {}).get("meta_refresh", [])
            + pc.get("script_redirects", [])
            if r.get("url")
        ][:10],
    }


def _host(url: str | None) -> str | None:
    return host_of(url) if url else None


def _abuse(s: dict) -> bool:
    return bool(s["credential_fields"] or s["card_fields"] or s["payees"] or s["donation_cues"])


def compare(static: dict, rendered: dict) -> dict:
    """`static` and `rendered` are `summary` results."""
    differences = []
    if set(static["brands"]) != set(rendered["brands"]):
        differences.append(
            {
                "field": "brands",
                "static": static["brands"],
                "rendered": rendered["brands"],
            }
        )
    for name in ("credential_fields", "card_fields"):
        if bool(static[name]) != bool(rendered[name]):
            field = "credential_form" if name == "credential_fields" else "payment"
            differences.append({"field": field, "static": static[name], "rendered": rendered[name]})
    if (bool(static["payees"]) != bool(rendered["payees"])) or (
        bool(static["donation_cues"]) != bool(rendered["donation_cues"])
    ):
        differences.append(
            {
                "field": "payment",
                "static": static["payees"] + static["donation_cues"],
                "rendered": rendered["payees"] + rendered["donation_cues"],
            }
        )
    redirect_sites = {registrable_of(_host(u)) for u in static["redirects"]}
    if (
        static["final_site"]
        and rendered["final_site"]
        and static["final_site"] != rendered["final_site"]
        and rendered["final_site"] not in redirect_sites
    ):
        differences.append(
            {"field": "final_site", "static": static["final_site"],
             "rendered": rendered["final_site"]}
        )  # fmt: skip
    if (static["status"] or 0) >= 400 and 200 <= (rendered["status"] or 0) < 400:
        differences.append(
            {"field": "status", "static": static["status"], "rendered": rendered["status"]}
        )
    # A script shell cannot show its content statically: differences are the
    # browser doing its job. An error status is no shell: it is a decoy too.
    expected = static["shell"] and (static["status"] or 0) < 400
    suspected = bool(differences) and not expected
    static_only = _abuse(static) and not _abuse(rendered)
    return {
        "version": VERSION,
        "suspected": suspected,
        "differences": differences[:10],
        "expected_difference": "static_shell" if expected and differences else None,
        "score_on": "static" if static_only else "rendered",
        "static": static,
        "rendered": rendered,
    }
