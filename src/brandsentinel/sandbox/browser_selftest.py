"""`brandsentinel sandbox selftest browser` (U19 verification).

Runs the real browser worker in a real browser container on the configured
sandbox network, after the network check, and checks the rendering gate's
container side:

- Chromium's own sandbox is on: its renderers run in their own user namespace
  and no Chromium process runs with `--no-sandbox`;
- the worker is not root, has no capabilities, runs with `no-new-privileges` and
  under a seccomp filter;
- a Chromium launched with no proxy setting at all cannot reach a public address
  (the network, not a browser setting, stops it), so the test sends nothing to the
  Internet;
- the container is removed afterwards.

The no-proxy launch exists only here; the browser client never asks for it.
"""

import secrets

from brandsentinel.config import BrowserSettings, SandboxSettings
from brandsentinel.sandbox.browser_client import BrowserClient
from brandsentinel.sandbox.preflight import Check
from brandsentinel.sandbox.runner import SandboxRunner

DIRECT_TARGET = "http://1.1.1.1/"


async def selftest(
    runner: SandboxRunner, settings: BrowserSettings, sandbox: SandboxSettings
) -> list[Check]:
    client = BrowserClient(runner, settings, sandbox)  # no lab-host filter: a fixed target
    job = f"selftest-browser-{secrets.token_hex(4)}"
    r = await client.render(
        DIRECT_TARGET, job=job, selftest={"no_proxy": True, "sandbox_probe": True}
    )
    checks = [Check("worker_ran", r.status == "ok", f"{r.status}: {r.reason or ''}".strip())]
    if r.status != "ok":
        return checks
    box = r.doc.get("sandbox") or {}
    checks.append(
        Check(
            "chromium_sandbox",
            box.get("in_own_user_namespace", 0) >= 1 and box.get("no_sandbox_flag", 1) == 0,
            f"{box.get('in_own_user_namespace')} of {box.get('processes')} Chromium processes in"
            f" their own user namespace; {box.get('no_sandbox_flag')} with --no-sandbox",
        )
    )
    checks.append(
        Check(
            "unprivileged",
            box.get("uid") not in (None, 0)
            and int(box.get("cap_eff") or "f", 16) == 0
            and box.get("no_new_privs") == "1"
            and box.get("seccomp") == "2",
            f"uid {box.get('uid')}, CapEff {box.get('cap_eff')}, NoNewPrivs"
            f" {box.get('no_new_privs')}, Seccomp {box.get('seccomp')}",
        )
    )
    reached = r.doc.get("main_status") is not None or any(
        q.get("status") is not None for q in r.doc.get("requests") or []
    )
    checks.append(
        Check(
            "no_direct_route",
            not reached and bool(r.doc.get("navigation_error")),
            f"{DIRECT_TARGET} without a proxy: {r.doc.get('navigation_error') or 'reached'}",
        )
    )
    removed = all(run.get("removed") for run in r.runs)
    checks.append(Check("container_removed", removed, "" if removed else "container left"))
    return checks
