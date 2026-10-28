"""The rendering gate's argument-level properties (U19, R39, R41, KTD9): the
browser container's fixed configuration, Chromium's own sandbox, the seccomp
profile, and a worker that cannot interact with a page. The live container
checks are in tests/integration/test_browser_client.py."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
from tests.docker_support import make_runner
from tests.security.test_media_limits import APPLICATION_MODULES

from brandsentinel.config import BrowserSettings, SandboxSettings
from brandsentinel.sandbox import browser_worker as W
from brandsentinel.sandbox.browser_client import SECCOMP_PROFILE, browser_spec
from brandsentinel.sandbox.runner import DockerCli

pytestmark = pytest.mark.security

WORKER = Path(W.__file__)
# Playwright calls that act on a page: never made by the worker (R39).
INTERACTIONS = {
    "click", "dblclick", "tap", "fill", "type", "press", "press_sequentially",
    "check", "uncheck", "set_checked", "select_option", "select_text", "set_input_files",
    "hover", "drag_and_drop", "drag_to", "dispatch_event", "focus", "submit",
    "grant_permissions", "set_geolocation", "expect_download", "save_as",
    "evaluate", "evaluate_handle", "add_init_script", "expose_function", "expose_binding",
}  # fmt: skip
# Profile rules Chromium's namespace sandbox needs beyond Docker's default.
CHROMIUM_DELTA = ["clone", "unshare", "chroot"]


def _called_attributes(tree: ast.AST) -> set[str]:
    return {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }


def test_the_worker_never_interacts_with_a_page():
    called = _called_attributes(ast.parse(WORKER.read_text()))
    assert called & INTERACTIONS == set(), called & INTERACTIONS
    # Positive control: the check sees the calls the worker does make.
    assert {"goto", "content", "screenshot", "dismiss", "continue_"} <= called


def test_chromium_keeps_its_own_sandbox():
    tree = ast.parse(WORKER.read_text())
    # No string argument disables it (docstrings and the self-test's bytes
    # pattern, which looks for the flag, are not arguments).
    flags = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
             and isinstance(n.value, str) and n.value.startswith("--")]  # fmt: skip
    assert flags and not [f for f in flags if "sandbox" in f or "zygote" in f], flags
    assert not any(a.startswith("--no-sandbox") or "zygote" in a for a in W.CHROMIUM_ARGS)
    launch = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "launch"
    )  # fmt: skip
    keys = {k.value: v for k, v in zip(launch.value.keys, launch.value.values, strict=True)}
    assert isinstance(keys["chromium_sandbox"], ast.Constant) and keys["chromium_sandbox"].value


def test_quic_and_direct_webrtc_are_off():
    assert "--disable-quic" in W.CHROMIUM_ARGS
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in W.CHROMIUM_ARGS


def test_seccomp_profile_is_dockers_default_plus_only_what_chromium_needs():
    profile = json.loads(SECCOMP_PROFILE.read_text())
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    extra = profile["syscalls"][-1]
    assert extra["names"] == CHROMIUM_DELTA and extra["action"] == "SCMP_ACT_ALLOW"
    assert "args" not in extra and "includes" not in extra
    # Nothing else is allowed unconditionally that Docker gates on CAP_SYS_ADMIN.
    gated = {"mount", "umount2", "bpf", "setns", "pivot_root", "kexec_load", "init_module"}
    unconditional = {
        n
        for s in profile["syscalls"]
        if s["action"] == "SCMP_ACT_ALLOW" and not s.get("includes") and not s.get("args")
        for n in s["names"]
    }
    assert unconditional & gated == set()
    # clone3 stays ENOSYS (glibc falls back to clone, which the rule above covers).
    assert any("clone3" in s["names"] and s.get("errnoRet") == 38 for s in profile["syscalls"])


def test_browser_container_arguments_are_fixed_and_unprivileged():
    runner = make_runner(DockerCli("unix:///nonexistent.sock"))
    spec = browser_spec(SandboxSettings(), BrowserSettings())
    args = runner.create_args(spec, "bs-test-browser-j-0", "j", 0)
    joined = " ".join(args)
    assert "--privileged" not in args and "--cap-add" not in args
    assert args[args.index("--cap-drop") : args.index("--cap-drop") + 2] == ["--cap-drop", "ALL"]
    assert "--read-only" in args and "no-new-privileges=true" in args
    assert f"seccomp={SECCOMP_PROFILE.resolve()}" in args
    assert args[args.index("--network") + 1] == "bs_sandbox"
    assert args[args.index("--user") + 1] == "pwuser"
    assert args[args.index("--ipc") + 1] == "private" and "--shm-size" in args
    for flag in ("--volume", "-v", "--mount", "--device", "--publish", "-p", "--pid", "--userns"):
        assert flag not in args, flag
    assert "SYS_ADMIN" not in joined and "unconfined" not in joined
    lim = BrowserSettings().limits
    assert args[args.index("--memory") + 1] == f"{lim.memory_mb}m"
    assert args[args.index("--memory-swap") + 1] == f"{lim.memory_mb}m"
    assert args[args.index("--pids-limit") + 1] == str(lim.pids)


def test_only_the_self_test_may_run_without_the_proxy():
    job = {"version": 1, "url": "http://a.test/", "options": {}}
    with pytest.raises(W.JobError, match="proxy"):
        W.parse_job(json.dumps({**job, "proxy": None}).encode())
    with pytest.raises(W.JobError, match="proxy"):
        W.parse_job(json.dumps({**job, "proxy": "socks5://1.1.1.1:1080"}).encode())
    W.parse_job(json.dumps({**job, "proxy": None, "selftest": {"no_proxy": True}}).encode())


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "chrome://settings", "data:text/html,x", "javascript:1", 7]
)
def test_the_worker_refuses_anything_but_http_urls(url):
    raw = json.dumps({"version": 1, "url": url, "proxy": "http://p:1", "options": {}})
    with pytest.raises(W.JobError):
        W.parse_job(raw.encode())


def test_the_client_never_offers_the_no_proxy_self_test_for_cases():
    source = (Path(W.__file__).with_name("browser_client.py")).read_text()
    assert "no_proxy" not in source


def test_the_application_never_imports_the_browser_driver():
    # Chromium runs only in the browser container; the host has no way to start it.
    code = (
        "import importlib, sys\n"
        f"for m in {APPLICATION_MODULES!r}:\n"
        "    importlib.import_module(m)\n"
        "print(sorted(m for m in ('playwright', 'greenlet', 'pyee') if m in sys.modules))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]", out.stdout + out.stderr


def test_only_one_browser_runs_at_a_time():
    from brandsentinel.config import Config

    with pytest.raises(ValueError):
        Config(stages={"render": 2})


def test_the_worker_has_time_to_report_before_the_wall():
    from brandsentinel.config import SandboxLimits

    with pytest.raises(ValueError, match="wall_seconds"):
        BrowserSettings(limits=SandboxLimits(wall_seconds=45, stdout_max_bytes=16 * 2**20))
    s = BrowserSettings()
    assert s.navigation_timeout_seconds + s.settle_seconds + W.POST_SETTLE_SECONDS < (
        s.limits.wall_seconds
    )


def test_control_characters_cannot_inflate_the_worker_output():
    # Each C0 control is six bytes in JSON; a page of them must not overflow stdout.
    page = "\x01\x02\x1b\x7f" * 1000 + "\tok\n\r"
    assert W.clean(page) == "\tok\n\r"
    s = BrowserSettings()
    html, _ = W.cap_bytes(W.clean("\x00" * s.max_html_bytes + '"\\' * s.max_html_bytes),
                          s.max_html_bytes)  # fmt: skip
    doc = json.dumps({"html": html}, ensure_ascii=False).encode()
    assert len(doc) <= 2 * s.max_html_bytes + 64
