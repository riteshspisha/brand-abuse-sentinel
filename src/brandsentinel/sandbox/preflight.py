"""Startup checks for the sandbox runtime (U23, R50) and its network (U18, R41).

Account checks (`check_account`), run before `brandsentinel run` starts. The
application handles untrusted content, so it must not run as root, as the owner
of its own code, or with access to a rootful Docker socket. Root is always
refused; the other two are allowed only under `runtime.allow_developer_account`,
and then reported as warnings.

Runtime checks (`check_runtime`) decide whether sandbox stages may run: the
endpoint answers, it is rootless, cgroup v2 enforces memory, PID and CPU limits,
seccomp is available, and the sandbox image exists. Any failure disables sandbox
stages, and `status` says why.

Network checks (`check_network`) gate the browser stage: the sandbox network is
internal, the egress proxy is the only long-running container on it and is
hardened, and a throwaway container on it cannot reach the Internet directly.
"""

import json
import os
import re
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import brandsentinel
from brandsentinel.config import Config, SandboxSettings
from brandsentinel.sandbox.runner import DockerCli, SandboxError, SandboxRunner, SandboxSpec

ROOTFUL_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_JOB_NAME = re.compile(r"^bs-[a-z0-9]{1,16}-[a-z]{1,16}-[a-z0-9][a-z0-9-]*-[0-9]+$")

# Runs inside a container on the sandbox network; every attempt must fail.
EGRESS_PROBE = r"""
import json, socket
res = {}
for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 80)):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, port))
        res[f"tcp {host}:{port}"] = "connected"
    except OSError as e:
        res[f"tcp {host}:{port}"] = type(e).__name__
    finally:
        s.close()
try:
    socket.getaddrinfo("example.com", 443)
    res["dns example.com"] = "resolved"
except OSError as e:
    res["dns example.com"] = type(e).__name__
print(json.dumps(res))
"""


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""
    warning: bool = False  # passed only because of the developer override


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    docker: DockerCli | None = None  # the endpoint checked, for runtime reports

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.ok and c.warning]

    def add(self, name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        self.checks.append(Check(name, ok, detail, warning))

    def reasons(self) -> list[str]:
        return [f"{c.name}: {c.detail}" for c in self.failures]


def code_paths() -> list[Path]:
    """The application's package directory and, for a source checkout, its root."""
    package = Path(brandsentinel.__file__).resolve().parent
    paths = [package]
    root = package.parents[1]
    if (root / "pyproject.toml").is_file():
        paths.append(root)
    return paths


def _overridable(report: Report, name: str, ok: bool, detail: str, override: bool) -> None:
    if ok:
        report.add(name, True)
    elif override:
        report.add(
            name, True, f"{detail} (allowed by runtime.allow_developer_account)", warning=True
        )
    else:
        report.add(name, False, detail)


def check_account(
    config: Config,
    *,
    uid: int | None = None,
    paths: Sequence[Path] | None = None,
    sockets: Sequence[str] = ROOTFUL_SOCKETS,
    access: Callable[[str, int], bool] = os.access,
) -> Report:
    uid = os.getuid() if uid is None else uid
    override = config.runtime.allow_developer_account
    report = Report()
    report.add("not_root", uid != 0, "refusing to run as UID 0" if uid == 0 else "")
    owned = [str(p) for p in (paths if paths is not None else code_paths()) if _owner(p) == uid]
    _overridable(
        report,
        "not_code_owner",
        not owned,
        f"UID {uid} owns the application code ({', '.join(owned)})",
        override,
    )
    unique = dict.fromkeys(os.path.realpath(s) for s in sockets)  # /var/run -> /run
    reachable = [s for s in unique if os.path.exists(s) and access(s, os.R_OK | os.W_OK)]
    _overridable(
        report,
        "no_rootful_docker",
        not reachable,
        f"a rootful Docker socket is accessible ({', '.join(reachable)})",
        override,
    )
    return report


def _owner(path: Path) -> int | None:
    try:
        return path.stat().st_uid
    except OSError:
        return None


async def check_runtime(docker: DockerCli, settings: SandboxSettings) -> Report:
    report = Report()
    info_call = await docker.call("info", "--format", "{{json .}}", timeout=20)
    if not info_call.ok:
        report.add("endpoint", False, f"{docker.host}: {info_call.stderr.strip()[:300]}")
        return report
    try:
        info = json.loads(info_call.stdout)
    except ValueError:
        report.add("endpoint", False, "docker info returned invalid JSON")
        return report
    report.add("endpoint", True, docker.host)
    options = [str(o) for o in info.get("SecurityOptions") or []]
    report.add(
        "rootless",
        any(o.startswith("name=rootless") for o in options),
        "the Docker endpoint is not rootless",
    )
    report.add(
        "seccomp",
        any(o.startswith("name=seccomp") for o in options),
        "seccomp is not available",
    )
    report.add(
        "cgroup_v2",
        str(info.get("CgroupVersion")) == "2",
        f"cgroup version {info.get('CgroupVersion')!r}, need 2",
    )
    missing = [
        name
        for name, key in (("memory", "MemoryLimit"), ("pids", "PidsLimit"), ("cpu", "CpuCfsQuota"))
        if not info.get(key)
    ]
    report.add(
        "cgroup_controllers",
        not missing,
        f"controller(s) not delegated: {', '.join(missing)}",
    )
    image = await docker.call("image", "inspect", "--format", "{{.Id}}", settings.image)
    report.add("sandbox_image", image.ok, f"image {settings.image} not found; build it first")
    return report


async def prepare_runtime(config: Config) -> tuple[SandboxRunner | None, Report]:
    """A runner when every runtime check passes, else None and the reasons."""
    try:
        docker = DockerCli(config.runtime.docker_host, config.runtime.docker_binary)
    except SandboxError as e:
        report = Report()
        report.add("endpoint", False, str(e))
        return None, report
    report = await check_runtime(docker, config.sandbox)
    report.docker = docker
    return (SandboxRunner(config.sandbox, docker) if report.ok else None), report


async def check_network(
    docker: DockerCli,
    settings: SandboxSettings,
    runner: SandboxRunner,
    *,
    network: str | None = None,
    probe: bool = True,
) -> Report:
    report = Report()
    network = network or settings.network
    net_call = await docker.call("network", "inspect", "--format", "{{json .}}", network)
    if not net_call.ok:
        report.add("network_exists", False, f"network {network} not found")
        return report
    net = json.loads(net_call.stdout)
    report.add("network_internal", net.get("Internal") is True, f"{network} is not internal")
    attached = sorted(c.get("Name", "") for c in (net.get("Containers") or {}).values())
    # Job containers of any instance (`bs-<instance>-<role>-...`) are expected.
    others = [n for n in attached if n != settings.proxy_container and not _JOB_NAME.match(n)]
    report.add(
        "network_members",
        not others,
        f"unexpected container(s) on {network}: {', '.join(others)}",
    )
    report.add(
        "proxy_attached",
        settings.proxy_container in attached,
        f"{settings.proxy_container} is not on {network}",
    )
    proxy = await docker.call(
        "container", "inspect", "--format", "{{json .}}", settings.proxy_container
    )
    if proxy.ok:
        problems = proxy_hardening_problems(json.loads(proxy.stdout))
        report.add("proxy_hardened", not problems, "; ".join(problems))
    else:
        report.add("proxy_hardened", False, f"{settings.proxy_container} not found")
    if probe and report.ok:
        report.checks.append(await _egress_probe(runner, network))
    return report


def proxy_hardening_problems(inspect: dict) -> list[str]:
    """What is missing from a proxy container's hardening (KTD10)."""
    cfg = inspect.get("Config") or {}
    host = inspect.get("HostConfig") or {}
    problems = []
    if not (inspect.get("State") or {}).get("Running"):
        problems.append("not running")
    user = str(cfg.get("User") or "").split(":", 1)[0]
    if user in ("", "0", "root"):
        problems.append("runs as root")
    if "ALL" not in [c.upper() for c in host.get("CapDrop") or []]:
        problems.append("capabilities not dropped")
    if host.get("CapAdd"):
        problems.append("capabilities added")
    if host.get("Privileged"):
        problems.append("privileged")
    if not host.get("ReadonlyRootfs"):
        problems.append("root filesystem writable")
    if not any(str(o).startswith("no-new-privileges") for o in host.get("SecurityOpt") or []):
        problems.append("no-new-privileges not set")
    if not host.get("Memory"):
        problems.append("no memory limit")
    if not host.get("PidsLimit") or host["PidsLimit"] <= 0:
        problems.append("no PID limit")
    if not (host.get("NanoCpus") or host.get("CpuQuota")):
        problems.append("no CPU limit")
    if any(m.get("RW") for m in inspect.get("Mounts") or []):
        problems.append("writable mount")
    if host.get("NetworkMode") == "host":
        problems.append("host network")
    return problems


async def _egress_probe(runner: SandboxRunner, network: str) -> Check:
    spec = SandboxSpec(role="probe", command=("python3", "-c", EGRESS_PROBE), network=network)
    try:
        job = f"preflight-{int(time.time())}-{secrets.token_hex(4)}"
        result = await runner.run(spec, job=job, attempt=0)
    except SandboxError as e:
        return Check("direct_egress_blocked", False, f"probe could not run: {e}")
    if result.output is None:
        return Check("direct_egress_blocked", False, f"probe {result.status}: {result.error}")
    leaks = [k for k, v in result.output.items() if v in ("connected", "resolved")]
    if leaks:
        return Check("direct_egress_blocked", False, f"direct egress possible: {', '.join(leaks)}")
    return Check("direct_egress_blocked", True, json.dumps(result.output, sort_keys=True))
