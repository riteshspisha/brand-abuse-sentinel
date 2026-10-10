"""The sandbox runner (U23, KTD8): every sandbox container starts, is bounded and
is cleaned up here.

A job runs as one named, labelled, one-shot container,
`bs-<instance>-<role>-<job>-<attempt>`, on the service account's rootless Docker
endpoint (always passed explicitly, so neither DOCKER_HOST nor a Docker context
can redirect the runner to a rootful daemon). The container is created first and
then started attached, so it exists under its name before the wall clock starts
and `docker kill <name>` can always reach it. The job goes in on stdin and one
JSON document comes back on stdout; stdout and stderr are read under their own
caps. Wall-time expiry or any cap overflow kills the container by name. Its final
state is inspected (to tell a memory-limit kill from a crash) and the container
is then force-removed; no container outlives its `run` call.

The container configuration is fixed here and cannot be widened by a caller: no
mounts, no devices, no added capabilities, read-only root with a small noexec
tmpfs, `no-new-privileges`, all capabilities dropped, memory (without swap), CPU
and PID limits, no Docker logs, and either no network or one of the networks the
runner was constructed with (the internal sandbox network).

Before a job runs, any container left for the same job by an earlier attempt is
removed, and the run is refused if one survives. At startup, before job leases
are recovered, `sweep_orphans` removes every container carrying this instance's
label (and only those).
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from brandsentinel.config import SandboxLimits, SandboxSettings

log = logging.getLogger(__name__)

LABEL_INSTANCE = "brandsentinel.instance"
LABEL_JOB = "brandsentinel.job"
LABEL_ROLE = "brandsentinel.role"
LABEL_ATTEMPT = "brandsentinel.attempt"

_ROLE = re.compile(r"^[a-z]{1,16}$")
_JOB = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")
# Networks a sandbox may never join, whatever the caller asks for.
_FORBIDDEN_NETWORKS = frozenset({"host", "bridge", "default"})
_CONTROL_OUTPUT = 1024 * 1024  # cap on output of docker management commands
_READ_CHUNK = 65536

Status = Literal[
    "ok",
    "timeout",
    "stdout_overflow",
    "stderr_overflow",
    "oom",
    "exit_error",
    "invalid_output",
    "start_error",
]


class SandboxError(Exception):
    """The runtime could not be used for this job (Docker error, invalid spec)."""


class SandboxBusy(SandboxError):
    """A container from an earlier attempt of this job could not be removed."""


def default_docker_host() -> str:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return f"unix://{runtime_dir}/docker.sock"


@dataclass(frozen=True)
class Call:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class DockerCli:
    """The Docker CLI pointed at one explicit endpoint with a minimal environment."""

    def __init__(self, host: str = "", binary: str = "docker", *, timeout: float = 60.0) -> None:
        self.host = host or default_docker_host()
        if not self.host.startswith("unix:///"):
            raise SandboxError("the Docker endpoint must be a unix socket")
        self.binary = binary
        self.timeout = timeout

    def argv(self, *args: str) -> list[str]:
        return [self.binary, "--host", self.host, *args]

    @staticmethod
    def env() -> dict[str, str]:
        # No DOCKER_* variables: the endpoint comes only from --host.
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LANG": "C.UTF-8",
            "DOCKER_CLI_HINTS": "false",
        }

    async def call(self, *args: str, timeout: float | None = None) -> Call:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.argv(*args),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env(),
            )
        except OSError as e:  # missing or unexecutable docker binary
            return Call(-1, "", f"cannot run docker: {e}")
        try:
            async with asyncio.timeout(timeout or self.timeout):
                out, err = await asyncio.gather(
                    _read_up_to(proc.stdout, _CONTROL_OUTPUT),
                    _read_up_to(proc.stderr, _CONTROL_OUTPUT),
                )
                rc = await proc.wait()
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return Call(-1, "", f"docker {args[0]} timed out")
        except BaseException:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        return Call(rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))

    def call_sync(self, *args: str, timeout: float | None = None) -> Call:
        try:
            p = subprocess.run(  # noqa: S603 - fixed argv, no shell
                self.argv(*args),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=self.env(),
                timeout=timeout or self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return Call(-1, "", f"docker {args[0]} timed out")
        except OSError as e:
            return Call(-1, "", f"cannot run docker: {e}")
        return Call(
            p.returncode,
            p.stdout[:_CONTROL_OUTPUT].decode("utf-8", "replace"),
            p.stderr[:_CONTROL_OUTPUT].decode("utf-8", "replace"),
        )


@dataclass(frozen=True)
class SandboxSpec:
    """What a job may choose. Everything else about the container is fixed."""

    role: str
    command: tuple[str, ...]
    network: str = "none"
    limits: SandboxLimits | None = None  # None: the configured default limits
    image: str | None = None  # None: the configured sandbox image
    user: str | None = None  # None: the image's (non-root) user
    env: tuple[tuple[str, str], ...] = ()
    seccomp_profile: str | None = None  # absolute path; None: the runtime default
    expect_json: bool = True


@dataclass
class SandboxResult:
    name: str
    status: Status = "ok"
    exit_code: int | None = None
    oom_killed: bool = False
    killed: bool = False  # the runner killed it (timeout or cap overflow)
    removed: bool = False
    stdout: bytes = b""
    stderr: bytes = b""
    output: dict | None = None  # the parsed JSON document, when expected and valid
    error: str | None = None
    elapsed_ms: int = 0

    def summary(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "exit_code": self.exit_code,
            "oom_killed": self.oom_killed,
            "killed": self.killed,
            "removed": self.removed,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
        }


class _Overflow(Exception):
    def __init__(self, kind: Status) -> None:
        super().__init__(kind)
        self.kind = kind


class SandboxRunner:
    def __init__(
        self,
        settings: SandboxSettings,
        docker: DockerCli,
        *,
        networks: Iterable[str] = (),
    ) -> None:
        """`networks` are the named networks a spec may join besides `none`; the
        configured sandbox network is always one of them."""
        self.settings = settings
        self.docker = docker
        self.instance = settings.instance
        self.networks = frozenset({settings.network, *networks})
        bad = self.networks & _FORBIDDEN_NETWORKS
        if bad or any(n.startswith("container:") for n in self.networks):
            raise SandboxError(f"network(s) never allowed for sandboxes: {sorted(bad)}")

    # --- naming and arguments ----------------------------------------------------

    def container_name(self, role: str, job: str, attempt: int) -> str:
        return f"bs-{self.instance}-{role}-{job}-{attempt}"

    def validate(self, spec: SandboxSpec) -> None:
        if not _ROLE.match(spec.role):
            raise SandboxError("role must be 1-16 lowercase letters")
        if spec.network != "none" and spec.network not in self.networks:
            raise SandboxError(f"network {spec.network!r} is not a sandbox network")
        if not spec.command or any(not c or "\0" in c for c in spec.command):
            raise SandboxError("command must be non-empty strings")
        image = spec.image or self.settings.image
        if not _IMAGE.match(image):
            raise SandboxError("invalid image reference")
        if spec.user is not None:
            parts = spec.user.split(":")
            if len(parts) > 2 or any(
                not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", p)
                or p == "root"
                or (p.isdigit() and int(p) == 0)
                for p in parts
            ):
                raise SandboxError("sandboxes never run as root (user or group)")
        for key, value in spec.env:
            if not _ENV_KEY.match(key) or any(c in value for c in "\0\n\r"):
                raise SandboxError(f"invalid environment variable {key!r}")
        if spec.seccomp_profile is not None and (
            not os.path.isabs(spec.seccomp_profile) or not os.path.isfile(spec.seccomp_profile)
        ):
            raise SandboxError("seccomp profile must be an existing absolute path")

    def create_args(self, spec: SandboxSpec, name: str, job: str, attempt: int) -> list[str]:
        lim = spec.limits or self.settings.limits
        args = [
            "create",
            "--name",
            name,
            "--label",
            f"{LABEL_INSTANCE}={self.instance}",
            "--label",
            f"{LABEL_JOB}={job}",
            "--label",
            f"{LABEL_ROLE}={spec.role}",
            "--label",
            f"{LABEL_ATTEMPT}={attempt}",
            "--interactive",
            "--log-driver",
            "none",
            "--network",
            spec.network,
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={lim.tmpfs_mb}m",  # noqa: S108 - container path
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--memory",
            f"{lim.memory_mb}m",
            "--memory-swap",
            f"{lim.memory_mb}m",
            "--cpus",
            f"{lim.cpus:g}",
            "--pids-limit",
            str(lim.pids),
            "--ipc",
            "private",
            "--shm-size",
            f"{lim.shm_mb}m",
            "--ulimit",
            "core=0",
            "--ulimit",
            "nofile=1024:1024",
            "--init",
            "--hostname",
            "sandbox",
            "--workdir",
            "/tmp",  # noqa: S108 - container path
            "--pull",
            "never",
            "--no-healthcheck",
        ]
        if spec.seccomp_profile:
            args += ["--security-opt", f"seccomp={spec.seccomp_profile}"]
        if spec.user:
            args += ["--user", spec.user]
        for key, value in spec.env:
            args += ["--env", f"{key}={value}"]
        # Best-effort self-deadline so a container outliving a crashed application
        # still ends; the runner's kill by name and the startup sweep remain the
        # enforcement (a process in the container could kill this `timeout`).
        deadline = int(lim.wall_seconds + self.settings.kill_grace_seconds) + 1
        args += ["--", spec.image or self.settings.image]
        args += ["timeout", "--signal=KILL", f"{deadline}s", *spec.command]
        return args

    # --- lifecycle -----------------------------------------------------------------

    async def run(
        self, spec: SandboxSpec, *, job: str | int, attempt: int, stdin: bytes = b""
    ) -> SandboxResult:
        """Run one job attempt to completion. Raises SandboxError only when the
        container could not be started or a previous attempt's container survives;
        everything the container itself does is reported in the result."""
        job = str(job)
        if not _JOB.match(job) or attempt < 0:
            raise SandboxError("invalid job id or attempt")
        self.validate(spec)
        lim = spec.limits or self.settings.limits
        name = self.container_name(spec.role, job, attempt)
        await self.clear_job(job)
        result = SandboxResult(name=name)
        start = time.monotonic()
        try:
            created = await self.docker.call(*self.create_args(spec, name, job, attempt))
            if not created.ok:
                result.status = "start_error"
                result.error = created.stderr.strip()[:500]
                return result
            await self._attach(name, stdin, lim, result)
            if result.status == "ok":
                await self._inspect(name, result)
                # Docker records OOMKilled from an asynchronous cgroup event that
                # can trail the exit status; look again before calling it a crash.
                for _ in range(3):
                    if result.status != "ok" or result.exit_code != 137 or result.oom_killed:
                        break
                    await asyncio.sleep(0.3)
                    await self._inspect(name, result)
            if result.status == "ok":
                self._judge(spec, result)
        finally:
            result.removed = await self.remove(name)
            result.elapsed_ms = int((time.monotonic() - start) * 1000)
            log.info("sandbox job finished", extra={"fields": {"sandbox": result.summary()}})
        return result

    async def _attach(self, name: str, stdin: bytes, lim: SandboxLimits, result) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.docker.argv("start", "--attach", "--interactive", name),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.docker.env(),
            )
        except OSError as e:
            result.status, result.error = "start_error", f"cannot run docker: {e}"[:500]
            return
        try:
            async with asyncio.timeout(lim.wall_seconds):
                await self._exchange(proc, stdin, lim, result)
        except TimeoutError:
            result.status = "timeout"
            result.error = f"wall time {lim.wall_seconds:g}s exceeded"
        finally:
            # Keep reading (and discarding) the CLI's output from here on: dockerd
            # blocks on an attached stream nobody reads, and `docker kill` would
            # then not return until it timed out.
            drains = [asyncio.create_task(_discard(s)) for s in (proc.stdout, proc.stderr)]
            if result.status != "ok" or proc.returncode is None:
                result.killed = result.status != "ok"
                await self.kill(name)
            await self._reap(proc, drains)

    @staticmethod
    async def _exchange(proc, stdin: bytes, lim: SandboxLimits, result: SandboxResult) -> None:
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_feed(proc.stdin, stdin))
                out = tg.create_task(
                    _read_capped(proc.stdout, lim.stdout_max_bytes, "stdout_overflow")
                )
                err = tg.create_task(
                    _read_capped(proc.stderr, lim.stderr_max_bytes, "stderr_overflow")
                )
        except* _Overflow as group:
            result.status = group.exceptions[0].kind
            result.error = f"{result.status.replace('_', ' ')} (cap reached)"
        if result.status == "ok":
            result.stdout, result.stderr = out.result(), err.result()
            result.exit_code = await proc.wait()

    async def _reap(self, proc: asyncio.subprocess.Process, drains: list[asyncio.Task]) -> None:
        try:
            await asyncio.wait_for(proc.wait(), self.settings.kill_grace_seconds)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        if proc.stdin is not None and not proc.stdin.is_closing():
            proc.stdin.close()
        # The CLI has exited, so its pipes reach EOF; let the drains finish so
        # the transport closes cleanly.
        _, pending = await asyncio.wait(drains, timeout=2)
        for task in pending:
            task.cancel()
        await asyncio.gather(*drains, return_exceptions=True)

    async def _inspect(self, name: str, result: SandboxResult) -> None:
        r = await self.docker.call("container", "inspect", "--format", "{{json .State}}", name)
        if not r.ok:
            result.status, result.error = "start_error", r.stderr.strip()[:500]
            return
        try:
            state = json.loads(r.stdout)
        except ValueError:
            state = {}
        result.oom_killed = bool(state.get("OOMKilled"))
        if isinstance(state.get("ExitCode"), int):
            result.exit_code = state["ExitCode"]
        if state.get("Error"):  # the runtime could not start the process
            result.status, result.error = "start_error", str(state["Error"])[:500]

    @staticmethod
    def _judge(spec: SandboxSpec, result: SandboxResult) -> None:
        if result.oom_killed:
            result.status = "oom"
        elif result.exit_code != 0:
            result.status = "exit_error"
        elif spec.expect_json:
            try:
                doc = json.loads(result.stdout)
            except (ValueError, RecursionError):  # hostile nesting is invalid output
                doc = None
            if not isinstance(doc, dict):
                result.status = "invalid_output"
                result.error = "stdout is not one JSON object"
            else:
                result.output = doc

    async def kill(self, name: str) -> None:
        await self.docker.call("kill", "--signal", "KILL", name, timeout=30)

    async def remove(self, name: str) -> bool:
        """Force-remove a container; True once it no longer exists."""
        for _ in range(5):
            await self.docker.call("rm", "--force", name, timeout=30)
            if not await self._exists(name):
                return True
            await asyncio.sleep(0.5)
        log.error("sandbox container could not be removed", extra={"fields": {"name": name}})
        return False

    async def _exists(self, name: str) -> bool:
        """False only when the daemon says the container does not exist; any
        other failure (daemon down, timeout) counts as still existing."""
        r = await self.docker.call("container", "inspect", "--format", "{{.Id}}", name)
        return r.ok or "no such container" not in r.stderr.lower()

    def _label_filters(self, job: str | None = None) -> list[str]:
        args = ["--filter", f"label={LABEL_INSTANCE}={self.instance}"]
        if job is not None:
            args += ["--filter", f"label={LABEL_JOB}={job}"]
        return args

    async def list_containers(self, job: str | None = None) -> list[str]:
        r = await self.docker.call(
            "ps", "--all", "--no-trunc", "--format", "{{.Names}}", *self._label_filters(job)
        )
        if not r.ok:
            raise SandboxError(f"cannot list sandbox containers: {r.stderr.strip()[:300]}")
        return _names(r.stdout)

    async def clear_job(self, job: str) -> None:
        """Remove any container left by an earlier attempt of `job`; refuse to go
        on while one still exists, so a job never has two containers."""
        stale = await self.list_containers(job)
        if not stale:
            return
        log.warning("removing earlier sandbox containers", extra={"fields": {"names": stale}})
        for name in stale:
            await self.remove(name)
        if survivors := await self.list_containers(job):
            raise SandboxBusy(f"earlier containers of job {job} still exist: {survivors}")

    def sweep_orphans(self) -> int:
        """Remove every container labelled with this instance. Synchronous, for
        the orchestrator's startup hooks (which run before lease recovery)."""
        listed = self.docker.call_sync(
            "ps", "--all", "--no-trunc", "--format", "{{.Names}}", *self._label_filters()
        )
        if not listed.ok:
            raise SandboxError(f"cannot list sandbox containers: {listed.stderr.strip()[:300]}")
        names = _names(listed.stdout)
        if names:
            removed = self.docker.call_sync("rm", "--force", *names)
            if not removed.ok:
                raise SandboxError(f"orphan removal failed: {removed.stderr.strip()[:300]}")
            log.warning("removed orphaned sandbox containers", extra={"fields": {"names": names}})
        return len(names)


def _names(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


async def _feed(writer: asyncio.StreamWriter, data: bytes) -> None:
    try:
        if data:
            writer.write(data)
            await writer.drain()
        writer.close()
        await writer.wait_closed()
    except (BrokenPipeError, ConnectionResetError):
        pass  # the container exited or closed stdin; its result tells the story


async def _read_up_to(reader: asyncio.StreamReader, cap: int) -> bytes:
    """Read to EOF, keeping at most `cap` bytes."""
    buf = bytearray()
    while chunk := await reader.read(_READ_CHUNK):
        buf += chunk[: max(0, cap - len(buf))]
    return bytes(buf)


async def _discard(reader: asyncio.StreamReader) -> None:
    while await reader.read(_READ_CHUNK):
        pass


async def _read_capped(reader: asyncio.StreamReader, cap: int, kind: Status) -> bytes:
    buf = bytearray()
    while chunk := await reader.read(_READ_CHUNK):
        buf += chunk
        if len(buf) > cap:
            raise _Overflow(kind)
    return bytes(buf)
