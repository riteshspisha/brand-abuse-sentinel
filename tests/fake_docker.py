"""A fake `docker` CLI for testing runner and preflight logic without a daemon.

Invoked as `python fake_docker.py <state_dir> <docker args...>` through a small
wrapper script (see `make_fake_docker`). Containers are JSON records in
`<state_dir>/state.json`; every invocation's argv is appended to `calls.jsonl`.
A container's behaviour is chosen by its image name:

- `fake/echo`: reads stdin, prints `{"echo": <stdin>}`
- `fake/sleep`: sleeps until killed
- `fake/flood`: writes 8 MiB to stdout
- `fake/stderr`: writes 8 MiB to stderr
- `fake/oom`: exits 137 and reports OOMKilled
- `fake/fail`: exits 3
- `fake/text`: prints a line that is not JSON
- `fake/nested`: prints JSON nested far deeper than the parser's recursion limit

`info.json` in the state dir, if present, is the `docker info` document;
`networks/<name>.json` and `containers/<name>.json` answer `network inspect`
and `container inspect` for names not created through `create`.
"""

import fcntl
import json
import os
import signal
import sys
import time
from contextlib import contextmanager, suppress
from pathlib import Path

IMAGES = {
    "fake/echo",
    "fake/sleep",
    "fake/flood",
    "fake/stderr",
    "fake/oom",
    "fake/fail",
    "fake/text",
    "fake/nested",
}


@contextmanager
def locked(state_dir: Path):
    with open(state_dir / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = state_dir / "state.json"
        state = json.loads(path.read_text()) if path.exists() else {}
        yield state
        path.write_text(json.dumps(state))


def fail(msg: str, code: int = 1) -> None:
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def cmd_create(state_dir: Path, args: list[str]) -> None:
    name, labels = None, {}
    i = 0
    while i < len(args) and args[i] != "--":
        if args[i] == "--name":
            name = args[i + 1]
            i += 2
            continue
        if args[i] == "--label":
            k, _, v = args[i + 1].partition("=")
            labels[k] = v
            i += 2
            continue
        i += 1
    image = args[i + 1]
    if image not in IMAGES:
        fail(f"Error response from daemon: No such image: {image}", 125)
    with locked(state_dir) as state:
        if name in state:
            fail(f"Conflict. The container name {name} is already in use", 125)
        state[name] = {
            "Id": f"id-{name}",
            "Image": image,
            "Labels": labels,
            "State": {"Status": "created", "ExitCode": 0, "OOMKilled": False},
            "pid": None,
        }
    print(f"id-{name}")


def cmd_start(state_dir: Path, name: str) -> None:
    with locked(state_dir) as state:
        if name not in state:
            fail(f"Error: No such container: {name}")
        c = state[name]
        c["pid"] = os.getpid()
        c["State"]["Status"] = "running"
        image = c["Image"]
    code, oom = run_behaviour(image)
    with locked(state_dir) as state:
        if name in state:
            state[name]["State"].update(Status="exited", ExitCode=code, OOMKilled=oom)
            state[name]["pid"] = None
    sys.exit(code)


def run_behaviour(image: str) -> tuple[int, bool]:
    out = sys.stdout.buffer
    if image == "fake/echo":
        data = sys.stdin.buffer.read()
        out.write(json.dumps({"echo": data.decode()}).encode())
        return 0, False
    if image == "fake/sleep":
        time.sleep(3600)
    if image == "fake/flood":
        for _ in range(128):
            out.write(b"x" * 65536)
            out.flush()
        return 0, False
    if image == "fake/stderr":
        for _ in range(128):
            sys.stderr.buffer.write(b"e" * 65536)
            sys.stderr.flush()
        return 0, False
    if image == "fake/oom":
        return 137, True
    if image == "fake/fail":
        return 3, False
    if image == "fake/nested":  # hostile: nesting deeper than the JSON parser recurses
        out.write(b"[" * 200_000 + b"]" * 200_000)
        return 0, False
    if image == "fake/text":
        out.write(b"hello\n")
        return 0, False
    fail(f"Unable to find image '{image}' locally", 125)
    return 125, False


def cmd_kill(state_dir: Path, name: str) -> None:
    with locked(state_dir) as state:
        c = state.get(name)
        if c is None:
            fail(f"Error: No such container: {name}")
        pid = c.get("pid")
        if c["State"]["Status"] != "running" or not pid:
            fail(f"Error: container {name} is not running")
        c["State"].update(Status="exited", ExitCode=137)
        c["pid"] = None
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)


def cmd_rm(state_dir: Path, names: list[str]) -> None:
    missing = []
    with locked(state_dir) as state:
        for name in names:
            c = state.pop(name, None)
            if c is None:
                missing.append(name)
            elif c.get("pid"):
                with suppress(ProcessLookupError):
                    os.kill(c["pid"], signal.SIGKILL)
    if missing and "--force" not in sys.argv:
        fail(f"Error: No such container: {missing[0]}")


def cmd_inspect(state_dir: Path, fmt: str, name: str) -> None:
    with locked(state_dir) as state:
        c = state.get(name)
    if c is None:
        extra = state_dir / "containers" / f"{name}.json"
        if extra.exists():
            print(extra.read_text())
            return
        fail(f"Error: No such container: {name}")
    if fmt == "{{json .State}}":
        print(json.dumps(c["State"]))
    elif fmt == "{{.Id}}":
        print(c["Id"])
    else:
        print(json.dumps(c))


def cmd_ps(state_dir: Path, args: list[str]) -> None:
    filters = [args[i + 1] for i, a in enumerate(args) if a == "--filter"]
    wanted = {}
    for f in filters:
        _, _, kv = f.partition("=")
        k, _, v = kv.partition("=")
        wanted[k] = v
    with locked(state_dir) as state:
        for name, c in state.items():
            if all(c["Labels"].get(k) == v for k, v in wanted.items()):
                print(name)


def main() -> None:
    state_dir = Path(sys.argv[1])
    argv = sys.argv[2:]
    with open(state_dir / "calls.jsonl", "a") as f:
        f.write(json.dumps(argv) + "\n")
    if argv[:1] == ["--host"]:
        argv = argv[2:]
    cmd, rest = argv[0], argv[1:]
    if (state_dir / "unreachable").exists():
        fail("Cannot connect to the Docker daemon at unix:///fake.sock")
    if cmd == "create":
        cmd_create(state_dir, rest)
    elif cmd == "start":
        cmd_start(state_dir, rest[-1])
    elif cmd == "kill":
        cmd_kill(state_dir, rest[-1])
    elif cmd == "rm":
        cmd_rm(state_dir, [a for a in rest if not a.startswith("--")])
    elif cmd == "container" and rest[0] == "inspect":
        cmd_inspect(state_dir, rest[2], rest[3])
    elif cmd == "ps":
        cmd_ps(state_dir, rest)
    elif cmd == "info":
        info = state_dir / "info.json"
        print(info.read_text() if info.exists() else "{}")
    elif cmd == "image" and rest[0] == "inspect":
        if (state_dir / "no-image").exists():
            fail(f"Error: No such image: {rest[-1]}")
        print("sha256:fake")
    elif cmd == "network" and rest[0] == "inspect":
        net = state_dir / "networks" / f"{rest[-1]}.json"
        if not net.exists():
            fail(f"Error: network {rest[-1]} not found")
        print(net.read_text())
    else:
        fail(f"fake docker: unsupported command {argv}")


if __name__ == "__main__":
    main()
