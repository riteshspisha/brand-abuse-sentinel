"""Read-only view of the rootless Docker network namespace (SP1).

Rootless dockerd keeps its bridges in a network namespace that RootlessKit
creates for the account. Which namespace that is depends on the mode:

- with `--detach-netns` (the default of dockerd-rootless.sh for Docker 29), the
  bridges live in the namespace bind-mounted at `$STATE_DIR/netns` inside the
  RootlessKit child's mount namespace, reachable from outside as
  `/proc/<child>/root$STATE_DIR/netns` (the path slirp4netns itself is given).
  The child process and dockerd may stay in the HOST namespace, so the child's
  own `/proc/<child>/net` must not be trusted;
- without it, the child process sits in the bridge namespace.

`RootlessNamespace.for_endpoint` resolves the authoritative namespace (the netns
file when present) and refuses one that is the host's own namespace, so a check
can never pass or fail on the host's addresses and listeners. Tables are read
from `/proc/<child>/net` when the child is in that namespace, and otherwise from
inside it through `nsenter` (as the owning account, no privilege: the namespace
belongs to the account's user namespace). Callers can confirm identity further
with `interfaces()` (the sandbox bridge must be there).

It answers:

- which IPv4 addresses the namespace holds (`fib_trie` LOCAL entries): a bridge
  holding an address in the sandbox subnet is a gateway sandboxes can talk to;
- which sockets listen on a non-loopback address (`tcp`, `tcp6`, `udp`, `udp6`);
- which interfaces it has (`dev`).

Nothing here changes the namespace.
"""

import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

_TCP_LISTEN = "0A"
_UDP_UNCONNECTED = "07"
_TABLES = ("tcp", "tcp6", "udp", "udp6", "fib_trie", "dev")
_READ_TIMEOUT = 15


class NamespaceUnavailable(Exception):
    """The rootless network namespace cannot be identified or inspected."""


@dataclass(frozen=True)
class Listener:
    proto: str  # tcp | tcp6 | udp | udp6
    address: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.proto} {host}:{self.port}"


def _ipv4(hexaddr: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(hexaddr, 16)))


def _ipv6(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_sockets(text: str, proto: str) -> list[Listener]:
    """Listening (TCP) or unconnected (UDP) sockets from a /proc/net table."""
    state = _TCP_LISTEN if proto.startswith("tcp") else _UDP_UNCONNECTED
    conv = _ipv6 if proto.endswith("6") else _ipv4
    out = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != state:
            continue
        addr, _, port = fields[1].rpartition(":")
        out.append(Listener(proto, conv(addr), int(port, 16)))
    return out


def parse_local_ipv4(fib_trie: str) -> set[str]:
    """Addresses marked `host LOCAL` in /proc/net/fib_trie."""
    local: set[str] = set()
    last = None
    for line in fib_trie.splitlines():
        stripped = line.strip()
        if stripped.startswith("|--"):
            last = stripped[3:].strip()
        elif last and "host LOCAL" in stripped:
            local.add(last)
    return local


def parse_interfaces(dev: str) -> set[str]:
    """Interface names from /proc/net/dev."""
    return {line.split(":", 1)[0].strip() for line in dev.splitlines()[2:] if ":" in line}


def is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def _inode(path: Path) -> int:
    return os.stat(path).st_ino  # follows the nsfs link


def _nsenter() -> str:
    return shutil.which("nsenter") or "/usr/bin/nsenter"


def _run(argv: list[str]) -> str:
    try:
        r = subprocess.run(  # noqa: S603 - fixed argv
            argv, capture_output=True, text=True, timeout=_READ_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise NamespaceUnavailable(f"cannot run nsenter: {e}") from e
    if r.returncode != 0:
        raise NamespaceUnavailable(f"nsenter failed: {r.stderr.strip()[:300]}")
    return r.stdout


@dataclass(frozen=True)
class RootlessNamespace:
    child_pid: int
    inode: int  # identity of the bridge namespace
    netns_path: Path | None = None  # the detached netns file, when in that mode
    direct: bool = True  # the child process is in this namespace: read /proc/<child>/net
    proc: Path = Path("/proc")
    run: Callable[[list[str]], str] = field(default=_run, compare=False, repr=False)

    @classmethod
    def for_endpoint(
        cls,
        docker_host: str,
        proc: Path = Path("/proc"),
        *,
        inode: Callable[[Path], int] = _inode,
        run: Callable[[list[str]], str] = _run,
    ) -> "RootlessNamespace":
        """The bridge namespace of the rootless daemon behind `unix://.../docker.sock`."""
        state = Path(docker_host.removeprefix("unix://")).parent / "dockerd-rootless"
        pid_file = state / "child_pid"
        try:
            pid = int(pid_file.read_text().strip())
            owner = (proc / str(pid)).stat().st_uid
        except (OSError, ValueError) as e:
            raise NamespaceUnavailable(f"cannot read {pid_file}: {e}") from e
        if owner != os.getuid():
            raise NamespaceUnavailable(f"process {pid} does not belong to this account")
        try:
            host = inode(proc / "self" / "ns" / "net")
            child = inode(proc / str(pid) / "ns" / "net")
        except OSError as e:
            raise NamespaceUnavailable(f"cannot identify network namespaces: {e}") from e
        netns_path = proc / str(pid) / "root" / str(state).lstrip("/") / "netns"
        try:
            detached = inode(netns_path)
        except OSError:
            detached = None  # not in detach-netns mode: the child holds the bridges
        target = detached if detached is not None else child
        if target == host:
            raise NamespaceUnavailable(
                f"the rootless network namespace resolved to the host's own (net:[{host}])"
            )
        return cls(
            child_pid=pid,
            inode=target,
            netns_path=netns_path if detached is not None else None,
            direct=child == target,
            proc=proc,
            run=run,
        )

    def nsenter_prefix(self) -> list[str]:
        """argv prefix that runs a command inside this namespace (as the account)."""
        net = f"--net={self.netns_path}" if self.netns_path else "-n"
        return [_nsenter(), "-U", "--preserve-credentials", "-t", str(self.child_pid), net]

    def describe(self) -> str:
        where = f"detached netns file {self.netns_path}" if self.netns_path else "child process"
        how = "read directly" if self.direct else "read through nsenter"
        return f"net:[{self.inode}] ({where}, child pid {self.child_pid}, {how})"

    def _tables(self) -> dict[str, str]:
        if self.direct:
            out = {}
            for name in _TABLES:
                try:
                    out[name] = (self.proc / str(self.child_pid) / "net" / name).read_text()
                except OSError as e:
                    raise NamespaceUnavailable(
                        f"cannot read /proc/{self.child_pid}/net/{name}: {e}"
                    ) from e
            return out
        script = (
            "import json, os\n"
            f"print(json.dumps({{n: open('/proc/self/net/' + n).read() for n in {_TABLES!r}}}"
            "  | {'_ns': os.readlink('/proc/self/ns/net')}))"
        )
        data = json.loads(self.run([*self.nsenter_prefix(), sys.executable, "-c", script]))
        if data.pop("_ns", None) != f"net:[{self.inode}]":
            raise NamespaceUnavailable("nsenter entered a different network namespace")
        return data

    def local_ipv4(self) -> set[str]:
        return parse_local_ipv4(self._tables()["fib_trie"])

    def interfaces(self) -> set[str]:
        return parse_interfaces(self._tables()["dev"])

    def listeners(self) -> list[Listener]:
        tables = self._tables()
        out: list[Listener] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            out += parse_sockets(tables[proto], proto)
        return out

    def exposed_listeners(self) -> list[Listener]:
        """Listeners bound to a wildcard or any non-loopback address."""
        return [li for li in self.listeners() if not is_loopback(li.address)]


# --- egress diagnosis (environment, not security) ------------------------------------

_EGRESS = r"""
import json, socket, struct, sys
resolver, name = sys.argv[1], sys.argv[2]
out = {"resolver": resolver}
q = (struct.pack(">HHHHHH", 0x5350, 0x0100, 1, 0, 0, 0)
     + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
     + struct.pack(">HH", 1, 1))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(q, (resolver, 53))
    r = s.recv(512)
    out["dns"] = "ok" if (r[3] & 15) == 0 and struct.unpack(">H", r[6:8])[0] else "no_answer"
except OSError as e:
    out["dns"] = type(e).__name__
for key, fam, addr in (("tcp4", socket.AF_INET, ("1.1.1.1", 443)),
                       ("tcp6", socket.AF_INET6, ("2606:4700:4700::1111", 443))):
    c = socket.socket(fam)
    c.settimeout(5)
    try:
        c.connect(addr)
        out[key] = "ok"
    except OSError as e:
        out[key] = type(e).__name__
    finally:
        c.close()
print(json.dumps(out))
"""


def egress(ns: RootlessNamespace, docker_host: str, name: str = "example.com") -> dict:
    """What the egress proxy's network path offers, measured inside the bridge
    namespace: DNS through the resolver RootlessKit gives containers (slirp4netns
    forwards it to the host's), IPv4 TCP, and IPv6 TCP (informational: the proxy
    path is IPv4-only with slirp4netns)."""
    resolv = Path(docker_host.removeprefix("unix://")).parent / "dockerd-rootless" / "resolv.conf"
    resolver = "10.0.2.3"
    try:
        for line in resolv.read_text().splitlines():
            if line.startswith("nameserver"):
                resolver = line.split()[1]
                break
    except OSError:
        pass
    return json.loads(ns.run([*ns.nsenter_prefix(), sys.executable, "-c", _EGRESS, resolver, name]))


def main() -> int:
    """`python -m brandsentinel.sandbox.netns [--egress]`: print the resolved
    namespace (and the egress diagnosis) as JSON; exit 1 if unavailable, 2 if
    DNS or IPv4 egress fails."""
    from brandsentinel.sandbox.runner import default_docker_host

    host = os.environ.get("DOCKER_HOST") or default_docker_host()
    try:
        ns = RootlessNamespace.for_endpoint(host)
        report = {
            "namespace": ns.describe(),
            "host_namespace": os.readlink("/proc/self/ns/net"),
            "interfaces": sorted(ns.interfaces()),
            "exposed_listeners": [str(li) for li in ns.exposed_listeners()],
        }
    except NamespaceUnavailable as e:
        print(json.dumps({"error": str(e)}))
        return 1
    code = 0
    if "--egress" in sys.argv:
        measured = egress(ns, host)
        report["egress"] = measured
        code = 0 if measured.get("dns") == "ok" and measured.get("tcp4") == "ok" else 2
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
