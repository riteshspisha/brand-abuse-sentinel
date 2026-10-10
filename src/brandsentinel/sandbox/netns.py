"""Read-only view of the rootless Docker network namespace (SP1).

Rootless dockerd runs its bridges inside a network namespace that rootlesskit
creates for the account (`$XDG_RUNTIME_DIR/dockerd-rootless/child_pid` names a
process in it). The account can read that process's `/proc/<pid>/net/*` files
without privileges, which is enough to answer two questions:

- which IPv4 addresses the namespace itself holds (`fib_trie`, LOCAL entries):
  a bridge that holds an address in the sandbox subnet is a gateway sandboxes
  can talk to;
- which sockets listen on a non-loopback address (`tcp`, `tcp6`, `udp`, `udp6`):
  a listener there would be reachable from any network that has a gateway.

Nothing here changes the namespace.
"""

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

_TCP_LISTEN = "0A"
_UDP_UNCONNECTED = "07"


class NamespaceUnavailable(Exception):
    """The rootless network namespace cannot be inspected."""


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


def is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


@dataclass(frozen=True)
class RootlessNamespace:
    pid: int
    proc: Path = Path("/proc")

    @classmethod
    def for_endpoint(cls, docker_host: str, proc: Path = Path("/proc")) -> "RootlessNamespace":
        """The namespace of the rootless daemon behind `unix://.../docker.sock`."""
        sock = Path(docker_host.removeprefix("unix://"))
        pid_file = sock.parent / "dockerd-rootless" / "child_pid"
        try:
            pid = int(pid_file.read_text().strip())
            owner = (proc / str(pid)).stat().st_uid
        except (OSError, ValueError) as e:
            raise NamespaceUnavailable(f"cannot read {pid_file}: {e}") from e
        if owner != os.getuid():
            raise NamespaceUnavailable(f"process {pid} does not belong to this account")
        return cls(pid, proc)

    def _read(self, name: str) -> str:
        try:
            return (self.proc / str(self.pid) / "net" / name).read_text()
        except OSError as e:
            raise NamespaceUnavailable(f"cannot read /proc/{self.pid}/net/{name}: {e}") from e

    def local_ipv4(self) -> set[str]:
        return parse_local_ipv4(self._read("fib_trie"))

    def listeners(self) -> list[Listener]:
        out: list[Listener] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            out += parse_sockets(self._read(proto), proto)
        return out

    def exposed_listeners(self) -> list[Listener]:
        """Listeners bound to a wildcard or any non-loopback address."""
        return [li for li in self.listeners() if not is_loopback(li.address)]
