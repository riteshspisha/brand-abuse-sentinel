"""Rootless namespace view: parsing /proc/net tables and fib_trie (SP1)."""

import os

import pytest

from brandsentinel.sandbox.netns import (
    NamespaceUnavailable,
    RootlessNamespace,
    is_loopback,
    parse_local_ipv4,
    parse_sockets,
)

WILDCARD = ".".join(["0"] * 4)  # a parsed address, not a bind

# Shapes copied from a real rootless namespace (addresses as on the dev host).
FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.2.0/24 2 0 2
        |-- 10.0.2.100
           /32 host LOCAL
     +-- 172.31.251.0/24 2 0 2
        |-- 172.31.251.0
           /24 link UNICAST
     |-- 172.31.252.1
        /32 host LOCAL
Local:
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.1
        /32 host LOCAL
"""
TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:0C39 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000
   2: 0100007F:0C39 0100007F:A000 01 00000000:00000000 00:00000000 00000000  1000
"""
TCP6 = """  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:48AD 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A
"""
UDP = """  sl  local_address rem_address   st
   0: 6402000A:0035 00000000:0000 07
"""


def test_local_addresses_are_the_host_local_entries():
    assert parse_local_ipv4(FIB_TRIE) == {"10.0.2.100", "172.31.252.1", "127.0.0.1"}


def test_listening_sockets_are_parsed_and_connected_ones_ignored():
    tcp = parse_sockets(TCP, "tcp")
    assert [(li.address, li.port) for li in tcp] == [("127.0.0.1", 3129), (WILDCARD, 8080)]
    tcp6 = parse_sockets(TCP6, "tcp6")
    assert [(li.address, li.port) for li in tcp6] == [("::", 18605), ("::1", 8081)]
    assert [str(li) for li in parse_sockets(UDP, "udp")] == ["udp 10.0.2.100:53"]


def test_loopback_detection():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("::ffff:127.0.0.2")
    assert not is_loopback(WILDCARD) and not is_loopback("::") and not is_loopback("10.0.2.100")


def test_exposed_listeners_from_a_fake_proc(tmp_path):
    net = tmp_path / str(os.getpid()) / "net"
    net.mkdir(parents=True)
    for name, text in (("tcp", TCP), ("tcp6", TCP6), ("udp", UDP), ("udp6", "header\n")):
        (net / name).write_text(text)
    (net / "fib_trie").write_text(FIB_TRIE)
    (net / "dev").write_text("Inter-|\n face |\n    lo: 0\n")
    ns = RootlessNamespace(os.getpid(), 1, proc=tmp_path)
    assert [str(li) for li in ns.exposed_listeners()] == [
        "tcp 0.0.0.0:8080",
        "tcp6 [::]:18605",
        "udp 10.0.2.100:53",
    ]


def test_endpoint_without_rootless_child_is_unavailable(tmp_path):
    with pytest.raises(NamespaceUnavailable):
        RootlessNamespace.for_endpoint(f"unix://{tmp_path}/docker.sock")


def test_endpoint_resolves_its_child_pid(tmp_path):
    host, proc, _ = fake_runtime(tmp_path, detached=False)
    ns = RootlessNamespace.for_endpoint(host, proc, inode=inodes({"self/ns/net": HOST,
                                                                  "/ns/net": BRIDGE}))  # fmt: skip
    assert ns.child_pid == os.getpid() and ns.netns_path is None and ns.direct


# --- resolving the authoritative namespace (SP1 acceptance failure, 2026-10-11) ------
#
# Under RootlessKit --detach-netns the bridges live in $STATE_DIR/netns; on the
# service account the child process sat in the HOST namespace, so reading
# /proc/<child>/net examined the host (listeners 0.0.0.0:22, 192.168.122.1:53).


def fake_runtime(tmp_path, *, detached=True):
    """A fake /proc and runtime dir; returns (docker_host, proc, inode map)."""
    pid = os.getpid()
    run = tmp_path / "run"
    (run / "dockerd-rootless").mkdir(parents=True)
    (run / "dockerd-rootless" / "child_pid").write_text(f"{pid}\n")
    proc = tmp_path / "proc"
    (proc / str(pid) / "ns").mkdir(parents=True)
    (proc / "self" / "ns").mkdir(parents=True)
    (proc / str(pid) / "ns" / "net").write_text("")
    (proc / "self" / "ns" / "net").write_text("")
    netns = proc / str(pid) / "root" / str(run / "dockerd-rootless").lstrip("/") / "netns"
    if detached:
        netns.parent.mkdir(parents=True)
        netns.write_text("")
    return f"unix://{run}/docker.sock", proc, netns


def inodes(mapping):
    def inode(path):
        for suffix, value in mapping.items():
            if str(path).endswith(suffix):
                return value
        raise OSError(f"no such namespace {path}")

    return inode


HOST, BRIDGE = 4026531833, 4026533037


def test_detached_netns_with_child_in_host_namespace_uses_the_netns_file(tmp_path):
    host, proc, netns = fake_runtime(tmp_path)
    ns = RootlessNamespace.for_endpoint(
        host, proc, inode=inodes({"self/ns/net": HOST, f"{os.getpid()}/ns/net": HOST,
                                  "/netns": BRIDGE})
    )  # fmt: skip
    assert ns.inode == BRIDGE and ns.netns_path == netns and ns.direct is False
    assert ns.nsenter_prefix()[-1] == f"--net={netns}"


def test_detached_netns_with_child_inside_it_reads_directly(tmp_path):
    host, proc, netns = fake_runtime(tmp_path)
    ns = RootlessNamespace.for_endpoint(
        host, proc, inode=inodes({"self/ns/net": HOST, f"{os.getpid()}/ns/net": BRIDGE,
                                  "/netns": BRIDGE})
    )  # fmt: skip
    assert ns.direct is True and ns.netns_path == netns


def test_a_namespace_that_is_the_hosts_own_is_refused(tmp_path):
    host, proc, _ = fake_runtime(tmp_path)
    with pytest.raises(NamespaceUnavailable, match="host's own"):
        RootlessNamespace.for_endpoint(
            host, proc, inode=inodes({"self/ns/net": HOST, "/ns/net": HOST, "/netns": HOST})
        )
    host, proc, _ = fake_runtime(tmp_path / "plain", detached=False)
    with pytest.raises(NamespaceUnavailable, match="host's own"):
        RootlessNamespace.for_endpoint(host, proc, inode=inodes({"/ns/net": HOST}))


def test_tables_are_read_inside_the_namespace_and_identity_is_checked(tmp_path):
    import json

    host, proc, _ = fake_runtime(tmp_path)
    tables = {"tcp": TCP, "tcp6": TCP6, "udp": UDP, "udp6": "h\n", "fib_trie": FIB_TRIE,
              "dev": "Inter-|\n face |\n    lo: 0\n  tap0: 0\nbr-6af1c7b4f369: 0\n"}  # fmt: skip
    calls = []

    def run(argv):
        calls.append(argv)
        return json.dumps({**tables, "_ns": f"net:[{BRIDGE}]"})

    ns = RootlessNamespace.for_endpoint(
        host, proc, run=run,
        inode=inodes({"self/ns/net": HOST, f"{os.getpid()}/ns/net": HOST, "/netns": BRIDGE}),
    )  # fmt: skip
    assert ns.interfaces() == {"lo", "tap0", "br-6af1c7b4f369"}
    assert "udp 10.0.2.100:53" in [str(li) for li in ns.exposed_listeners()]
    assert calls[0][:3][1:] == ["-U", "--preserve-credentials"]

    def wrong(argv):
        return json.dumps({**tables, "_ns": f"net:[{HOST}]"})

    other = RootlessNamespace(ns.child_pid, BRIDGE, ns.netns_path, direct=False, run=wrong)
    with pytest.raises(NamespaceUnavailable, match="different network namespace"):
        other.interfaces()
