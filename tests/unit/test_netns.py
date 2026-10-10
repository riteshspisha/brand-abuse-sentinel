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
    ns = RootlessNamespace(os.getpid(), tmp_path)
    assert [str(li) for li in ns.exposed_listeners()] == [
        "tcp 0.0.0.0:8080",
        "tcp6 [::]:18605",
        "udp 10.0.2.100:53",
    ]


def test_endpoint_without_rootless_child_is_unavailable(tmp_path):
    with pytest.raises(NamespaceUnavailable):
        RootlessNamespace.for_endpoint(f"unix://{tmp_path}/docker.sock")


def test_endpoint_resolves_its_child_pid(tmp_path):
    (tmp_path / "dockerd-rootless").mkdir()
    (tmp_path / "dockerd-rootless" / "child_pid").write_text(f"{os.getpid()}\n")
    ns = RootlessNamespace.for_endpoint(f"unix://{tmp_path}/docker.sock")
    assert ns.pid == os.getpid()
