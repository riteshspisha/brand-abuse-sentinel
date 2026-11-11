"""The offline suite's name-resolution tripwires (tests/resolver_tripwire.py): the
host's resolver is never asked, a refused query is never silent, and explicitly
configured resolvers keep working (B7 U3-A remediation, PR-1)."""

import asyncio
import socket

import dns.asyncresolver
import dns.resolver
import pytest
from tests import resolver_tripwire
from tests.resolver_tripwire import TripwireNameserver

from brandsentinel.config import DnsSettings
from brandsentinel.net.netguard import make_dns_resolver


def without_sockets(monkeypatch, query):
    """Run `query(loop)` with socket creation refused, on an event loop made
    beforehand (the loop opens its own wake-up socket pair). Returns the sockets
    the query tried to open: none may be."""
    opened = []

    def refuse(*a, **k):
        opened.append(a)
        raise AssertionError("a socket was opened")

    loop = asyncio.new_event_loop()
    try:
        with monkeypatch.context() as m:
            m.setattr(socket, "socket", refuse)
            query(loop)
    finally:
        loop.close()
    return opened


def test_a_system_configured_resolver_is_built_but_never_asks_the_host(monkeypatch):
    """`make_dns_resolver` with no nameservers is what `build_network` and
    `AnalysisStages` build by default: construction works, a query is refused
    before any socket exists, and it is recorded."""
    r = make_dns_resolver(DnsSettings())
    assert [type(ns) for ns in r.nameservers] == [TripwireNameserver]

    def query(loop):
        with pytest.raises(dns.resolver.NoNameservers):
            loop.run_until_complete(r.resolve("x.test", "A", search=False))

    with resolver_tripwire.expected() as trips:
        assert without_sockets(monkeypatch, query) == []
    assert [(t.kind, t.name) for t in trips] == [("dnspython", "x.test.")]
    assert "test_a_system_configured_resolver" in trips[0].test


@pytest.mark.parametrize(
    "build",
    [
        lambda: dns.resolver.Resolver(),
        lambda: dns.asyncresolver.Resolver(configure=True),
        dns.resolver.get_default_resolver,
    ],
    ids=["sync", "async", "module-default"],
)
def test_every_dnspython_entry_point_that_reads_the_host_configuration_is_covered(
    build, monkeypatch
):
    r = build()
    assert [type(ns) for ns in r.nameservers] == [TripwireNameserver]

    def query(loop):
        with pytest.raises(dns.resolver.NoNameservers):
            if isinstance(r, dns.asyncresolver.Resolver):
                loop.run_until_complete(r.resolve("leak.test", "AAAA"))
            else:
                r.resolve("leak.test", "AAAA")

    with resolver_tripwire.expected() as trips:
        assert without_sockets(monkeypatch, query) == []
    assert {t.name for t in trips} == {"leak.test."}


def test_explicit_nameservers_are_untouched_and_still_answer(harness):
    """The harness stub is configured explicitly, so it never reads the host
    configuration and real queries to it on loopback still work."""
    from tests.security.harness import harness_resolver

    explicit = make_dns_resolver(DnsSettings(nameservers=["127.77.0.53"]))
    assert [str(ns) for ns in explicit.nameservers] == ["127.77.0.53"]
    r = harness_resolver(harness)
    assert not any(isinstance(ns, TripwireNameserver) for ns in r.nameservers)
    start = resolver_tripwire.mark()
    answer = asyncio.run(r.resolve("site.harness.test", "A", search=False))
    assert [rr.to_text() for rr in answer] == ["127.77.0.1"]
    assert resolver_tripwire.since(start) == []


@pytest.mark.parametrize(
    "call",
    [
        lambda: socket.getaddrinfo("example.invalid", 80),
        lambda: socket.getaddrinfo("localhost", 80),
        lambda: socket.getaddrinfo("", 80),
        lambda: socket.gethostbyname("example.invalid"),
        lambda: socket.gethostbyname_ex("example.invalid"),
    ],
    ids=[
        "getaddrinfo",
        "getaddrinfo-localhost",
        "getaddrinfo-empty",
        "gethostbyname",
        "gethostbyname_ex",
    ],
)
def test_forward_lookups_of_names_are_refused_and_recorded(call):
    with resolver_tripwire.expected() as trips, pytest.raises(socket.gaierror):
        call()
    assert [t.kind for t in trips] in (["getaddrinfo"], ["gethostbyname"], ["gethostbyname_ex"])


@pytest.mark.parametrize("call", [lambda: socket.getfqdn("127.77.0.1"),
                                  lambda: socket.gethostbyaddr("127.77.0.1"),
                                  lambda: socket.getfqdn()])  # fmt: skip
def test_reverse_lookups_are_refused_and_recorded(call):
    with resolver_tripwire.expected() as trips, pytest.raises(socket.herror):
        call()
    assert len(trips) == 1


def test_getnameinfo_is_refused_unless_numeric():
    addr = ("127.77.0.1", 80)
    assert socket.getnameinfo(addr, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)[0] == (
        "127.77.0.1"
    )
    with resolver_tripwire.expected() as trips, pytest.raises(socket.gaierror):
        socket.getnameinfo(addr, 0)
    assert [(t.kind, t.name) for t in trips] == [("getnameinfo", "127.77.0.1")]


def test_dnspython_system_resolver_override_and_restore_stay_guarded():
    """dnspython's override_system_resolver()/restore_system_resolver() keep their
    own copies of the socket functions; a restore must not unwrap them."""
    dns.resolver.override_system_resolver()
    dns.resolver.restore_system_resolver()
    with resolver_tripwire.expected() as trips, pytest.raises(socket.gaierror):
        socket.getaddrinfo("example.invalid", 80)
    assert [t.kind for t in trips] == ["getaddrinfo"]


@pytest.mark.parametrize("host", ["127.77.0.1", "::1", "fe80::1%lo", None, b"127.0.0.1", "127.1"])
def test_literals_and_the_bind_host_pass_through(host):
    start = resolver_tripwire.mark()
    assert socket.getaddrinfo(host, 80, proto=socket.IPPROTO_TCP)
    assert resolver_tripwire.since(start) == []


def test_a_recorded_trip_fails_the_test():
    start = resolver_tripwire.mark()
    resolver_tripwire.fail_if_tripped(start)  # nothing recorded: passes
    with resolver_tripwire.expected():
        resolver_tripwire.record("dnspython", "x.test.")
        expected_message = r"host resolver \(dnspython:x\.test\. \(in tests/unit/"
        with pytest.raises(pytest.fail.Exception, match=expected_message):
            resolver_tripwire.fail_if_tripped(start)


def test_harness_http_servers_bind_without_a_reverse_lookup():
    """`http.server.HTTPServer.server_bind` reverse-resolves the bound address
    (`socket.getfqdn`), which sent PTR queries for 127.77.0.x to the host's
    resolver. The harness servers bind without it."""
    from tests.security.harness import HttpServer, NoLookupHTTPServer, Recorder

    start = resolver_tripwire.mark()
    s = HttpServer("127.77.0.9", Recorder(), b"")
    try:
        assert s.server.server_name == "127.77.0.9" and s.server.server_port == s.port
    finally:
        s.close()
    plain = NoLookupHTTPServer(("127.77.0.9", 0), None)  # the base the IPv6 test uses
    plain.server_close()
    assert plain.server_name == "127.77.0.9"
    assert resolver_tripwire.since(start) == []


def test_a_trip_outside_any_test_fails_the_next_check_once():
    """A trip recorded during collection, between tests or by a background thread
    after its test ended is reported by the next check, and only once."""
    resolver_tripwire.check_since_last()  # nothing pending
    resolver_tripwire.record("getaddrinfo", "between.test")
    with pytest.raises(pytest.fail.Exception, match=r"getaddrinfo:between\.test \(in tests/"):
        resolver_tripwire.check_since_last()
    resolver_tripwire.check_since_last()  # already reported: passes
    assert resolver_tripwire.unchecked() == []


def test_no_loaded_module_holds_an_unwrapped_lookup_function(monkeypatch):
    import sys
    import types

    assert resolver_tripwire.aliases() == []
    early = types.ModuleType("early_binder")
    early.resolve_name = resolver_tripwire._originals["getaddrinfo"]  # bound before install
    monkeypatch.setitem(sys.modules, "early_binder", early)
    assert resolver_tripwire.aliases() == ["early_binder.resolve_name (getaddrinfo)"]


def test_expected_keeps_another_threads_trip_for_the_check():
    """A lookup another thread makes while a tripwire self-test is inside
    `expected()` is not swallowed: it stays recorded and fails the check."""
    import threading

    resolver_tripwire.check_since_last()
    with resolver_tripwire.expected() as mine:
        resolver_tripwire.record("getfqdn", "own.test")
        other = threading.Thread(target=resolver_tripwire.record, args=("getaddrinfo", "bg.test"))
        other.start()
        other.join()
    assert [t.name for t in mine] == ["own.test"]
    assert [t.name for t in resolver_tripwire.unchecked()] == ["bg.test"]
    with pytest.raises(pytest.fail.Exception, match=r"getaddrinfo:bg\.test"):
        resolver_tripwire.check_since_last()
