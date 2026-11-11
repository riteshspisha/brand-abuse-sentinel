"""Offline-test tripwires for name resolution (B7 U3-A remediation, PR-1).

The offline suite must never ask the host's resolver anything. Two in-process
paths could do that, and this module closes both for the test process:

- **dnspython.** A resolver built without explicit nameservers
  (`Resolver(configure=True)`, which is what `make_dns_resolver` builds when
  `DnsSettings.nameservers` is empty) reads the host's resolver configuration.
  Under the tripwire it gets a single `TripwireNameserver` instead. Building one
  still works (several tests build the real network objects and never resolve);
  any *query* is recorded and refused before a socket exists. dnspython turns the
  refusal into `NoNameservers`, which product code may handle quietly, so the
  per-test check in `tests/conftest.py` fails the test from the record.
  Resolvers with explicit nameservers (the harness stub on 127.77.0.53) never
  read the configuration and are untouched.
- **The C library, called from Python.** Reverse lookups (`getfqdn`,
  `gethostbyaddr`, and `getnameinfo` unless it asks for a numeric host) and
  forward lookups of anything but an IP literal or `None`, the wildcard bind host
  (`getaddrinfo`, `gethostbyname`, `gethostbyname_ex`), are recorded and refused
  with the error the library would raise. Not even `localhost` is allowed: on
  some hosts the C library asks a resolver for it.

`tests/conftest.py` installs this in `pytest_configure`, before collection, so
imports during collection are covered too. After each test it fails that test for
every trip since the previous check (`check_since_last`), so trips during
collection or between tests are reported too, and at the end of the session it
fails the run for any trip left unreported or any module holding an unwrapped
function (`aliases`).

Not covered, and stated wherever this is cited:
- anything in a subprocess (the CLI subprocess tests, `uv`, containers);
- native code that resolves without these Python functions (a C extension calling
  the C library, a bundled resolver);
- a query sent directly over a socket (`dns.query.udp` to an explicit server, a
  hand-built packet) and resolvers given explicit non-loopback nameservers;
- a hostname passed straight to a socket method (`connect`, `connect_ex`, `bind`,
  `sendto`), which the C socket module resolves itself;
- a process-wide resolver replacement (an event loop or library with its own
  resolver, or dnspython's `override_system_resolver` given explicit nameservers);
- a reference to an unwrapped function taken before installation: `aliases`
  reports module-level names only, not one held in a default argument, closure,
  class attribute or container, and it reports rather than prevents.
Those need a network boundary or a trace.
"""

import ipaddress
import os
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import dns.nameserver
import dns.resolver


@dataclass(frozen=True)
class Trip:
    kind: str  # "dnspython" or the socket function's name
    name: str
    test: str  # the test running when it was recorded (a background thread's may differ)
    thread: int


_lock = threading.Lock()
_trips: list[Trip] = []
_checked = 0  # trips before this index have been reported to a test
_originals: dict[str, object] = {}
FORWARD = ("getaddrinfo", "gethostbyname", "gethostbyname_ex")
REVERSE = ("getfqdn", "gethostbyaddr")


def _current_test() -> str:
    return os.environ.get("PYTEST_CURRENT_TEST", "<no test>").rsplit(" ", 1)[0]


def record(kind: str, name: str) -> None:
    with _lock:
        _trips.append(Trip(kind, name, _current_test(), threading.get_ident()))


def mark() -> int:
    with _lock:
        return len(_trips)


def since(start: int) -> list[Trip]:
    with _lock:
        return list(_trips[start:])


@contextmanager
def expected() -> Iterator[list[Trip]]:
    """For tests of the tripwire itself: yields the trips this thread recorded inside
    the block, then removes them so the per-test check does not fail the test.
    Trips other threads record meanwhile stay, and are reported as usual."""
    start = mark()
    me = threading.get_ident()
    got: list[Trip] = []
    try:
        yield got
    finally:
        with _lock:
            window = _trips[start:]
            got.extend(t for t in window if t.thread == me)
            _trips[start:] = [t for t in window if t.thread != me]


class TripwireNameserver(dns.nameserver.Nameserver):
    """Stands in for the host's nameservers: records each query and refuses it
    without opening a socket."""

    def __str__(self) -> str:
        return "offline-test-tripwire"

    def kind(self) -> str:
        return "Tripwire"

    def is_always_max_size(self) -> bool:
        return False

    def answer_nameserver(self) -> str:
        return str(self)

    def answer_port(self) -> int:
        return 0

    def _refuse(self, request) -> None:
        name = request.question[0].name.to_text() if request.question else "?"
        record("dnspython", name)
        raise ConnectionRefusedError(f"offline tests may not use the host resolver ({name})")

    def query(self, request, *args, **kwargs):
        self._refuse(request)

    async def async_query(self, request, *args, **kwargs):
        self._refuse(request)


def _read_resolv_conf(self, f) -> None:
    self.nameservers = [TripwireNameserver()]


def _is_ip_literal_or_none(host) -> bool:
    """An address the C library parses without asking a resolver: `None`, an IP
    literal, or a legacy numeric IPv4 form such as `127.1` (`inet_aton`)."""
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).split("%", 1)[0]  # an IPv6 scope id
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            socket.inet_aton(host)
        except (OSError, ValueError):
            return False
    return True


def _guard_forward(real, kind: str):
    def guarded(host, *args, **kwargs):
        if not _is_ip_literal_or_none(host):
            record(kind, str(host))
            raise socket.gaierror(socket.EAI_NONAME, f"offline tests may not resolve {host!r}")
        return real(host, *args, **kwargs)

    return guarded


def _guard_reverse(kind: str):
    def refused(name="", *args, **kwargs):
        record(kind, str(name))
        raise socket.herror(1, f"offline tests may not reverse-resolve {name!r}")

    return refused


def check_since_last() -> None:
    """Fail the current test for every trip since the previous check, including any
    recorded during collection or between tests, so none goes unreported."""
    global _checked
    with _lock:
        start, _checked = _checked, len(_trips)
    fail_if_tripped(start)


def unchecked() -> list[Trip]:
    """Trips no test was failed for (recorded after the last check)."""
    return since(_checked)


def aliases() -> list[str]:
    """Loaded modules that hold the unwrapped functions under any name (for example
    `from socket import getaddrinfo` run before installation). Those calls bypass
    the tripwire."""
    import sys

    found = []
    originals = {id(f): n for n, f in _originals.items()}
    for mod_name, mod in list(sys.modules.items()):
        if mod is None or mod_name in ("socket", "_socket", __name__):
            continue
        try:
            items = list(vars(mod).items())
        except TypeError:
            continue
        found += [f"{mod_name}.{k} ({originals[id(v)]})" for k, v in items if id(v) in originals]
    return found


def fail_if_tripped(start: int) -> None:
    """Fail the current test if anything was recorded since `start`."""
    import pytest

    trips = since(start)
    if trips:
        names = ", ".join(sorted({f"{t.kind}:{t.name} (in {t.test})" for t in trips}))
        pytest.fail(f"the test tried to use the host resolver ({names})", pytrace=False)


def _guard_getnameinfo(real):
    def guarded(sockaddr, flags, *args, **kwargs):
        if not flags & socket.NI_NUMERICHOST:
            record("getnameinfo", str(sockaddr[0]) if sockaddr else "?")
            raise socket.gaierror(socket.EAI_NONAME, "offline tests may not reverse-resolve")
        return real(sockaddr, flags, *args, **kwargs)

    return guarded


def install(monkeypatch) -> None:
    monkeypatch.setattr(dns.resolver.BaseResolver, "read_resolv_conf", _read_resolv_conf)
    for fn in (*FORWARD, *REVERSE, "getnameinfo"):
        _originals[fn] = getattr(socket, fn)
    wrapped = {fn: _guard_forward(_originals[fn], fn) for fn in FORWARD}
    wrapped |= {fn: _guard_reverse(fn) for fn in REVERSE}
    wrapped["getnameinfo"] = _guard_getnameinfo(_originals["getnameinfo"])
    for fn, guarded in wrapped.items():
        monkeypatch.setattr(socket, fn, guarded)
        # dnspython keeps the originals for override/restore_system_resolver();
        # rebinding them means even a restore puts the guarded versions back.
        monkeypatch.setattr(dns.resolver, f"_original_{fn}", guarded)
