"""netguard: the network policy for every connection to an untrusted host.

`NetGuard.validate(url)` parses a URL, resolves its host once, and checks every
answer. The result is a `Validated` target whose `addresses` are the only places
a caller may connect to; callers must connect to one of them (pinning) and send
the original hostname for SNI and Host, so a second DNS answer can never be used.

Refused:
- schemes other than http and https, userinfo, ports outside the allowlist,
  backslashes, control characters, zone ids and malformed hosts
- any answer outside globally routable unicast space, including IPv4-mapped,
  IPv4-compatible, NAT64 and 6to4 forms that wrap a blocked IPv4 address
- an answer set that mixes public and blocked addresses (`dns_mixed_private`)

IP literals are parsed the way browsers do (`2130706433`, `0x7f.1`, `127.1`), so
a numeric trick cannot slip past as a "hostname". Lab mode (KTD13) adds exactly
the pinned lab subnet, and only for hostnames in the lab map. Test address ranges
are accepted only as a constructor argument, never from configuration.
"""

import asyncio
import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver

from brandsentinel.config import LAB_SUBNET, DnsSettings, NetSettings
from brandsentinel.matching.normalize import InvalidName, canonical_host

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_URL_CHARS = 8192
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Characters left unescaped when re-quoting a path or query: RFC 3986 reserved
# and unreserved characters, plus existing percent escapes.
_SAFE_PATH = "/%:@!$&'()*+,;=-._~"
_SAFE_QUERY = _SAFE_PATH + "?"

_V4 = ipaddress.IPv4Network
_V6 = ipaddress.IPv6Network
# Ordered: the first matching range names the class.
_BLOCKED_V4: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (_V4("0.0.0.0/8"), "unspecified"),
    (_V4("10.0.0.0/8"), "private"),
    (_V4("100.64.0.0/10"), "cgnat"),
    (_V4("127.0.0.0/8"), "loopback"),
    (_V4("169.254.0.0/16"), "link_local"),  # includes 169.254.169.254 (metadata)
    (_V4("172.16.0.0/12"), "private"),
    (_V4("192.0.0.0/24"), "reserved"),
    (_V4("192.0.2.0/24"), "documentation"),
    (_V4("192.88.99.0/24"), "reserved"),  # deprecated 6to4 relay anycast
    (_V4("192.168.0.0/16"), "private"),
    (_V4("198.18.0.0/15"), "benchmarking"),
    (_V4("198.51.100.0/24"), "documentation"),
    (_V4("203.0.113.0/24"), "documentation"),
    (_V4("224.0.0.0/4"), "multicast"),
    (_V4("255.255.255.255/32"), "broadcast"),
    (_V4("240.0.0.0/4"), "reserved"),
)
_BLOCKED_V6: tuple[tuple[ipaddress.IPv6Network, str], ...] = (
    (_V6("::/128"), "unspecified"),
    (_V6("::1/128"), "loopback"),
    (_V6("64:ff9b:1::/48"), "nat64_local"),
    (_V6("100::/64"), "reserved"),  # discard-only
    (_V6("2001::/32"), "teredo"),
    (_V6("2001:db8::/32"), "documentation"),
    (_V6("fc00::/7"), "unique_local"),
    (_V6("fe80::/10"), "link_local"),
    (_V6("fec0::/10"), "site_local"),
    (_V6("ff00::/8"), "multicast"),
)
_NAT64 = _V6("64:ff9b::/96")
_V4_COMPATIBLE = _V6("::/96")
_V4_TRANSLATED = _V6("::ffff:0:0:0/96")  # SIIT (RFC 6052/7915); reaches IPv4 via a translator
_SIX_TO_FOUR = _V6("2002::/16")


class NetGuardError(Exception):
    def __init__(self, reason: str, detail: dict | None = None) -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail or {}


class PolicyViolation(NetGuardError):
    """The URL or one of its addresses is not allowed. Never retried."""


class ResolutionFailed(NetGuardError):
    """The name could not be resolved (nxdomain, timeout, no address, ...)."""

    @property
    def transient(self) -> bool:
        return self.reason in ("dns_timeout", "dns_servfail", "dns_error")


def classify_ip(ip: IPAddress) -> str | None:
    """Return the blocked class of an address, or None if it is public."""
    if isinstance(ip, ipaddress.IPv4Address):
        for net, name in _BLOCKED_V4:
            if ip in net:
                return name
        return None if ip.is_global else "non_global"
    if ip.ipv4_mapped is not None:
        return _wrapped("ipv4_mapped", ip.ipv4_mapped, block_public=False)
    if ip in _NAT64:
        return _wrapped("nat64", ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF), block_public=False)
    if ip in _V4_TRANSLATED:  # never legitimate for a public site
        return _wrapped("ipv4_translated", ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    for net, name in _BLOCKED_V6:
        if ip in net:
            return name
    if ip in _V4_COMPATIBLE:  # deprecated ::a.b.c.d; never legitimate on the Internet
        return _wrapped("ipv4_compatible", ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip.sixtofour is not None:
        return _wrapped("6to4", ip.sixtofour)
    return None if ip.is_global else "non_global"


def _wrapped(kind: str, inner: ipaddress.IPv4Address, *, block_public: bool = True) -> str | None:
    inner_class = classify_ip(inner)
    if inner_class:
        return f"{kind}:{inner_class}"
    return kind if block_public else None


@dataclass(frozen=True)
class Target:
    """A syntactically allowed URL, not yet resolved."""

    scheme: str
    host: str  # lowercase ASCII hostname, or an IP address in canonical text form
    port: int
    target: str  # request target: path and query, ASCII, never empty
    ip_literal: bool

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if _DEFAULT_PORTS[self.scheme] == self.port else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.target}"


@dataclass(frozen=True)
class Validated(Target):
    """A target whose every resolved address passed policy. Connect only to these."""

    addresses: tuple[str, ...] = ()
    lab: bool = False


def _num(part: str) -> int | None:
    if re.fullmatch(r"0[xX][0-9a-fA-F]*", part):
        return int(part[2:] or "0", 16)
    if re.fullmatch(r"0[0-7]+", part):
        return int(part, 8)
    if re.fullmatch(r"[0-9]+", part):
        return int(part)
    return None


def _ipv4_like(host: str) -> ipaddress.IPv4Address | None:
    """Parse a host the way browsers do when its last label is numeric.

    Returns None for an ordinary hostname; raises for a numeric host that is not
    a valid IPv4 address (so it can never be treated as a name)."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts.pop()
    if not parts or _num(parts[-1]) is None:
        return None
    values = [_num(p) for p in parts]
    if len(values) > 4 or any(v is None for v in values):
        raise PolicyViolation("invalid_url", {"why": "malformed numeric host"})
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(values)):
        raise PolicyViolation("invalid_url", {"why": "numeric host out of range"})
    value = last
    for i, v in enumerate(head):
        value += v << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


def parse_url(url: str, *, allowed_ports: Iterable[int]) -> Target:
    """Check a URL's syntax, scheme, userinfo and port. Raises PolicyViolation."""
    if not isinstance(url, str) or len(url) > MAX_URL_CHARS:
        raise PolicyViolation("invalid_url", {"why": "not a string of plausible length"})
    url = url.strip(" \t\r\n")
    # Browsers treat backslash as slash in http(s) URLs while urllib does not; any
    # disagreement about where the host is could be exploited, so refuse it.
    if "\\" in url or any((ord(c) < 0x21 and c != " ") or ord(c) == 0x7F for c in url):
        raise PolicyViolation("invalid_url", {"why": "control character or backslash"})
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise PolicyViolation("invalid_url", {"why": str(e)}) from e
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise PolicyViolation("scheme_not_allowed", {"scheme": scheme[:20]})
    if "@" in parts.netloc:
        raise PolicyViolation("userinfo_not_allowed")
    raw_host = parts.hostname or ""
    if not raw_host or "%" in raw_host or " " in parts.netloc:
        raise PolicyViolation("invalid_url", {"why": "missing or invalid host"})
    try:
        port = _DEFAULT_PORTS[scheme] if parts.port is None else parts.port
    except ValueError as e:
        raise PolicyViolation("invalid_url", {"why": "invalid port"}) from e
    if port not in set(allowed_ports):
        raise PolicyViolation("port_not_allowed", {"port": port})

    ip: IPAddress | None
    if parts.netloc.startswith("["):
        try:
            ip = ipaddress.IPv6Address(raw_host)
        except ValueError as e:
            raise PolicyViolation("invalid_url", {"why": "invalid IPv6 literal"}) from e
    else:
        ip = _ipv4_like(raw_host)
    if ip is not None:
        host = str(ip)
    else:
        try:
            host, wildcard = canonical_host(raw_host)
        except InvalidName as e:
            raise PolicyViolation("invalid_url", {"why": f"invalid host: {e}"}) from e
        if wildcard:
            raise PolicyViolation("invalid_url", {"why": "wildcard host"})

    path = quote(parts.path or "/", safe=_SAFE_PATH, encoding="utf-8", errors="strict")
    if not path.startswith("/"):
        path = "/" + path
    target = path
    if parts.query:
        target += "?" + quote(parts.query, safe=_SAFE_QUERY, encoding="utf-8")
    return Target(scheme, host, port, target, ip is not None)


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[str]:
        """All A and AAAA answers for `host`. Raises ResolutionFailed."""
        ...


def make_dns_resolver(
    settings: DnsSettings, *, port: int | None = None
) -> dns.asyncresolver.Resolver:
    """A dnspython resolver with BrandSentinel's timeouts. Never reads /etc/hosts."""
    r = dns.asyncresolver.Resolver(configure=not settings.nameservers)
    if settings.nameservers:
        r.nameservers = list(settings.nameservers)
    if port is not None:
        r.port = port
    r.timeout = settings.timeout_seconds
    r.lifetime = settings.lifetime_seconds
    r.cache = None
    return r


def dns_failure(e: Exception, name: str) -> ResolutionFailed:
    if isinstance(e, dns.resolver.NXDOMAIN):
        return ResolutionFailed("dns_nxdomain", {"name": name})
    if isinstance(e, dns.resolver.NoAnswer):
        return ResolutionFailed("dns_no_answer", {"name": name})
    if isinstance(e, dns.resolver.LifetimeTimeout | dns.exception.Timeout):
        return ResolutionFailed("dns_timeout", {"name": name})
    if isinstance(e, dns.resolver.NoNameservers):
        return ResolutionFailed("dns_servfail", {"name": name})
    return ResolutionFailed("dns_error", {"name": name, "error": f"{type(e).__name__}"})


class DnsResolver:
    """Resolves A and AAAA concurrently. NXDOMAIN or a missing record type for one
    family is not an error as long as some address comes back."""

    def __init__(self, resolver: dns.asyncresolver.Resolver) -> None:
        self._r = resolver

    async def _one(self, host: str, rdtype: str) -> list[str]:
        try:
            answer = await self._r.resolve(host, rdtype, search=False)
        except dns.resolver.NoAnswer:
            return []
        return [rr.to_text() for rr in answer if rr.rdtype == dns.rdatatype.from_text(rdtype)]

    async def resolve(self, host: str) -> list[str]:
        results = await asyncio.gather(
            self._one(host, "A"), self._one(host, "AAAA"), return_exceptions=True
        )
        addresses: list[str] = []
        errors = []
        for r in results:
            if isinstance(r, BaseException):
                if not isinstance(r, Exception):
                    raise r
                errors.append(r)
            else:
                addresses += r
        if addresses:
            return addresses
        if errors:
            # NXDOMAIN wins over a timeout on the other family; it is authoritative.
            errors.sort(key=lambda e: not isinstance(e, dns.resolver.NXDOMAIN))
            raise dns_failure(errors[0], host)
        return []


class StaticResolver:
    """A fixed answer map, for tests and for lab hostnames."""

    def __init__(self, answers: dict[str, list[str] | Exception]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        answer = self.answers.get(host)
        if answer is None:
            raise ResolutionFailed("dns_nxdomain", {"name": host})
        if isinstance(answer, Exception):
            raise answer
        return list(answer)


class NetGuard:
    def __init__(
        self,
        settings: NetSettings,
        resolver: Resolver,
        *,
        test_networks: Sequence[IPNetwork] = (),
        allowed_ports: Iterable[int] | None = None,
    ) -> None:
        """`test_networks` lets test code treat a private range (for example a
        loopback /16 used by the local harness) as public. It is deliberately a
        constructor argument only: configuration and environment cannot set it."""
        self.settings = settings
        self.resolver = resolver
        self.allowed_ports = tuple(allowed_ports or settings.allowed_ports)
        self._test_networks = tuple(test_networks)
        lab = settings.lab
        self._lab_hosts = dict(lab.hosts) if lab.enabled else {}
        self._lab_net = ipaddress.ip_network(LAB_SUBNET)

    @property
    def lab_mode(self) -> bool:
        return self.settings.lab.enabled

    def is_lab_host(self, host: str) -> bool:
        """True for a hostname in the lab map (always False outside lab mode)."""
        return host in self._lab_hosts

    def check_address(self, address: str, *, lab_host: bool = False) -> str | None:
        """The blocked class of `address` for this guard, or None if allowed."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "invalid_address"
        if any(ip in net for net in self._test_networks):
            return None
        if lab_host and ip in self._lab_net:
            return None
        return classify_ip(ip)

    def parse(self, url: str) -> Target:
        return parse_url(url, allowed_ports=self.allowed_ports)

    async def validate(self, url: str) -> Validated:
        t = self.parse(url)
        lab_host = t.host in self._lab_hosts
        if t.ip_literal:
            addresses = [t.host]
        elif lab_host:
            addresses = [self._lab_hosts[t.host]]
        else:
            addresses = await self.resolver.resolve(t.host)
        return self.check_addresses(t, addresses, lab_host=lab_host)

    def check_addresses(
        self, t: Target, addresses: list[str], *, lab_host: bool = False
    ) -> Validated:
        if not addresses:
            raise ResolutionFailed("dns_no_address", {"name": t.host})
        unique = list(dict.fromkeys(addresses))
        verdicts = [(a, self.check_address(a, lab_host=lab_host)) for a in unique]
        blocked = [{"ip": a, "class": c} for a, c in verdicts if c]
        if blocked:
            if len(blocked) < len(verdicts):
                raise PolicyViolation("dns_mixed_private", {"host": t.host, "blocked": blocked})
            raise PolicyViolation(
                "blocked_address", {"host": t.host, **blocked[0], "blocked": blocked}
            )
        v4 = [a for a in unique if ":" not in a]
        v6 = [a for a in unique if ":" in a]
        ordered = v6 + v4 if self.settings.prefer_ipv6 else v4 + v6
        return Validated(
            t.scheme, t.host, t.port, t.target, t.ip_literal, tuple(ordered), lab=lab_host
        )
