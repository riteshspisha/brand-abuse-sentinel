"""Passive enrichment (U10): DNS, RDAP, TLS and similarity facts per candidate.

Sources register by name (`register_source`), so another source such as passive
DNS can be added without touching the stage. All sources for a host run
concurrently and independently: one that raises becomes a `<source>_error`
observation with the error kind, and the others are unaffected. Observations are
facts; the stage writes them through the sanitizing fact writer.
"""

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import dns.asyncresolver

from brandsentinel.config import EnrichSettings
from brandsentinel.enrich import dns_records as dns_source
from brandsentinel.enrich import rdap as rdap_source
from brandsentinel.enrich import similarity as similarity_source
from brandsentinel.enrich import tls as tls_source
from brandsentinel.net.netguard import NetGuardError
from brandsentinel.registry.model import Registry


@dataclass
class Observation:
    source: str
    name: str
    value: dict
    collector_version: str


class Cache:
    """Per-source result cache (for example RDAP per registrable domain)."""

    def get(self, source: str, key: str, max_age: float) -> tuple[dict, float] | None:
        return None

    def put(self, source: str, key: str, value: dict) -> None:
        pass


@dataclass
class EnrichContext:
    host: str
    registrable_domain: str
    guard: object  # NetGuard
    resolver: dns.asyncresolver.Resolver
    rdap: rdap_source.RdapClient
    registry: Registry
    settings: EnrichSettings
    cache: Cache = field(default_factory=Cache)
    verify_context: ssl.SSLContext | None = None
    clock: Callable[[], float] | None = None
    tls_port: int = 443


Source = Callable[[EnrichContext], Awaitable[list[Observation]]]
SOURCES: dict[str, Source] = {}


def register_source(name: str) -> Callable[[Source], Source]:
    def deco(fn: Source) -> Source:
        if name in SOURCES:
            raise ValueError(f"enrichment source {name!r} already registered")
        SOURCES[name] = fn
        return fn

    return deco


def _error(source: str, e: BaseException) -> Observation:
    kind = getattr(e, "kind", None) or getattr(e, "reason", None) or type(e).__name__
    detail = getattr(e, "detail", None)
    value = {"kind": str(kind), "message": str(e)[:500]}
    if isinstance(detail, dict):
        value["detail"] = detail
    return Observation(source, f"{source}_error", value, "enrich/1")


async def run_sources(ctx: EnrichContext, names: list[str] | None = None) -> list[Observation]:
    selected = [(n, SOURCES[n]) for n in (names or list(SOURCES))]

    async def one(name: str, fn: Source) -> list[Observation]:
        try:
            return await fn(ctx)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return [_error(name, e)]

    results = await asyncio.gather(*(one(n, fn) for n, fn in selected))
    return [o for batch in results for o in batch]


# --- built-in sources ---------------------------------------------------------


@register_source("dns")
async def _dns(ctx: EnrichContext) -> list[Observation]:
    value = await dns_source.collect_dns(ctx.resolver, ctx.guard, ctx.host)
    return [Observation("dns", "dns_records", value, dns_source.COLLECTOR_VERSION)]


@register_source("rdap")
async def _rdap(ctx: EnrichContext) -> list[Observation]:
    domain = ctx.registrable_domain
    if not domain:
        raise rdap_source.RdapError("no_registrable_domain", {"host": ctx.host})
    max_age = ctx.settings.rdap_cache_hours * 3600
    cached = ctx.cache.get("rdap", domain, max_age) if max_age > 0 else None
    if cached is not None:
        value, observed_at = cached
        value = {**value, "cached": True, "cached_observed_at": observed_at}
    else:
        value = await ctx.rdap.lookup(domain)
        ctx.cache.put("rdap", domain, value)
        value = {**value, "cached": False}
    value["domain"] = domain
    return [Observation("rdap", "rdap_registration", value, rdap_source.COLLECTOR_VERSION)]


def official_sans(sans: list[str], registry: Registry) -> list[dict]:
    found = []
    for san in sans:
        name = san.lower().removeprefix("*.").rstrip(".")
        for d in registry.domains:
            if d.kind == "official" and (name == d.name or name.endswith("." + d.name)):
                found.append({"san": san, "domain": d.name, "status": d.status})
    return found


@register_source("tls")
async def _tls(ctx: EnrichContext) -> list[Observation]:
    try:
        value = await tls_source.collect_tls(
            ctx.guard,
            ctx.host,
            port=ctx.tls_port,
            timeout=ctx.settings.tls_timeout_seconds,
            verify_context=ctx.verify_context,
        )
    except NetGuardError as e:
        raise tls_source.TlsCollectError(e.reason, str(e.detail)[:300]) from e
    out = [Observation("tls", "tls_certificate", value, tls_source.COLLECTOR_VERSION)]
    official = official_sans(value["certificate"]["san_dns"], ctx.registry)
    if official:
        out.append(
            Observation(
                "tls",
                "tls_official_san",
                {"certificate_sha256": value["certificate"]["sha256"], "matches": official},
                tls_source.COLLECTOR_VERSION,
            )
        )
    return out


@register_source("similarity")
async def _similarity(ctx: EnrichContext) -> list[Observation]:
    value = similarity_source.similarity(ctx.host, ctx.registry)
    return [Observation("similarity", "similarity", value, similarity_source.COLLECTOR_VERSION)]
