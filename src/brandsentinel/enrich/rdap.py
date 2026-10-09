"""RDAP registration data for a registrable domain (U10).

The registry's RDAP base URL comes from the IANA DNS bootstrap file, cached
under `data/cache/` and refreshed when older than the configured age (a stale
copy is used if a refresh fails). Queries go through the hardened fetcher in
verified-TLS mode, accepting only RDAP/JSON media types under a small body cap,
so a redirect to a private address is refused like any other fetch.

The parsed result records registration, expiry and last-changed dates,
registrar, status values, abuse contact, nameservers and whether data is
redacted. Domain age and privacy redaction are context for the policy layer;
neither is a maliciousness indicator on its own.
"""

import asyncio
import json
import os
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from brandsentinel.config import EnrichSettings
from brandsentinel.net.fetcher import Fetcher
from brandsentinel.store.fsutil import ensure_private_dir

COLLECTOR_VERSION = "rdap/1"
RDAP_TYPES = ("application/rdap+json", "application/json")
BOOTSTRAP_FILE = "rdap-dns.json"
MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_LIST = 50
# After a failed bootstrap refresh, wait this long before trying again.
BOOTSTRAP_RETRY_SECONDS = 600.0


class RdapError(Exception):
    def __init__(self, kind: str, detail: dict | None = None) -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail or {}


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _vcard(entity: dict, field: str) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value)[:300] if value else None
    return None


def _entities(doc: dict):
    """Entities with their roles, including those nested one level down."""
    for e in doc.get("entities") or []:
        if not isinstance(e, dict):
            continue
        yield e
        for inner in e.get("entities") or []:
            if isinstance(inner, dict):
                yield inner


def parse_rdap(doc: dict, now: float) -> dict:
    if not isinstance(doc, dict):
        raise RdapError("malformed", {"why": "not an object"})
    events: dict[str, datetime] = {}
    for ev in doc.get("events") or []:
        if isinstance(ev, dict) and isinstance(ev.get("eventAction"), str):
            t = _parse_time(ev.get("eventDate"))
            if t is not None:
                events.setdefault(ev["eventAction"].lower(), t)
    registered = events.get("registration")
    registrar = abuse = None
    redacted = bool(doc.get("redacted"))
    for e in _entities(doc):
        roles = [r for r in e.get("roles") or [] if isinstance(r, str)]
        if "registrar" in roles and registrar is None:
            iana = next(
                (
                    p.get("identifier")
                    for p in e.get("publicIds") or []
                    if isinstance(p, dict) and p.get("type") == "IANA Registrar ID"
                ),
                None,
            )
            registrar = {"name": _vcard(e, "fn"), "iana_id": iana}
        if "abuse" in roles and abuse is None:
            abuse = {"email": _vcard(e, "email"), "phone": _vcard(e, "tel")}
        if "registrant" in roles:
            name = (_vcard(e, "fn") or "").lower()
            if any(w in name for w in ("redacted", "privacy", "withheld", "proxy")):
                redacted = True
    age_days = None
    if registered is not None:
        age_days = int((now - registered.timestamp()) // 86400)
    return {
        "ldh_name": str(doc.get("ldhName") or "")[:300] or None,
        "handle": str(doc.get("handle") or "")[:300] or None,
        "registered_at": registered.isoformat() if registered else None,
        "expires_at": events["expiration"].isoformat() if "expiration" in events else None,
        "last_changed_at": events["last changed"].isoformat() if "last changed" in events else None,
        "domain_age_days": age_days,
        "registrar": registrar,
        "status": [s for s in doc.get("status") or [] if isinstance(s, str)][:MAX_LIST],
        "abuse_contact": abuse,
        "nameservers": sorted(
            str(ns.get("ldhName")).lower()[:300]
            for ns in (doc.get("nameservers") or [])[:MAX_LIST]
            if isinstance(ns, dict) and ns.get("ldhName")
        ),
        "redacted": redacted,
    }


def base_url_for(bootstrap: dict, domain: str) -> str | None:
    """The longest matching suffix's first HTTPS service URL."""
    table: dict[str, list[str]] = {}
    for service in bootstrap.get("services") or []:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        suffixes, urls = service
        if not (isinstance(suffixes, list) and isinstance(urls, list)):
            continue
        for s in suffixes:
            if isinstance(s, str):
                table[s.lower().rstrip(".")] = [u for u in urls if isinstance(u, str)]
    labels = domain.lower().split(".")
    for i in range(1, len(labels)):
        urls = table.get(".".join(labels[i:]))
        https = [u for u in (urls or []) if u.startswith("https://")]
        if https:  # plain-http services are skipped: no integrity for cached facts
            chosen = https[0]
            return chosen if chosen.endswith("/") else chosen + "/"
    return None


class RdapClient:
    def __init__(
        self,
        fetcher: Fetcher,
        settings: EnrichSettings,
        cache_dir: Path,
        *,
        bootstrap: dict | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """`bootstrap` pins the bootstrap table (tests); otherwise it is fetched
        and cached under `cache_dir`."""
        self._fetcher = fetcher
        self._settings = settings
        self._cache = cache_dir / BOOTSTRAP_FILE
        self._bootstrap = bootstrap
        self._loaded_at = 0.0 if bootstrap is None else float("inf")
        self._clock = clock
        self._lock = asyncio.Lock()  # one bootstrap refresh at a time
        self._failed_at: float | None = None

    async def _get_json(self, url: str, max_bytes: int) -> dict:
        r = await self._fetcher.fetch(url, mode="verified", accept=RDAP_TYPES, max_bytes=max_bytes)
        if r.outcome != "ok":
            raise RdapError(r.outcome, {"error": r.error, "url": url[:300]})
        if r.status == 404:
            raise RdapError("not_found", {"url": url[:300]})
        if r.status != 200:
            raise RdapError("http_status", {"status": r.status, "url": url[:300]})
        if r.body is None:
            raise RdapError("unexpected_content_type", {"url": url[:300]})
        if r.body.truncated:
            raise RdapError("too_large", {"limit": max_bytes})
        try:
            doc = json.loads(r.body.data)
        except (ValueError, RecursionError) as e:
            raise RdapError("malformed", {"why": type(e).__name__}) from e
        if not isinstance(doc, dict):
            raise RdapError("malformed", {"why": "not an object"})
        return doc

    def _read_cache(self) -> tuple[dict | None, float]:
        try:
            st = self._cache.stat()
            if st.st_size > MAX_BOOTSTRAP_BYTES:
                return None, 0.0
            return json.loads(self._cache.read_text(encoding="utf-8")), st.st_mtime
        except (OSError, ValueError):
            return None, 0.0

    def _write_cache(self, doc: dict) -> None:
        ensure_private_dir(self._cache.parent)
        fd, tmp = tempfile.mkstemp(dir=self._cache.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, self._cache)

    async def bootstrap(self) -> dict:
        async with self._lock:
            return await self._bootstrap_locked()

    async def _bootstrap_locked(self) -> dict:
        max_age = self._settings.rdap_bootstrap_max_age_days * 86400
        now = self._clock()
        if self._bootstrap is not None and now - self._loaded_at < max_age:
            return self._bootstrap
        cached, mtime = self._read_cache()
        if cached is not None and now - mtime < max_age:
            self._bootstrap, self._loaded_at = cached, mtime
            return cached
        if self._failed_at is not None and now - self._failed_at < BOOTSTRAP_RETRY_SECONDS:
            if self._bootstrap is not None:
                return self._bootstrap
            raise RdapError("bootstrap_backoff", {"retry_after": BOOTSTRAP_RETRY_SECONDS})
        try:
            doc = await self._get_json(self._settings.rdap_bootstrap_url, MAX_BOOTSTRAP_BYTES)
            if not isinstance(doc.get("services"), list):
                raise RdapError("malformed", {"why": "bootstrap has no services"})
            self._write_cache(doc)
            self._bootstrap, self._loaded_at, self._failed_at = doc, now, None
            return doc
        except (RdapError, OSError):
            self._failed_at = now
            if cached is not None:  # stale beats nothing; retried after the backoff
                self._bootstrap = cached
                self._loaded_at = now - max_age
                return cached
            raise

    async def lookup(self, domain: str) -> dict:
        try:
            boot = await self.bootstrap()
        except (RdapError, OSError) as e:
            raise RdapError("bootstrap_unavailable", {"error": str(e)[:300]}) from e
        base = base_url_for(boot, domain)
        if base is None:
            raise RdapError("no_rdap_service", {"domain": domain})
        url = f"{base}domain/{domain}"
        doc = await self._get_json(url, self._settings.rdap_max_bytes)
        parsed = parse_rdap(doc, self._clock())
        parsed["source_url"] = url
        return parsed
