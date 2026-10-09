"""DNS records for a candidate host (U10).

A, AAAA, CNAME, MX, NS and TXT are queried concurrently, each with the resolver's
timeouts. Every record type gets its own status, so one failing type never hides
the others. A and AAAA answers are also checked against netguard, so the facts
show when a candidate points at private or otherwise blocked address space
(`dns_mixed_private` when public and blocked answers mix).
"""

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from brandsentinel.net.netguard import NetGuard, dns_failure

COLLECTOR_VERSION = "dns/1"
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
MAX_RECORDS = 50
MAX_TXT_CHARS = 1024


def _value(rdtype: str, rr) -> str:
    if rdtype == "TXT":
        text = b"".join(rr.strings).decode("utf-8", errors="replace")
        return text[:MAX_TXT_CHARS]
    return rr.to_text()[:MAX_TXT_CHARS]


async def _query(resolver: dns.asyncresolver.Resolver, host: str, rdtype: str) -> dict:
    try:
        answer = await resolver.resolve(host, rdtype, search=False)
    except dns.resolver.NoAnswer:
        return {"status": "no_answer", "values": []}
    except (dns.exception.DNSException, OSError) as e:
        failure = dns_failure(e, host)
        return {"status": failure.reason.removeprefix("dns_"), "values": []}
    wanted = dns.rdatatype.from_text(rdtype)
    values = sorted(_value(rdtype, rr) for rr in answer if rr.rdtype == wanted)
    ttl = answer.rrset.ttl if answer.rrset is not None else None
    out = {"status": "ok", "values": values[:MAX_RECORDS], "ttl": ttl}
    if len(values) > MAX_RECORDS:
        out["truncated_from"] = len(values)
    return out


async def collect_dns(resolver: dns.asyncresolver.Resolver, guard: NetGuard, host: str) -> dict:
    results = await asyncio.gather(*(_query(resolver, host, t) for t in RECORD_TYPES))
    records = dict(zip(RECORD_TYPES, results, strict=True))
    statuses = {r["status"] for r in records.values()}
    if statuses <= {"ok", "no_answer"}:
        status = "ok"
    elif "nxdomain" in statuses and statuses <= {"nxdomain", "no_answer"}:
        status = "nxdomain"
    elif statuses & {"ok", "no_answer"}:
        status = "partial"
    else:
        status = "error"
    addresses = records["A"]["values"] + records["AAAA"]["values"]
    checked = [{"ip": a, "class": guard.check_address(a)} for a in addresses]
    blocked = [c for c in checked if c["class"]]
    return {
        "host": host,
        "status": status,
        "records": records,
        "address_policy": {
            "addresses": checked,
            "all_public": bool(addresses) and not blocked,
            "dns_mixed_private": bool(blocked) and len(blocked) < len(checked),
        },
    }
