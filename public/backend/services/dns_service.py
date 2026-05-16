"""
PhishGuard — DNS Service
Resolves A, MX, NS, and TXT records for a given URL's domain.
"""
import asyncio
import dns.asyncresolver
import tldextract

async def _resolve(resolver, domain: str, rtype: str) -> list:
    try:
        answers = await resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except Exception:
        return []

async def get_dns_records(url: str) -> dict:
    ext    = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0

    a, mx, ns, txt = await asyncio.gather(
        _resolve(resolver, domain, "A"),
        _resolve(resolver, domain, "MX"),
        _resolve(resolver, domain, "NS"),
        _resolve(resolver, domain, "TXT"),
    )

    return {"A": a, "MX": mx, "NS": ns, "TXT": txt, "domain": domain}
