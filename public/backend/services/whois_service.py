"""
PhishGuard — WHOIS Service
Retrieves domain registration data and calculates domain age.
"""
import asyncio
from datetime import datetime, timezone
import whois

async def get_whois_info(url: str) -> dict:
    try:
        from urllib.parse import urlparse
        import tldextract
        ext    = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(None, whois.whois, domain)

        created = info.creation_date
        if isinstance(created, list):
            created = created[0]

        age_days = -1
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days

        return {
            "registrar":     info.registrar or "Unknown",
            "creation_date": str(created) if created else "Unknown",
            "age_days":      age_days,
            "country":       info.country or "Unknown",
            "name_servers":  info.name_servers or [],
        }
    except Exception as exc:
        return {"registrar": "Unknown", "creation_date": "Unknown", "age_days": -1, "error": str(exc)}
