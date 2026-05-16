# ============================================================
# PhishGuard — WHOIS Service
# ============================================================
# Retrieves domain registration metadata using python-whois.
# Results are cached for 24 hours to avoid rate limits.
# ============================================================

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import whois
from cachetools import TTLCache
from loguru import logger
import tldextract

_WHOIS_CACHE: TTLCache = TTLCache(maxsize=2000, ttl=86400)  # 24-hour TTL


def get_domain_age_days(url: str) -> int:
    """
    Return how many days old a domain is.
    Returns -1 if WHOIS lookup fails or date is unavailable.
    """
    domain = _extract_registered_domain(url)
    if not domain:
        return -1

    if domain in _WHOIS_CACHE:
        return _WHOIS_CACHE[domain].get("age_days", -1)

    info = get_whois_info(url)
    return info.get("age_days", -1)


def get_whois_info(url: str) -> Dict[str, Any]:
    """
    Full WHOIS lookup for a URL.

    Returns:
        {
            "domain":        str,
            "registrar":     str | None,
            "registrant":    str | None,
            "country":       str | None,
            "email":         str | None,
            "creation_date": str | None,
            "expiry_date":   str | None,
            "updated_date":  str | None,
            "age_days":      int,          # -1 = unknown
            "name_servers":  list[str],
            "status":        list[str],
            "source":        str,
        }
    """
    domain = _extract_registered_domain(url)
    if not domain:
        return _empty()

    if domain in _WHOIS_CACHE:
        result = dict(_WHOIS_CACHE[domain])
        result["source"] = "cache"
        return result

    try:
        w = whois.whois(domain)

        creation = _first_date(w.creation_date)
        expiry   = _first_date(w.expiration_date)
        updated  = _first_date(w.updated_date)

        age_days = -1
        if creation:
            try:
                now = datetime.now(timezone.utc)
                # Make creation timezone-aware if it isn't
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = max(0, (now - creation).days)
            except Exception:
                pass

        def _str(val: Any) -> Optional[str]:
            if isinstance(val, list):
                val = val[0] if val else None
            return str(val).strip() if val else None

        emails = w.emails
        if isinstance(emails, list):
            emails = emails[0] if emails else None

        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        ns = [str(s).lower() for s in ns][:6]

        status = w.status or []
        if isinstance(status, str):
            status = [status]

        result = {
            "domain":        domain,
            "registrar":     _str(w.registrar),
            "registrant":    _str(w.org) or _str(w.name),
            "country":       _str(w.country),
            "email":         _str(emails),
            "creation_date": creation.isoformat() if creation else None,
            "expiry_date":   expiry.isoformat()   if expiry   else None,
            "updated_date":  updated.isoformat()  if updated  else None,
            "age_days":      age_days,
            "name_servers":  ns,
            "status":        [str(s) for s in status[:4]],
            "source":        "whois",
        }
        _WHOIS_CACHE[domain] = result
        return result

    except Exception as exc:
        logger.debug(f"WHOIS failed for {domain}: {exc}")
        result = _empty()
        result["domain"] = domain
        _WHOIS_CACHE[domain] = result
        return result


def format_age(age_days: int) -> str:
    """Convert age_days → human-readable string."""
    if age_days < 0:    return "Unknown"
    if age_days == 0:   return "0 days (just registered)"
    if age_days < 7:    return f"{age_days} days"
    if age_days < 30:   return f"{age_days // 7} week(s)"
    if age_days < 365:  return f"{age_days // 30} month(s)"
    years = age_days // 365
    months = (age_days % 365) // 30
    return f"{years} year(s)" + (f", {months} month(s)" if months else "")


# ── Helpers ───────────────────────────────────────────────────

def _extract_registered_domain(url: str) -> Optional[str]:
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return None


def _first_date(val: Any) -> Optional[datetime]:
    """Extract the first datetime from a value that may be a list."""
    if isinstance(val, list):
        val = next((v for v in val if v is not None), None)
    if isinstance(val, datetime):
        return val
    return None


def _empty() -> Dict[str, Any]:
    return {
        "domain": "",
        "registrar": None, "registrant": None, "country": None,
        "email": None, "creation_date": None, "expiry_date": None,
        "updated_date": None, "age_days": -1,
        "name_servers": [], "status": [], "source": "error",
    }
