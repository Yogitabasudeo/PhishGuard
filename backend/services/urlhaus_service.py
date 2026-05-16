# ============================================================
# PhishGuard — URLHaus API Service
# ============================================================
# Queries the Abuse.ch URLHaus database for URL/domain listings.
# URLHaus API is free and does not require an API key.
#
# API docs: https://urlhaus-api.abuse.ch/
# ============================================================

import asyncio
import hashlib
from typing import Any, Dict
from urllib.parse import urlparse

import httpx
from loguru import logger
from cachetools import TTLCache

_URLHAUS_CACHE: TTLCache = TTLCache(maxsize=2000, ttl=1800)   # 30 min TTL

URLHAUS_API    = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_DOMAIN = "https://urlhaus-api.abuse.ch/v1/host/"
TIMEOUT        = 8.0


async def check_url_urlhaus(url: str) -> Dict[str, Any]:
    """
    Check if a URL is listed in the URLHaus malware / botnet feed.

    Returns:
        {
            "listed":       bool,
            "status":       str | None,   # "online" | "offline" | None
            "threat":       str | None,   # "malware_download" | "botnet_cc" | None
            "tags":         list[str],
            "reporter":     str | None,
            "date_added":   str | None,
            "source":       str,
        }
    """
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in _URLHAUS_CACHE:
        result = dict(_URLHAUS_CACHE[cache_key])
        result["source"] = "cache"
        return result

    # ── Try exact URL lookup first ─────────────────────────────
    result = await _query_url(url)
    if result["listed"]:
        _URLHAUS_CACHE[cache_key] = result
        return result

    # ── Fall back to host/domain lookup ───────────────────────
    try:
        domain = urlparse(url).netloc.replace("www.", "").split(":")[0]
        result = await _query_host(domain)
    except Exception:
        pass

    _URLHAUS_CACHE[cache_key] = result
    return result


async def _query_url(url: str) -> Dict[str, Any]:
    payload = {"url": url}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(URLHAUS_API, data=payload)
        if resp.status_code != 200:
            return _empty()

        data = resp.json()
        if data.get("query_status") == "is_listed":
            return {
                "listed":     True,
                "status":     data.get("url_status"),
                "threat":     data.get("threat"),
                "tags":       data.get("tags") or [],
                "reporter":   data.get("reporter"),
                "date_added": data.get("date_added"),
                "source":     "urlhaus",
            }
        return _empty()
    except httpx.TimeoutException:
        logger.debug(f"URLHaus URL timeout for {url}")
        return _empty("timeout")
    except Exception as exc:
        logger.debug(f"URLHaus URL error: {exc}")
        return _empty("error")


async def _query_host(domain: str) -> Dict[str, Any]:
    payload = {"host": domain}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(URLHAUS_DOMAIN, data=payload)
        if resp.status_code != 200:
            return _empty()

        data = resp.json()
        if data.get("query_status") == "is_listed":
            urls = data.get("urls", [])
            tags = list({tag for u in urls for tag in (u.get("tags") or [])})
            return {
                "listed":     True,
                "status":     None,
                "threat":     urls[0].get("threat") if urls else None,
                "tags":       tags,
                "reporter":   None,
                "date_added": urls[0].get("date_added") if urls else None,
                "source":     "urlhaus_host",
            }
        return _empty()
    except Exception as exc:
        logger.debug(f"URLHaus host error: {exc}")
        return _empty("error")


def _empty(source: str = "not_listed") -> Dict[str, Any]:
    return {
        "listed":     False,
        "status":     None,
        "threat":     None,
        "tags":       [],
        "reporter":   None,
        "date_added": None,
        "source":     source,
    }
