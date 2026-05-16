# ============================================================
# PhishGuard — PhishTank API Service
# ============================================================
# Checks URLs against the PhishTank community phishing database.
#
# Get a free API key at: https://www.phishtank.com/api_register.php
# Set PHISHTANK_API_KEY in your .env file.
#
# Rate limit: 20 requests/minute for free accounts.
# ============================================================

import hashlib
import os
from typing import Any, Dict

import httpx
from loguru import logger
from cachetools import TTLCache

_PT_CACHE: TTLCache = TTLCache(maxsize=2000, ttl=1800)

PHISHTANK_API     = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")
TIMEOUT           = 8.0


async def check_url_phishtank(url: str) -> Dict[str, Any]:
    """
    Check if a URL is in the PhishTank verified phishing database.

    Returns:
        {
            "listed":       bool,
            "verified":     bool,
            "in_database":  bool,
            "phish_id":     str | None,
            "phish_detail_url": str | None,
            "verified_at":  str | None,
            "source":       str,
        }
    """
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in _PT_CACHE:
        result = dict(_PT_CACHE[cache_key])
        result["source"] = "cache"
        return result

    if not PHISHTANK_API_KEY:
        logger.debug("PHISHTANK_API_KEY not set — skipping PhishTank lookup")
        return _empty("no_api_key")

    payload = {
        "url":         url,
        "format":      "json",
        "app_key":     PHISHTANK_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(PHISHTANK_API, data=payload,
                                     headers={"User-Agent": "PhishGuard/1.0"})

        if resp.status_code != 200:
            logger.warning(f"PhishTank returned {resp.status_code}")
            return _empty(f"http_{resp.status_code}")

        data  = resp.json()
        inner = data.get("results", {})

        if not inner.get("in_database", False):
            result = _empty("not_found")
            _PT_CACHE[cache_key] = result
            return result

        result = {
            "listed":           inner.get("valid", False),
            "verified":         inner.get("verified", False),
            "in_database":      True,
            "phish_id":         str(inner.get("phish_id", "")),
            "phish_detail_url": inner.get("phish_detail_url"),
            "verified_at":      inner.get("verified_at"),
            "source":           "phishtank",
        }
        _PT_CACHE[cache_key] = result
        return result

    except httpx.TimeoutException:
        logger.debug(f"PhishTank timeout for {url}")
        return _empty("timeout")
    except Exception as exc:
        logger.error(f"PhishTank error for {url}: {exc}")
        return _empty("error")


def _empty(source: str = "not_listed") -> Dict[str, Any]:
    return {
        "listed":           False,
        "verified":         False,
        "in_database":      False,
        "phish_id":         None,
        "phish_detail_url": None,
        "verified_at":      None,
        "source":           source,
    }
