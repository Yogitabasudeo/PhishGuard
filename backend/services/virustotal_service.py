# ============================================================
# PhishGuard — VirusTotal API Service
# ============================================================
# Queries the VirusTotal v3 API for URL reputation data.
#
# Set VT_API_KEY in your .env file:
#   VT_API_KEY=your_virustotal_api_key_here
#
# Free tier: 4 requests/minute, 500/day.
# ============================================================

import asyncio
import hashlib
import os
import base64
from typing import Any, Dict, Optional

import httpx
from loguru import logger
from cachetools import TTLCache

# Cache VT results for 1 hour to avoid rate limits
_VT_CACHE: TTLCache = TTLCache(maxsize=1000, ttl=3600)

VT_API_KEY  = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT  = 10.0   # seconds


async def check_url_virustotal(url: str) -> Dict[str, Any]:
    """
    Query VirusTotal for the given URL.

    Returns:
        {
            "positives": int,      # number of engines flagging the URL
            "total":     int,      # total engines scanned (≈ 90)
            "harmless":  int,
            "malicious": int,
            "suspicious": int,
            "undetected": int,
            "scan_date": str,
            "permalink": str,
            "detected_by": list[str],   # engine names that flagged it
            "source": "virustotal" | "cache" | "unavailable"
        }
    """
    # ── Check cache ───────────────────────────────────────────
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in _VT_CACHE:
        result = dict(_VT_CACHE[cache_key])
        result["source"] = "cache"
        return result

    # ── No API key → return safe mock ─────────────────────────
    if not VT_API_KEY:
        logger.debug("VT_API_KEY not set — returning empty VT result")
        return _empty_vt_result("no_api_key")

    # ── URL lookup using ID (base64url of URL) ─────────────────
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {
        "x-apikey":   VT_API_KEY,
        "accept":     "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=VT_TIMEOUT) as client:
            resp = await client.get(
                f"{VT_BASE_URL}/urls/{url_id}",
                headers=headers,
            )

            if resp.status_code == 404:
                # URL not in VT database — submit for analysis
                submit_resp = await client.post(
                    f"{VT_BASE_URL}/urls",
                    headers=headers,
                    data={"url": url},
                )
                if submit_resp.status_code == 200:
                    analysis_id = submit_resp.json()["data"]["id"]
                    logger.debug(f"VT: submitted URL for analysis, id={analysis_id}")
                return _empty_vt_result("not_found")

            if resp.status_code != 200:
                logger.warning(f"VT API returned {resp.status_code} for {url}")
                return _empty_vt_result(f"http_{resp.status_code}")

            data   = resp.json()["data"]["attributes"]["last_analysis_stats"]
            results= resp.json()["data"]["attributes"].get("last_analysis_results", {})
            meta   = resp.json()["data"]["attributes"]

            malicious  = data.get("malicious",  0)
            suspicious = data.get("suspicious", 0)
            harmless   = data.get("harmless",   0)
            undetected = data.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            detected_by = [
                engine for engine, res in results.items()
                if res.get("category") in ("malicious", "suspicious")
            ][:20]  # cap at 20 engine names

            result = {
                "positives":   malicious + suspicious,
                "total":       total or 90,
                "harmless":    harmless,
                "malicious":   malicious,
                "suspicious":  suspicious,
                "undetected":  undetected,
                "scan_date":   meta.get("last_analysis_date", ""),
                "permalink":   f"https://www.virustotal.com/gui/url/{url_id}",
                "detected_by": detected_by,
                "source":      "virustotal",
            }
            _VT_CACHE[cache_key] = result
            return result

    except httpx.TimeoutException:
        logger.warning(f"VT timeout for {url}")
        return _empty_vt_result("timeout")
    except Exception as exc:
        logger.error(f"VT error for {url}: {exc}")
        return _empty_vt_result("error")


def _empty_vt_result(source: str = "unavailable") -> Dict[str, Any]:
    return {
        "positives":   0,
        "total":       90,
        "harmless":    0,
        "malicious":   0,
        "suspicious":  0,
        "undetected":  90,
        "scan_date":   "",
        "permalink":   "",
        "detected_by": [],
        "source":      source,
    }
