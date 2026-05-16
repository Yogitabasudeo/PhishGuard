# ============================================================
# PhishGuard — Real-Time Feature Extraction Service
# ============================================================
# Orchestrates all live lookups (WHOIS, DNS, SSL) and calls
# feature_extractor.extract_features() with the enriched data.
# ============================================================

import asyncio
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from loguru import logger

sys.path.insert(0, str(Path(__file__).parent.parent))
from feature_extractor import extract_features, feature_dict_to_vector, FEATURE_NAMES

from .whois_service  import get_domain_age_days
from .dns_service    import get_dns_records, resolve_ip
from .ssl_service    import check_ssl


async def extract_all_features(
    url:              str,
    vt_positives:     int  = 0,
    urlhaus_listed:   bool = False,
    phishtank_listed: bool = False,
) -> Dict[str, Any]:
    """
    Full async feature pipeline:
      1. WHOIS domain age lookup
      2. DNS resolution
      3. SSL certificate check
      4. URL-structural feature extraction

    Returns the full 26-feature dictionary ready for ML inference.
    """
    t0 = time.perf_counter()

    # Run WHOIS and DNS concurrently (both are I/O bound)
    age_task = asyncio.create_task(_safe_domain_age(url))
    dns_task = asyncio.create_task(_safe_dns(url))
    ssl_task = asyncio.create_task(_safe_ssl(url))

    domain_age_days, dns_records, ssl_info = await asyncio.gather(
        age_task, dns_task, ssl_task
    )

    ssl_valid = ssl_info.get("valid", True)

    # Build the feature vector using the shared extractor
    feat_dict = extract_features(
        url              = url,
        domain_age_days  = domain_age_days,
        ssl_valid        = ssl_valid,
        vt_positives     = vt_positives,
        urlhaus_listed   = urlhaus_listed,
        phishtank_listed = phishtank_listed,
    )

    feat_dict["_dns"]     = dns_records
    feat_dict["_ssl"]     = ssl_info
    feat_dict["_age"]     = domain_age_days
    feat_dict["_extract_ms"] = int((time.perf_counter() - t0) * 1000)

    return feat_dict


# ── Safe async wrappers ───────────────────────────────────────

async def _safe_domain_age(url: str) -> int:
    """Wrap WHOIS lookup; return -1 on any error."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(get_domain_age_days, url), timeout=5.0
        )
    except Exception as exc:
        logger.debug(f"WHOIS lookup failed for {url}: {exc}")
        return -1


async def _safe_dns(url: str) -> Dict[str, Any]:
    """Wrap DNS lookup; return empty records on error."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(get_dns_records, url), timeout=5.0
        )
    except Exception as exc:
        logger.debug(f"DNS lookup failed for {url}: {exc}")
        return {"A": [], "MX": [], "NS": [], "TXT": []}


async def _safe_ssl(url: str) -> Dict[str, Any]:
    """Wrap SSL check; return valid=True on error (conservative default)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(check_ssl, url), timeout=8.0
        )
    except Exception as exc:
        logger.debug(f"SSL check failed for {url}: {exc}")
        return {"valid": True, "days_remaining": None, "issuer": None, "error": str(exc)}
