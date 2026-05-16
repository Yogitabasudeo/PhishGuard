#!/usr/bin/env python3
# ============================================================
# PhishGuard — FastAPI Backend
# ============================================================
# Real-time phishing detection REST API.
#
# Endpoints:
#   GET  /                     Health / welcome
#   GET  /health               Detailed service health
#   GET  /stats                Aggregate scan statistics
#   POST /scan                 Main phishing detection endpoint
#   GET  /scan/{scan_id}       Retrieve a previous scan result
#   GET  /history              Paginated scan history
#   DELETE /history            Clear scan history
#
# Run:
#   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# ============================================================

import asyncio
import os
import sys
import time
import uuid
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

# ── Load .env ─────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / ".env")

# ── Local imports ─────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from schemas import (
    ScanRequest, ScanResponse, IOCData, FeatureVector,
    ScanHistoryItem, ScanHistoryResponse,
    HealthResponse, ServiceStatus, StatsResponse,
    ErrorResponse,
)
from feature_extractor import extract_features, FEATURE_NAMES
from services.model_service  import get_model_service
from services.virustotal_service import check_url_virustotal
from services.urlhaus_service    import check_url_urlhaus
from services.phishtank_service  import check_url_phishtank
from services.whois_service      import get_whois_info, format_age
from services.dns_service        import get_dns_records
from services.ssl_service        import check_ssl

# ── Known brands list (mirrors background.js) ─────────────────
KNOWN_BRANDS = [
    "paypal","google","microsoft","apple","amazon","facebook","instagram",
    "twitter","netflix","spotify","discord","github","linkedin","youtube",
    "ebay","walmart","stripe","coinbase","binance","flipkart","ajio",
    "myntra","paytm","phonepe","swiggy","zomato","hdfc","icici","sbi",
    "axis","kotak","iitg","iitb","adobe","dropbox","slack","zoom",
]

UNICODE_MAP = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i",
    "в":"b","н":"n","т":"t","α":"a","ε":"e","ο":"o","ρ":"p","υ":"u",
}
LEET_MAP = {"0":"o","1":"l","2":"z","3":"e","4":"a","5":"s","6":"g","7":"t","8":"b","9":"g"}

# ── In-memory scan store (replace with DB in production) ──────
_SCAN_STORE: Dict[str, ScanResponse] = {}
_STARTUP_TIME = time.time()

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title        = "PhishGuard API",
    description  = "ML-powered real-time phishing URL detection API.",
    version      = "1.0.0",
    docs_url     = "/docs",
    redoc_url    = "/redoc",
    contact      = {"name": "PhishGuard", "url": "https://phishguard.io"},
    license_info = {"name": "MIT"},
)

# ── CORS (allow the React dashboard & Chrome extension) ──────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Request logging middleware ────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0   = time.perf_counter()
    resp = await call_next(request)
    ms   = int((time.perf_counter() - t0) * 1000)
    logger.debug(f"{request.method} {request.url.path} → {resp.status_code} ({ms}ms)")
    return resp

# ── Startup / shutdown ────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("PhishGuard API starting up …")
    # Load the serialised ML model
    model_svc = get_model_service()
    model_svc.load()
    if model_svc.is_loaded:
        logger.info("✓ ML model loaded successfully")
    else:
        logger.warning("⚠ ML model not found — using heuristic fallback")
    logger.info("✓ PhishGuard API ready")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("PhishGuard API shutting down.")

# ============================================================
# DETECTION HELPERS
# ============================================================

def _normalize(text: str) -> str:
    r = text.lower()
    for g, a in UNICODE_MAP.items(): r = r.replace(g, a)
    for d, l in LEET_MAP.items():   r = r.replace(d, l)
    return r

def _detect_brand(domain: str) -> Optional[str]:
    """Return the first brand detected as being impersonated, or None."""
    from rapidfuzz import fuzz
    sld = domain.replace("www.", "").split(".")[0]
    for brand in KNOWN_BRANDS:
        if sld == brand:
            return None          # exact match = legitimate
        if brand in domain and not domain.endswith(f"{brand}.com"):
            return brand
    sld_norm = _normalize(re.sub(r"(.)\1+", r"\1", sld))
    for brand in KNOWN_BRANDS:
        score = fuzz.ratio(sld_norm, brand)
        if score >= 75 and sld_norm != brand:
            return brand
    return None

def _score_to_classification(risk_score: int) -> str:
    if   risk_score >= 76: return "Malicious"
    elif risk_score >= 56: return "Suspicious"
    elif risk_score >= 26: return "Low Suspicion"
    else:                  return "Legitimate"

def _build_threat_indicators(
    feat: Dict[str, Any],
    vt: Dict[str, Any],
    urlhaus: Dict[str, Any],
    phishtank: Dict[str, Any],
    whois_info: Dict[str, Any],
    ssl_info: Dict[str, Any],
    impersonated_brand: Optional[str],
) -> List[str]:
    signals: List[str] = []
    if not feat.get("has_https"):            signals.append("HTTP only — no TLS encryption")
    if feat.get("has_ip_address"):           signals.append("IP-based URL — no domain name")
    if feat.get("suspicious_tld"):           signals.append("High-abuse TLD detected")
    if feat.get("num_hyphens", 0) >= 3:      signals.append(f"Excessive hyphens ({feat['num_hyphens']}) in domain")
    if feat.get("has_at_in_url"):            signals.append("@ symbol in URL — credential theft pattern")
    if feat.get("url_length", 0) > 100:      signals.append(f"Excessively long URL ({feat['url_length']} chars)")
    if feat.get("has_suspicious_keywords"):  signals.append(f"High-risk keywords in URL: {feat.get('num_keywords_matched', 0)} matched")
    if feat.get("has_brand_not_in_tld"):     signals.append("Brand name injected outside registered domain")
    if impersonated_brand:                   signals.append(f"Brand impersonation detected — targeting \"{impersonated_brand.capitalize()}\"")
    if vt.get("positives", 0) > 0:          signals.append(f"{vt['positives']}/{vt['total']} VirusTotal detections")
    if urlhaus.get("listed"):               signals.append("Listed on URLHaus malware feed")
    if phishtank.get("listed"):             signals.append("Confirmed on PhishTank phishing database")
    age = whois_info.get("age_days", -1)
    if 0 <= age <= 7:                        signals.append(f"Domain registered {age} day(s) ago — suspicious")
    elif 8 <= age <= 30:                     signals.append(f"Very new domain ({age} days old)")
    if not ssl_info.get("valid"):            signals.append("Invalid or missing SSL/TLS certificate")
    dr = ssl_info.get("days_remaining")
    if dr is not None and dr < 15:           signals.append(f"SSL certificate expires in {dr} days")
    return signals[:10]

def _build_positive_signals(
    feat: Dict[str, Any],
    vt: Dict[str, Any],
    urlhaus: Dict[str, Any],
    phishtank: Dict[str, Any],
    whois_info: Dict[str, Any],
) -> List[str]:
    pos: List[str] = []
    if feat.get("has_https"):               pos.append("HTTPS with valid TLS encryption")
    if vt.get("positives", 1) == 0:        pos.append(f"0/{vt.get('total', 90)} VirusTotal engines clean")
    if not urlhaus.get("listed"):           pos.append("Not listed in URLHaus database")
    if not phishtank.get("listed"):         pos.append("No PhishTank phishing reports")
    age = whois_info.get("age_days", -1)
    if age > 365:                           pos.append(f"Established domain ({age // 365}+ years old)")
    if not feat.get("suspicious_tld"):      pos.append("Reputable TLD")
    if not feat.get("has_suspicious_keywords"): pos.append("No phishing keywords in URL")
    return pos[:6]

def _detect_attack_vectors(feat: Dict[str, Any], domain: str) -> List[str]:
    vectors: List[str] = []
    from urllib.parse import urlparse
    sld = domain.replace("www.", "").split(".")[0]
    if feat.get("has_ip_address"):          vectors.append("IP-Based Phishing")
    if feat.get("has_brand_not_in_tld"):    vectors.append("Subdomain Brand Impersonation")
    if feat.get("suspicious_tld"):          vectors.append("Malicious TLD Exploitation")
    # Unicode chars
    if any(ord(c) > 127 for c in sld):     vectors.append("Unicode Homoglyph Attack")
    # Leet speak
    if any(c in "0135" for c in sld):      vectors.append("L33t Speak Substitution")
    # Repeated chars
    if re.search(r"(.)\1{2,}", sld):        vectors.append("Character Repetition Attack")
    if feat.get("has_at_in_url"):           vectors.append("Credential Harvesting (@-redirect)")
    if feat.get("has_double_slash_path"):   vectors.append("Double-Slash Path Redirect")
    if feat.get("has_suspicious_keywords"): vectors.append("Phishing Keyword Injection")
    return vectors[:5]

def _generate_verdict(classification: str, impersonated_brand: Optional[str]) -> str:
    brand_suffix = f" targeting {impersonated_brand.capitalize()}" if impersonated_brand else ""
    verdicts = {
        "Malicious":     f"HIGH RISK — This URL is very likely a phishing page{brand_suffix}. Do NOT enter any credentials.",
        "Suspicious":    f"CAUTION — Suspicious URL detected{brand_suffix}. Verify the site before proceeding.",
        "Low Suspicion": f"LOW RISK — Some unusual signals detected. Exercise caution.",
        "Legitimate":    "SAFE — This URL appears to be a legitimate, well-established domain.",
    }
    return verdicts.get(classification, verdicts["Legitimate"])

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/", tags=["System"])
async def root():
    """Welcome / API info."""
    return {
        "name":     "PhishGuard API",
        "version":  "1.0.0",
        "status":   "running",
        "docs":     "/docs",
        "model":    get_model_service().is_loaded,
        "scans":    len(_SCAN_STORE),
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Detailed health status of all downstream services."""
    model_ok  = get_model_service().is_loaded
    vt_ok     = bool(os.getenv("VT_API_KEY"))
    pt_ok     = bool(os.getenv("PHISHTANK_API_KEY"))

    services = [
        ServiceStatus(name="ML Model",   status="ok"      if model_ok else "degraded"),
        ServiceStatus(name="VirusTotal", status="ok"      if vt_ok    else "degraded"),
        ServiceStatus(name="URLHaus",    status="ok"),      # no key required
        ServiceStatus(name="PhishTank",  status="ok"      if pt_ok    else "degraded"),
        ServiceStatus(name="WHOIS",      status="ok"),
        ServiceStatus(name="DNS",        status="ok"),
    ]
    overall = "healthy" if all(s.status == "ok" for s in services) else "degraded"
    return HealthResponse(
        status       = overall,
        model_loaded = model_ok,
        services     = services,
        uptime_s     = time.time() - _STARTUP_TIME,
    )


@app.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_stats():
    """Aggregate statistics over all scans in the current session."""
    scans = list(_SCAN_STORE.values())
    if not scans:
        return StatsResponse(
            total_scans=0, phishing_detected=0, suspicious_detected=0,
            safe_detected=0, avg_risk_score=0.0, avg_confidence=0.0,
            avg_scan_duration_ms=0.0, top_attack_types={}, top_impersonated={},
        )
    attack_counts: Dict[str, int] = defaultdict(int)
    brand_counts:  Dict[str, int] = defaultdict(int)
    for s in scans:
        for v in s.attack_vectors:
            attack_counts[v] += 1
        if s.impersonated_brand:
            brand_counts[s.impersonated_brand] += 1

    return StatsResponse(
        total_scans          = len(scans),
        phishing_detected    = sum(1 for s in scans if s.classification == "Malicious"),
        suspicious_detected  = sum(1 for s in scans if s.classification in ("Suspicious","Low Suspicion")),
        safe_detected        = sum(1 for s in scans if s.classification == "Legitimate"),
        avg_risk_score       = round(sum(s.risk_score for s in scans) / len(scans), 1),
        avg_confidence       = round(sum(s.confidence for s in scans) / len(scans), 4),
        avg_scan_duration_ms = round(sum(s.scan_duration_ms for s in scans) / len(scans), 1),
        top_attack_types     = dict(sorted(attack_counts.items(), key=lambda x: -x[1])[:8]),
        top_impersonated     = dict(sorted(brand_counts.items(),  key=lambda x: -x[1])[:8]),
    )


# ── POST /scan — MAIN ENDPOINT ────────────────────────────────

@app.post(
    "/scan",
    response_model  = ScanResponse,
    status_code     = 200,
    summary         = "Scan a URL for phishing indicators",
    tags            = ["Detection"],
    responses       = {
        400: {"model": ErrorResponse, "description": "Invalid URL"},
        500: {"model": ErrorResponse, "description": "Internal scan error"},
    },
)
async def scan_url(request: ScanRequest) -> ScanResponse:
    """
    Full phishing detection pipeline:

    1. URL feature extraction (structural analysis)
    2. Concurrent CTI lookups (VirusTotal, URLHaus, PhishTank)
    3. Async WHOIS, DNS, SSL checks
    4. ML model inference (XGBoost)
    5. Attack vector & brand detection
    6. Structured JSON response with IoCs
    """
    scan_id = str(uuid.uuid4())
    url     = request.url
    t_start = time.perf_counter()

    logger.info(f"[{scan_id[:8]}] Scanning: {url}")

    try:
        # ── Step 1: Concurrent CTI & infrastructure lookups ───
        vt_task      = asyncio.create_task(check_url_virustotal(url))
        urlhaus_task = asyncio.create_task(check_url_urlhaus(url))
        phishtank_task = asyncio.create_task(check_url_phishtank(url))
        whois_task   = asyncio.create_task(_async_whois(url))
        dns_task     = asyncio.create_task(_async_dns(url))
        ssl_task     = asyncio.create_task(_async_ssl(url))

        vt, urlhaus, phishtank, whois_info, dns_records, ssl_info = await asyncio.gather(
            vt_task, urlhaus_task, phishtank_task,
            whois_task, dns_task, ssl_task,
        )

        # ── Step 2: Feature extraction ────────────────────────
        feat_dict = extract_features(
            url              = url,
            domain_age_days  = whois_info.get("age_days", -1),
            ssl_valid        = ssl_info.get("valid", True),
            vt_positives     = vt.get("positives", 0),
            urlhaus_listed   = urlhaus.get("listed", False),
            phishtank_listed = phishtank.get("listed", False),
        )

        # ── Step 3: ML inference ──────────────────────────────
        model_svc    = get_model_service()
        ml_result    = model_svc.predict(feat_dict)
        risk_score   = ml_result["risk_score"]
        confidence   = ml_result["confidence"]
        classification = _score_to_classification(risk_score)

        # ── Step 4: Attack intelligence ───────────────────────
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace("www.", "").split(":")[0].lower()

        impersonated_brand = _detect_brand(domain)
        attack_vectors     = _detect_attack_vectors(feat_dict, domain)
        threat_indicators  = _build_threat_indicators(
            feat_dict, vt, urlhaus, phishtank, whois_info, ssl_info, impersonated_brand
        )
        positive_signals   = _build_positive_signals(
            feat_dict, vt, urlhaus, phishtank, whois_info
        )
        verdict = _generate_verdict(classification, impersonated_brand)

        # Primary attack type
        attack_type = attack_vectors[0] if attack_vectors else (
            "Brand Impersonation"   if impersonated_brand else
            "Credential Phishing"   if feat_dict.get("has_suspicious_keywords") else
            None
        )

        # ── Step 5: Build IoC object ──────────────────────────
        age_label = format_age(whois_info.get("age_days", -1))
        ssl_label = "valid" if ssl_info.get("valid") else "invalid"

        ip_addr = (
            dns_records.get("ip_address")
            or dns_records.get("A", [None])[0]
        )

        ioc = IOCData(
            domain              = domain,
            ip_address          = ip_addr,
            domain_age          = age_label,
            ssl                 = ssl_label,
            ssl_days_remaining  = ssl_info.get("days_remaining"),
            ssl_issuer          = ssl_info.get("issuer"),
            vt_detections       = vt.get("positives", 0),
            vt_total            = vt.get("total", 90),
            urlhaus_listed      = urlhaus.get("listed", False),
            phishtank_listed    = phishtank.get("listed", False),
            dns_a_records       = dns_records.get("A", [])[:4],
            dns_mx_records      = dns_records.get("MX", [])[:3],
            dns_ns_records      = dns_records.get("NS", [])[:3],
            whois_registrar     = whois_info.get("registrar"),
            whois_country       = whois_info.get("country"),
        )

        # ── Step 6: Assemble response ─────────────────────────
        scan_duration_ms = int((time.perf_counter() - t_start) * 1000)

        feat_obj = FeatureVector(**{
            k: bool(v) if k in (
                "has_https","has_ip_address","has_double_slash_path",
                "has_at_in_url","has_suspicious_keywords","has_brand_not_in_tld",
                "suspicious_tld","ssl_valid","urlhaus_listed","phishtank_listed",
            ) else v
            for k, v in feat_dict.items()
            if k in FeatureVector.model_fields
        })

        response = ScanResponse(
            scan_id            = scan_id,
            url                = url,
            timestamp          = datetime.now(timezone.utc),
            classification     = classification,
            risk_score         = risk_score,
            confidence         = confidence,
            attack_type        = attack_type,
            attack_vectors     = attack_vectors,
            impersonated_brand = impersonated_brand,
            ioc                = ioc,
            threat_indicators  = threat_indicators,
            positive_signals   = positive_signals,
            final_verdict      = verdict,
            features           = feat_obj,
            scan_duration_ms   = scan_duration_ms,
        )

        # Store for history
        _SCAN_STORE[scan_id] = response
        logger.info(
            f"[{scan_id[:8]}] Done: {classification} "
            f"(score={risk_score}, {scan_duration_ms}ms)"
        )
        return response

    except Exception as exc:
        logger.exception(f"[{scan_id[:8]}] Scan failed: {exc}")
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail      = f"Scan failed: {str(exc)}",
        )


@app.get(
    "/scan/{scan_id}",
    response_model = ScanResponse,
    tags           = ["Detection"],
    summary        = "Retrieve a previous scan result",
)
async def get_scan(scan_id: str):
    """Fetch a scan result by its UUID."""
    if scan_id not in _SCAN_STORE:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _SCAN_STORE[scan_id]


@app.get(
    "/history",
    response_model = ScanHistoryResponse,
    tags           = ["Detection"],
    summary        = "Paginated scan history",
)
async def get_history(
    page:     int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    all_scans = sorted(
        _SCAN_STORE.values(),
        key=lambda s: s.timestamp,
        reverse=True,
    )
    start   = (page - 1) * per_page
    page_items = all_scans[start: start + per_page]
    items = [
        ScanHistoryItem(
            scan_id            = s.scan_id,
            url                = s.url,
            domain             = s.ioc.domain,
            classification     = s.classification,
            risk_score         = s.risk_score,
            confidence         = s.confidence,
            attack_type        = s.attack_type,
            impersonated_brand = s.impersonated_brand,
            timestamp          = s.timestamp,
        )
        for s in page_items
    ]
    return ScanHistoryResponse(
        items    = items,
        total    = len(all_scans),
        page     = page,
        per_page = per_page,
    )


@app.delete("/history", tags=["Detection"])
async def clear_history():
    """Clear all stored scan results."""
    count = len(_SCAN_STORE)
    _SCAN_STORE.clear()
    return {"cleared": count}


# ── Async wrappers for synchronous service functions ──────────

async def _async_whois(url: str):
    return await asyncio.to_thread(get_whois_info, url)

async def _async_dns(url: str):
    return await asyncio.to_thread(get_dns_records, url)

async def _async_ssl(url: str):
    return await asyncio.to_thread(check_ssl, url)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host      = "0.0.0.0",
        port      = int(os.getenv("PORT", 8000)),
        reload    = True,
        log_level = "info",
    )
