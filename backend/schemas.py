# ============================================================
# PhishGuard — Pydantic Schemas (API Request / Response)
# ============================================================

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict
import re


# ── Request ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """POST /scan request body."""
    url: str = Field(
        ...,
        min_length=4,
        max_length=4096,
        description="The URL to scan for phishing indicators.",
        json_schema_extra={"example": "https://paypal-verify-account.xyz/login"},
    )

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://", v, re.IGNORECASE):
            v = "http://" + v      # add scheme if missing
        return v


# ── IOC sub-object ────────────────────────────────────────────

class IOCData(BaseModel):
    """Indicators of Compromise returned with every scan."""
    model_config = ConfigDict(populate_by_name=True)

    domain:           str
    ip_address:       Optional[str]   = None
    domain_age:       str             = "Unknown"
    ssl:              str             = "unknown"        # "valid" | "invalid" | "unknown"
    ssl_days_remaining: Optional[int] = None
    ssl_issuer:       Optional[str]   = None
    vt_detections:    int             = 0
    vt_total:         int             = 90
    urlhaus_listed:   bool            = False
    phishtank_listed: bool            = False
    dns_a_records:    List[str]       = Field(default_factory=list)
    dns_mx_records:   List[str]       = Field(default_factory=list)
    dns_ns_records:   List[str]       = Field(default_factory=list)
    whois_registrar:  Optional[str]   = None
    whois_country:    Optional[str]   = None
    asn:              Optional[str]   = None
    isp:              Optional[str]   = None


# ── Feature vector sub-object ─────────────────────────────────

class FeatureVector(BaseModel):
    """The 26-dimensional feature vector used for ML inference."""
    url_length:              int
    domain_length:           int
    num_subdomains:          int
    num_dots:                int
    num_hyphens:             int
    num_at_symbols:          int
    num_special_chars:       int
    url_path_depth:          int
    num_digits_in_domain:    int
    num_digits_in_path:      int
    has_https:               bool
    has_ip_address:          bool
    has_double_slash_path:   bool
    has_at_in_url:           bool
    url_entropy:             float
    domain_entropy:          float
    has_suspicious_keywords: bool
    num_keywords_matched:    int
    brand_similarity_score:  float
    has_brand_not_in_tld:    bool
    suspicious_tld:          bool
    domain_age_days:         int
    ssl_valid:               bool
    vt_positives:            int
    urlhaus_listed:          bool
    phishtank_listed:        bool


# ── Scan Response ─────────────────────────────────────────────

class ScanResponse(BaseModel):
    """POST /scan full response."""
    model_config = ConfigDict(populate_by_name=True)

    # ── Identity ───────────────────────────────────────────────
    scan_id:          str
    url:              str
    timestamp:        datetime

    # ── ML Classification ──────────────────────────────────────
    classification:   str   = Field(
        description="Legitimate | Low Suspicion | Suspicious | Malicious"
    )
    risk_score:       int   = Field(ge=0, le=100)
    confidence:       float = Field(ge=0.0, le=1.0)

    # ── Attack details ─────────────────────────────────────────
    attack_type:      Optional[str] = None   # e.g. "Typosquatting"
    attack_vectors:   List[str]     = Field(default_factory=list)
    impersonated_brand: Optional[str] = None

    # ── Indicators of Compromise ───────────────────────────────
    ioc:              IOCData

    # ── Threat intelligence ────────────────────────────────────
    threat_indicators:      List[str] = Field(default_factory=list)
    positive_signals:       List[str] = Field(default_factory=list)
    final_verdict:          str       = ""

    # ── Feature vector (for transparency / debugging) ──────────
    features:         FeatureVector

    # ── Performance ────────────────────────────────────────────
    scan_duration_ms: int   = 0
    model_version:    str   = "1.0.0"


# ── History ───────────────────────────────────────────────────

class ScanHistoryItem(BaseModel):
    """Abbreviated scan record for history listings."""
    scan_id:       str
    url:           str
    domain:        str
    classification: str
    risk_score:    int
    confidence:    float
    attack_type:   Optional[str] = None
    impersonated_brand: Optional[str] = None
    timestamp:     datetime


class ScanHistoryResponse(BaseModel):
    items:   List[ScanHistoryItem]
    total:   int
    page:    int
    per_page: int


# ── Health check ──────────────────────────────────────────────

class ServiceStatus(BaseModel):
    name:    str
    status:  str         # "ok" | "degraded" | "offline"
    latency_ms: Optional[int] = None


class HealthResponse(BaseModel):
    status:        str         # "healthy" | "degraded"
    version:       str         = "1.0.0"
    model_loaded:  bool
    services:      List[ServiceStatus]
    uptime_s:      float


# ── Stats ─────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total_scans:          int
    phishing_detected:    int
    suspicious_detected:  int
    safe_detected:        int
    avg_risk_score:       float
    avg_confidence:       float
    avg_scan_duration_ms: float
    top_attack_types:     Dict[str, int]
    top_impersonated:     Dict[str, int]


# ── Error response ────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error:   str
    detail:  Optional[str] = None
    scan_id: Optional[str] = None
