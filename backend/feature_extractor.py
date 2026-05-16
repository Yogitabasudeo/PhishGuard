# ============================================================
# PhishGuard — Feature Extractor
# ============================================================
# Extracts a fixed-length numerical feature vector from a URL.
# This module is used by BOTH the training pipeline and the
# FastAPI inference endpoint — ensuring identical features at
# train time and prediction time.
#
# Feature Vector (26 dimensions):
#   [0]  url_length
#   [1]  domain_length
#   [2]  num_subdomains
#   [3]  num_dots
#   [4]  num_hyphens
#   [5]  num_at_symbols
#   [6]  num_special_chars
#   [7]  url_path_depth
#   [8]  num_digits_in_domain
#   [9]  num_digits_in_path
#   [10] has_https              (0/1)
#   [11] has_ip_address         (0/1)
#   [12] has_double_slash_path  (0/1)
#   [13] has_at_in_url          (0/1)
#   [14] url_entropy
#   [15] domain_entropy
#   [16] has_suspicious_keywords(0/1)
#   [17] num_keywords_matched
#   [18] brand_similarity_score (0.0–1.0)
#   [19] has_brand_not_in_tld   (0/1)
#   [20] suspicious_tld         (0/1)
#   [21] domain_age_days        (-1 = unknown)
#   [22] ssl_valid              (0/1)
#   [23] vt_positives
#   [24] urlhaus_listed         (0/1)
#   [25] phishtank_listed       (0/1)
# ============================================================

import re
import math
import unicodedata
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Optional

import tldextract
from rapidfuzz import fuzz

# ── Constants ────────────────────────────────────────────────

FEATURE_NAMES: List[str] = [
    "url_length",
    "domain_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_at_symbols",
    "num_special_chars",
    "url_path_depth",
    "num_digits_in_domain",
    "num_digits_in_path",
    "has_https",
    "has_ip_address",
    "has_double_slash_path",
    "has_at_in_url",
    "url_entropy",
    "domain_entropy",
    "has_suspicious_keywords",
    "num_keywords_matched",
    "brand_similarity_score",
    "has_brand_not_in_tld",
    "suspicious_tld",
    "domain_age_days",
    "ssl_valid",
    "vt_positives",
    "urlhaus_listed",
    "phishtank_listed",
]

NUM_FEATURES = len(FEATURE_NAMES)   # 26

KNOWN_BRANDS: List[str] = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "twitter", "netflix", "spotify", "discord", "github",
    "linkedin", "youtube", "ebay", "walmart", "stripe", "coinbase",
    "binance", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "barclays", "flipkart", "ajio", "myntra", "meesho", "paytm",
    "phonepe", "swiggy", "zomato", "ola", "jio", "airtel",
    "hdfc", "icici", "sbi", "axis", "kotak", "adobe", "dropbox",
    "slack", "zoom", "notion", "figma", "steam", "twitch", "roblox",
]

PHISHING_KEYWORDS: List[str] = [
    "login", "verify", "secure", "account", "banking", "update",
    "confirm", "signin", "authenticate", "reactivate", "suspended",
    "blocked", "wallet", "credential", "password", "recovery",
    "support", "helpdesk", "invoice", "payment", "refund",
    "alert", "notice", "validate", "activate", "unlock",
]

SUSPICIOUS_TLDS: List[str] = [
    ".xyz", ".info", ".online", ".site", ".ru", ".cn", ".tk",
    ".ml", ".ga", ".cf", ".pw", ".top", ".work", ".click",
    ".gq", ".icu", ".buzz", ".cam", ".vip", ".link", ".bid", ".win",
]

IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ── Unicode / L33t normalisation ────────────────────────────

_UNICODE_MAP: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "в": "b", "н": "n", "т": "t",      # Cyrillic
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "υ": "u", "σ": "s",  # Greek
}
_LEET_MAP: Dict[str, str] = {
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
}


def _normalize(text: str) -> str:
    """Apply unicode → ASCII + leet-speak normalisation."""
    result = text.lower()
    for glyph, ascii_char in _UNICODE_MAP.items():
        result = result.replace(glyph, ascii_char)
    for digit, letter in _LEET_MAP.items():
        result = result.replace(digit, letter)
    return result


# ── Entropy calculation ──────────────────────────────────────

def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ── Brand similarity ─────────────────────────────────────────

def _brand_similarity(domain_sld: str) -> float:
    """
    Returns the maximum fuzzy similarity score [0.0–1.0]
    between the SLD and any known brand.
    Uses rapidfuzz for fast approximate matching.
    """
    sld_norm = _normalize(domain_sld)
    # Exact match → 1.0 (no impersonation risk from this feature alone)
    if sld_norm in KNOWN_BRANDS:
        return 1.0
    best: float = 0.0
    for brand in KNOWN_BRANDS:
        score = fuzz.ratio(sld_norm, brand) / 100.0
        if score > best:
            best = score
    return round(best, 4)


def _has_brand_outside_registered_domain(netloc: str) -> bool:
    """
    Returns True if a known brand appears in the netloc but is NOT
    the registered domain.  E.g. paypal.evil-host.com → True
                                  paypal.com            → False
    """
    ext = tldextract.extract(netloc)
    reg_domain = ext.domain.lower()
    # Check subdomains / full netloc for brand injection
    full_netloc_lower = netloc.lower()
    for brand in KNOWN_BRANDS:
        if brand in full_netloc_lower and brand != reg_domain:
            return True
    return False


# ── Main extraction function ─────────────────────────────────

def extract_features(
    url: str,
    domain_age_days: int = -1,
    ssl_valid: bool = True,
    vt_positives: int = 0,
    urlhaus_listed: bool = False,
    phishtank_listed: bool = False,
) -> Dict[str, Any]:
    """
    Extract a 26-dimensional feature dictionary from a URL.

    External threat-intelligence values (domain_age_days, ssl_valid,
    vt_positives, urlhaus_listed, phishtank_listed) are passed in from
    the calling service after live CTI lookups.  Defaults are provided
    so the function can be used standalone (e.g. during training with
    synthetic CTI values).

    Returns:
        dict mapping each FEATURE_NAMES entry to its numeric value.
    """
    url = unquote(url.strip())
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path   = parsed.path.lower()
    ext    = tldextract.extract(url)

    domain     = netloc.replace("www.", "")
    sld        = ext.domain.lower()         # second-level domain
    suffix     = f".{ext.suffix}".lower() if ext.suffix else ""
    subdomains = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []

    # ── [0] url_length
    url_length = len(url)

    # ── [1] domain_length
    domain_length = len(domain)

    # ── [2] num_subdomains
    num_subdomains = len(subdomains)

    # ── [3] num_dots
    num_dots = domain.count(".")

    # ── [4] num_hyphens
    num_hyphens = domain.count("-")

    # ── [5] num_at_symbols
    num_at = url.count("@")

    # ── [6] num_special_chars  (excluding standard ://?.=&/)
    special = re.findall(r"[^a-zA-Z0-9\-._/:?=&#+@%]", url)
    num_special = len(special)

    # ── [7] url_path_depth
    path_parts = [p for p in path.split("/") if p]
    url_path_depth = len(path_parts)

    # ── [8] num_digits_in_domain
    num_digits_domain = sum(c.isdigit() for c in domain)

    # ── [9] num_digits_in_path
    num_digits_path = sum(c.isdigit() for c in path)

    # ── [10] has_https
    has_https = 1 if parsed.scheme == "https" else 0

    # ── [11] has_ip_address
    has_ip = 1 if IP_REGEX.match(netloc.split(":")[0]) else 0

    # ── [12] has_double_slash_path
    has_double_slash = 1 if "//" in path else 0

    # ── [13] has_at_in_url
    has_at = 1 if "@" in url else 0

    # ── [14] url_entropy
    url_entropy = round(_entropy(url), 4)

    # ── [15] domain_entropy
    domain_entropy = round(_entropy(domain), 4)

    # ── [16] has_suspicious_keywords
    url_lower = url.lower()
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    has_kw = 1 if matched_kw else 0

    # ── [17] num_keywords_matched
    num_kw = len(matched_kw)

    # ── [18] brand_similarity_score
    brand_sim = _brand_similarity(sld)

    # ── [19] has_brand_not_in_tld
    has_brand_outside = 1 if _has_brand_outside_registered_domain(netloc) else 0

    # ── [20] suspicious_tld
    susp_tld = 1 if any(suffix == tld or url_lower.endswith(tld + "/")
                        for tld in SUSPICIOUS_TLDS) else 0

    # ── [21–25] external CTI values (passed in)
    _domain_age   = int(domain_age_days)
    _ssl_valid    = 1 if ssl_valid else 0
    _vt_positives = int(vt_positives)
    _urlhaus      = 1 if urlhaus_listed  else 0
    _phishtank    = 1 if phishtank_listed else 0

    return {
        "url_length":              url_length,
        "domain_length":           domain_length,
        "num_subdomains":          num_subdomains,
        "num_dots":                num_dots,
        "num_hyphens":             num_hyphens,
        "num_at_symbols":          num_at,
        "num_special_chars":       num_special,
        "url_path_depth":          url_path_depth,
        "num_digits_in_domain":    num_digits_domain,
        "num_digits_in_path":      num_digits_path,
        "has_https":               has_https,
        "has_ip_address":          has_ip,
        "has_double_slash_path":   has_double_slash,
        "has_at_in_url":           has_at,
        "url_entropy":             url_entropy,
        "domain_entropy":          domain_entropy,
        "has_suspicious_keywords": has_kw,
        "num_keywords_matched":    num_kw,
        "brand_similarity_score":  brand_sim,
        "has_brand_not_in_tld":    has_brand_outside,
        "suspicious_tld":          susp_tld,
        "domain_age_days":         _domain_age,
        "ssl_valid":               _ssl_valid,
        "vt_positives":            _vt_positives,
        "urlhaus_listed":          _urlhaus,
        "phishtank_listed":        _phishtank,
    }


def feature_dict_to_vector(feat_dict: Dict[str, Any]) -> List[float]:
    """Convert feature dictionary → ordered list matching FEATURE_NAMES."""
    return [float(feat_dict[name]) for name in FEATURE_NAMES]


if __name__ == "__main__":
    # Quick smoke test
    test_url = "http://paypal-verify-account.xyz/login?user=test"
    feats = extract_features(test_url, domain_age_days=3, ssl_valid=False,
                              vt_positives=12, urlhaus_listed=True)
    print("Feature vector:")
    for k, v in feats.items():
        print(f"  {k:<30} {v}")
