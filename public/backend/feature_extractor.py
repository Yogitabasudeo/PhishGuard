"""
PhishGuard Feature Extractor
Extracts 26 URL/domain features for the XGBoost phishing classifier.
"""
import re
import math
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".online", ".site"}
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "banking", "password", "credential", "signin", "auth", "wallet",
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
]
KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "ebay", "alibaba",
]

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())

def _normalize_leet(s: str) -> str:
    table = str.maketrans("01345@!$", "oieasais")
    return s.translate(table)

def extract_features(url: str) -> dict:
    parsed   = urlparse(url)
    ext      = tldextract.extract(url)
    domain   = ext.domain.lower()
    suffix   = f".{ext.suffix}" if ext.suffix else ""
    subdomain = ext.subdomain.lower()
    full_host = parsed.netloc.lower()
    path      = parsed.path

    # URL-level features
    url_length          = len(url)
    num_dots            = url.count(".")
    num_hyphens         = url.count("-")
    num_underscores     = url.count("_")
    num_digits          = sum(c.isdigit() for c in url)
    num_special_chars   = sum(c in "@?=&%#!" for c in url)
    has_https           = parsed.scheme == "https"
    has_ip              = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", full_host.split(":")[0]))
    has_at_symbol       = "@" in url
    has_double_slash    = "//" in url[7:]
    url_entropy         = _entropy(url)

    # Domain-level features
    domain_length       = len(domain)
    subdomain_count     = subdomain.count(".") + 1 if subdomain else 0
    suspicious_tld      = suffix in SUSPICIOUS_TLDS

    # Keyword / brand features
    normalized_domain   = _normalize_leet(domain + subdomain)
    has_suspicious_keywords = any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)
    keyword_count       = sum(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)

    detected_brand      = next((b for b in KNOWN_BRANDS if b in normalized_domain), None)
    has_brand_not_in_tld = bool(detected_brand and detected_brand not in ext.registered_domain)

    # Typosquatting / similarity (Levenshtein approximation)
    from rapidfuzz import fuzz
    brand_similarity_score = max(
        (fuzz.ratio(domain, b) / 100 for b in KNOWN_BRANDS), default=0.0
    )

    # Path features
    path_depth          = path.count("/")
    has_executable      = any(path.endswith(ext) for ext in [".exe", ".bat", ".sh", ".msi", ".dmg"])

    return {
        "url_length":             url_length,
        "num_dots":               num_dots,
        "num_hyphens":            num_hyphens,
        "num_underscores":        num_underscores,
        "num_digits":             num_digits,
        "num_special_chars":      num_special_chars,
        "has_https":              int(has_https),
        "has_ip":                 int(has_ip),
        "has_at_symbol":          int(has_at_symbol),
        "has_double_slash":       int(has_double_slash),
        "url_entropy":            round(url_entropy, 4),
        "domain_length":          domain_length,
        "subdomain_count":        subdomain_count,
        "suspicious_tld":         int(suspicious_tld),
        "has_suspicious_keywords": int(has_suspicious_keywords),
        "keyword_count":          keyword_count,
        "has_brand_not_in_tld":   int(has_brand_not_in_tld),
        "brand_similarity_score": round(brand_similarity_score, 4),
        "path_depth":             path_depth,
        "has_executable":         int(has_executable),
        # Filled in later by CTI services:
        "vt_positives":           0,
        "vt_total":               70,
        "urlhaus_listed":         0,
        "phishtank_listed":       0,
        "ssl_valid":              int(has_https),
        "domain_age_days":        -1,
    }
