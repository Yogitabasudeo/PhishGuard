# ============================================================
# PhishGuard — DNS Analysis Service
# ============================================================
# Resolves DNS records and detects anomalies that are
# indicative of phishing infrastructure.
# ============================================================

import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import tldextract
from cachetools import TTLCache
from loguru import logger

_DNS_CACHE: TTLCache = TTLCache(maxsize=2000, ttl=3600)  # 1-hour TTL


def get_dns_records(url: str) -> Dict[str, Any]:
    """
    Resolve A, MX, NS, and TXT records for the URL's domain.

    Returns:
        {
            "A":  list[str],  "MX": list[str],
            "NS": list[str],  "TXT": list[str],
            "ip_address": str | None,
            "anomalies":  list[str],
            "source": str,
        }
    """
    domain = _extract_domain(url)
    if not domain:
        return _empty()

    if domain in _DNS_CACHE:
        result = dict(_DNS_CACHE[domain])
        result["source"] = "cache"
        return result

    records: Dict[str, List[str]] = {"A": [], "MX": [], "NS": [], "TXT": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0    # 5-second timeout

    for rtype in ("A", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "A":
                records["A"] = [r.address for r in answers][:8]
            elif rtype == "MX":
                records["MX"] = [str(r.exchange).rstrip(".") for r in answers][:6]
            elif rtype == "NS":
                records["NS"] = [str(r.target).rstrip(".") for r in answers][:6]
            elif rtype == "TXT":
                records["TXT"] = [b.decode(errors="ignore") for r in answers
                                   for b in r.strings][:4]
        except dns.exception.DNSException as exc:
            logger.debug(f"DNS {rtype} failed for {domain}: {exc}")

    ip_address = records["A"][0] if records["A"] else _resolve_ip(domain)
    anomalies  = _detect_anomalies(domain, records)

    result = {
        "A":           records["A"],
        "MX":          records["MX"],
        "NS":          records["NS"],
        "TXT":         records["TXT"],
        "ip_address":  ip_address,
        "anomalies":   anomalies,
        "source":      "dns",
    }
    _DNS_CACHE[domain] = result
    return result


def resolve_ip(url: str) -> Optional[str]:
    """Resolve URL → IP address (best effort)."""
    domain = _extract_domain(url)
    return _resolve_ip(domain) if domain else None


# ── Anomaly detection ─────────────────────────────────────────

def _detect_anomalies(domain: str, records: Dict[str, List[str]]) -> List[str]:
    anomalies: List[str] = []

    # No A record at all
    if not records["A"]:
        anomalies.append("No A record — domain may not resolve")

    # No MX record (unusual for a 'legitimate business' domain)
    if not records["MX"]:
        anomalies.append("No MX record — not configured for email")

    # Single-hop NS delegation (many phishing domains use free DNS)
    if len(records["NS"]) == 1:
        anomalies.append("Single NS server — minimal DNS setup")

    # Free/bulletproof DNS providers commonly used by phishing ops
    ABUSE_DNS = {
        "cloudflare.com", "dnsimple.com",   # often abused
        "afraid.org", "he.net",
        "1984.is", "njal.la",
    }
    for ns in records["NS"]:
        ns_lower = ns.lower()
        if any(bad in ns_lower for bad in ABUSE_DNS):
            anomalies.append(f"Potentially privacy-focused NS: {ns}")
            break

    # Private / reserved IP in A record
    for ip in records["A"]:
        if (ip.startswith("10.")
                or ip.startswith("192.168.")
                or ip.startswith("172.")
                or ip == "127.0.0.1"):
            anomalies.append(f"Private/loopback IP in A record: {ip}")

    return anomalies


# ── Helpers ───────────────────────────────────────────────────

def _extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or url
        domain = netloc.split(":")[0].replace("www.", "").lower()
        return domain if domain else None
    except Exception:
        return None


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _empty() -> Dict[str, Any]:
    return {
        "A": [], "MX": [], "NS": [], "TXT": [],
        "ip_address": None, "anomalies": [], "source": "error",
    }
