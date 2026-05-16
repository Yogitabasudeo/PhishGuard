# ============================================================
# PhishGuard — SSL Certificate Checker
# ============================================================
# Validates the SSL/TLS certificate for a given URL and
# extracts key certificate metadata.
# ============================================================

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from cachetools import TTLCache
from loguru import logger

_SSL_CACHE: TTLCache = TTLCache(maxsize=1000, ttl=3600)  # 1-hour TTL


def check_ssl(url: str) -> Dict[str, Any]:
    """
    Connect to the URL's host over TLS and inspect the certificate.

    Returns:
        {
            "valid":           bool,
            "days_remaining":  int | None,
            "issuer":          str | None,
            "subject":         str | None,
            "not_before":      str | None,
            "not_after":       str | None,
            "san":             list[str],
            "error":           str | None,
        }
    """
    parsed  = urlparse(url)
    scheme  = parsed.scheme.lower()
    host    = parsed.netloc.split(":")[0]
    port    = int(parsed.port or 443)

    # HTTP → no SSL
    if scheme == "http":
        return {
            "valid":          False,
            "days_remaining": None,
            "issuer":         None,
            "subject":        None,
            "not_before":     None,
            "not_after":      None,
            "san":            [],
            "error":          "HTTP scheme — no TLS",
        }

    cache_key = f"{host}:{port}"
    if cache_key in _SSL_CACHE:
        result = dict(_SSL_CACHE[cache_key])
        result["source"] = "cache"
        return result

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")

        # Parse expiry date
        not_after: Optional[datetime] = None
        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        days_remaining: Optional[int] = None
        if not_after:
            diff = (not_after - datetime.now(timezone.utc)).days
            days_remaining = max(0, diff)

        # Issuer
        issuer_dict = {k: v for tup in cert.get("issuer", []) for k, v in tup}
        issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

        # Subject
        subj_dict = {k: v for tup in cert.get("subject", []) for k, v in tup}
        subject = subj_dict.get("commonName")

        # SAN (Subject Alternative Names)
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"][:10]

        result = {
            "valid":          True,
            "days_remaining": days_remaining,
            "issuer":         issuer,
            "subject":        subject,
            "not_before":     not_before_str or None,
            "not_after":      not_after_str  or None,
            "san":            san,
            "error":          None,
        }
        _SSL_CACHE[cache_key] = result
        return result

    except ssl.SSLCertVerificationError as exc:
        logger.debug(f"SSL cert verification failed for {host}: {exc}")
        return _ssl_invalid(str(exc))
    except ssl.SSLError as exc:
        logger.debug(f"SSL error for {host}: {exc}")
        return _ssl_invalid(str(exc))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug(f"SSL connection failed for {host}: {exc}")
        return _ssl_invalid(str(exc))
    except Exception as exc:
        logger.debug(f"SSL unexpected error for {host}: {exc}")
        return _ssl_invalid(str(exc))


def _ssl_invalid(error: str = "Unknown error") -> Dict[str, Any]:
    return {
        "valid":          False,
        "days_remaining": None,
        "issuer":         None,
        "subject":        None,
        "not_before":     None,
        "not_after":      None,
        "san":            [],
        "error":          error,
    }
