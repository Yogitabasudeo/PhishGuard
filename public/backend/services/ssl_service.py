"""
PhishGuard — SSL/TLS Certificate Service
Validates TLS certificate chain and extracts certificate metadata.
"""
import asyncio
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

async def check_ssl(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"valid": False, "reason": "Not HTTPS", "issuer": None, "expires": None}

    hostname = parsed.hostname
    port     = parsed.port or 443

    def _check():
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    return {
                        "valid":      True,
                        "issuer":     issuer.get("organizationName", "Unknown"),
                        "expires":    not_after.isoformat(),
                        "days_left":  (not_after - datetime.now(timezone.utc)).days,
                        "subject":    hostname,
                    }
        except ssl.SSLCertVerificationError as e:
            return {"valid": False, "reason": str(e), "issuer": None, "expires": None}
        except Exception as e:
            return {"valid": False, "reason": str(e), "issuer": None, "expires": None}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check)
