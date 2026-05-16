"""
PhishGuard — VirusTotal v3 Service
Queries the VirusTotal API for URL threat intelligence.
"""
import os
import asyncio
import httpx

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_API_KEY_HERE")
VT_BASE    = "https://www.virustotal.com/api/v3"
TIMEOUT    = 10.0

async def check_virustotal(url: str) -> dict:
    if VT_API_KEY == "YOUR_VT_API_KEY_HERE":
        return {"positives": 0, "total": 70, "permalink": "", "scan_date": "", "error": "API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            # Submit URL for analysis
            await client.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
            # Retrieve report
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
            if resp.status_code != 200:
                return {"positives": 0, "total": 70, "error": f"HTTP {resp.status_code}"}

            data  = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "positives":  stats.get("malicious", 0),
                "total":      sum(stats.values()) or 70,
                "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
                "scan_date":  data.get("last_analysis_date", ""),
            }
    except httpx.TimeoutException:
        return {"positives": 0, "total": 70, "error": "Timeout"}
    except Exception as exc:
        return {"positives": 0, "total": 70, "error": str(exc)}
