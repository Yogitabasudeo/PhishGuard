"""
PhishGuard — URLhaus Service
Checks URLhaus threat feed for malicious URL listings.
"""
import asyncio
import httpx

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT     = 8.0

async def check_urlhaus(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(URLHAUS_API, data={"url": url})
            if resp.status_code != 200:
                return {"listed": False, "threat": None, "error": f"HTTP {resp.status_code}"}

            data   = resp.json()
            listed = data.get("query_status") == "is_listed"
            return {
                "listed":     listed,
                "threat":     data.get("threat"),
                "url_status": data.get("url_status"),
                "tags":       data.get("tags", []),
                "reporter":   data.get("reporter"),
            }
    except httpx.TimeoutException:
        return {"listed": False, "threat": None, "error": "Timeout"}
    except Exception as exc:
        return {"listed": False, "threat": None, "error": str(exc)}
