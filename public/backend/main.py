from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import uuid
from datetime import datetime, timezone

from schemas import ScanRequest, ScanResponse, HistoryResponse, StatsResponse
from services.model_service import ModelService
from services.virustotal_service import check_virustotal
from services.urlhaus_service import check_urlhaus
from services.whois_service import get_whois_info
from services.dns_service import get_dns_records
from services.ssl_service import check_ssl
from feature_extractor import extract_features

model_service = ModelService()
scan_db: list[dict] = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    model_service.load()
    yield

app = FastAPI(
    title="PhishGuard API",
    description="ML-powered phishing URL detection API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": model_service.is_loaded, "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/scan", response_model=ScanResponse)
async def scan_url(req: ScanRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features = extract_features(url)

    vt_result   = await check_virustotal(url)
    uh_result   = await check_urlhaus(url)
    whois_info  = await get_whois_info(url)
    dns_records = await get_dns_records(url)
    ssl_info    = await check_ssl(url)

    features.update({
        "vt_positives":    vt_result.get("positives", 0),
        "vt_total":        vt_result.get("total", 70),
        "urlhaus_listed":  uh_result.get("listed", False),
        "phishtank_listed": False,
        "ssl_valid":       ssl_info.get("valid", False),
        "domain_age_days": whois_info.get("age_days", -1),
    })

    prediction, risk_score, confidence = model_service.predict(features)

    record = {
        "id":          str(uuid.uuid4()),
        "url":         url,
        "scan_time":   datetime.now(timezone.utc).isoformat(),
        "prediction":  prediction,
        "risk_score":  risk_score,
        "confidence":  confidence,
        "features":    features,
        "vt":          vt_result,
        "urlhaus":     uh_result,
        "whois":       whois_info,
        "dns":         dns_records,
        "ssl":         ssl_info,
    }
    scan_db.append(record)
    return ScanResponse(**record)

@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    for r in reversed(scan_db):
        if r["id"] == scan_id:
            return r
    raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/history", response_model=list[HistoryResponse])
async def get_history(limit: int = 100, offset: int = 0):
    return list(reversed(scan_db))[offset : offset + limit]

@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    total = len(scan_db)
    phishing   = sum(1 for r in scan_db if r["prediction"] == "phishing")
    suspicious = sum(1 for r in scan_db if r["prediction"] == "suspicious")
    safe       = total - phishing - suspicious
    return StatsResponse(total=total, phishing=phishing, suspicious=suspicious, safe=safe)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
