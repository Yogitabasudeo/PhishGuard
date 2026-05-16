from pydantic import BaseModel, HttpUrl
from datetime import datetime
from typing import Optional

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    id: str
    url: str
    scan_time: datetime
    prediction: str          # "phishing" | "suspicious" | "safe"
    risk_score: int          # 0–100
    confidence: float        # 0.0–1.0
    features: dict
    vt: dict
    urlhaus: dict
    whois: dict
    dns: dict
    ssl: dict

class HistoryResponse(BaseModel):
    id: str
    url: str
    scan_time: datetime
    prediction: str
    risk_score: int
    confidence: float

class StatsResponse(BaseModel):
    total: int
    phishing: int
    suspicious: int
    safe: int
