"""
PhishGuard — XGBoost Model Service
Loads the trained model and exposes a predict() method used by the API.
"""
import json
import joblib
import numpy as np
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent / "models"

class ModelService:
    def __init__(self):
        self.model    = None
        self.scaler   = None
        self.features = []
        self.is_loaded = False

    def load(self):
        try:
            self.model   = joblib.load(MODELS_DIR / "phishguard_xgb.pkl")
            self.scaler  = joblib.load(MODELS_DIR / "scaler.pkl")
            with open(MODELS_DIR / "feature_names.json") as f:
                self.features = json.load(f)
            self.is_loaded = True
            print(f"[ModelService] Model loaded — {len(self.features)} features")
        except FileNotFoundError:
            print("[ModelService] ⚠ Model files not found — run train_model.py first")

    def predict(self, feature_dict: dict) -> tuple[str, int, float]:
        """
        Returns (prediction, risk_score, confidence).
        Falls back to a heuristic rule-set if the model is not loaded.
        """
        if not self.is_loaded:
            return self._heuristic(feature_dict)

        vec   = np.array([[feature_dict.get(f, 0) for f in self.features]], dtype=np.float32)
        vec_s = self.scaler.transform(vec)
        proba = self.model.predict_proba(vec_s)[0]   # [p_legit, p_phishing]
        p_phish = float(proba[1])
        risk_score = int(round(p_phish * 100))

        if p_phish >= 0.76:
            label = "phishing"
        elif p_phish >= 0.40:
            label = "suspicious"
        else:
            label = "safe"

        return label, risk_score, p_phish

    # ── Heuristic fallback ────────────────────────────────────────────────────
    def _heuristic(self, f: dict) -> tuple[str, int, float]:
        score = 0
        if f.get("urlhaus_listed"):        score += 40
        if f.get("vt_positives", 0) > 5:   score += 30
        if f.get("brand_similarity_score", 0) > 0.7: score += 20
        if f.get("suspicious_tld"):        score += 10
        if f.get("has_ip"):                score += 15
        if f.get("has_suspicious_keywords"): score += 8
        if not f.get("ssl_valid"):         score += 5
        score = min(score, 99)

        if score >= 76:
            label, conf = "phishing",   score / 100
        elif score >= 40:
            label, conf = "suspicious", score / 100
        else:
            label, conf = "safe",       1 - score / 100

        return label, score, round(conf, 3)
