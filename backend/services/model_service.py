# ============================================================
# PhishGuard — ML Model Service
# ============================================================
# Loads the serialised XGBoost artefact and exposes a
# single predict() call used by the scan endpoint.
# ============================================================

import sys
import time
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List

import joblib
import numpy as np
from loguru import logger

# Shared constants from the feature extractor
sys.path.insert(0, str(Path(__file__).parent.parent))
from feature_extractor import FEATURE_NAMES, NUM_FEATURES

# ── Default model path ────────────────────────────────────────
DEFAULT_MODEL_PATH = Path(__file__).parent.parent / "models" / "phishing_model.pkl"

# Classification thresholds (probability of phishing class)
THRESHOLD_PHISHING   = 0.76   # > this → Malicious    (risk 76–100)
THRESHOLD_SUSPICIOUS = 0.56   # > this → Suspicious   (risk 56–75)
THRESHOLD_LOW        = 0.26   # > this → Low Suspicion (risk 26–55)


class ModelService:
    """
    Loads the trained XGBoost model artefact and performs
    real-time inference on extracted feature vectors.
    """

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self._path    = Path(model_path or DEFAULT_MODEL_PATH)
        self._artefact: Optional[Dict[str, Any]] = None
        self._loaded  = False

    def load(self) -> None:
        """Load model from disk.  Called once at FastAPI startup."""
        if not self._path.exists():
            logger.warning(
                f"Model file not found at {self._path}. "
                "Run train_model.py to generate it. "
                "Inference will fall back to heuristic scoring."
            )
            self._loaded = False
            return
        try:
            self._artefact = joblib.load(self._path)
            feat_count = self._artefact.get("num_features", "?")
            logger.info(
                f"✓ Model loaded from {self._path} "
                f"({feat_count} features, "
                f"accuracy={self._artefact.get('metrics', {}).get('accuracy', 0)*100:.1f}%)"
            )
            self._loaded = True
        except Exception as exc:
            logger.error(f"Failed to load model: {exc}")
            self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def predict(
        self,
        feature_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run inference on a feature dictionary.

        Returns a dict with:
            phishing_probability: float [0.0–1.0]
            classification:       str
            risk_score:           int  [0–100]
            confidence:           float
            ml_used:              bool  (False → heuristic fallback)
        """
        t0 = time.perf_counter()

        if self._loaded and self._artefact is not None:
            result = self._predict_ml(feature_dict)
        else:
            result = self._predict_heuristic(feature_dict)

        result["inference_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    # ── ML inference ─────────────────────────────────────────────

    def _predict_ml(self, feat: Dict[str, Any]) -> Dict[str, Any]:
        model = self._artefact["model"]          # type: ignore[index]

        # Build feature vector in the exact order used at training time
        try:
            vec = np.array([[float(feat[name]) for name in FEATURE_NAMES]])
        except KeyError as e:
            logger.warning(f"Missing feature {e} — falling back to heuristic")
            return self._predict_heuristic(feat)

        proba       = float(model.predict_proba(vec)[0][1])
        risk_score  = min(100, max(0, int(proba * 100)))
        classification, confidence = self._classify(proba, risk_score)

        return {
            "phishing_probability": round(proba, 4),
            "classification":       classification,
            "risk_score":           risk_score,
            "confidence":           round(confidence, 4),
            "ml_used":              True,
        }

    # ── Heuristic fallback (no model file available) ──────────────

    def _predict_heuristic(self, feat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rule-based risk scoring used when the ML model isn't available.
        Mirrors the weighting logic in background.js for consistency.
        """
        score = 5.0

        if not feat.get("has_https",         1): score += 12
        if     feat.get("has_ip_address",    0): score += 30
        if     feat.get("suspicious_tld",    0): score += 15
        if     feat.get("has_at_in_url",     0): score += 10
        if     feat.get("has_double_slash_path", 0): score += 8
        if     feat.get("url_length",        0) > 100: score += 8
        if     feat.get("num_hyphens",       0) >= 3: score += 12
        if     feat.get("has_suspicious_keywords", 0): score += feat.get("num_keywords_matched", 0) * 7
        if     feat.get("has_brand_not_in_tld", 0): score += 40

        sim = feat.get("brand_similarity_score", 0.0)
        if 0.65 <= sim < 1.0:
            score += (sim - 0.65) / 0.35 * 40

        age = feat.get("domain_age_days", -1)
        if 0 <= age <= 7:   score += 25
        elif 8 <= age <= 30: score += 15
        elif 31 <= age <= 90: score += 5

        if not feat.get("ssl_valid", 1): score += 12
        vt = feat.get("vt_positives", 0)
        score += min(vt * 1.5, 20)
        if feat.get("urlhaus_listed",   0): score += 15
        if feat.get("phishtank_listed", 0): score += 12

        risk_score  = min(100, max(0, int(score)))
        proba       = risk_score / 100.0
        classification, confidence = self._classify(proba, risk_score)

        return {
            "phishing_probability": round(proba, 4),
            "classification":       classification,
            "risk_score":           risk_score,
            "confidence":           round(confidence, 4),
            "ml_used":              False,
        }

    # ── Classification thresholds ─────────────────────────────────

    @staticmethod
    def _classify(proba: float, risk_score: int) -> Tuple[str, float]:
        """Map probability → (classification label, confidence)."""
        if   risk_score >= 76: label = "Malicious";     base_conf = 0.88
        elif risk_score >= 56: label = "Suspicious";    base_conf = 0.72
        elif risk_score >= 26: label = "Low Suspicion"; base_conf = 0.60
        else:                  label = "Legitimate";    base_conf = 0.94

        # Confidence = how far the probability is from the nearest threshold
        nearest_threshold = (
            THRESHOLD_PHISHING if proba >= THRESHOLD_PHISHING else
            THRESHOLD_SUSPICIOUS if proba >= THRESHOLD_SUSPICIOUS else
            THRESHOLD_LOW if proba >= THRESHOLD_LOW else 0
        )
        margin = abs(proba - nearest_threshold)
        confidence = min(0.99, base_conf + margin * 0.5)
        return label, confidence

    def feature_importances(self) -> Dict[str, float]:
        """Return sorted feature importances (requires loaded model)."""
        if not self._loaded:
            return {}
        imp = self._artefact["model"].feature_importances_        # type: ignore[index]
        return dict(sorted(zip(FEATURE_NAMES, imp),
                            key=lambda x: x[1], reverse=True))


# ── Singleton instance ────────────────────────────────────────
_model_service = ModelService()


def get_model_service() -> ModelService:
    """FastAPI dependency injection — returns the shared service instance."""
    return _model_service
