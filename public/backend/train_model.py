"""
PhishGuard — XGBoost Model Training Pipeline
Trains a phishing URL classifier on 30,000 labeled samples.

Usage:
    python train_model.py

Output:
    models/phishguard_xgb.pkl   — trained XGBoost model
    models/scaler.pkl            — StandardScaler for numeric features
    models/feature_names.json   — ordered feature list
"""
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
)
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

FEATURE_COLS = [
    "url_length", "num_dots", "num_hyphens", "num_underscores",
    "num_digits", "num_special_chars", "has_https", "has_ip",
    "has_at_symbol", "has_double_slash", "url_entropy", "domain_length",
    "subdomain_count", "suspicious_tld", "has_suspicious_keywords",
    "keyword_count", "has_brand_not_in_tld", "brand_similarity_score",
    "path_depth", "has_executable", "vt_positives", "vt_total",
    "urlhaus_listed", "phishtank_listed", "ssl_valid", "domain_age_days",
]

def load_dataset(path: str = "data/phishguard_dataset.csv") -> tuple:
    df = pd.read_csv(path)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["label"].values          # 1 = phishing, 0 = legitimate
    return X, y

def train():
    print("Loading dataset …")
    X, y = load_dataset()
    print(f"  Samples: {len(y)}  |  Phishing: {y.sum()}  |  Legit: {(y==0).sum()}")

    print("Applying SMOTE to balance classes …")
    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X, y)

    print("Scaling features …")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_res)

    print("Training XGBoost classifier …")
    model = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    print("5-fold cross-validation …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_scaled, y_res, cv=cv, scoring="accuracy")
    print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    model.fit(X_scaled, y_res)

    y_pred  = model.predict(X_scaled)
    y_proba = model.predict_proba(X_scaled)[:, 1]
    print("\nTraining metrics:")
    print(f"  Accuracy : {accuracy_score(y_res, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_res, y_pred):.4f}")
    print(f"  Recall   : {recall_score(y_res, y_pred):.4f}")
    print(f"  F1       : {f1_score(y_res, y_pred):.4f}")
    print(f"  AUC-ROC  : {roc_auc_score(y_res, y_proba):.4f}")
    print(classification_report(y_res, y_pred, target_names=["Legitimate", "Phishing"]))

    print("Saving artefacts …")
    joblib.dump(model,  MODELS_DIR / "phishguard_xgb.pkl")
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    with open(MODELS_DIR / "feature_names.json", "w") as f:
        json.dump(FEATURE_COLS, f, indent=2)
    print("Done → models/")

if __name__ == "__main__":
    train()
