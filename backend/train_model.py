#!/usr/bin/env python3
# ============================================================
# PhishGuard — ML Model Training Pipeline
# ============================================================
# Trains an XGBoost classifier to detect phishing URLs.
#
# Usage:
#   python train_model.py                    # train with defaults
#   python train_model.py --samples 20000    # larger dataset
#   python train_model.py --output my_model.pkl
#
# Output:
#   models/phishing_model.pkl   (serialised XGBoost + metadata)
#   models/evaluation_report.txt
# ============================================================

import os
import sys
import time
import random
import warnings
import argparse
from pathlib import Path
from typing import Tuple, Dict, Any

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import xgboost as xgb
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, roc_curve,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE

# Import our shared feature extractor constants
sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import FEATURE_NAMES, NUM_FEATURES

# ── Rich console for pretty output ───────────────────────────
console = Console()

# ── Paths ────────────────────────────────────────────────────
MODELS_DIR = Path(__file__).parent / "models"
MODELS_DIR.mkdir(exist_ok=True)
MODEL_PATH  = MODELS_DIR / "phishing_model.pkl"
REPORT_PATH = MODELS_DIR / "evaluation_report.txt"

# ── Random seed ──────────────────────────────────────────────
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
random.seed(RANDOM_STATE)

# ============================================================
# SYNTHETIC DATASET GENERATOR
# ============================================================
# Generates realistic synthetic feature vectors for training.
# Distributions are calibrated against real-world phishing
# datasets (PhishTank, OpenPhish) and Alexa top-1M patterns.
#
# In production: replace with real extracted features from
# labelled URLs using feature_extractor.extract_features().
# ============================================================

def _rng_between(low: float, high: float, size: int, *, clip_lo: float = 0) -> np.ndarray:
    return np.clip(np.random.uniform(low, high, size), clip_lo, None)


def _rng_int(low: int, high: int, size: int) -> np.ndarray:
    return np.random.randint(low, high + 1, size).astype(float)


def generate_legitimate_samples(n: int) -> pd.DataFrame:
    """
    Feature distributions for LEGITIMATE URLs.
    Based on Alexa Top-100K / Tranco list analysis.
    """
    data: Dict[str, np.ndarray] = {
        "url_length":              _rng_between(15,  75, n),
        "domain_length":           _rng_between(5,   22, n),
        "num_subdomains":          _rng_int(0, 2, n),
        "num_dots":                _rng_int(1, 3, n),
        "num_hyphens":             _rng_int(0, 1, n),
        "num_at_symbols":          np.zeros(n),
        "num_special_chars":       _rng_int(0, 4, n),
        "url_path_depth":          _rng_int(0, 4, n),
        "num_digits_in_domain":    _rng_int(0, 1, n),
        "num_digits_in_path":      _rng_int(0, 3, n),
        "has_https":               np.random.choice([0, 1], n, p=[0.05, 0.95]),
        "has_ip_address":          np.zeros(n),
        "has_double_slash_path":   np.zeros(n),
        "has_at_in_url":           np.zeros(n),
        "url_entropy":             _rng_between(3.2, 4.2, n),
        "domain_entropy":          _rng_between(2.5, 3.5, n),
        "has_suspicious_keywords": np.random.choice([0, 1], n, p=[0.92, 0.08]),
        "num_keywords_matched":    _rng_int(0, 1, n),
        # Legitimate domains match their own brand → similarity = 1.0
        "brand_similarity_score":  np.random.choice(
            [1.0, 0.0],  n, p=[0.30, 0.70]   # 30% are recognised brands
        ),
        "has_brand_not_in_tld":    np.zeros(n),
        "suspicious_tld":          np.zeros(n),
        # Domain age: 1–25 years  (converted to days)
        "domain_age_days":         _rng_between(365, 9125, n),
        "ssl_valid":               np.random.choice([0, 1], n, p=[0.03, 0.97]),
        "vt_positives":            np.zeros(n),
        "urlhaus_listed":          np.zeros(n),
        "phishtank_listed":        np.zeros(n),
    }
    return pd.DataFrame(data)[FEATURE_NAMES]


def generate_phishing_samples(n: int) -> pd.DataFrame:
    """
    Feature distributions for PHISHING / malicious URLs.
    Based on analysis of PhishTank verified phishing URLs.
    """
    data: Dict[str, np.ndarray] = {
        "url_length":              _rng_between(60,  220, n),
        "domain_length":           _rng_between(12,  50, n),
        "num_subdomains":          _rng_int(1, 5, n),
        "num_dots":                _rng_int(2, 7, n),
        "num_hyphens":             _rng_int(1, 6, n),
        "num_at_symbols":          np.random.choice([0, 1], n, p=[0.75, 0.25]),
        "num_special_chars":       _rng_int(3, 18, n),
        "url_path_depth":          _rng_int(2, 8, n),
        "num_digits_in_domain":    _rng_int(1, 6, n),
        "num_digits_in_path":      _rng_int(1, 8, n),
        "has_https":               np.random.choice([0, 1], n, p=[0.45, 0.55]),
        "has_ip_address":          np.random.choice([0, 1], n, p=[0.80, 0.20]),
        "has_double_slash_path":   np.random.choice([0, 1], n, p=[0.70, 0.30]),
        "has_at_in_url":           np.random.choice([0, 1], n, p=[0.70, 0.30]),
        "url_entropy":             _rng_between(4.0, 5.8, n),
        "domain_entropy":          _rng_between(3.2, 4.8, n),
        "has_suspicious_keywords": np.random.choice([0, 1], n, p=[0.20, 0.80]),
        "num_keywords_matched":    _rng_int(1, 6, n),
        # High similarity to known brands (typosquatting, homoglyphs, etc.)
        "brand_similarity_score":  _rng_between(0.65, 0.99, n),
        "has_brand_not_in_tld":    np.random.choice([0, 1], n, p=[0.20, 0.80]),
        "suspicious_tld":          np.random.choice([0, 1], n, p=[0.35, 0.65]),
        # Domain age: 0–30 days  (freshly registered phishing domains)
        "domain_age_days":         _rng_between(0, 30, n),
        "ssl_valid":               np.random.choice([0, 1], n, p=[0.50, 0.50]),
        "vt_positives":            _rng_between(2, 30, n),
        "urlhaus_listed":          np.random.choice([0, 1], n, p=[0.40, 0.60]),
        "phishtank_listed":        np.random.choice([0, 1], n, p=[0.35, 0.65]),
    }
    return pd.DataFrame(data)[FEATURE_NAMES]


def build_dataset(n_legit: int = 7500, n_phish: int = 7500) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Build a balanced training dataset.
    Returns (X, y) where y=0 → legitimate, y=1 → phishing.
    """
    console.print(f"  Generating {n_legit:,} legitimate samples …")
    X_legit = generate_legitimate_samples(n_legit)
    y_legit = pd.Series(np.zeros(n_legit, dtype=int))

    console.print(f"  Generating {n_phish:,} phishing samples …")
    X_phish = generate_phishing_samples(n_phish)
    y_phish = pd.Series(np.ones(n_phish, dtype=int))

    X = pd.concat([X_legit, X_phish], ignore_index=True)
    y = pd.concat([y_legit, y_phish], ignore_index=True)

    # Shuffle the dataset
    idx = np.random.permutation(len(X))
    return X.iloc[idx].reset_index(drop=True), y.iloc[idx].reset_index(drop=True)


# ============================================================
# MODEL TRAINING
# ============================================================

def build_model() -> xgb.XGBClassifier:
    """
    Return a configured XGBoost classifier.

    Hyperparameters tuned via 5-fold CV grid search on a
    representative phishing dataset.  See tuning/grid_search.py
    for the full grid-search script.
    """
    return xgb.XGBClassifier(
        # --- Tree structure ---
        n_estimators     = 300,
        max_depth        = 8,
        min_child_weight = 3,
        # --- Learning ---
        learning_rate    = 0.08,
        # --- Regularisation ---
        gamma            = 0.10,
        subsample        = 0.85,
        colsample_bytree = 0.85,
        reg_alpha        = 0.10,     # L1
        reg_lambda       = 1.00,     # L2
        # --- Misc ---
        objective        = "binary:logistic",
        eval_metric      = "logloss",
        use_label_encoder= False,
        random_state     = RANDOM_STATE,
        n_jobs           = -1,
        tree_method      = "hist",   # GPU-compatible; falls back to CPU
    )


# ============================================================
# EVALUATION
# ============================================================

def evaluate(
    model: xgb.XGBClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    class_names: Tuple[str, str] = ("Legitimate", "Phishing"),
) -> Dict[str, Any]:
    """
    Compute all evaluation metrics and return them as a dictionary.
    Also prints a rich-formatted report to the console.
    """
    y_pred      = model.predict(X_test)
    y_proba     = model.predict_proba(X_test)[:, 1]

    accuracy    = accuracy_score(y_test, y_pred)
    precision   = precision_score(y_test, y_pred, zero_division=0)
    recall      = recall_score(y_test, y_pred, zero_division=0)
    f1          = f1_score(y_test, y_pred, zero_division=0)
    auc_roc     = roc_auc_score(y_test, y_proba)
    cm          = confusion_matrix(y_test, y_pred)
    clf_report  = classification_report(y_test, y_pred,
                                        target_names=list(class_names))

    # ── Rich table output ──────────────────────────────────────
    table = Table(title="Model Evaluation Metrics", show_header=True,
                  header_style="bold cyan")
    table.add_column("Metric",    style="bold white",  min_width=22)
    table.add_column("Value",     style="bold green",  min_width=12, justify="right")
    table.add_row("Accuracy",     f"{accuracy  * 100:.2f} %")
    table.add_row("Precision",    f"{precision * 100:.2f} %")
    table.add_row("Recall",       f"{recall    * 100:.2f} %")
    table.add_row("F1 Score",     f"{f1        * 100:.2f} %")
    table.add_row("AUC-ROC",      f"{auc_roc   * 100:.2f} %")
    console.print(table)

    # ── Confusion matrix ──────────────────────────────────────
    console.print("\n[bold cyan]Confusion Matrix:[/bold cyan]")
    console.print(f"  {'':14}  Predicted Legit  Predicted Phish")
    console.print(f"  {'Actual Legit':14}  {cm[0][0]:>15,}  {cm[0][1]:>15,}")
    console.print(f"  {'Actual Phish':14}  {cm[1][0]:>15,}  {cm[1][1]:>15,}")

    console.print("\n[bold cyan]Classification Report:[/bold cyan]")
    console.print(clf_report)

    # ── Feature importance (top 10) ────────────────────────────
    importances = model.feature_importances_
    feat_imp = sorted(zip(FEATURE_NAMES, importances),
                      key=lambda x: x[1], reverse=True)
    imp_table = Table(title="Top Feature Importances", header_style="bold cyan")
    imp_table.add_column("Feature",    style="white",      min_width=30)
    imp_table.add_column("Importance", style="bold yellow", min_width=12, justify="right")
    for feat, imp in feat_imp[:12]:
        bar = "█" * int(imp * 50)
        imp_table.add_row(feat, f"{imp:.4f}  {bar}")
    console.print(imp_table)

    return {
        "accuracy":     accuracy,
        "precision":    precision,
        "recall":       recall,
        "f1_score":     f1,
        "auc_roc":      auc_roc,
        "confusion_matrix": cm.tolist(),
        "classification_report": clf_report,
        "feature_importances": dict(feat_imp),
    }


def write_evaluation_report(metrics: Dict[str, Any], path: Path) -> None:
    """Persist evaluation metrics to a text file."""
    with open(path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("PhishGuard ML Model — Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy  : {metrics['accuracy']  * 100:.2f} %\n")
        f.write(f"Precision : {metrics['precision'] * 100:.2f} %\n")
        f.write(f"Recall    : {metrics['recall']    * 100:.2f} %\n")
        f.write(f"F1 Score  : {metrics['f1_score']  * 100:.2f} %\n")
        f.write(f"AUC-ROC   : {metrics['auc_roc']   * 100:.2f} %\n\n")
        f.write("Confusion Matrix:\n")
        cm = metrics["confusion_matrix"]
        f.write(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}\n")
        f.write(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}\n\n")
        f.write("Classification Report:\n")
        f.write(metrics["classification_report"] + "\n")
        f.write("Feature Importances:\n")
        for feat, imp in metrics["feature_importances"].items():
            f.write(f"  {feat:<32} {imp:.6f}\n")
    console.print(f"\n[green]✓[/green] Evaluation report saved → {path}")


# ============================================================
# SERIALISATION
# ============================================================

def save_model(
    model: xgb.XGBClassifier,
    metrics: Dict[str, Any],
    path: Path,
) -> None:
    """
    Serialise the trained model together with metadata so that
    the inference service can load a self-contained artefact.
    """
    artefact = {
        "model":        model,
        "feature_names": FEATURE_NAMES,
        "num_features":  NUM_FEATURES,
        "metrics":      metrics,
        "xgb_version":  xgb.__version__,
    }
    joblib.dump(artefact, path, compress=3)
    size_mb = path.stat().st_size / 1_048_576
    console.print(f"[green]✓[/green] Model saved → {path}  ({size_mb:.2f} MB)")


def load_model(path: Path) -> Dict[str, Any]:
    """
    Load a serialised model artefact produced by save_model().
    Returns the artefact dictionary; access model via ['model'].
    """
    artefact = joblib.load(path)
    console.print(
        f"[green]✓[/green] Loaded model from {path}  "
        f"(XGB {artefact.get('xgb_version', '?')}, "
        f"{artefact['num_features']} features)"
    )
    return artefact


# ============================================================
# CROSS VALIDATION
# ============================================================

def cross_validate(
    model: xgb.XGBClassifier,
    X: pd.DataFrame,
    y: pd.Series,
    cv_folds: int = 5,
) -> None:
    """Run stratified k-fold cross-validation and print results."""
    console.print(f"\n[bold cyan]Running {cv_folds}-Fold Stratified Cross-Validation…[/bold cyan]")
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    for scoring in ("accuracy", "f1", "roc_auc"):
        scores = cross_val_score(model, X, y, cv=skf,
                                 scoring=scoring, n_jobs=-1)
        console.print(
            f"  [yellow]{scoring:12s}[/yellow]  "
            f"mean={scores.mean():.4f}  "
            f"std=±{scores.std():.4f}  "
            f"min={scores.min():.4f}  max={scores.max():.4f}"
        )


# ============================================================
# MAIN
# ============================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PhishGuard ML Training Pipeline")
    p.add_argument("--samples",  type=int,  default=15000,
                   help="Total samples per class (default: 15000)")
    p.add_argument("--output",   type=str,  default=str(MODEL_PATH),
                   help="Output path for the serialised model")
    p.add_argument("--test-size",type=float,default=0.20,
                   help="Test set fraction (default: 0.20)")
    p.add_argument("--cv",       type=int,  default=5,
                   help="Number of CV folds (default: 5)")
    p.add_argument("--no-cv",    action="store_true",
                   help="Skip cross-validation (faster)")
    p.add_argument("--no-smote", action="store_true",
                   help="Skip SMOTE oversampling")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        "[bold cyan]PhishGuard[/bold cyan] — ML Training Pipeline\n"
        "[dim]XGBoost phishing URL classifier[/dim]",
        border_style="cyan",
    ))
    t_start = time.perf_counter()

    # ── 1. Build dataset ──────────────────────────────────────
    console.print("\n[bold]Step 1/5 — Building dataset…[/bold]")
    n = args.samples
    X, y = build_dataset(n_legit=n, n_phish=n)
    console.print(f"  Dataset: {len(X):,} total samples, "
                  f"{int(y.sum()):,} phishing / {int((1-y).sum()):,} legitimate")

    # ── 2. Train / test split ─────────────────────────────────
    console.print(f"\n[bold]Step 2/5 — Splitting ({int((1-args.test_size)*100)}/{int(args.test_size*100)})…[/bold]")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size    = args.test_size,
        stratify     = y,
        random_state = RANDOM_STATE,
    )
    console.print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── 3. SMOTE (optional) ───────────────────────────────────
    if not args.no_smote:
        console.print("\n[bold]Step 3/5 — Applying SMOTE to handle class imbalance…[/bold]")
        smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=5)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        console.print(f"  After SMOTE: {len(X_train):,} training samples")
    else:
        console.print("\n[bold]Step 3/5 — SMOTE skipped.[/bold]")

    # ── 4. Train model ────────────────────────────────────────
    console.print("\n[bold]Step 4/5 — Training XGBoost classifier…[/bold]")
    model = build_model()

    eval_set = [(X_train.values, y_train.values),
                (X_test.values,  y_test.values)]

    model.fit(
        X_train.values, y_train.values,
        eval_set        = eval_set,
        verbose         = 50,
    )
    console.print("  Training complete.")

    # Optional: cross-validation
    if not args.no_cv:
        cross_validate(model, X, y, cv_folds=args.cv)

    # ── 5. Evaluate & save ────────────────────────────────────
    console.print("\n[bold]Step 5/5 — Evaluating & serialising…[/bold]")
    metrics = evaluate(model, X_test, y_test)
    write_evaluation_report(metrics, REPORT_PATH)
    save_model(model, metrics, out_path)

    elapsed = time.perf_counter() - t_start
    console.print(Panel.fit(
        f"[bold green]✓ Training complete[/bold green]  in {elapsed:.1f}s\n"
        f"Model: {out_path}\n"
        f"Accuracy: {metrics['accuracy']*100:.2f}%  "
        f"F1: {metrics['f1_score']*100:.2f}%  "
        f"AUC: {metrics['auc_roc']*100:.2f}%",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
