"""Phase 3: train, compare, calibrate and save the URL classifier.

Leakage control:
- The Phase 1 domain-grouped test set is used ONLY for final reporting.
- Model selection and calibration use a validation split carved from train,
  again grouped by registered domain (no domain in both fit and validation).
- Scaling (LR) lives inside a Pipeline, so it is fit on training rows only.

Imbalance: models are fit with "balanced" sample weights. Calibration is fit WITHOUT
weights so calibrated probabilities reflect real class frequencies (needed for scoring).

Run: python -m src.train
"""
import json
import time
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score, classification_report,
                             confusion_matrix, f1_score, log_loss, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src.features import MODEL_FEATURES

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports" / "phase3"
LABELS = ["benign", "phishing", "malware", "defacement"]  # class index order
RANDOM_STATE = 42
MODEL_VERSION = "v2-no-https"
VAL_SIZE = 0.15


def load(split: str):
    df = pd.read_csv(PROCESSED / f"features_{split}.csv")
    y = df["type"].map({l: i for i, l in enumerate(LABELS)}).to_numpy()
    assert "has_https" not in df.columns, "rebuild matrices: has_https must not be a model input"
    return df[MODEL_FEATURES], y, df["domain"].to_numpy()


def make_models() -> dict:
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        "random_forest": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=5, max_features="sqrt", n_jobs=-1, random_state=RANDOM_STATE),
        "xgboost": XGBClassifier(
            objective="multi:softprob", num_class=len(LABELS), n_estimators=400, max_depth=8,
            learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, tree_method="hist",
            n_jobs=-1, random_state=RANDOM_STATE),
    }


def fit(model, X, y, w):
    if hasattr(model, "steps"):  # Pipeline: route weights to the final estimator
        return model.fit(X, y, **{f"{model.steps[-1][0]}__sample_weight": w})
    return model.fit(X, y, sample_weight=w)


def evaluate(y, proba) -> dict:
    pred = proba.argmax(1)
    rep = classification_report(y, pred, labels=range(len(LABELS)), target_names=LABELS,
                                output_dict=True, zero_division=0)
    return {
        "macro_f1": f1_score(y, pred, average="macro"),
        "roc_auc_ovr_macro": roc_auc_score(y, proba, multi_class="ovr", average="macro"),
        "accuracy": accuracy_score(y, pred),
        "log_loss": log_loss(y, proba, labels=range(len(LABELS))),
        "per_class": {l: {k: rep[l][k] for k in ("precision", "recall", "f1-score", "support")} for l in LABELS},
        "confusion_matrix": confusion_matrix(y, pred, labels=range(len(LABELS))).tolist(),
    }


def plot_confusion(cm, title, path):
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    ConfusionMatrixDisplay(np.array(cm), display_labels=LABELS).plot(ax=ax, values_format="d", colorbar=False)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def plot_calibration(y, proba_raw, proba_cal, path):
    fig, axes = plt.subplots(1, len(LABELS), figsize=(16, 4), sharey=True)
    for i, (ax, label) in enumerate(zip(axes, LABELS)):
        for proba, name in ((proba_raw, "uncalibrated"), (proba_cal, "calibrated")):
            frac, mean = calibration_curve(y == i, proba[:, i], n_bins=10, strategy="quantile")
            ax.plot(mean, frac, marker="o", label=name)
        ax.plot([0, 1], [0, 1], "k--", lw=1)
        ax.set_title(label)
        ax.set_xlabel("predicted probability")
    axes[0].set_ylabel("observed frequency")
    axes[0].legend()
    fig.suptitle("Calibration on test set (one-vs-rest)")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def main():
    MODELS.mkdir(exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    X_train, y_train, g_train = load("train")
    X_test, y_test, g_test = load("test")
    assert not set(g_train) & set(g_test), "domain leakage between train and test"

    gss = GroupShuffleSplit(n_splits=1, test_size=VAL_SIZE, random_state=RANDOM_STATE)
    fit_idx, val_idx = next(gss.split(X_train, y_train, groups=g_train))
    assert not set(g_train[fit_idx]) & set(g_train[val_idx])
    X_fit, y_fit, X_val, y_val = X_train.iloc[fit_idx], y_train[fit_idx], X_train.iloc[val_idx], y_train[val_idx]
    w_fit = compute_sample_weight("balanced", y_fit)
    print(f"fit={len(fit_idx)} val={len(val_idx)} test={len(y_test)}")

    results, fitted = {}, {}
    for name, model in make_models().items():
        t = time.time()
        fit(model, X_fit, y_fit, w_fit)
        fitted[name] = model
        results[name] = {"validation": evaluate(y_val, model.predict_proba(X_val)),
                         "test": evaluate(y_test, model.predict_proba(X_test)),
                         "fit_seconds": round(time.time() - t, 1)}
        v, te = results[name]["validation"], results[name]["test"]
        print(f"{name:14s} val macroF1={v['macro_f1']:.4f} AUC={v['roc_auc_ovr_macro']:.4f} | "
              f"test macroF1={te['macro_f1']:.4f} AUC={te['roc_auc_ovr_macro']:.4f} ({results[name]['fit_seconds']}s)")
        plot_confusion(te["confusion_matrix"], f"{name} (test)", REPORTS / f"confusion_{name}.png")

    # Selection on VALIDATION only: macro F1, ROC-AUC as tie-breaker.
    best = max(results, key=lambda n: (round(results[n]["validation"]["macro_f1"], 3),
                                       results[n]["validation"]["roc_auc_ovr_macro"]))
    print(f"\nbest by validation macro F1: {best}")

    # Calibrate the frozen best model on the domain-disjoint validation split (isotonic: plenty of data).
    calibrated = CalibratedClassifierCV(FrozenEstimator(fitted[best]), method="isotonic")
    calibrated.fit(X_val, y_val)
    proba_raw, proba_cal = fitted[best].predict_proba(X_test), calibrated.predict_proba(X_test)
    results["calibrated_best"] = {"base_model": best, "test": evaluate(y_test, proba_cal)}
    c = results["calibrated_best"]["test"]
    print(f"calibrated {best}: test macroF1={c['macro_f1']:.4f} AUC={c['roc_auc_ovr_macro']:.4f} "
          f"logloss {results[best]['test']['log_loss']:.4f} -> {c['log_loss']:.4f}")
    plot_confusion(c["confusion_matrix"], f"calibrated {best} (test)", REPORTS / "confusion_calibrated.png")
    plot_calibration(y_test, proba_raw, proba_cal, REPORTS / "calibration_curve.png")

    joblib.dump({"model": calibrated, "labels": LABELS, "features": MODEL_FEATURES, "base_model": best,
                 "version": MODEL_VERSION},
                MODELS / "webshield_model.joblib", compress=3)
    for name, model in fitted.items():
        joblib.dump(model, MODELS / f"{name}_uncalibrated.joblib", compress=3)

    (REPORTS / "metrics.json").write_text(json.dumps(results, indent=2))
    rows = [{"model": n, "split": s, "macro_f1": r[s]["macro_f1"], "roc_auc": r[s]["roc_auc_ovr_macro"],
             "accuracy": r[s]["accuracy"], "log_loss": r[s]["log_loss"],
             **{f"{l}_{m}": r[s]["per_class"][l][k] for l in LABELS
                for m, k in (("P", "precision"), ("R", "recall"), ("F1", "f1-score"))}}
            for n, r in results.items() for s in ("validation", "test") if s in r]
    pd.DataFrame(rows).round(4).to_csv(REPORTS / "model_comparison.csv", index=False)
    print(f"\nsaved models to {MODELS}, reports to {REPORTS}")


if __name__ == "__main__":
    main()
