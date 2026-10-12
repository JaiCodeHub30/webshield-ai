"""Phase 4: ML-only URL risk score (0-10) with type, confidence and plain-English reasons.

ml_score = 10 * (1.0*P(malware) + 0.9*P(phishing) + 0.5*P(defacement))   (CLAUDE.md)
Probabilities come from the calibrated model. Threat intel is added in Phase 5.
"""
import numpy as np
import pandas as pd

from src.explain import explain_features, load_bundle
from src.features import MODEL_FEATURES, extract_features

RISK_WEIGHTS = {"benign": 0.0, "phishing": 0.9, "malware": 1.0, "defacement": 0.5}


def ml_score(probabilities: dict) -> float:
    """CLAUDE.md formula on a {label: probability} dict, clipped to [0, 10]."""
    total = sum(probabilities.values())
    if not np.isclose(total, 1.0, atol=1e-3):
        raise ValueError(f"probabilities must sum to 1, got {total:.4f}")
    if any(p < 0 for p in probabilities.values()):
        raise ValueError("probabilities must be non-negative")
    raw = 10 * sum(RISK_WEIGHTS[label] * p for label, p in probabilities.items())
    return float(np.clip(raw, 0.0, 10.0))


def predict_probabilities(features: dict) -> dict:
    bundle = load_bundle()
    X = pd.DataFrame([features], columns=MODEL_FEATURES)
    proba = bundle["model"].predict_proba(X)[0]
    return {label: float(p) for label, p in zip(bundle["labels"], proba)}


def score_url(url: str, top_k: int = 5) -> dict:
    """Score one URL (string only, never fetched). Returns score, type, confidence, reasons."""
    features = extract_features(url)
    probs = predict_probabilities(features)
    url_type = max(probs, key=probs.get)
    explanation = explain_features(features, top_k)
    return {
        "url": url,
        "score": round(ml_score(probs), 1),
        "type": url_type,
        "confidence": round(probs[url_type], 3),
        "probabilities": {k: round(v, 3) for k, v in probs.items()},
        "uses_https": bool(features["has_https"]),  # display only; not a model input
        "reasons": [e["sentence"] for e in explanation],
        "explanation": explanation,
    }


def format_result(r: dict) -> str:
    reasons = "; ".join(r["reasons"]) or "no strong signals"
    return f"Score: {r['score']}/10 | Type: {r['type'].capitalize()} ({r['confidence']:.0%}) | Reasons: {reasons}"
