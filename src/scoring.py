"""URL risk score (0-10) with type, confidence and plain-English reasons.

ml_score = 10 * (1.0*P(malware) + 0.9*P(phishing) + 0.5*P(defacement))   (CLAUDE.md)
Probabilities come from the calibrated model.

Rule layer (string analysis only, nothing fetched):
  * brand impersonation (src/brands.py): look-alike, misspelled or combined brand domains
  * attack payloads (src/attack_rules.py): traversal, injection, sensitive-file probes
Each finding carries a severity on the 0-10 scale. The final score is
    max(ml_score, rule_floor)
so rules can only raise the score, never lower it, and the ML score is always reported too.
Threat intel is added in Phase 5.
"""
import numpy as np
import pandas as pd

from src.attack_rules import attack_floor, find_attacks
from src.brands import analyze as brand_signals
from src.brands import brand_findings
from src.explain import explain_features, load_bundle
from src.features import MODEL_FEATURES, extract_features, split_url

RISK_WEIGHTS = {"benign": 0.0, "phishing": 0.9, "malware": 1.0, "defacement": 0.5}
RULE_TYPES = {"brand": "phishing", "attack": "attack payload"}


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


def rule_findings(url: str) -> list[dict]:
    """Brand-impersonation and attack-payload findings, each tagged with its family."""
    _, body, host, path, query = split_url(url)
    found = []
    if host and not host.replace(".", "").isdigit():
        signals = brand_signals(host, path + ("?" + query if query else ""))
        found += [{**f, "family": "brand"} for f in brand_findings(signals)]
    found += [{**f, "family": "attack"} for f in find_attacks(body)]
    return sorted(found, key=lambda f: -f["severity"])


def rule_floor(findings: list[dict]) -> float:
    """Highest severity, plus a small bonus per extra finding (attack_rules.COMBINATION_BONUS)."""
    return attack_floor(findings)


def score_url(url: str, top_k: int = 5) -> dict:
    """Score one URL (string only, never fetched). Returns score, type, confidence, reasons."""
    features = extract_features(url)
    probs = predict_probabilities(features)
    ml_type = max(probs, key=probs.get)
    ml = ml_score(probs)
    findings = rule_findings(url)
    floor = rule_floor(findings)
    rule_driven = floor > ml
    url_type = RULE_TYPES[findings[0]["family"]] if rule_driven else ml_type
    explanation = explain_features(features, top_k)
    rule_reasons = [f"{f['description'][0].upper()}{f['description'][1:]} (rule, severity {f['severity']:.1f})"
                    for f in findings]
    return {
        "url": url,
        "score": round(max(ml, floor), 1),
        "type": url_type,
        # ML confidence only describes the ML type; for a rule-driven verdict it is None.
        "confidence": None if rule_driven else round(probs[ml_type], 3),
        "ml_score": round(ml, 1),
        "ml_type": ml_type,
        "rule_floor": round(floor, 1),
        "rule_findings": findings,
        "probabilities": {k: round(v, 3) for k, v in probs.items()},
        "uses_https": bool(features["has_https"]),  # display only; not a model input
        "reasons": rule_reasons + [e["sentence"] for e in explanation],
        "explanation": explanation,
    }


def format_result(r: dict) -> str:
    reasons = "; ".join(r["reasons"]) or "no strong signals"
    conf = f"{r['confidence']:.0%}" if r["confidence"] is not None else "rule-based"
    return f"Score: {r['score']}/10 | Type: {r['type'].capitalize()} ({conf}) | Reasons: {reasons}"
