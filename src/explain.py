"""Phase 4: SHAP explanations for the URL classifier, turned into plain-English sentences.

What is explained: the RISK, not a single class. The ML score is a linear combination of
class probabilities (see scoring.RISK_WEIGHTS), and SHAP values are additive per class, so
    risk_shap[f] = 10 * sum_c RISK_WEIGHTS[c] * shap[f, c]
is an exact per-feature attribution of the uncalibrated model's risk score.

Caveat: TreeExplainer explains the base Random Forest. The served probabilities come from
isotonic calibration on top of it (monotone per class, then renormalised), so SHAP reasons
explain the direction and drivers of the risk, not the calibrated number to the decimal.
"""
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap

from src.features import MODEL_FEATURES, SUSPICIOUS_KEYWORDS, extract_features

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "webshield_model.joblib"
MIN_CONTRIBUTION = 0.05  # ignore features moving the risk by < 0.05 points (on the 0-10 scale)


@lru_cache(maxsize=1)
def load_bundle(path: Path = MODEL_PATH) -> dict:
    bundle = joblib.load(path)
    assert bundle["features"] == MODEL_FEATURES, "model was trained on a different feature set; retrain"
    return bundle


def base_estimator(calibrated):
    """Underlying fitted tree model inside CalibratedClassifierCV(FrozenEstimator(model))."""
    est = calibrated.calibrated_classifiers_[0].estimator
    return getattr(est, "estimator", est)


@lru_cache(maxsize=1)
def get_explainer() -> shap.TreeExplainer:
    return shap.TreeExplainer(base_estimator(load_bundle()["model"]))


def shap_values_3d(explainer, X: pd.DataFrame) -> np.ndarray:
    """Return SHAP values as (n_rows, n_features, n_classes) across SHAP versions."""
    sv = explainer.shap_values(X)
    if isinstance(sv, list):  # older SHAP: list of (n_rows, n_features), one per class
        sv = np.stack(sv, axis=-1)
    return np.asarray(sv)


_KW = {f"kw_{k}": k for k in SUSPICIOUS_KEYWORDS}


def feature_sentence(name: str, value: float) -> str:
    """Describe a feature's value for one URL in plain English."""
    v = int(value) if float(value).is_integer() else value
    if name in _KW:
        return f'contains the word "{_KW[name]}"' if v else f'does not contain the word "{_KW[name]}"'
    templates = {
        "url_length": f"URL is {v} characters long",
        "domain_length": f"domain name is {v} characters long",
        "path_length": f"path is {v} characters long",
        "query_length": f"query string is {v} characters long",
        "num_dots": f"URL has {v} dots",
        "num_hyphens": f"URL has {v} hyphens",
        "num_digits": f"URL contains {v} digits",
        "digit_ratio": f"{value:.0%} of the URL's characters are digits",
        "num_special_chars": f"URL has {v} special characters",
        "num_at": f'URL contains {v} "@" sign(s)' if v else 'URL has no "@" sign',
        "num_double_slash": f'URL contains {v} extra "//"' if v else 'URL has no extra "//"',
        "num_percent": f"URL has {v} percent-encoded characters" if v else "URL has no percent-encoding",
        "num_query_params": f"URL has {v} query parameters",
        "has_ip": "uses a raw IP address instead of a domain name" if v else "uses a domain name, not an IP address",
        "num_subdomains": f"domain has {v} subdomain level(s)" if v else "domain has no subdomains",
        "has_https": "uses HTTPS" if v else "does not use HTTPS",
        "num_suspicious_keywords": f"contains {v} suspicious keyword(s)",
        "suspicious_tld": "uses a top-level domain often abused by attackers" if v else "uses a common top-level domain",
        "tld_length": f"top-level domain is {v} characters long",
        "is_shortener": "is a URL-shortener link (hides the real destination)" if v else "is not a shortener link",
        "url_entropy": f"URL looks {'random' if value >= 4.5 else 'fairly regular'} (character entropy {value:.2f})",
    }
    return templates[name]


def _sentence_case(s: str) -> str:
    return s[:1].upper() + s[1:]  # unlike str.capitalize(), keeps "URL", "IP", "HTTPS" intact


def explain_features(features: dict, top_k: int = 5) -> list[dict]:
    """Top features by absolute contribution to the 0-10 risk, with plain-English sentences."""
    from src.scoring import RISK_WEIGHTS  # local import: scoring imports this module

    bundle = load_bundle()
    X = pd.DataFrame([features], columns=MODEL_FEATURES)
    sv = shap_values_3d(get_explainer(), X)[0]  # (n_features, n_classes)
    weights = np.array([RISK_WEIGHTS[label] for label in bundle["labels"]])
    risk_contrib = 10 * sv @ weights  # (n_features,)

    order = np.argsort(-np.abs(risk_contrib))
    out = []
    for i in order[:top_k]:
        c = float(risk_contrib[i])
        if abs(c) < MIN_CONTRIBUTION:
            break
        name = MODEL_FEATURES[i]
        out.append({
            "feature": name,
            "value": features[name],
            "contribution": round(c, 3),
            "sentence": f"{_sentence_case(feature_sentence(name, features[name]))} "
                        f"({'raises' if c > 0 else 'lowers'} risk by {abs(c):.1f})",
        })
    return out


def explain_url(url: str, top_k: int = 5) -> list[dict]:
    return explain_features(extract_features(url), top_k)
