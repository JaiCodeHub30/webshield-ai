import numpy as np
import pandas as pd
import pytest

from src.explain import MODEL_PATH, feature_sentence
from src.features import FEATURE_NAMES, MODEL_FEATURES, SUSPICIOUS_KEYWORDS, extract_features
from src.scoring import RISK_WEIGHTS, ml_score

needs_model = pytest.mark.skipif(not MODEL_PATH.exists(), reason="trained model not present (run src.train)")


# --- pure scoring formula ---------------------------------------------------------------
@pytest.mark.parametrize("probs, expected", [
    ({"benign": 1, "phishing": 0, "malware": 0, "defacement": 0}, 0.0),
    ({"benign": 0, "phishing": 0, "malware": 1, "defacement": 0}, 10.0),
    ({"benign": 0, "phishing": 1, "malware": 0, "defacement": 0}, 9.0),
    ({"benign": 0, "phishing": 0, "malware": 0, "defacement": 1}, 5.0),
    ({"benign": 0.25, "phishing": 0.25, "malware": 0.25, "defacement": 0.25}, 6.0),
])
def test_ml_score_formula(probs, expected):
    assert ml_score(probs) == pytest.approx(expected)


def test_ml_score_bounds_random():
    rng = np.random.default_rng(0)
    for p in rng.dirichlet(np.ones(4), size=500):
        s = ml_score(dict(zip(["benign", "phishing", "malware", "defacement"], p)))
        assert 0.0 <= s <= 10.0


def test_ml_score_rejects_bad_probabilities():
    with pytest.raises(ValueError):
        ml_score({"benign": 0.5, "phishing": 0.1, "malware": 0, "defacement": 0})
    with pytest.raises(ValueError):
        ml_score({"benign": 1.2, "phishing": -0.2, "malware": 0, "defacement": 0})


def test_every_feature_has_a_sentence():
    for name in FEATURE_NAMES:
        for v in (0, 1, 3.7):
            assert isinstance(feature_sentence(name, v), str)
    assert "IP address" in feature_sentence("has_ip", 1)
    assert SUSPICIOUS_KEYWORDS[0] in feature_sentence(f"kw_{SUSPICIOUS_KEYWORDS[0]}", 1)


# --- model-backed ---------------------------------------------------------------------
@needs_model
def test_model_feature_alignment():
    from src.explain import load_bundle
    b = load_bundle()
    assert b["features"] == MODEL_FEATURES
    assert "has_https" not in b["features"]
    assert b["model"].n_features_in_ == len(MODEL_FEATURES)
    assert set(b["labels"]) == set(RISK_WEIGHTS)


@needs_model
@pytest.mark.parametrize("url", ["google.com", "http://192.168.10.5/secure/login/bank-update.php", ""])
def test_score_url_output(url):
    from src.scoring import score_url
    r = score_url(url)
    assert 0.0 <= r["score"] <= 10.0
    assert r["type"] in RISK_WEIGHTS
    assert sum(r["probabilities"].values()) == pytest.approx(1.0, abs=0.01)
    assert r["confidence"] == max(r["probabilities"].values())
    for e in r["explanation"]:
        assert e["feature"] in MODEL_FEATURES  # display-only features never appear as reasons
        assert e["value"] == extract_features(url)[e["feature"]]  # explanation describes THIS url
    assert len(r["reasons"]) == len(r["explanation"]) <= 5


@needs_model
def test_shap_risk_contributions_are_additive():
    """Risk SHAP values + base value must equal the (uncalibrated) base-model risk."""
    from src.explain import base_estimator, get_explainer, load_bundle, shap_values_3d
    b = load_bundle()
    f = extract_features("http://paypal-secure-verify.tk/account/login?id=123456")
    X = pd.DataFrame([f], columns=MODEL_FEATURES)
    w = np.array([RISK_WEIGHTS[label] for label in b["labels"]])
    ex = get_explainer()
    contrib = 10 * shap_values_3d(ex, X)[0] @ w
    base = 10 * np.asarray(ex.expected_value) @ w
    model_risk = 10 * base_estimator(b["model"]).predict_proba(X)[0] @ w
    assert contrib.sum() + base == pytest.approx(model_risk, abs=1e-6)


@needs_model
@pytest.mark.parametrize("rest", ["www.google.com/search?q=weather", "docs.python.org/3/library/urllib.parse.html",
                                  "198.51.100.23:8080/Photo.scr"])
def test_score_is_scheme_invariant(rest):
    """Scheme must not move the score (v1 learned https = phishing from a Kaggle artifact)."""
    from src.scoring import score_url
    plain, http, https = (score_url(p + rest) for p in ("", "http://", "https://"))
    assert plain["probabilities"] == http["probabilities"] == https["probabilities"]
    assert plain["score"] == http["score"] == https["score"]
    assert https["uses_https"] and not http["uses_https"]
    assert not any("HTTPS" in r for r in https["reasons"])
