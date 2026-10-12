# Phase 4 notes: explainability and ML-only scoring

## Method
- `ml_score = 10 * (1.0*P(malware) + 0.9*P(phishing) + 0.5*P(defacement))`, using the **calibrated** model's probabilities, clipped to 0-10.
- `type` = most probable calibrated class; `confidence` = its probability.
- Reasons explain the **risk score**, not one class: because the score is a linear mix of class probabilities and SHAP values are additive, `risk_shap = 10 * shap_values @ weights` is an exact per-feature attribution (checked by a unit test to 1e-6).
- Reasons with |contribution| < 0.05 points are dropped; top 5 are shown.

## SHAP compatibility
- SHAP 0.53.0, scikit-learn 1.9.1. `TreeExplainer` is applied to the Random Forest inside `CalibratedClassifierCV(FrozenEstimator(rf))`, reached via `calibrated_classifiers_[0].estimator.estimator`.
- SHAP 0.53 returns shape `(rows, features, classes)`; older versions return a list per class. `shap_values_3d()` handles both.
- SHAP cannot explain the isotonic calibration step. Reasons describe the base RF's risk drivers; the shown score is from calibrated probabilities. Calibration is monotone per class, so directions agree, but contribution sizes are on the uncalibrated scale.

## Performance
- Explainer construction: ~0.6 s (cached once per process).
- Per URL: ~1.0 s, almost entirely exact TreeSHAP over 200 deep trees (`min_samples_leaf=5`). First call ~3 s (warm-up).
- Acceptable for single-URL lookups in the UI; too slow for bulk explanation. Options if needed: explain only on demand, `shap.TreeExplainer(..., feature_perturbation="tree_path_dependent")` with shallower trees, or explain the XGBoost model (much faster).

## Model version
These notes and `examples.md` are for model **v2-no-https** (see `reports/CHANGELOG.md`). `has_https` is display-only and never appears as a reason. v1 outputs are archived in `reports/archive/v1_with_https/`.

## Current weaknesses seen in the examples (v2)
- **Bare domains:** `google.com` scores 9.0 (phishing): "Path is 0 characters long" is the top reason. Kaggle phishing URLs are often bare domains while benign ones mostly have paths. Needs fixing before Phase 5 Tranco evaluation (e.g. drop/transform path features or add benign bare-domain training examples).
- **Dot count:** `docs.python.org/3/library/urllib.parse.html` scores 6.1 because "URL has 4 dots" raises risk.
- **Look-alike phishing** scores only mid-range (4.1-4.8): keywords and abused TLDs help but are weak in this data.
- **Shorteners** are inconsistent (`tinyurl.com/...` 1.9, `bit.ly/...` 6.0, `t.co/...` 6.7), driven by 2-letter TLD and length rather than the shortener flag, which is rare in training data.
- **Raw-IP URLs** score 9.7-10.0 (malware) as intended.
