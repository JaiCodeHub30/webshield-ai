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

## Known model issue (from Phase 2/3, not fixed here)
`has_https` acts as a dataset artifact. In the Kaggle data ~92% of benign URLs have no scheme, so `https` almost only appears on malicious rows. Result: legitimate HTTPS URLs get high scores (examples: `https://www.google.com/...` 6.4, `https://docs.python.org/...` 8.2) with "Uses HTTPS" as the top reason.
Recommended fix (needs a Phase 3 retrain on training data only): drop `has_https` from the model features (keep it for display), retrain, recalibrate. The Phase 5 fresh evaluation would otherwise be distorted, since OpenPhish/Tranco URLs all carry schemes.

Other observations: obvious keyword/TLD phishing (`...secure-login.tk/signin/update.php`) only scores 3.6, and the `bit.ly` shortener flag barely registers (very few shorteners in training data).
