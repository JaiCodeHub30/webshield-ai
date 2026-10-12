# Model changelog

## v2-no-https (current)
**Change:** `has_https` removed from model inputs. It is still extracted by `extract_features()` and returned by `score_url()` as `uses_https` for display, but it is excluded from `MODEL_FEATURES`, the saved feature matrices, training, SHAP explanations and the score.

**Why:** in the Kaggle training data ~92% of benign URLs have no scheme, so `https://` almost only appears on malicious rows. v1 learned "HTTPS = phishing": `https://www.google.com/search?q=weather` scored 6.4 (phishing) and `https://docs.python.org/...` 8.2, with "Uses HTTPS" as the top reason. Real-world inputs (and the Phase 5 OpenPhish/Tranco set) almost always carry a scheme.

**Procedure (no test-set use):** same Phase 1 domain split; matrices rebuilt with 29 features; LR/RF/XGBoost refit with balanced sample weights on the same domain-grouped fit split; best chosen on the same validation split by macro F1 (RF again); isotonic calibration on validation. Test set used only for the report.

**Results (test set, reporting only):**

| | v1 (with has_https) | v2 (no has_https) |
|---|---|---|
| Validation macro F1 (RF, selection metric) | 0.762 | 0.750 |
| Test macro F1, calibrated RF | 0.732 | 0.716 |
| Test ROC-AUC, calibrated RF | 0.955 | 0.942 |
| Test log loss, calibrated RF | 0.418 | 0.466 |

The small drop is the share of v1's score that came from the artifact; v2's numbers are the more honest estimate.

**Verification:** 26 tests pass, including a new test that `http://`, `https://` and scheme-less versions of a URL get identical probabilities and score, and that no HTTPS reason appears. Google example 6.4 -> 2.8.

**Previous artifacts:** `models/archive/v1_with_https/` (gitignored joblib files), `reports/archive/v1_with_https/` (v1 Phase 3 metrics and Phase 4 examples), `data/processed/features_*_v1.csv` (gitignored). v1 code is git commit `6019a1c`.

**Known remaining artifact (not fixed in v2):** empty/short paths push toward phishing. 25% of phishing training URLs have no path vs 12% of benign, and 0% of defacement. Bare `google.com` scores 9.0 (phishing), top reason "Path is 0 characters long (raises risk by 2.8)". This is the CLAUDE.md "path" pitfall in reverse and will matter for Tranco domains in Phase 5.

## v1-with-https
Original Phase 3 model (commit `6c1b14b`): 30 features including `has_https`.
