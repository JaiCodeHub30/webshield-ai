# WebShield AI

Malicious URL grading system. Takes a URL and returns a risk score (0-10), a URL type, and a plain-English explanation.

Example: `Score: 8.6/10 | Type: Phishing (78%) | Reasons: suspicious TLD, high digit count, "login" keyword, flagged by VirusTotal`

## What this project is (and is not)
- NOT a new detection algorithm. Our contribution is the risk-assessment and explanation layer: ML analysis of URL features + live threat intel, turned into an explainable 0-10 score.
- Explainability matters more than the last 0.5% accuracy. Do NOT use deep learning (CNN/LSTM/BERT) as the main model.

## Tech stack
Python 3.10+, pandas, numpy, scikit-learn, xgboost, shap, tldextract, joblib, python-dotenv, Streamlit.

## Working rules
- Work ONE phase at a time. Stop at the end of each phase and summarize.
- Commit to git after each working step.
- `data/` and `.env` must be in `.gitignore`. Never commit raw data or API keys.
- Never visit, request, or open any URL from the datasets. Treat them as strings only.
- Keep code in reusable modules (not only notebooks). `extract_features(url)` must be the single function used in both training and the live app.

## Folder structure
```
webshield-ai/
  CLAUDE.md
  README.md
  requirements.txt
  .gitignore
  .env.example
  data/
    raw/         # malicious_phish.csv (Kaggle), openphish.txt, urlhaus_recent.csv, top-1m.csv (Tranco)
    processed/   # cleaned data, splits, feature matrices
  notebooks/     # EDA
  src/
    data_prep.py
    features.py
    train.py
    explain.py
    scoring.py
    threat_intel.py
  models/
  app/
    streamlit_app.py
  reports/
```

## Datasets (in data/raw/)
- **Training:** Kaggle "Malicious URLs Dataset" (sid321axn). Columns: `url`, `type` (benign, phishing, malware, defacement).
- **Fresh test set (Phase 5):** OpenPhish feed (phishing, one URL per line) + Tranco top domains (benign, domains only; add realistic paths).
- **Live lookups only (Phase 5):** URLhaus, VirusTotal, Google Safe Browsing. Do NOT use these as test labels (circularity).
- URLhaus CSV: skip `#` comment lines, columns are `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`.

## ML approach
- 4-class classification: benign / phishing / malware / defacement.
- Hand-made, human-readable features (so SHAP can explain them): URL/domain/path length, dots, hyphens, digits, special chars (@, //, %), IP instead of domain, subdomain count, HTTPS, suspicious keywords (login, verify, secure, bank, update), TLD, URL shortener, string entropy.
- Models: Logistic Regression (baseline), Random Forest, XGBoost (`multi:softprob`). Pick best by macro F1 and ROC-AUC.
- Handle imbalance with sample weights. Report per-class precision/recall, not just accuracy.
- Split by domain with `GroupShuffleSplit` (group = registered domain from tldextract).
- Calibrate with `CalibratedClassifierCV`.
- SHAP `TreeExplainer` for top features per prediction.

## Scoring
- `ml_score = 10 * (1.0*P(malware) + 0.9*P(phishing) + 0.5*P(defacement))`
- Threat intel pushes the score up (Safe Browsing hit, VirusTotal engine count, URLhaus match).
- Final score = ML score blended with threat intel, clipped to 0-10. Weights must be justified in the report.
- Explanation = top SHAP features as plain sentences + which threat-intel sources matched.

## Pitfalls
- Data leakage: same domain in train and test.
- Circularity: same source for training labels and live lookups.
- Stale data: evaluate on fresh URLs collected after training.
- Tranco gives only domains: add realistic paths so the model doesn't learn "has a path = malicious".

## Phases and prompts

### Phase 1: Setup and data preparation
Prompt: "Read CLAUDE.md. Do Phase 1 only: create the project structure, .gitignore, requirements.txt and venv. Load the Kaggle CSV from data/raw/, clean it (drop duplicates, strip/normalize URLs, handle nulls), check class balance, extract the registered domain with tldextract, and create a GroupShuffleSplit train/test split by domain. Save outputs to data/processed/. Make an EDA notebook with class distribution plots. Verify no domain appears in both train and test. Commit when done."

### Phase 2: Feature engineering
Prompt: "Do Phase 2 only: write src/features.py with extract_features(url) covering all features listed in CLAUDE.md. Add a few unit tests. Build feature matrices for train and test and save to data/processed/. Commit when done."

### Phase 3: Model training and evaluation
Prompt: "Do Phase 3 only: train Logistic Regression, Random Forest and XGBoost with sample weights. Compare on macro F1, ROC-AUC, per-class precision/recall, and confusion matrices. Calibrate the best model with CalibratedClassifierCV, plot a calibration curve, and save with joblib to models/. Commit when done."

### Phase 4: Explainability and scoring engine
Prompt: "Do Phase 4 only: add SHAP TreeExplainer, convert top features into plain-English sentences, and implement score_url(url) returning score, type, confidence and reasons (ML only). Show 10 example outputs. Commit when done."

### Phase 5: Threat intel, UI, final evaluation
Prompt: "Do Phase 5 only: integrate Google Safe Browsing, VirusTotal and URLhaus with caching and rate-limit handling (keys from .env). Blend with ML score. Build the Streamlit UI. Evaluate on a fresh set (OpenPhish + Tranco with added paths) and report ML-only and blended results separately. Commit when done."
