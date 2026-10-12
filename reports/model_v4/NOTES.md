# Model v4: brand-impersonation features + rule layer

**Changes vs v3:** 7 brand features in the model (`src/brands.py`: look-alike characters, misspellings,
brand+words, brand in subdomain/path, punycode, non-ASCII host) and a rule layer on top of the ML score
(`src/brands.py` brand findings, `src/attack_rules.py` traversal/injection/sensitive-file patterns).
Final score = max(ML score, rule floor); rules never lower a score.

**ML metrics (test, calibrated RF):** macro F1 0.731, ROC-AUC 0.925 (v3: 0.733 / 0.926). The brand
features are rare (about 0.3% of phishing URLs have a typosquat flag), so the ML model barely changes;
the gain comes from the rule layer.

**Full system on the test split (rules + ML):** phishing flagged (score >= 5) 43.9% -> 44.4%;
benign flagged 8.6% -> 9.5%.

**Why the "benign" increase is mostly label noise:** 1,075 benign-labelled test URLs reach >= 5 only
through rules, all from Kaggle (0 of 19,958 Tranco). 918 of the 1,105 rule-flagged Kaggle "benign" URLs
impersonate PayPal (`paypal.com.cgi-bin.webscr...`, `paypal-confirm.de`), the rest mostly eBay, Facebook,
Mastercard look-alikes. These are phishing URLs mislabelled benign in the Kaggle data. Genuine false
alarms are rare (a few hundred at most, <0.25% of benign), e.g. `print-2-mail.com`.
Kaggle-label ROC-AUC (malicious vs benign) therefore drops 0.881 -> 0.875, which understates the rules.

**Tuning on training data only:** the typosquat target list (top 300 Tranco labels + TARGET_BRANDS) and
the lure-word requirement for everyday-word brands (office, orange, chase...) were chosen from train
URLs and a hand-made positive/negative list; the test split was only used for this report.

**Attack rules:** 0 of 523,701 benign URLs (and 0 `etc/passwd` rows of any class) existed to learn from,
so these are rules, not ML. 15 benign URLs matched any attack rule (0.003%), mostly `file:///` in redirect
parameters; a single `../` is scored 5.0, `../` reaching a sensitive file 9.0.

**Known weaknesses:** `docs.python.org/...` still scores 6.7 (dots/subdomain features; ML only);
phishing recall of the ML model on PhishTank is ~39%: the features cannot see most modern phishing
hosted on free platforms. Brand lists come from the Tranco top-10k plus ~70 hand-picked targets, so
brands outside that list are not covered.
