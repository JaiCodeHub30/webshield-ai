# Legacy artifacts (pre-redesign)

The project was redesigned starting from a new Phase 1 (`src/build_dataset.py`). Everything below belongs to the **old** pipeline (git commits `44aadb6`..`0c85768`) and is **incompatible** with the redesigned dataset. Do not use it as input to, or evidence for, the new pipeline.

| Artifact | Location now | Why incompatible |
|---|---|---|
| Old cleaned data and Kaggle-only split (`clean.csv`, `train.csv`, `test.csv`) | `data/processed/legacy_pre_redesign/` (gitignored) | Kaggle only; string labels; schemes kept; old dedup rules |
| Old feature matrices (`features_*.csv`, `features_*_v1.csv`) | `data/processed/legacy_pre_redesign/` (gitignored) | Built from the old data; string `type` column; 29/30-feature layouts |
| Old models (`webshield_model.joblib`, `*_uncalibrated.joblib`, `archive/v1_with_https/`) | `models/legacy_pre_redesign/` (gitignored) | Trained on old data; label index order came from old code, not `label_map.json` |
| Old code: `src/data_prep.py`, `src/features.py`, `src/train.py`, `src/explain.py`, `src/scoring.py`, `src/examples.py` | unchanged in `src/` | Read the old files above. `data_prep.py` would write `clean/train/test.csv` into `data/processed/`; do not run it alongside the new pipeline |
| Old reports (`reports/phase3`, `reports/phase4`, `reports/archive`, `reports/CHANGELOG.md`) | unchanged | Metrics for the old model only |
| `notebooks/01_eda.ipynb` | unchanged | Reads old `clean.csv`/`train.csv`/`test.csv` |
| `CLAUDE.md` | unchanged | No longer the specification for the redesign |

Old tests that need the old model (`tests/test_scoring.py` model-backed tests) now **skip**, because the model was moved out of `models/`. Nothing was deleted.

## New Phase 1 outputs (the only valid inputs for later phases)
- `data/processed/final_dataset.csv`: `url,type`; integer labels; deterministic shuffle
- `data/processed/combined_with_source.csv`: `url,type,source`, for auditing and domain-based splitting only (never use `source` as a feature)
- `data/processed/label_map.json`: `benign=0, phishing=1, malware=2, defacement=3`

These are not committed: `data/` is gitignored because the files are derived from raw data and contain live malicious URLs (~60 MB). Rebuild with `python -m src.build_dataset`. The label map is also defined in code (`src/build_dataset.py: LABEL_MAP`) and checked by tests.
