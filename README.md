# WebShield AI

Explainable malicious URL grading: risk score 0-10, URL type, and plain-English reasons.

**Status:** redesigned from Phase 1. See `LEGACY_ARTIFACTS.md` for the old pipeline's files, which do not apply to the redesign.

## Setup
```
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Phase 1: build the combined dataset
Put the five raw sources in `data/raw/`:

| Source | Expected file (matched by pattern) | Label |
|---|---|---|
| Kaggle Malicious URLs | `malicious_phish*.csv` | its own `type` |
| Tranco top domains | `tranco*.csv` (`rank,domain`, no header) | benign (100k sampled from top 200k, with generated paths) |
| URLhaus | `urlhaus*.csv` or `.xlsx` | malware |
| PhishTank | `verified_online*.csv` | phishing (`verified == yes`) |
| OpenPhish | `*openphish*.txt` or `.xlsx` (one URL per line) | phishing |

```
python -m src.build_dataset     # writes data/processed/{final_dataset.csv, combined_with_source.csv, label_map.json}
python -m pytest tests
```
Labels: `benign=0, phishing=1, malware=2, defacement=3`. URLs are treated as text only and are never fetched. Leading `http://`/`https://` is removed from every source (`STRIP_SCHEME`), because scheme presence differs sharply between sources and classes. Normalization and dedup rules are documented at the top of `src/build_dataset.py`.
