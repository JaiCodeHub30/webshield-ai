"""Domain-grouped train/test split and feature matrices for the redesigned dataset.

Input:  data/processed/combined_with_source.csv (from src.build_dataset; url,type,source)
Output: data/processed/split_{train,test}.csv    url,type,source,domain
        data/processed/features_{train,test}.csv MODEL_FEATURES + type + domain + source

Split: GroupShuffleSplit by registered domain (tldextract, offline suffix list), so no domain
is in both train and test. `source` is kept for auditing/analysis only, never as a feature.
URLs are strings only; nothing is fetched.

Run: python -m src.prepare_training
"""
import json
from pathlib import Path

import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit

from src.build_dataset import LABEL_MAP
from src.features import MODEL_FEATURES, build_matrix, validate

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"
RANDOM_STATE = 42
TEST_SIZE = 0.2

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled suffix list


def registered_domain(url: str) -> str:
    """Registered domain (e.g. 'example.co.uk'); falls back to the bare host for IPs/odd hosts."""
    ext = _EXTRACT(url)
    if ext.top_domain_under_public_suffix:
        return ext.top_domain_under_public_suffix
    return ".".join(p for p in (ext.subdomain, ext.domain, ext.suffix) if p) or url


def split_by_domain(df: pd.DataFrame):
    gss = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    tr, te = next(gss.split(df, df["type"], groups=df["domain"]))
    return df.iloc[tr].reset_index(drop=True), df.iloc[te].reset_index(drop=True)


def main():
    label_map = json.loads((PROCESSED / "label_map.json").read_text())["label_to_id"]
    assert label_map == LABEL_MAP, "label_map.json does not match build_dataset.LABEL_MAP"
    df = pd.read_csv(PROCESSED / "combined_with_source.csv", dtype={"url": str},
                     keep_default_na=False)
    assert list(df.columns) == ["url", "type", "source"] and df["url"].is_unique
    df["domain"] = df["url"].map(registered_domain)
    print(f"rows={len(df):,}  unique domains={df['domain'].nunique():,}")

    train, test = split_by_domain(df)
    overlap = set(train["domain"]) & set(test["domain"])
    assert not overlap, f"{len(overlap)} domains in both train and test"
    names = {v: k for k, v in LABEL_MAP.items()}
    for name, d in (("train", train), ("test", test)):
        c = d["type"].map(names).value_counts()
        print(f"{name}: {len(d):,} rows, " + ", ".join(f"{k}={c.get(k, 0):,} ({c.get(k, 0) / len(d):.1%})"
                                                       for k in LABEL_MAP))
        print(f"   by source: {d['source'].value_counts().to_dict()}")
    print("domain overlap train/test: 0 (verified)")

    for name, d in (("train", train), ("test", test)):
        d.to_csv(PROCESSED / f"split_{name}.csv", index=False)
        X = build_matrix(d["url"])
        validate(X, len(d))
        pd.concat([X, d[["type", "domain", "source"]]], axis=1).to_csv(
            PROCESSED / f"features_{name}.csv", index=False)
        print(f"features_{name}.csv: {X.shape[0]:,} x {X.shape[1]} features")


if __name__ == "__main__":
    main()
