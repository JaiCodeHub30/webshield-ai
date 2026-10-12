"""Phase 1: clean the Kaggle malicious URL dataset and split train/test by registered domain.

URLs are treated as strings only; nothing is ever requested.
Run: python -m src.data_prep
"""
from pathlib import Path

import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "malicious_phish.csv"
PROCESSED = ROOT / "data" / "processed"
LABELS = ["benign", "phishing", "malware", "defacement"]
RANDOM_STATE = 42
TEST_SIZE = 0.2

# Offline extractor: use the bundled public-suffix snapshot, never hit the network.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def normalize_url(url: str) -> str:
    """Strip whitespace/quotes and lowercase the scheme and host (path case is kept)."""
    url = str(url).strip().strip("'\"").strip()
    scheme, sep, rest = url.partition("://")
    if sep and scheme.isalpha():
        host, slash, path = rest.partition("/")
        return f"{scheme.lower()}://{host.lower()}{slash}{path}"
    host, slash, path = url.partition("/")
    return f"{host.lower()}{slash}{path}"


def registered_domain(url: str) -> str:
    """Registered domain (e.g. 'example.co.uk'); falls back to the bare host for IPs/odd hosts."""
    ext = _EXTRACT(url)
    reg = ext.top_domain_under_public_suffix
    if reg:
        return reg
    return ".".join(p for p in (ext.subdomain, ext.domain, ext.suffix) if p) or url


def load_and_clean(path: Path = RAW) -> pd.DataFrame:
    df = pd.read_csv(path)
    n0 = len(df)
    df = df.dropna(subset=["url", "type"])
    df["url"] = df["url"].map(normalize_url)
    df["type"] = df["type"].str.strip().str.lower()
    df = df[(df["url"] != "") & df["type"].isin(LABELS)]
    df = df.drop_duplicates(subset=["url", "type"])
    # The same URL with different labels is ambiguous: drop all copies.
    conflicting = df["url"].duplicated(keep=False)
    print(f"rows: raw={n0}, after clean/dedup={len(df)}, conflicting-label rows dropped={conflicting.sum()}")
    df = df[~conflicting].reset_index(drop=True)
    df["domain"] = df["url"].map(registered_domain)
    return df


def split_by_domain(df: pd.DataFrame):
    gss = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    train_idx, test_idx = next(gss.split(df, df["type"], groups=df["domain"]))
    return df.iloc[train_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)


def class_balance(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["type"].value_counts().reindex(LABELS, fill_value=0)
    return pd.DataFrame({"count": counts, "pct": (100 * counts / counts.sum()).round(2)})


def main():
    PROCESSED.mkdir(parents=True, exist_ok=True)
    df = load_and_clean()
    print("\nClass balance (full):\n", class_balance(df))
    print(f"\nunique domains: {df['domain'].nunique()}")

    train, test = split_by_domain(df)
    overlap = set(train["domain"]) & set(test["domain"])
    assert not overlap, f"{len(overlap)} domains leak between train and test"
    print(f"\ntrain={len(train)}  test={len(test)}  domain overlap=0 (verified)")
    print("\nClass balance (train):\n", class_balance(train))
    print("\nClass balance (test):\n", class_balance(test))

    df.to_csv(PROCESSED / "clean.csv", index=False)
    train.to_csv(PROCESSED / "train.csv", index=False)
    test.to_csv(PROCESSED / "test.csv", index=False)
    print(f"\nsaved to {PROCESSED}")


if __name__ == "__main__":
    main()
