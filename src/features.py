"""Phase 2: human-readable URL features.

`extract_features(url)` is the single feature function used for training and the live app.
URLs are parsed as strings only; nothing is ever requested.

Dataset artifact: in the Kaggle data almost every defacement/malware URL carries an
"http(s)://" prefix while ~92% of benign URLs have none. To stop the model learning
"has a scheme = malicious", every feature except `has_https` is computed on the URL with
the scheme removed, and scheme presence itself is not a feature.

`has_https` is still extracted (FEATURE_NAMES) for display, but it is DISPLAY-ONLY: it is
excluded from MODEL_FEATURES, the saved matrices and the model. With it, v1 of the model
learned "https = phishing" (https almost never appears on benign Kaggle rows) and scored
https://www.google.com as 6.4/10. See reports/CHANGELOG.md.

Run: python -m src.features   (builds feature matrices from data/processed/{train,test}.csv)
"""
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

from src.brands import analyze as brand_signals

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled suffix list
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "bank", "update", "account", "signin", "password", "confirm"]
# TLDs frequently abused for phishing/malware (Spamhaus / Interisle reports); a judgement call, kept short.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "work", "click", "link", "country",
    "kim", "loan", "men", "date", "racing", "review", "stream", "download", "cam", "rest", "icu", "ru", "cn",
}
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "qrco.de", "lnkd.in", "db.tt",
}

# Brand-impersonation signals from src/brands.py (typosquatting family).
BRAND_FEATURES = ["brand_homoglyph", "brand_typosquat", "brand_combosquat", "brand_in_subdomain",
                  "brand_in_path", "has_punycode", "non_ascii_host"]

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_digits", "digit_ratio", "num_special_chars",
    "num_at", "num_double_slash", "num_percent", "num_query_params",
    "has_ip", "num_subdomains", "has_https",
    *[f"kw_{k}" for k in SUSPICIOUS_KEYWORDS], "num_suspicious_keywords",
    "suspicious_tld", "tld_length", "is_shortener", "url_entropy",
    *BRAND_FEATURES,
]


# Extracted but never fed to the model (dataset artifacts); shown to users only.
DISPLAY_ONLY_FEATURES = ["has_https"]
MODEL_FEATURES = [f for f in FEATURE_NAMES if f not in DISPLAY_ONLY_FEATURES]


def _strip_scheme(url: str) -> tuple[str, str]:
    m = _SCHEME_RE.match(url)
    return (url[: m.end() - 3].lower(), url[m.end():]) if m else ("", url)


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Hex / dword-encoded IPv4 such as 0x7f000001 or 3232235777
        return bool(re.fullmatch(r"0x[0-9a-f]{1,8}|\d{8,10}", host))


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_url(url: str) -> tuple[str, str, str, str, str]:
    """(scheme, body-without-scheme, host, path, query) for a URL string; never fetches."""
    url = str(url).strip()
    scheme, body = _strip_scheme(url)
    try:
        parts = urlsplit("http://" + body)
        host = (parts.hostname or "").lower()
        path, query = parts.path, parts.query
    except ValueError:  # malformed (e.g. broken IPv6 brackets): fall back to manual split
        host, _, rest = body.partition("/")
        host = host.split(":")[0].lower()
        path, _, query = ("/" + rest).partition("?")
    return scheme, body, host, path, query


def extract_features(url: str) -> dict:
    """Return a dict of numeric, human-readable features (keys == FEATURE_NAMES)."""
    scheme, body, host, path, query = split_url(url)

    ext = _EXTRACT(host)
    is_ip = _is_ip(host)
    sub = [s for s in ext.subdomain.split(".") if s and s != "www"] if not is_ip else []
    lower = body.lower()
    kw = {f"kw_{k}": int(k in lower) for k in SUSPICIOUS_KEYWORDS}
    digits = sum(ch.isdigit() for ch in body)
    reg = ext.top_domain_under_public_suffix

    f = {
        "url_length": len(body),
        "domain_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": body.count("."),
        "num_hyphens": body.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / len(body) if body else 0.0,
        "num_special_chars": sum(not ch.isalnum() and ch not in "./-" for ch in body),
        "num_at": body.count("@"),
        "num_double_slash": body.count("//"),
        "num_percent": body.count("%"),
        "num_query_params": len([p for p in query.split("&") if p]) if query else 0,
        "has_ip": int(is_ip),
        "num_subdomains": len(sub),
        "has_https": int(scheme == "https"),
        **kw,
        "num_suspicious_keywords": sum(kw.values()),
        "suspicious_tld": int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS) if ext.suffix else 0,
        "tld_length": len(ext.suffix),
        "is_shortener": int(reg in SHORTENERS or host in SHORTENERS),
        "url_entropy": _entropy(body),
    }
    if is_ip or not host:
        f.update({k: 0 for k in BRAND_FEATURES})
    else:
        b = brand_signals(host, path + ("?" + query if query else ""))
        f.update({k: b[k] for k in BRAND_FEATURES})
    return f


def build_matrix(urls, columns=MODEL_FEATURES) -> pd.DataFrame:
    return pd.DataFrame([extract_features(u) for u in urls], columns=columns)


def validate(X: pd.DataFrame, n_rows: int) -> None:
    assert list(X.columns) == MODEL_FEATURES, "feature columns out of order"
    assert len(X) == n_rows, "row count mismatch"
    assert not X.isna().any().any(), "NaN in features"
    assert all(pd.api.types.is_numeric_dtype(t) for t in X.dtypes), "non-numeric feature"
    assert (X >= 0).all().all(), "negative feature value"


def main():
    for split in ("train", "test"):
        df = pd.read_csv(PROCESSED / f"{split}.csv")
        X = build_matrix(df["url"])
        validate(X, len(df))
        # Keep label and group (domain) alongside so Phase 3 can do grouped CV without re-deriving.
        out = pd.concat([X, df[["type", "domain"]]], axis=1)
        out.to_csv(PROCESSED / f"features_{split}.csv", index=False)
        print(f"{split}: {out.shape} -> features_{split}.csv")
        print(X.groupby(df["type"])[["url_length", "num_digits", "has_ip",
                                      "num_suspicious_keywords", "suspicious_tld", "url_entropy"]].mean().round(3))


if __name__ == "__main__":
    main()
