"""Phase 1 (redesign): build the combined labelled URL dataset from five local sources.

Sources (resolved from data/raw/ by filename pattern, never downloaded):
    kaggle     malicious_phish*.csv        url,type (benign/phishing/malware/defacement)
    tranco     tranco*.csv                 rank,domain (no header) -> generated benign URLs
    urlhaus    urlhaus*.csv|.xlsx          id,dateadded,url,... -> malware
    phishtank  verified_online*.csv        phish_id,url,...,verified,... -> phishing
    openphish  *openphish*.txt|.xlsx       one URL per line/row, no header -> phishing

Every URL is plain text. Nothing here imports a network library or resolves, fetches or
visits any URL (a unit test checks this).

URL normalization (applied identically to every source, in this order):
    1. strip surrounding whitespace
    2. drop null / empty URLs, then URLs longer than MAX_URL_LENGTH characters
    3. if STRIP_SCHEME: remove only a LEADING "http://" or "https://" (case-insensitive)
       ("http://" with nothing after it becomes empty and is dropped as empty)
    4. lowercase only the host. The authority is the text before the first "/", "?" or "#"
       (after any remaining "scheme://"). Inside it, text up to the last "@" is userinfo and
       kept as-is; the rest (host, port, [IPv6] literal) is lowercased. Path, query and
       fragment are never changed: no decoding, re-encoding or parameter reordering.

Dedup rule: after normalization, URLs that appear with more than one label are removed
entirely (all copies). For single-label duplicates one row is kept: the one from the
earliest source in SOURCE_ORDER, then the earliest row within that source.

Run: python -m src.build_dataset
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"

# --- configuration ------------------------------------------------------------------------
RANDOM_STATE = 42
TRANCO_TOP_N = 200_000
TRANCO_SAMPLE_SIZE = 100_000
STRIP_SCHEME = True
MAX_URL_LENGTH = 2_000

LABEL_MAP = {"benign": 0, "phishing": 1, "malware": 2, "defacement": 3}
INV_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

# Order also defines which source is kept as representative for cross-source duplicates.
SOURCE_ORDER = ["kaggle", "tranco", "urlhaus", "phishtank", "openphish"]
SOURCE_PATTERNS = {
    "kaggle": ["malicious_phish*"],
    "tranco": ["tranco*"],
    "urlhaus": ["urlhaus*"],
    "phishtank": ["verified_online*", "phishtank*"],
    "openphish": ["*openphish*"],
}
SUPPORTED_EXT = {
    "kaggle": {".csv"},
    "tranco": {".csv"},
    "urlhaus": {".csv", ".xlsx"},
    "phishtank": {".csv"},
    "openphish": {".txt", ".xlsx", ".csv"},
}
URLHAUS_COLUMNS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
                   "urlhaus_link", "reporter"]

# Tranco URL shapes: (name, share). Shares must sum to 1.
TRANCO_SHAPES = [("bare", 0.30), ("www", 0.25), ("path", 0.45)]
# Path/query patterns for the "path" shape. {id}, {slug}, {term}, {year}, {month} are filled
# from the seeded generator. Several deliberately contain login/account/secure so the model
# cannot learn "these words = malicious" from benign data never containing them.
TRANCO_PATH_PATTERNS = [
    "/", "/about", "/login", "/products/{id}", "/blog/{slug}", "/search?q={term}", "/en/contact",
    "/account/settings", "/news/{year}/{month}/{slug}", "/secure/account", "/account/login",
    "/help/faq", "/careers", "/privacy-policy", "/docs/getting-started", "/signin",
]
_SLUG_WORDS = ["annual", "report", "new", "features", "guide", "how", "to", "update", "your",
               "team", "summer", "sale", "release", "notes", "community", "event", "tips",
               "privacy", "security", "travel", "recipe", "review", "market", "data"]
_SEARCH_TERMS = ["shoes", "weather", "laptop", "python", "hotels", "news", "recipes", "jobs",
                 "flights", "music", "books", "maps"]

SCHEME_RE = re.compile(r"^\s*https?://", re.IGNORECASE)
_LEADING_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_ANY_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


class DatasetError(RuntimeError):
    """Raised for missing/ambiguous sources or failed validation."""


@dataclass
class SourceInfo:
    name: str
    path: Path | None = None
    fmt: str = ""
    original_rows: int = 0
    parsed_rows: int = 0
    notes: list[str] = field(default_factory=list)


# --- source resolution ----------------------------------------------------------------------
def resolve_sources(raw_dir: Path = RAW_DIR) -> dict[str, Path]:
    """Map each source to exactly one file in raw_dir (case-insensitive patterns)."""
    files = [p for p in raw_dir.iterdir() if p.is_file()]
    resolved, errors = {}, []
    for name in SOURCE_ORDER:
        hits = sorted({p for p in files for pat in SOURCE_PATTERNS[name]
                       if p.match(pat) or Path(p.name.lower()).match(pat.lower())})
        hits = [p for p in hits if p.suffix.lower() in SUPPORTED_EXT[name]]
        if not hits:
            errors.append(f"{name}: no file matching {SOURCE_PATTERNS[name]} with extension "
                          f"{sorted(SUPPORTED_EXT[name])} in {raw_dir}")
        elif len(hits) > 1:
            errors.append(f"{name}: ambiguous, several files match: {[h.name for h in hits]}")
        else:
            resolved[name] = hits[0]
    if errors:
        raise DatasetError("Source resolution failed:\n  " + "\n  ".join(errors))
    return resolved


def _frame(urls, label: int, source: str) -> pd.DataFrame:
    return pd.DataFrame({"url": pd.Series(urls, dtype=object).to_numpy(),
                         "type": np.full(len(urls), label, dtype=np.int64), "source": source})


def _count_csv_lines(path: Path) -> int:
    with open(path, "rb") as fh:
        return sum(1 for line in fh if line.strip())


# --- A. Kaggle ------------------------------------------------------------------------------
def load_kaggle(path: Path) -> tuple[pd.DataFrame, SourceInfo]:
    info = SourceInfo("kaggle", path, "csv (header)")
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
    cols = {c.strip().lower(): c for c in df.columns}
    if "url" not in cols or "type" not in cols:
        raise DatasetError(f"kaggle: expected columns url,type; found {list(df.columns)}")
    df = df[[cols["url"], cols["type"]]].set_axis(["url", "type"], axis=1)
    info.original_rows = len(df)
    labels = df["type"].str.strip().str.lower()
    info.notes.append(f"class counts before validation: {labels.value_counts(dropna=False).to_dict()}")
    mapped = labels.map(LABEL_MAP)
    missing_url, unknown = df["url"].isna(), mapped.isna()
    info.notes.append(f"dropped {int(missing_url.sum())} missing-URL rows, "
                      f"{int((unknown & ~missing_url).sum())} unknown-label rows")
    keep = ~missing_url & ~unknown
    out = pd.DataFrame({"url": df.loc[keep, "url"].to_numpy(),
                        "type": mapped[keep].astype(np.int64).to_numpy(), "source": "kaggle"})
    info.parsed_rows = len(out)
    info.notes.append("class counts after validation: "
                      f"{out['type'].map(INV_LABEL_MAP).value_counts().to_dict()}")
    return out, info


# --- B. Tranco ------------------------------------------------------------------------------
def read_tranco(path: Path) -> pd.DataFrame:
    """Read rank,domain (headerless). Validates ranks are integer, unique and ascending."""
    df = pd.read_csv(path, header=None, dtype=str, keep_default_na=False)
    if df.shape[1] != 2:
        raise DatasetError(f"tranco: expected 2 columns (rank, domain), found {df.shape[1]}")
    df.columns = ["rank", "domain"]
    if not df["rank"].str.strip().str.fullmatch(r"\d+").all():
        raise DatasetError("tranco: rank column contains non-integers (unexpected header?)")
    df["rank"] = df["rank"].astype(np.int64)
    df["domain"] = df["domain"].str.strip().str.lower()
    if not df["rank"].is_monotonic_increasing or df["rank"].duplicated().any():
        raise DatasetError("tranco: ranks are not unique and ascending")
    return df


_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+$")


def sample_tranco(df: pd.DataFrame, top_n: int | None = None, sample_size: int | None = None,
                  random_state: int | None = None) -> tuple[pd.DataFrame, list[str]]:
    """Reproducible sample of `sample_size` valid domains from the `top_n` best-ranked rows."""
    top_n = TRANCO_TOP_N if top_n is None else top_n
    sample_size = TRANCO_SAMPLE_SIZE if sample_size is None else sample_size
    random_state = RANDOM_STATE if random_state is None else random_state
    notes = []
    if len(df) < top_n:
        raise DatasetError(f"tranco: only {len(df)} rows, need the top {top_n}")
    top = df.nsmallest(top_n, "rank")
    valid = top["domain"].str.fullmatch(_DOMAIN_RE.pattern) & ~top["domain"].duplicated()
    notes.append(f"top {top_n} by rank: ranks {top['rank'].min()}-{top['rank'].max()}, "
                 f"{int((~valid).sum())} invalid/duplicate domains excluded")
    pool = top[valid]
    if len(pool) < sample_size:
        raise DatasetError(f"tranco: only {len(pool)} valid domains in top {top_n}, need {sample_size}")
    return pool.sample(n=sample_size, random_state=random_state).reset_index(drop=True), notes


def _shape_counts(n: int) -> dict[str, int]:
    shares = dict(TRANCO_SHAPES)
    assert abs(sum(shares.values()) - 1) < 1e-9, "TRANCO_SHAPES shares must sum to 1"
    counts = {k: int(round(v * n)) for k, v in shares.items()}
    counts[TRANCO_SHAPES[-1][0]] += n - sum(counts.values())  # absorb rounding
    return counts


def _fill_pattern(pattern: str, rng: np.random.Generator) -> str:
    slug = "-".join(rng.choice(_SLUG_WORDS, size=int(rng.integers(2, 5)), replace=False))
    return pattern.format(id=int(rng.integers(1, 100_000)), slug=slug, term=rng.choice(_SEARCH_TERMS),
                          year=int(rng.integers(2015, 2026)), month=f"{int(rng.integers(1, 13)):02d}")


def generate_tranco_urls(domains: list[str], random_state: int = RANDOM_STATE) -> tuple[list[str], list[str]]:
    """Deterministic benign URL strings: returns (urls, shape per url)."""
    rng = np.random.default_rng(random_state)
    counts = _shape_counts(len(domains))
    shapes = np.array([s for s, c in counts.items() for _ in range(c)], dtype=object)
    rng.shuffle(shapes)
    urls = []
    for domain, shape in zip(domains, shapes):
        bare = domain[4:] if domain.startswith("www.") else domain
        if shape == "bare":
            urls.append(domain)
        elif shape == "www":
            urls.append("www." + bare)
        else:
            host = "www." + bare if rng.random() < 0.5 else domain
            urls.append(host + _fill_pattern(rng.choice(TRANCO_PATH_PATTERNS), rng))
    return urls, list(shapes)


def load_tranco(path: Path) -> tuple[pd.DataFrame, SourceInfo]:
    info = SourceInfo("tranco", path, "csv (no header: rank,domain)")
    df = read_tranco(path)
    info.original_rows = len(df)
    sample, notes = sample_tranco(df)
    info.notes += notes
    urls, shapes = generate_tranco_urls(sample["domain"].tolist())
    sc = pd.Series(shapes).value_counts()
    info.notes.append("generated shapes: " + ", ".join(f"{k}={sc.get(k, 0)} ({sc.get(k, 0) / len(urls):.1%})"
                                                       for k, _ in TRANCO_SHAPES))
    dup = pd.Series(urls).duplicated().sum()
    info.notes.append(f"duplicate generated URLs: {int(dup)}")
    out = _frame(urls, LABEL_MAP["benign"], "tranco")
    info.parsed_rows = len(out)
    return out, info


# --- C. URLhaus -----------------------------------------------------------------------------
def read_urlhaus(path: Path) -> tuple[pd.DataFrame, list[str]]:
    """Parse URLhaus CSV (with '#' comment lines / commented header) or an XLSX export.

    CSV note: pandas' comment="#" truncates a line at ANY '#', which would silently cut URL
    fragments. Instead only lines whose first non-space character is '#' are dropped, then
    the rest is parsed with the fixed column names and skipinitialspace=True.
    """
    notes = []
    if path.suffix.lower() == ".xlsx":
        raw = pd.read_excel(path, header=None, dtype=str)
    else:
        with open(path, encoding="utf-8-sig") as fh:
            lines = [ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        import io
        raw = pd.read_csv(io.StringIO("".join(lines)), header=None, dtype=str,
                          skipinitialspace=True, quotechar='"')
    if raw.shape[1] != len(URLHAUS_COLUMNS):
        raise DatasetError(f"urlhaus: expected {len(URLHAUS_COLUMNS)} columns, parsed {raw.shape[1]}")
    first = raw.iloc[:, 0].astype(str).str.strip()
    comment_rows = first.str.startswith("#")
    header_rows = (raw.astype(str).apply(lambda c: c.str.strip().str.lstrip("# ").str.lower())
                   .eq(URLHAUS_COLUMNS).all(axis=1))
    if comment_rows.any() or header_rows.any():
        notes.append(f"skipped {int((comment_rows | header_rows).sum())} comment/header rows")
    raw = raw[~comment_rows & ~header_rows].copy()
    raw.columns = URLHAUS_COLUMNS
    if raw.empty:
        raise DatasetError("urlhaus: parsed zero data rows")
    bad_id = ~raw["id"].astype(str).str.strip().str.fullmatch(r"\d+")
    if bad_id.any():
        notes.append(f"WARNING: {int(bad_id.sum())} rows with non-numeric id (possible misparse)")
    return raw.reset_index(drop=True), notes


def load_urlhaus(path: Path) -> tuple[pd.DataFrame, SourceInfo]:
    fmt = "xlsx (header row)" if path.suffix.lower() == ".xlsx" else "csv ('#' comments, fixed columns)"
    info = SourceInfo("urlhaus", path, fmt)
    info.original_rows = (len(pd.read_excel(path, header=None)) if path.suffix.lower() == ".xlsx"
                          else _count_csv_lines(path))
    raw, notes = read_urlhaus(path)
    info.notes += notes
    info.notes.append(f"threat values: {raw['threat'].value_counts(dropna=False).to_dict()}")
    out = _frame(raw["url"].tolist(), LABEL_MAP["malware"], "urlhaus")
    info.parsed_rows = len(out)
    return out, info


# --- D. PhishTank ---------------------------------------------------------------------------
def load_phishtank(path: Path) -> tuple[pd.DataFrame, SourceInfo]:
    info = SourceInfo("phishtank", path, "csv (header)")
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
    df.columns = [c.strip().lower() for c in df.columns]
    if "url" not in df.columns:
        raise DatasetError(f"phishtank: no 'url' column; found {list(df.columns)}")
    info.original_rows = len(df)
    if "verified" in df.columns:
        ok = df["verified"].fillna("").str.strip().str.lower().eq("yes")
        info.notes.append(f"verified filter: kept {int(ok.sum())}, dropped {int((~ok).sum())}")
        df = df[ok]
    else:
        info.notes.append("WARNING: no 'verified' column; verification filter unavailable, kept all rows")
    out = _frame(df["url"].tolist(), LABEL_MAP["phishing"], "phishtank")
    info.parsed_rows = len(out)
    return out, info


# --- E. OpenPhish ---------------------------------------------------------------------------
def load_openphish(path: Path) -> tuple[pd.DataFrame, SourceInfo]:
    """One URL per line/row, no header (the first line is data)."""
    if path.suffix.lower() == ".xlsx":
        raw = pd.read_excel(path, header=None, dtype=str)
        if raw.shape[1] != 1:
            raise DatasetError(f"openphish: expected 1 column, found {raw.shape[1]}")
        values = raw.iloc[:, 0].tolist()
        info = SourceInfo("openphish", path, "xlsx (1 column, no header)")
    else:
        with open(path, encoding="utf-8-sig") as fh:
            values = fh.read().splitlines()
        info = SourceInfo("openphish", path, "text (one URL per line, no header)")
    info.original_rows = len(values)
    urls = [v for v in values if isinstance(v, str) and v.strip()]
    if len(urls) < len(values):
        info.notes.append(f"skipped {len(values) - len(urls)} blank lines")
    out = _frame(urls, LABEL_MAP["phishing"], "openphish")
    info.parsed_rows = len(out)
    return out, info


LOADERS = {"kaggle": load_kaggle, "tranco": load_tranco, "urlhaus": load_urlhaus,
           "phishtank": load_phishtank, "openphish": load_openphish}


# --- scheme bias ----------------------------------------------------------------------------
def has_scheme(urls: pd.Series) -> pd.Series:
    """Case-insensitive http(s):// at the start, allowing leading whitespace. Null -> False."""
    return urls.astype("string").str.contains(SCHEME_RE, na=False).astype(bool)


def scheme_stats(df: pd.DataFrame, by: str) -> pd.DataFrame:
    flag = has_scheme(df["url"])
    g = flag.groupby(df[by])
    out = pd.DataFrame({"with_scheme": g.sum().astype(int), "total": g.size()})
    out["pct"] = (100 * out["with_scheme"] / out["total"]).round(2)
    return out


def strip_scheme(url: str) -> str:
    """Remove only a leading http:// or https:// (case-insensitive)."""
    return _LEADING_SCHEME_RE.sub("", url, count=1)


def lowercase_host(url: str) -> str:
    """Lowercase only the host[:port] part of a URL; userinfo, path, query, fragment unchanged."""
    m = _ANY_SCHEME_RE.match(url)
    prefix_end = m.end() if m else 0
    rest = url[prefix_end:]
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    at = authority.rfind("@")
    userinfo, hostport = (authority[: at + 1], authority[at + 1:]) if at != -1 else ("", authority)
    return url[:prefix_end] + userinfo + hostport.lower() + tail


# --- cleaning --------------------------------------------------------------------------------
def clean_urls(df: pd.DataFrame, strip: bool = STRIP_SCHEME, max_len: int = MAX_URL_LENGTH):
    """Apply the documented normalization. Returns (clean_df, stats dict, per-source counts)."""
    stats = {}
    url = df["url"]
    null = url.isna()
    s = url.where(~null, "").astype(str).str.strip()
    empty = ~null & s.eq("")
    too_long = ~null & ~empty & (s.str.len() > max_len)
    stats.update(null=int(null.sum()), empty=int(empty.sum()), too_long=int(too_long.sum()))
    keep = ~(null | empty | too_long)
    out = df.loc[keep, ["url", "type", "source"]].copy()
    out["url"] = s[keep]

    if strip:
        before = out["url"]
        out["url"] = before.map(strip_scheme)
        stats["scheme_removed"] = int((before != out["url"]).sum())
        empty_after = out["url"].eq("")
        stats["empty_after_scheme_strip"] = int(empty_after.sum())
        out = out[~empty_after]
    else:
        stats["scheme_removed"] = stats["empty_after_scheme_strip"] = 0

    lowered = out["url"].map(lowercase_host)
    stats["host_lowercased"] = int((lowered != out["url"]).sum())
    out["url"] = lowered
    out["type"] = out["type"].astype(np.int64)
    return out.reset_index(drop=True), stats


# --- merge / dedup ---------------------------------------------------------------------------
def merge_and_dedupe(df: pd.DataFrame):
    """Remove all copies of conflicting-label URLs, then keep one row per URL (SOURCE_ORDER rule)."""
    df = df.copy()
    df["_src_rank"] = df["source"].map({s: i for i, s in enumerate(SOURCE_ORDER)})
    df["_row"] = np.arange(len(df))
    n_labels = df.groupby("url")["type"].transform("nunique")
    conflict = n_labels > 1
    stats = {
        "rows_in": len(df),
        "conflicting_url_keys": int(df.loc[conflict, "url"].nunique()),
        "conflicting_rows_removed": int(conflict.sum()),
    }
    df = df[~conflict]
    dup_mask = df.duplicated("url", keep=False)
    stats["duplicate_url_keys"] = int(df.loc[dup_mask, "url"].nunique())
    stats["dup_within_source_rows"] = int(df.duplicated(["url", "source"]).sum())
    df = df.sort_values(["_src_rank", "_row"], kind="stable")
    kept = df.drop_duplicates("url", keep="first")
    stats["duplicate_rows_removed"] = len(df) - len(kept)
    stats["dup_cross_source_rows"] = stats["duplicate_rows_removed"] - stats["dup_within_source_rows"]
    kept = kept.sort_values("_row", kind="stable").drop(columns=["_src_rank", "_row"])
    stats["rows_out"] = len(kept)
    return kept.reset_index(drop=True)[["url", "type", "source"]], stats


# --- validation & output ----------------------------------------------------------------------
def validate_combined(df: pd.DataFrame) -> list[str]:
    checks = []

    def check(cond: bool, msg: str):
        if not cond:
            raise DatasetError(f"validation failed: {msg}")
        checks.append(f"PASS {msg}")

    check(list(df.columns) == ["url", "type", "source"], "columns are url,type,source")
    check(df["type"].dtype == np.int64, "type is int64")
    check(set(df["type"].unique()) <= set(LABEL_MAP.values()), "labels within 0-3")
    check(set(df["source"].unique()) <= set(SOURCE_ORDER), "sources are known")
    check(df["url"].notna().all() and df["url"].str.len().gt(0).all(), "no null/empty URLs")
    check(df["url"].str.len().le(MAX_URL_LENGTH).all(), f"no URL longer than {MAX_URL_LENGTH}")
    check(not df["url"].duplicated().any(), "no duplicate URLs")
    check(df.groupby("url")["type"].nunique().max() == 1, "no URL with multiple labels")
    if STRIP_SCHEME:
        check(not has_scheme(df["url"]).any(), "no leading http(s):// remains")
    return checks


def final_dataset(combined: pd.DataFrame, random_state: int = RANDOM_STATE) -> pd.DataFrame:
    return combined[["url", "type"]].sample(frac=1, random_state=random_state).reset_index(drop=True)


def _atomic_write(path: Path, write_fn) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    os.close(fd)
    try:
        write_fn(tmp)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def label_map_payload() -> dict:
    return {"label_to_id": LABEL_MAP, "id_to_label": {str(k): v for k, v in INV_LABEL_MAP.items()}}


def write_outputs(combined: pd.DataFrame, final: pd.DataFrame, out_dir: Path = PROCESSED_DIR) -> dict:
    """Write all three outputs to temp files first, then move into place."""
    paths = {"combined": out_dir / "combined_with_source.csv", "final": out_dir / "final_dataset.csv",
             "label_map": out_dir / "label_map.json"}
    _atomic_write(paths["combined"], lambda p: combined.to_csv(p, index=False, encoding="utf-8"))
    _atomic_write(paths["final"], lambda p: final.to_csv(p, index=False, encoding="utf-8"))
    _atomic_write(paths["label_map"], lambda p: Path(p).write_text(json.dumps(label_map_payload(), indent=2)))
    return paths


def defang(url: str) -> str:
    """Console display only: never applied to saved data."""
    return re.sub("http", "hxxp", url, flags=re.IGNORECASE).replace(".", "[.]")


# --- main --------------------------------------------------------------------------------------
def _hr(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def build(raw_dir: Path = RAW_DIR, out_dir: Path = PROCESSED_DIR, write: bool = True) -> dict:
    _hr("STEP 1  Source resolution and baseline")
    sources = resolve_sources(raw_dir)
    frames, infos = {}, {}
    for name in SOURCE_ORDER:
        frames[name], infos[name] = LOADERS[name](sources[name])
        i = infos[name]
        print(f"\n[{name}] {i.path.name}  format={i.fmt}")
        print(f"  original rows={i.original_rows:,}  parsed rows={i.parsed_rows:,}  "
              f"labels={frames[name]['type'].map(INV_LABEL_MAP).value_counts().to_dict()}")
        for n in i.notes:
            print(f"  - {n}")

    _hr("STEP 2  Label encoding")
    print(json.dumps(label_map_payload()))

    raw = pd.concat([frames[n] for n in SOURCE_ORDER], ignore_index=True)
    _hr("STEP 4  Scheme bias BEFORE any modification (leading http:// or https://)")
    by_source = scheme_stats(raw, "source").reindex(SOURCE_ORDER)
    by_class = scheme_stats(raw.assign(cls=raw["type"].map(INV_LABEL_MAP)), "cls").reindex(list(LABEL_MAP))
    print("By source (numerator=with_scheme, denominator=total):\n" + by_source.to_string())
    print("\nBy class, all sources combined:\n" + by_class.to_string())

    _hr("STEP 5  Cleaning and normalization")
    clean, cstats = clean_urls(raw)
    print(f"STRIP_SCHEME={STRIP_SCHEME}; removed: null={cstats['null']}, empty={cstats['empty']}, "
          f">{MAX_URL_LENGTH} chars={cstats['too_long']}, empty after scheme strip="
          f"{cstats['empty_after_scheme_strip']}")
    print(f"scheme removals={cstats['scheme_removed']:,}  host-lowercasing changes={cstats['host_lowercased']:,}")
    after = scheme_stats(clean.assign(cls=clean["type"].map(INV_LABEL_MAP)), "cls").reindex(list(LABEL_MAP))
    print("By class AFTER cleaning:\n" + after.to_string())

    _hr("STEP 6  Merge, deduplicate, resolve conflicts")
    combined, dstats = merge_and_dedupe(clean)
    for k, v in dstats.items():
        print(f"  {k:28s} {v:,}")
    checks = validate_combined(combined)
    final = final_dataset(combined)
    if not (final["type"].dtype == np.int64 and list(final.columns) == ["url", "type"] and len(final) == len(combined)):
        raise DatasetError("validation failed: final dataset shape/columns/dtype")
    checks.append("PASS final_dataset columns url,type, int64, same rows as combined")
    checks.append(f"PASS final_dataset shuffled (row order differs from combined: "
                  f"{not final['url'].equals(combined['url'])})")

    paths = write_outputs(combined, final, out_dir) if write else {}

    _hr("STEP 8  Final report")
    per_src = pd.DataFrame({
        "input_rows": {n: infos[n].original_rows for n in SOURCE_ORDER},
        "after_validation": {n: infos[n].parsed_rows for n in SOURCE_ORDER},
        "after_cleaning": clean["source"].value_counts().reindex(SOURCE_ORDER, fill_value=0),
        "in_final": combined["source"].value_counts().reindex(SOURCE_ORDER, fill_value=0),
    })
    print("Per source:\n" + per_src.to_string())
    counts = combined["type"].value_counts().reindex(list(LABEL_MAP.values()), fill_value=0)
    cls = pd.DataFrame({"class": [INV_LABEL_MAP[i] for i in counts.index], "count": counts.to_numpy(),
                        "pct": (100 * counts / counts.sum()).round(2).to_numpy()}, index=counts.index)
    cls.index.name = "label"
    print("\nFinal classes:\n" + cls.to_string())
    print(f"\nduplicate rows removed={dstats['duplicate_rows_removed']:,}  conflicting URL keys="
          f"{dstats['conflicting_url_keys']:,}  conflicting rows removed={dstats['conflicting_rows_removed']:,}")
    print(f"removed null={cstats['null']}, empty={cstats['empty'] + cstats['empty_after_scheme_strip']}, "
          f"overlong={cstats['too_long']}; scheme removals={cstats['scheme_removed']:,}; "
          f"host normalizations={cstats['host_lowercased']:,}")
    print("\nExamples (5 per class, seeded; DEFANGED for display only):")
    for label, name in INV_LABEL_MAP.items():
        sub = final[final["type"] == label]
        n = min(5, len(sub))
        note = "" if n == 5 else f"  (only {len(sub)} rows in this class)"
        print(f"  {label} {name}{note}")
        for u in sub.sample(n=n, random_state=RANDOM_STATE)["url"]:
            print(f"     {defang(u)}")
    if paths:
        print(f"\nWrote {paths['combined']}  shape={combined.shape}")
        print(f"Wrote {paths['final']}  shape={final.shape}")
        print(f"Wrote {paths['label_map']}")
    print("\nValidation:\n  " + "\n  ".join(checks))
    return {"combined": combined, "final": final, "infos": infos, "clean_stats": cstats,
            "dedup_stats": dstats, "scheme_by_source": by_source, "scheme_by_class": by_class, "paths": paths}


if __name__ == "__main__":
    try:
        build()
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
