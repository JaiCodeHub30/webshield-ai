"""Unit tests for src/build_dataset.py using small synthetic fixtures (no real data, no network)."""
import ast
import json
import socket
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src import build_dataset as bd

SRC = Path(bd.__file__)


# --- fixtures --------------------------------------------------------------------------------
def _tranco_rows(n):
    return "\n".join(f"{i},site{i}.com" for i in range(1, n + 1)) + "\n"


@pytest.fixture
def raw_dir(tmp_path, monkeypatch):
    """A tiny but complete data/raw/ with all five sources (CSV/TXT variants)."""
    d = tmp_path / "raw"
    d.mkdir()
    (d / "malicious_phish.csv").write_text(
        "url,type\n"
        "Example.COM/Path/Of?Q=Case,benign\n"
        "http://Evil.example.net/Login,phishing\n"
        "evil.example.net/Login,phishing\n"            # duplicate of the above after scheme strip
        "conflict.org/x,benign\n"
        "HTTPS://conflict.org/x,phishing\n"            # conflicts with the above -> both removed
        "deface.example.org/index.php?option=com_content,defacement\n"
        ",benign\n"                                     # missing URL
        "unknown.org,spam\n"                            # unknown label
        f"{'a' * 2001},benign\n"                        # overlong
        "   ,benign\n",                                 # empty after strip
        encoding="utf-8")
    (d / "tranco_test.csv").write_text(_tranco_rows(60), encoding="utf-8")
    (d / "urlhaus_recent.csv").write_text(
        "################################\n"
        "# abuse.ch URLhaus Database Dump\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-10-01 00:00:00","http://192.0.2.10:8080/bin.sh","online","2026-10-01","malware_download","elf","https://urlhaus.abuse.ch/url/1/","r1"\n'
        '"2","2026-10-01 00:00:01","http://Mal.example/a#frag","offline","","malware_download","","https://urlhaus.abuse.ch/url/2/","r2"\n',
        encoding="utf-8")
    (d / "verified_online.csv").write_text(
        "phish_id,url,verified\n1,http://phish.example/a, yes \n2,http://unverified.example/b,no\n",
        encoding="utf-8")
    (d / "openphish_feed.txt").write_text(
        "http://first-line-is-data.example/\n\nhttps://op.example/verify\n", encoding="utf-8")
    monkeypatch.setattr(bd, "TRANCO_TOP_N", 50)
    monkeypatch.setattr(bd, "TRANCO_SAMPLE_SIZE", 20)
    return d


# --- labels ----------------------------------------------------------------------------------
def test_label_encoding_exact():
    assert bd.LABEL_MAP == {"benign": 0, "phishing": 1, "malware": 2, "defacement": 3}
    assert bd.label_map_payload()["id_to_label"] == {"0": "benign", "1": "phishing", "2": "malware",
                                                     "3": "defacement"}


# --- source resolution -----------------------------------------------------------------------
def test_resolve_missing_and_ambiguous(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    with pytest.raises(bd.DatasetError, match="no file matching"):
        bd.resolve_sources(d)
    for n in ("malicious_phish.csv", "tranco_a.csv", "tranco_b.csv", "urlhaus.csv", "verified_online.csv",
              "OpenPhish feed.txt"):
        (d / n).write_text("x")
    with pytest.raises(bd.DatasetError, match="ambiguous"):
        bd.resolve_sources(d)


# --- tranco ---------------------------------------------------------------------------------
def test_tranco_sampling_and_generation_deterministic(tmp_path):
    p = tmp_path / "tranco.csv"
    p.write_text(_tranco_rows(500))
    df = bd.read_tranco(p)
    s1, _ = bd.sample_tranco(df, top_n=400, sample_size=200)
    s2, _ = bd.sample_tranco(df, top_n=400, sample_size=200)
    assert s1.equals(s2) and s1["rank"].max() <= 400 and s1["domain"].is_unique
    u1, sh1 = bd.generate_tranco_urls(s1["domain"].tolist())
    u2, sh2 = bd.generate_tranco_urls(s1["domain"].tolist())
    assert u1 == u2 and sh1 == sh2


def test_tranco_fails_if_not_enough_domains(tmp_path):
    p = tmp_path / "tranco.csv"
    p.write_text(_tranco_rows(100))
    with pytest.raises(bd.DatasetError):
        bd.sample_tranco(bd.read_tranco(p), top_n=200, sample_size=50)
    with pytest.raises(bd.DatasetError):
        bd.sample_tranco(bd.read_tranco(p), top_n=100, sample_size=101)


def test_tranco_rejects_unsorted_ranks(tmp_path):
    p = tmp_path / "tranco.csv"
    p.write_text("2,b.com\n1,a.com\n")
    with pytest.raises(bd.DatasetError, match="ascending"):
        bd.read_tranco(p)


def test_tranco_proportions_and_paths():
    domains = [f"d{i}.com" for i in range(10_000)]
    urls, shapes = bd.generate_tranco_urls(domains)
    counts = pd.Series(shapes).value_counts()
    for name, share in bd.TRANCO_SHAPES:
        assert abs(counts[name] - share * len(domains)) <= 1
    for u, s in zip(urls, shapes):
        if s == "bare":
            assert "/" not in u and not u.startswith("www.")
        elif s == "www":
            assert u.startswith("www.") and "/" not in u
        else:
            assert "/" in u
    joined = "\n".join(urls)
    for term in ("login", "account", "secure"):
        assert term in joined
    assert len(set(urls)) == len(urls)


# --- scheme handling ------------------------------------------------------------------------
def test_scheme_percentages():
    df = pd.DataFrame({"url": ["http://a", "HTTPS://b", "  http://c", "d", "ftp://e", None, "x/http://y"],
                       "source": ["s"] * 7})
    st = bd.scheme_stats(df, "source").loc["s"]
    assert (st["with_scheme"], st["total"]) == (3, 7)
    assert st["pct"] == round(100 * 3 / 7, 2)


@pytest.mark.parametrize("url, expected", [
    ("http://a.com/x", "a.com/x"), ("HTTPS://a.com/x", "a.com/x"), ("HtTp://a.com", "a.com"),
    ("a.com/redirect?to=http://b.com", "a.com/redirect?to=http://b.com"),  # only leading scheme
    ("ftp://a.com", "ftp://a.com"), ("http://http://a.com", "http://a.com"),
])
def test_strip_scheme(url, expected):
    assert bd.strip_scheme(url) == expected


@pytest.mark.parametrize("url, expected", [
    ("Example.COM/Path/File.HTML?Q=AbC#Frag", "example.com/Path/File.HTML?Q=AbC#Frag"),
    ("WWW.Site.Org", "www.site.org"),
    ("Site.Org?Next=/A", "site.org?Next=/A"),
    ("User:PassWord@Host.COM:8080/P", "User:PassWord@host.com:8080/P"),
    ("[2001:DB8::1]:443/Path", "[2001:db8::1]:443/Path"),
    ("192.0.2.1:56963/I", "192.0.2.1:56963/I"),
    ("FTP://Host.COM/A", "FTP://host.com/A"),
    ("a.com/p%2Fq?b=2&a=1", "a.com/p%2Fq?b=2&a=1"),  # no decoding or reordering
])
def test_lowercase_host_only(url, expected):
    assert bd.lowercase_host(url) == expected


def test_clean_removes_bad_urls_and_normalizes():
    df = pd.DataFrame({"url": [None, "", "   ", "a" * 2001, "  HTTP://Host.COM/Keep?Case=Yes  ", "http://"],
                       "type": [0] * 6, "source": ["kaggle"] * 6})
    out, st = bd.clean_urls(df)
    assert (st["null"], st["empty"], st["too_long"], st["empty_after_scheme_strip"]) == (1, 2, 1, 1)
    assert out["url"].tolist() == ["host.com/Keep?Case=Yes"]
    assert st["scheme_removed"] == 2 and st["host_lowercased"] == 1


def test_clean_keeps_scheme_when_disabled():
    df = pd.DataFrame({"url": ["HTTP://Host.COM/A"], "type": [0], "source": ["kaggle"]})
    out, _ = bd.clean_urls(df, strip=False)
    assert out["url"].tolist() == ["HTTP://host.com/A"]


# --- loaders --------------------------------------------------------------------------------
def test_urlhaus_comments_header_and_fragments(raw_dir):
    df, info = bd.load_urlhaus(raw_dir / "urlhaus_recent.csv")
    assert df["url"].tolist() == ["http://192.0.2.10:8080/bin.sh", "http://Mal.example/a#frag"]
    assert (df["type"] == 2).all() and (df["source"] == "urlhaus").all()


def test_urlhaus_xlsx_with_header_row(tmp_path):
    p = tmp_path / "urlhaus.xlsx"
    rows = [bd.URLHAUS_COLUMNS, ["1", "d", "http://x.example/a", "online", "", "malware_download", "", "l", "r"]]
    pd.DataFrame(rows).to_excel(p, header=False, index=False)
    df, info = bd.load_urlhaus(p)
    assert df["url"].tolist() == ["http://x.example/a"]


def test_urlhaus_bad_columns_fail(tmp_path):
    p = tmp_path / "urlhaus.csv"
    p.write_text("# header\na,b,c\n")
    with pytest.raises(bd.DatasetError, match="expected 9 columns"):
        bd.load_urlhaus(p)


def test_phishtank_verified_filter(raw_dir, tmp_path):
    df, info = bd.load_phishtank(raw_dir / "verified_online.csv")
    assert df["url"].tolist() == ["http://phish.example/a"] and (df["type"] == 1).all()
    p = tmp_path / "verified_online.csv"
    p.write_text("phish_id,url\n1,http://a.example\n")
    df2, info2 = bd.load_phishtank(p)
    assert len(df2) == 1 and any("verification filter unavailable" in n for n in info2.notes)


def test_openphish_first_line_is_data(raw_dir):
    df, _ = bd.load_openphish(raw_dir / "openphish_feed.txt")
    assert df["url"].tolist() == ["http://first-line-is-data.example/", "https://op.example/verify"]
    assert (df["type"] == 1).all()


def test_kaggle_drops_missing_and_unknown(raw_dir):
    df, info = bd.load_kaggle(raw_dir / "malicious_phish.csv")
    assert "unknown.org" not in df["url"].tolist()
    assert df["url"].notna().all() and df["type"].dtype == np.int64


# --- dedup ----------------------------------------------------------------------------------
def test_exact_duplicates_and_conflicts():
    df = pd.DataFrame({
        "url": ["a.com", "a.com", "b.com", "b.com", "b.com", "c.com", "c.com"],
        "type": [1, 1, 0, 1, 0, 2, 2],
        "source": ["openphish", "phishtank", "kaggle", "kaggle", "tranco", "kaggle", "kaggle"],
    })
    out, st = bd.merge_and_dedupe(df)
    assert "b.com" not in out["url"].tolist()          # conflict: all copies removed
    assert st["conflicting_url_keys"] == 1 and st["conflicting_rows_removed"] == 3
    assert st["duplicate_rows_removed"] == 2
    assert out.set_index("url").loc["a.com", "source"] == "phishtank"  # SOURCE_ORDER representative
    assert out["url"].is_unique


# --- end to end -----------------------------------------------------------------------------
def test_build_end_to_end(raw_dir, tmp_path, monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)

    out = tmp_path / "processed"
    res = bd.build(raw_dir=raw_dir, out_dir=out)
    combined = pd.read_csv(out / "combined_with_source.csv")
    final = pd.read_csv(out / "final_dataset.csv")
    assert list(combined.columns) == ["url", "type", "source"]
    assert list(final.columns) == ["url", "type"]                      # no index column
    assert combined["type"].dtype == np.int64 and final["type"].dtype == np.int64
    assert set(combined["source"]) <= set(bd.SOURCE_ORDER)
    assert final["url"].is_unique and sorted(final["url"]) == sorted(combined["url"])
    assert final["url"].tolist() == bd.final_dataset(res["combined"])["url"].tolist()
    assert json.loads((out / "label_map.json").read_text())["label_to_id"] == bd.LABEL_MAP

    urls = set(combined["url"])
    assert "evil.example.net/Login" in urls and "conflict.org/x" not in urls
    assert "example.com/Path/Of?Q=Case" in urls
    assert not any(u.lower().startswith(("http://", "https://")) for u in urls)
    assert not list(out.glob("*.tmp"))


def test_shuffle_is_deterministic_and_reorders():
    df = pd.DataFrame({"url": [f"u{i}" for i in range(50)], "type": [0] * 50, "source": ["kaggle"] * 50})
    a, b = bd.final_dataset(df), bd.final_dataset(df)
    assert a.equals(b) and a["url"].tolist() != df["url"].tolist()


def test_no_network_imports():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not names & {"requests", "urllib3", "httpx", "socket", "http", "aiohttp", "tldextract"}
    assert "urllib.request" not in SRC.read_text(encoding="utf-8")
