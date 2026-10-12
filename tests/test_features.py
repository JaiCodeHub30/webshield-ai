import math

from src.features import DISPLAY_ONLY_FEATURES, FEATURE_NAMES, MODEL_FEATURES, build_matrix, extract_features


def test_keys_match_feature_names():
    assert list(extract_features("example.com").keys()) == FEATURE_NAMES


def test_scheme_does_not_change_features_except_https():
    a = extract_features("example.com/path?x=1")
    b = extract_features("http://example.com/path?x=1")
    c = extract_features("https://example.com/path?x=1")
    assert a == b
    assert c["has_https"] == 1
    drop = lambda d: {k: v for k, v in d.items() if k != "has_https"}
    assert drop(c) == drop(a)


def test_ip_detection():
    assert extract_features("http://192.168.0.1/login")["has_ip"] == 1
    assert extract_features("http://[2001:db8::1]/a")["has_ip"] == 1
    assert extract_features("example.com")["has_ip"] == 0


def test_keywords_and_tld():
    f = extract_features("secure-login.bank-update.tk/verify")
    assert f["kw_login"] == f["kw_verify"] == f["kw_secure"] == f["kw_bank"] == f["kw_update"] == 1
    assert f["num_suspicious_keywords"] == 5
    assert f["suspicious_tld"] == 1
    assert f["num_hyphens"] == 2


def test_subdomains_ignore_www():
    assert extract_features("www.example.co.uk")["num_subdomains"] == 0
    assert extract_features("a.b.example.co.uk")["num_subdomains"] == 2
    assert extract_features("example.co.uk")["tld_length"] == len("co.uk")


def test_shortener_and_special_chars():
    assert extract_features("https://bit.ly/abc")["is_shortener"] == 1
    f = extract_features("evil.com/a//b@c%20d")
    assert f["num_at"] == 1 and f["num_percent"] == 1 and f["num_double_slash"] == 1


def test_entropy_and_empty():
    assert extract_features("aaaa")["url_entropy"] == 0.0
    assert math.isclose(extract_features("ab")["url_entropy"], 1.0)
    f = extract_features("")
    assert f["url_length"] == 0 and f["digit_ratio"] == 0.0


def test_malformed_url_does_not_raise():
    extract_features("http://[broken/path")
    extract_features("   ")


def test_https_is_display_only():
    assert "has_https" in FEATURE_NAMES and "has_https" in DISPLAY_ONLY_FEATURES
    assert "has_https" not in MODEL_FEATURES
    assert MODEL_FEATURES == [f for f in FEATURE_NAMES if f != "has_https"]
    assert list(build_matrix(["https://example.com"]).columns) == MODEL_FEATURES


def test_model_features_scheme_invariant():
    rows = build_matrix(["example.com/a?b=1", "http://example.com/a?b=1", "https://example.com/a?b=1"])
    assert (rows.nunique() == 1).all()
