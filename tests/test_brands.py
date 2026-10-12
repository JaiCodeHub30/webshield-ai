"""Brand-impersonation detection on a small in-memory reference (no data files, no network)."""
import pytest

from src.brands import (BrandIndex, analyze, brand_findings, decode_punycode, homoglyph_variants,
                        osa_distance)

FLAGS = ("brand_homoglyph", "brand_typosquat", "brand_combosquat", "brand_in_subdomain", "brand_in_path")


@pytest.fixture(scope="module")
def index():
    brands = {"google": "google.com", "amazon": "amazon.com", "facebook": "facebook.com",
              "microsoft": "microsoft.com", "netflix": "netflix.com", "linkedin": "linkedin.com",
              "wikipedia": "wikipedia.org", "stackexchange": "stackexchange.com"}
    popular = {"google.com", "google.co.uk", "paypal.com", "paypal.de", "amazon.com", "github.com",
               "wikipedia.org", "stackexchange.com", "bing.com", "king.com", "blogspot.com"}
    return BrandIndex(brands, popular)


def flags(url, index):
    host, _, rest = url.partition("/")
    r = analyze(host, "/" + rest, index)
    return {k for k in FLAGS if r[k]}, r


def test_osa_distance():
    assert osa_distance("google", "google") == 0
    assert osa_distance("google", "gogle") == 1        # deletion
    assert osa_distance("google", "googel") == 1       # transposition
    assert osa_distance("google", "goolge") == 1
    assert osa_distance("amazon", "amazn") == 1


def test_homoglyph_variants_and_punycode():
    assert "google" in homoglyph_variants("g00gle")
    assert "paypal" in homoglyph_variants("paypa1")
    assert "microsoft" in homoglyph_variants("rnicrosoft")
    assert "apple" in homoglyph_variants("аpple")  # Cyrillic a
    assert decode_punycode("xn--pple-43d.com") == "аpple.com"


@pytest.mark.parametrize("url, expected", [
    ("www.g00gle.com", "brand_homoglyph"), ("paypa1.com", "brand_homoglyph"),
    ("rnicrosoft.com", "brand_homoglyph"), ("netfl1x.com", "brand_homoglyph"),
    ("xn--pple-43d.com", "brand_homoglyph"), ("аpple.com", "brand_homoglyph"),
    ("gooogle.com", "brand_typosquat"), ("gogle.com", "brand_typosquat"), ("googel.com", "brand_typosquat"),
    ("amazn.com", "brand_typosquat"), ("linkedln.com", "brand_typosquat"), ("paypal.help", "brand_typosquat"),
    ("paypal-account-verify.com", "brand_combosquat"), ("securepaypallogin.net", "brand_combosquat"),
    ("amaz0n-secure-update.xyz", "brand_combosquat"), ("wellsfargo-secure.info", "brand_combosquat"),
    ("apple-id-verify.com", "brand_combosquat"),
    ("paypal.com.account-verify.tk", "brand_in_subdomain"), ("login.microsoftonline.com.evil.ru", "brand_in_subdomain"),
    ("paypal.blogspot.com", "brand_in_subdomain"), ("unrelated-host.tk/paypal/signin", "brand_in_path"),
])
def test_impersonation_flagged(url, expected, index):
    found, _ = flags(url, index)
    assert expected in found


@pytest.mark.parametrize("url", [
    "google.com", "www.google.co.uk", "mail.google.com", "paypal.com", "www.paypal.de", "en.wikipedia.org",
    "bing.com", "king.com", "www.ncuindia.edu", "my-support-portal.com", "best-travel-deals.com",
    "university-library.edu", "kolblawoffice.com", "ny-orange.com", "charleychaseonline.com",
    "columbustelegram.com", "pineapple-farm.com", "apple.stackexchange.com",
])
def test_legitimate_not_flagged(url, index):
    found, _ = flags(url, index)
    assert not found - {"brand_in_path"}


def test_rule_findings_skip_popular_domains(index):
    _, r = flags("paypal.blogspot.com", index)
    assert r["is_popular"] and brand_findings(r) == []
    _, r = flags("www.g00gle.com", index)
    f = brand_findings(r)
    assert f and f[0]["category"] == "brand_homoglyph" and f[0]["severity"] >= 8
