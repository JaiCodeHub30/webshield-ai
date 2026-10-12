"""Attack-pattern rules: the traversal case from the brief plus false-alarm cases seen in real data."""
import pytest

from src.attack_rules import attack_floor, decoded_forms, find_attacks


def cats(url):
    return {f["category"] for f in find_attacks(url)}


def test_decoding_rounds():
    forms = decoded_forms("a.com/%252e%252e%252f")
    assert "a.com/../" in forms


@pytest.mark.parametrize("url", [
    "www.ncuindia.edu/../../etc/passwd",
    "example.com/index.php?page=../../../../etc/passwd",
    "example.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
])
def test_traversal_to_sensitive_file(url):
    found = find_attacks(url)
    assert {"path_traversal", "sensitive_file"} <= {f["category"] for f in found}
    assert attack_floor(found) >= 9.0


def test_single_parent_step_is_weak():
    found = find_attacks("example.com/view.php?xml=../album.xml")
    assert [f["category"] for f in found] == ["path_traversal"]
    assert found[0]["severity"] == 5.0


@pytest.mark.parametrize("url", [
    "github.com/login", "www.google.com/search?q=weather", "en.wikipedia.org/wiki/Phishing",
    "seesaawiki.jp/pathofexile/d/%a5%ad%a5%e3%ba%ee%c0%ae",             # EUC-JP text, not overlong UTF-8
    "example.org/deaths.php?sortfield=deaths.%60MAIDEN%60&sortby=DESC",  # backticked SQL column name
    "serverfault.com/questions/1/execute-powershell-add-computer-remotely-via-invoke-command",
    "example.com/images/.../index.html",                                   # folder named "...", not traversal
    "example.com/blog/how-to-use-select-in-sql",
])
def test_no_false_alarm(url):
    assert cats(url) == set()


def test_floor_combination():
    assert attack_floor([]) == 0.0
    two = [{"severity": 7.0}, {"severity": 6.0}]
    assert attack_floor(two) == 7.5
