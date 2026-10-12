"""Score URLs from the command line. The URL is analysed as text only; it is never opened.

Usage:
    python check_url.py "example.com/login"          # one or more URLs as arguments
    python check_url.py                              # interactive: type URLs, empty line to quit
"""
import sys
import warnings

warnings.filterwarnings("ignore")

from src.scoring import score_url  # noqa: E402


def show(url: str) -> None:
    r = score_url(url)
    conf = f"{r['confidence']:.0%}" if r["confidence"] is not None else "rule-based"
    print(f"\nURL:   {url}")
    print(f"Score: {r['score']}/10   Type: {r['type']}   Confidence: {conf}")
    print(f"ML model: {r['ml_score']}/10 ({r['ml_type']})   Rules: {r['rule_floor']}/10")
    print("Probabilities: " + ", ".join(f"{k} {v:.0%}" for k, v in r["probabilities"].items()))
    if r["rule_findings"]:
        print("Rule findings:")
        for f in r["rule_findings"]:
            print(f"  ! {f['description']} (severity {f['severity']:.1f})")
    print("Model reasons:")
    for e in r["explanation"]:
        print(f"  - {e['sentence']}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for u in sys.argv[1:]:
            show(u)
    else:
        print("Loading model... (type a URL and press Enter; empty line to quit)")
        while True:
            u = input("\nURL> ").strip()
            if not u:
                break
            show(u)
