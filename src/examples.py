"""Phase 4: print and save 10 example score_url outputs (hand-written URLs, never fetched)."""
import time
from pathlib import Path

from src.scoring import format_result, score_url

EXAMPLES = [
    "https://www.google.com/search?q=weather",
    "en.wikipedia.org/wiki/Machine_learning",
    "github.com/scikit-learn/scikit-learn/blob/main/README.rst",
    "https://docs.python.org/3/library/urllib.parse.html",
    "http://paypal-account-verify.secure-login.tk/signin/update.php?id=88231",
    "http://192.168.43.10/bins/mozi.arm7",
    "http://198.51.100.23:8080/Photo.scr",
    "bit.ly/3xYz9Ab",
    "http://www.example-school.edu/index.php?option=com_content&view=article&id=48&Itemid=55",
    "secure-bankofamerica.com-verify-account.info/login/confirm/password.html",
]

if __name__ == "__main__":
    lines = ["# Phase 4: example ML-only scores", "",
             "Hand-written example URLs (not from the training data; never fetched). Model: v2-no-https.", ""]
    for url in EXAMPLES:
        t = time.time()
        r = score_url(url)
        dt = time.time() - t
        line = format_result(r)
        print(f"{url}\n  {line}  [{dt:.2f}s]\n")
        lines += [f"**`{url}`**", "", f"- {line}",
                  f"- Probabilities: {r['probabilities']}", f"- Time: {dt:.2f}s", ""]
    Path("reports/phase4/examples.md").write_text("\n".join(lines), encoding="utf-8")
