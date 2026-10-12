"""Brand impersonation (typosquatting) detection on URL strings. Nothing is fetched or resolved.

Covers the general category, not individual examples:
  * homoglyph squatting   g00gle, paypa1, rnicrosoft, Cyrillic look-alikes, punycode (xn--)
  * typosquatting         one/two-character insert, delete, substitute or transpose (gogle, googel)
  * combosquatting        brand plus extra words in the registered domain (paypal-login-secure)
  * brand in subdomain    paypal.com.account-verify.tk, apple.id-support.xyz
  * brand in path/query   unrelated-host.tk/paypal/signin (weak signal: legit sites do this too)

Reference data (built offline from the local Tranco list, see build_reference):
  * brands     second-level labels of the top BRAND_TOP_N registered domains (len >= MIN_BRAND_LEN,
               letters only), plus TARGET_BRANDS (frequently phished brands)
  * popular    registered domains among the top POPULAR_TOP_N Tranco entries. A popular domain is never
               reported as squatting another one (e.g. bing.com vs king.com are both real sites).

Edit-distance search uses a symmetric-delete index (SymSpell idea) verified with optimal string
alignment distance, so lookups stay fast for 800k+ URLs.
"""
from __future__ import annotations

import json
import unicodedata
import warnings
from functools import lru_cache
from pathlib import Path

import tldextract

ROOT = Path(__file__).resolve().parent.parent
REFERENCE_PATH = ROOT / "data" / "processed" / "brand_reference.json"

BRAND_TOP_N = 10_000      # Tranco brand labels used for exact / look-alike-character matches
# Edit-distance (misspelling) search uses only the most popular labels plus TARGET_BRANDS.
# Measured on 40k train URLs per class: all 10k labels flag 1.2% of benign URLs (franco.ca ->
# "france"); top 300 + targets flag 0.06% of benign vs 0.28% of phishing (4.5x).
TYPO_TOP_N = 300
POPULAR_TOP_N = 200_000   # Tranco entries treated as genuine (never flagged as squats)
MIN_BRAND_LEN = 5         # shorter labels collide with ordinary words too often

# Frequently impersonated brands (APWG / vendor phishing reports). Matched in subdomains,
# paths and as combosquat tokens; typosquat search uses these plus the Tranco brands.
TARGET_BRANDS = {
    "paypal": ["paypal.com"], "apple": ["apple.com"], "icloud": ["icloud.com"],
    "microsoft": ["microsoft.com"], "office365": ["office.com"], "outlook": ["outlook.com", "live.com"],
    "onedrive": ["live.com"], "sharepoint": ["sharepoint.com"], "google": ["google.com"],
    "gmail": ["gmail.com", "google.com"], "amazon": ["amazon.com"], "netflix": ["netflix.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"], "twitter": ["twitter.com", "x.com"], "telegram": ["telegram.org"],
    "dropbox": ["dropbox.com"], "docusign": ["docusign.com", "docusign.net"], "adobe": ["adobe.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"], "hsbc": ["hsbc.com"], "barclays": ["barclays.co.uk"],
    "santander": ["santander.com"], "americanexpress": ["americanexpress.com"], "amex": ["americanexpress.com"],
    "mastercard": ["mastercard.com"], "visa": ["visa.com"], "coinbase": ["coinbase.com"],
    "binance": ["binance.com"], "metamask": ["metamask.io"], "blockchain": ["blockchain.com"],
    "kraken": ["kraken.com"], "steam": ["steampowered.com", "steamcommunity.com"], "roblox": ["roblox.com"],
    "epicgames": ["epicgames.com"], "ebay": ["ebay.com"], "alibaba": ["alibaba.com"], "aliexpress": ["aliexpress.com"],
    "walmart": ["walmart.com"], "dhl": ["dhl.com"], "fedex": ["fedex.com"], "usps": ["usps.com"],
    "yahoo": ["yahoo.com"], "spotify": ["spotify.com"], "discord": ["discord.com", "discord.gg"],
    "github": ["github.com"], "shopee": ["shopee.com"], "allegro": ["allegro.pl"], "uphold": ["uphold.com"],
    "irs": ["irs.gov"], "battlenet": ["battle.net"], "booking": ["booking.com"], "airbnb": ["airbnb.com"],
    "zoom": ["zoom.us"], "wetransfer": ["wetransfer.com"], "office": ["office.com"], "itau": ["itau.com.br"],
    "bradesco": ["bradesco.com.br"], "nubank": ["nubank.com.br"], "mercadolibre": ["mercadolibre.com"],
    "rakuten": ["rakuten.co.jp"], "naver": ["naver.com"], "orange": ["orange.fr"], "swisscom": ["swisscom.ch"],
}

# Target brands that are also everyday words ("office", "orange", "chase", "apple"...). Exact or
# embedded matches of these only count when the host also contains a phishing lure word; on the
# test split, unconditioned matches hit benign sites like kolblawoffice.com and ny-orange.com.
AMBIGUOUS_BRANDS = {
    "office", "outlook", "orange", "chase", "telegram", "booking", "steam", "zoom", "visa", "kraken",
    "apple", "discord", "allegro", "uphold", "blockchain", "naver", "shopee", "office365",
}
LURE_WORDS = (
    "login", "logon", "signin", "sign-in", "verify", "verif", "secure", "account", "update", "confirm",
    "support", "billing", "wallet", "auth", "password", "recover", "unlock", "suspend", "webscr",
    "service", "helpdesk", "free", "gift", "bonus", "claim", "id-", "-id", "payment", "invoice",
)

# Character-level look-alikes mapped to their Latin targets. Multi-valued entries produce variants.
_CHAR_HOMOGLYPHS = {
    "0": ["o"], "1": ["l", "i"], "3": ["e"], "4": ["a"], "5": ["s"], "7": ["t"], "8": ["b"], "9": ["g"],
    "@": ["a"], "$": ["s"], "!": ["i"], "|": ["l"],
    # Cyrillic / Greek / other confusables commonly used in IDN homograph attacks
    "а": ["a"], "е": ["e"], "о": ["o"], "р": ["p"], "с": ["c"], "у": ["y"], "х": ["x"], "і": ["i"],
    "ј": ["j"], "ԁ": ["d"], "ɡ": ["g"], "ո": ["n"], "ѕ": ["s"], "ӏ": ["l"], "ν": ["v"], "κ": ["k"],
    "α": ["a"], "ο": ["o"], "ρ": ["p"], "τ": ["t"], "ε": ["e"], "ι": ["i"], "м": ["m"], "т": ["t"],
    "в": ["b"], "н": ["h"], "к": ["k"], "ɩ": ["l"], "ı": ["i"],
}
_MULTI_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]
_MAX_VARIANTS = 16

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline


# --- distance helpers ---------------------------------------------------------------------
def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment (Damerau-Levenshtein with adjacent transpositions)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    prev2, prev = None, list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def max_typo_distance(brand: str) -> int:
    """Edits tolerated for a brand of this length (short names need exact-ish matches)."""
    return 1 if len(brand) <= 8 else 2


def _deletes(word: str, max_d: int) -> set[str]:
    """`word` plus every string obtained by deleting up to max_d characters (min length 3)."""
    out, frontier = {word}, {word}
    for _ in range(max_d):
        frontier = {w[:i] + w[i + 1:] for w in frontier if len(w) > 3 for i in range(len(w))}
        out |= frontier
    return out


def homoglyph_variants(s: str) -> set[str]:
    """Latin skeletons of a string after undoing common look-alike substitutions."""
    s = unicodedata.normalize("NFKC", s.lower())
    variants = {""}
    for ch in s:
        repl = _CHAR_HOMOGLYPHS.get(ch, [ch])
        variants = {v + r for v in variants for r in repl}
        if len(variants) > _MAX_VARIANTS:
            variants = set(sorted(variants)[:_MAX_VARIANTS])
    out = set(variants)
    for v in variants:
        for a, b in _MULTI_HOMOGLYPHS:
            if a in v:
                out.add(v.replace(a, b))
    return out


def decode_punycode(host: str) -> str:
    """Decode xn-- labels with the stdlib IDNA codec (pure computation, no DNS)."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


# --- reference data -------------------------------------------------------------------------
def build_reference(tranco_path: Path | None = None, out_path: Path = REFERENCE_PATH) -> dict:
    """Build brand/popular-domain reference from the local Tranco CSV (no network)."""
    from src.build_dataset import RAW_DIR, read_tranco, resolve_sources

    tranco_path = tranco_path or resolve_sources(RAW_DIR)["tranco"]
    df = read_tranco(tranco_path).nsmallest(POPULAR_TOP_N, "rank")
    popular, brands = [], {}
    for domain in df["domain"]:
        ext = _EXTRACT(domain)
        reg = ext.top_domain_under_public_suffix
        if not reg:
            continue
        popular.append(reg)
        label = ext.domain
        if (len(brands) < BRAND_TOP_N and len(label) >= MIN_BRAND_LEN and label.isalpha()
                and label not in brands):
            brands[label] = reg
    ref = {"brands": brands, "popular": sorted(set(popular)), "source": tranco_path.name,
           "brand_top_n": BRAND_TOP_N, "popular_top_n": POPULAR_TOP_N}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(ref), encoding="utf-8")
    return ref


class BrandIndex:
    def __init__(self, brands: dict[str, str], popular: set[str]):
        self.brands = dict(brands)  # label -> canonical registered domain
        self.official = {}
        for b, domains in TARGET_BRANDS.items():
            self.brands.setdefault(b, domains[0])
            self.official[b] = set(domains)
        for b, reg in self.brands.items():
            self.official.setdefault(b, set()).add(reg)
        self.targets = set(TARGET_BRANDS)
        self.popular = set(popular) | {d for ds in self.official.values() for d in ds}
        self._delete_index: dict[str, set[str]] = {}
        self._lengths = {len(b) for b in self.brands}
        typo_brands = set(list(brands)[:TYPO_TOP_N]) | self.targets
        for b in typo_brands:
            if len(b) < MIN_BRAND_LEN and b not in self.targets:
                continue
            for d in _deletes(b, max_typo_distance(b)):
                self._delete_index.setdefault(d, set()).add(b)

    def near_brands(self, token: str, targets_only: bool = False) -> list[tuple[str, int]]:
        """Brands within the allowed edit distance of `token` (excluding exact matches).

        Sorted by distance, then target brands first, then longer brands."""
        if len(token) < 4 or not self._lengths & set(range(len(token) - 2, len(token) + 3)):
            return []
        cands = set()
        for d in _deletes(token, 1 if len(token) <= 7 else 2):
            cands |= self._delete_index.get(d, set())
        out = []
        for b in cands:
            if b == token or abs(len(b) - len(token)) > max_typo_distance(b):
                continue
            if targets_only and b not in self.targets:
                continue
            if len(b) < 5:  # short target brands (dhl, usps, visa): only exact/homoglyph matches
                continue
            dist = osa_distance(token, b)
            if 0 < dist <= max_typo_distance(b):
                out.append((b, dist))
        return sorted(out, key=lambda x: (x[1], x[0] not in self.targets, -len(x[0]), x[0]))

    def is_official(self, brand: str, registered: str) -> bool:
        return registered in self.official.get(brand, set())


@lru_cache(maxsize=1)
def load_index(path: Path = REFERENCE_PATH) -> BrandIndex:
    if path.exists():
        ref = json.loads(path.read_text(encoding="utf-8"))
    else:
        try:
            ref = build_reference(out_path=path)
        except Exception as exc:  # no local Tranco list: fall back to TARGET_BRANDS only
            warnings.warn(f"brand reference unavailable ({exc}); using built-in target brands only")
            ref = {"brands": {}, "popular": []}
    return BrandIndex(ref["brands"], set(ref["popular"]))


# --- analysis -------------------------------------------------------------------------------
def _tokens(s: str) -> list[str]:
    out, cur = [], []
    for ch in s.lower():
        if ch.isalnum() or ch in "@$!|" or ord(ch) > 127:
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


def analyze(host: str, path_and_query: str, index: BrandIndex | None = None) -> dict:
    """Brand-impersonation signals for one URL. Returns flags plus the matched brand."""
    index = index or load_index()
    res = dict(_analyze_host_cached(host.lower().rstrip("."), id(index)) if index is load_index()
               else _analyze_host(host.lower().rstrip("."), index))
    if res["brand_in_path"] == 0:
        for tok in _tokens(path_and_query):
            if tok in index.targets and len(tok) >= 5 and not index.is_official(tok, res["registered"]):
                res["brand_in_path"] = 1
                res["matched_brand"] = res["matched_brand"] or tok
                break
    return res


@lru_cache(maxsize=500_000)
def _analyze_host_cached(host: str, _index_id: int) -> dict:
    return _analyze_host(host, load_index())


def _analyze_host(host: str, index: BrandIndex) -> dict:
    decoded = decode_punycode(host)
    ext = _EXTRACT(decoded)
    registered = ext.top_domain_under_public_suffix or decoded
    sld = ext.domain
    sub = ext.subdomain
    is_popular = registered in index.popular or host in index.popular
    res = {"has_punycode": int("xn--" in host), "non_ascii_host": int(any(ord(c) > 127 for c in decoded)),
           "brand_homoglyph": 0, "brand_typosquat": 0, "brand_combosquat": 0,
           "brand_in_subdomain": 0, "brand_in_path": 0, "matched_brand": None, "registered": registered,
           "is_popular": is_popular}

    has_lure = any(w in decoded for w in LURE_WORDS)

    def hit(flag, brand):
        res[flag] = 1
        res["matched_brand"] = res["matched_brand"] or brand

    def usable(brand):  # everyday-word brands need a lure word somewhere in the host
        return brand not in AMBIGUOUS_BRANDS or has_lure

    if not is_popular and sld:
        if sld in index.targets and not index.is_official(sld, registered) and usable(sld):
            hit("brand_typosquat", sld)                   # same brand, other TLD: paypal.help
        sld_tokens = [t for t in sld.replace("_", "-").split("-") if t]
        whole = sld.replace("-", "").replace("_", "")
        candidates = [whole] + (sld_tokens if len(sld_tokens) > 1 else [])
        for tok in candidates:
            is_whole = tok == whole
            if tok in index.brands:
                # exact brand word inside a multi-word label: paypal-login.com (targets only;
                # generic Tranco labels such as "account" or "library" are ordinary words)
                if (not is_whole or len(sld_tokens) > 1) and tok in index.targets and usable(tok):
                    hit("brand_combosquat", tok)
                continue
            if not is_whole and len(tok) < 4:
                continue
            variants = homoglyph_variants(tok) - {tok}
            glyph = next((v for v in sorted(variants) if v in index.brands), None)
            if glyph:
                hit("brand_homoglyph", glyph)             # g00gle.com, xn--pypal-4ve.com
                if not is_whole or len(sld_tokens) > 1:
                    res["brand_combosquat"] = 1
                continue
            # Whole label: any reference brand. Extra words in a multi-word label ("support",
            # "secure") only against target brands, to avoid matching ordinary words.
            for v in [tok] + sorted(variants)[:3]:
                near = index.near_brands(v, targets_only=not is_whole)
                if near:
                    hit("brand_typosquat", near[0][0])    # gooogle.com, amazn.com
                    if not is_whole or len(sld_tokens) > 1:
                        res["brand_combosquat"] = 1
                    break
        # brand embedded inside a longer label without separators: securepaypallogin.com
        if not (res["brand_homoglyph"] or res["brand_typosquat"] or res["brand_combosquat"]):
            for v in homoglyph_variants(whole):
                b = next((t for t in sorted(index.targets) if len(t) >= 5 and t in v and t != v and usable(t)), None)
                if b:
                    hit("brand_combosquat", b)
                    break

    # Target brand as (the start of) a subdomain word on a domain it doesn't own:
    # paypal.com.verify.tk, login.microsoftonline.com.evil.ru
    for tok in _tokens(sub):
        for v in homoglyph_variants(tok):
            b = v if v in index.targets else next(
                (t for t in index.targets if len(t) >= 5 and v.startswith(t)), None)
            if b and not index.is_official(b, registered) and usable(b):
                hit("brand_in_subdomain", b)
                break
        if res["brand_in_subdomain"]:
            break
    return res


# --- rule findings for the final score ------------------------------------------------------
# Minimum risk score when a strong impersonation signal fires on a domain that is NOT popular.
# Popular (Tranco top-200k) domains never get a floor: apple.stackexchange.com is not phishing.
BRAND_RULE_SEVERITY = {
    "brand_homoglyph": (8.0, "imitates the brand '{b}' with look-alike characters"),
    "brand_typosquat": (6.5, "is a misspelling or other-TLD copy of the brand '{b}'"),
    "brand_combosquat": (7.0, "combines the brand '{b}' with other words in an unrelated domain"),
    "brand_in_subdomain": (7.0, "puts the brand '{b}' in the subdomain of a domain it does not own"),
}


def brand_findings(signals: dict) -> list[dict]:
    """Findings (category, severity, description) from analyze() output; empty for popular domains."""
    if signals.get("is_popular") or not signals.get("matched_brand"):
        return []
    out = []
    for flag, (sev, text) in BRAND_RULE_SEVERITY.items():
        if signals.get(flag):
            out.append({"category": flag, "severity": sev, "description": text.format(b=signals["matched_brand"]),
                        "evidence": signals.get("registered", "")})
    return sorted(out, key=lambda f: -f["severity"])
