"""Rule-based detection of attack payloads inside URLs (string analysis only, nothing is fetched).

These are not one of the four ML classes (benign/phishing/malware/defacement) and the training
data has almost no examples (0 rows contain /etc/passwd), so a model cannot learn them. They are
detected with documented rules and pushed into the final score as a floor (see scoring.py).

Each rule family covers the general technique, including evasions:
  * URL decoding is applied repeatedly (catches %2e%2e%2f and double-encoded %252e%252e%252f)
  * HTML entities are unescaped, backslashes are treated as slashes, matching is case-insensitive
  * overlong UTF-8 encodings of "." and "/" (%c0%ae, %c0%af, %e0%80%ae) are recognised

Severities are on the 0-10 risk scale and are a judgement call (documented, tested):
  ~9-10 remote code execution style payloads; ~8-9 traversal reaching a sensitive file;
  ~7-8 injection payloads; ~6-7 probing for sensitive files without traversal.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import unquote

MAX_DECODE_ROUNDS = 3


@dataclass(frozen=True)
class Rule:
    category: str
    severity: float
    description: str
    patterns: tuple[str, ...]

    def compiled(self):
        return [re.compile(p, re.IGNORECASE) for p in self.patterns]


RULES = [
    Rule("path_traversal", 7.5, "directory traversal sequence (../) to escape the web root", (
        # Exactly two dots: a folder literally named "..." is a phishing-kit habit, not traversal.
        r"(?:^|[/=?&;,:\\])(?<!\.)\.\.(?!\.)[/\\]",  # ../  ..\  =../
        r"[/\\](?<!\.)\.\.(?!\.)(?:[/\\]|$)",        # /..  /../
        r"\.\.;[/\\]",                              # ..;/ (Tomcat path-parameter bypass)
        r"\.{4}[/\\]{2}",                           # ....// (filter that strips "../" once)
        # Overlong UTF-8 "." / "/" only in traversal shape (a lone %c0%ae is valid EUC-JP text).
        r"(?:%c0%ae|%e0%80%ae){2}", r"(?:\.|%c0%ae){2}(?:%c0%af|%c1%9c)",
    )),
    Rule("sensitive_file", 6.5, "request for a sensitive system or configuration file", (
        r"/etc/(?:passwd|shadow|group|hosts|issue|sudoers|crontab|fstab)\b",
        r"/proc/self/(?:environ|cmdline|maps|fd)",
        r"(?:win|boot|system)\.ini\b", r"windows[/\\]system32", r"\bc:[/\\]windows\b",
        r"(?:^|[/=])\.env(?:\.[a-z]+)?(?:$|[?#&/])", r"wp-config\.php", r"\.git/(?:config|head|index)",
        r"\.(?:htaccess|htpasswd|bash_history|ds_store)\b", r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
        r"\.ssh/(?:authorized_keys|known_hosts)", r"\.aws/credentials", r"\bweb\.config\b",
        r"\.(?:sql|bak|old|swp)(?:$|[?#])", r"/\.svn/", r"/server-status\b", r"phpinfo\.php",
    )),
    Rule("command_injection", 9.0, "operating-system command injection", (
        r"[;|&`]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|ping|nslookup|echo|rm|chmod)(?=\s|$|[;|&<>])",
        # $( ) and backticks only around a shell command (backticks also quote SQL column names)
        r"\$\(\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping|echo)\b[^)]{0,80}\)",
        r"`\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping|echo)\b[^`]{0,80}`",
        r"/bin/(?:ba)?sh\b", r"\bcmd(?:\.exe)?\s*/c\b",
        r"\bpowershell(?:\.exe)?\s+(?:\S+\s+){0,4}-(?:enc|encodedcommand|e|c|command|nop|w)\s",
        r"\|\s*(?:ba)?sh\b",
        r"\bnc\s+-[elv]", r"/dev/tcp/",
    )),
    Rule("code_injection", 9.5, "server-side code / template / JNDI injection", (
        r"\$\{\s*jndi\s*:", r"\$\{\s*(?:env|sys|lower|upper|::-)", r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"\$\{\s*\d+\s*\*\s*\d+\s*\}", r"<%=?\s*\d+\s*\*\s*\d+\s*%>", r"\{\{.*(?:__class__|config|self)\b.*\}\}",
        r"\b(?:php|expect|phar|zip|data)://", r"\b(?:system|exec|passthru|shell_exec|eval|assert)\s*\(",
        r"\bbase64_decode\s*\(",
    )),
    Rule("sql_injection", 8.0, "SQL injection payload", (
        r"\bunion\b[\s/*+()]+(?:all[\s/*+()]+)?select\b", r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"\bor\s+1\s*=\s*1\b", r"\b(?:sleep|pg_sleep)\s*\(\s*\d", r"\bbenchmark\s*\(", r"\bwaitfor\s+delay\b",
        r"\binformation_schema\b", r"\bxp_cmdshell\b", r";\s*(?:drop|truncate|delete|insert|update)\s+\w",
        r"['\"]\s*(?:--|#)\s*(?:$|&)", r"['\"]\s*/\*",r"\b(?:extractvalue|updatexml)\s*\(", r"\bselect\b.+\bfrom\b.+\bwhere\b",
    )),
    Rule("xss", 7.5, "cross-site scripting (script injection) payload", (
        r"<\s*/?\s*script\b", r"\bjavascript\s*:", r"\bvbscript\s*:", r"\bon(?:error|load|mouseover|focus|click|"
        r"toggle|begin|animationstart)\s*=", r"<\s*(?:svg|iframe|img|body|object|embed|details|video|audio)\b[^>]*"
        r"(?:on\w+|src|data)\s*=", r"\bdocument\s*\.\s*(?:cookie|domain|write|location)\b",
        r"\b(?:alert|prompt|confirm)\s*\(", r"\bstring\s*\.\s*fromcharcode\b", r"\bsrcdoc\s*=",
    )),
    Rule("ssrf_or_file_scheme", 7.0, "server-side request forgery / local resource access", (
        r"\b(?:file|gopher|dict|ldap|tftp|jar|netdoc)://", r"169\.254\.169\.254", r"metadata\.google\.internal",
        r"[?&][^=]{1,30}=\s*(?:https?://)?(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])\b",
    )),
    Rule("null_byte", 6.0, "null-byte injection (string truncation trick)", (r"\x00",)),
    Rule("crlf_injection", 6.5, "CRLF / HTTP header injection", (r"[\r\n]\s*(?:set-cookie|location|content-)\s*:",)),
]
_COMPILED = [(r, r.compiled()) for r in RULES]

COMBINATION_BONUS = 0.5  # per additional distinct category, capped at 10
TRAVERSAL_TO_FILE_SEVERITY = 9.0  # traversal that reaches a sensitive file (classic LFI)
SHALLOW_TRAVERSAL_SEVERITY = 5.0  # one "../" only: relative links in normal apps look like this
_TRAVERSAL_STEP = re.compile(r"(?<!\.)\.\.(?!\.)[/\\]|(?:%c0%ae|%e0%80%ae){2}", re.IGNORECASE)


def decoded_forms(url: str) -> list[str]:
    """Raw string plus successively URL-decoded / entity-unescaped forms (deduplicated)."""
    forms, cur = [url], url
    for _ in range(MAX_DECODE_ROUNDS):
        nxt = html.unescape(unquote(cur, errors="replace"))
        if nxt == cur:
            break
        forms.append(nxt)
        cur = nxt
    return list(dict.fromkeys(forms))


def find_attacks(url: str) -> list[dict]:
    """All matched rule categories with severity, description and the matching evidence."""
    forms = decoded_forms(url)
    findings = []
    for rule, patterns in _COMPILED:
        for form in forms:
            m = next((p.search(form) for p in patterns if p.search(form)), None)
            if m:
                ev = m.group(0)
                findings.append({"category": rule.category, "severity": rule.severity,
                                 "description": rule.description,
                                 "evidence": ev.encode("unicode_escape").decode("ascii")[:60]})
                break
    depth = max(len(_TRAVERSAL_STEP.findall(f)) for f in forms)
    for f in findings:
        if f["category"] == "path_traversal" and depth < 2:
            f["severity"] = SHALLOW_TRAVERSAL_SEVERITY
            f["description"] = "single parent-directory step (../); common in normal web apps, weak alone"
    cats = {f["category"] for f in findings}
    if {"path_traversal", "sensitive_file"} <= cats:
        for f in findings:
            if f["category"] == "path_traversal":
                f["severity"] = TRAVERSAL_TO_FILE_SEVERITY
                f["description"] = "directory traversal reaching a sensitive file (local file inclusion)"
    return sorted(findings, key=lambda f: -f["severity"])


def attack_floor(findings: list[dict]) -> float:
    """Minimum risk score implied by the findings (0 if none)."""
    if not findings:
        return 0.0
    return min(10.0, max(f["severity"] for f in findings) + COMBINATION_BONUS * (len(findings) - 1))
