#!/usr/bin/env python3
"""
main.py -- Plasma v3 CLI
--------------------------
Entry point for command-line scanning and UI server launch.

Usage examples:
  python main.py --url https://target.com
  python main.py --url https://target.com --profile aggressive --report html,markdown
  python main.py --url https://target.com --login-url https://target.com/login --login-data "u=admin&p=admin"
  python main.py --batch urls.txt --report html
  python main.py --replay scans/scan_20240101.json
  python main.py --ui                          # start the web dashboard
  python main.py --ui --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime

from config import (
    TOOL_NAME, TOOL_VERSION, DISCLAIMER,
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
    DEFAULT_CRAWL_DEPTH, DEFAULT_TIMEOUT, DEFAULT_REPORT_DIR,
    UI_HOST, UI_PORT,
)
from core.models import ScanSettings
from core.scan_manager import ScanManager
from utils.banner import print_banner
from utils import cli_ui


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plasma",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DISCLAIMER,
    )

    # ── Mode ──────────────────────────────────────────────────────────────────
    # --ui is a top-level mode switch; mutually exclusive with scanning flags
    p.add_argument(
        "--ui",
        action="store_true",
        help="Launch the web dashboard (http://127.0.0.1:5001 by default)",
    )
    p.add_argument("--host", default=UI_HOST, metavar="HOST",
                   help=f"Dashboard host (default: {UI_HOST}, use 0.0.0.0 for all interfaces)")
    p.add_argument("--port", type=int, default=UI_PORT, metavar="PORT",
                   help=f"Dashboard port (default: {UI_PORT})")

    # ── Target ────────────────────────────────────────────────────────────────
    target = p.add_mutually_exclusive_group()
    target.add_argument("--url",   "-u",  metavar="URL",  help="Target URL to scan")
    target.add_argument("--batch", "-b",  metavar="FILE", help="Batch file: one URL per line")
    target.add_argument("--replay", metavar="FILE",       help="Replay a scan saved with --save-scan. Reruns all phases against recorded state.")

    # Input sources (supplemental to --url / --batch)
    p.add_argument("--har",         metavar="FILE", dest="har_file",
                   help="Parse a browser HAR recording and use all requests as scan targets. "
                        "Enables scanning authenticated flows without re-crawling. "
                        "Export from: Chrome DevTools > Network > Save all as HAR.")
    p.add_argument("--diff-scans",  metavar="FILE", nargs=2, dest="diff_scans",
                   help="Compare two Plasma scan JSON files: plasma --diff-scans before.json after.json. "
                        "Shows NEW (regressions), FIXED, and UNCHANGED findings.")

    # ── Scan profile & depth ──────────────────────────────────────────────────
    p.add_argument("--profile", "-p", default=DEFAULT_SCAN_PROFILE,
                   choices=list(SCAN_PROFILES.keys()),
                   help=("Scan aggressiveness profile (default: %(default)s). safe=passive/no payloads, default=moderate, aggressive=full payloads/no delays ⚠, stealth=low-rate/evasive"))
    p.add_argument("--depth",   "-d", type=int, default=DEFAULT_CRAWL_DEPTH,
                   help="Max crawl depth (default: %(default)s)")
    p.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT,
                   help="Request timeout seconds (default: %(default)s)")

    # ── Authentication ────────────────────────────────────────────────────────
    auth = p.add_argument_group("Authentication")
    auth.add_argument("--login-url",    metavar="URL",
                      help="Login form URL (e.g. https://site.com/login)")
    auth.add_argument("--login-method", default="POST", metavar="METHOD",
                      help="HTTP method for login (default: POST)")
    auth.add_argument("--login-data",   metavar="DATA",
                      help="Login POST data: 'username=admin&password=admin'")
    auth.add_argument("--login-script", metavar="FILE",
                      help=("Path to a Python script for custom multi-step auth (OAuth, MFA, SAML). Must define: def authenticate(session): return session"))
    auth.add_argument("--auth-cookie",  metavar="STR",
                      help="Raw cookie string to inject: 'sessionid=abc; csrftoken=xyz'")

    # ── Network ───────────────────────────────────────────────────────────────
    net = p.add_argument_group("Network")
    net.add_argument("--proxy", metavar="URL",
                     help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    net.add_argument("--collaborator", metavar="URL",
                     help=("OOB (Out-of-Band) collaborator URL — receives DNS/HTTP callbacks from blind SSRF, SQLi, and RCE payloads that produce no visible response. Use Burp Collaborator, interactsh, or similar. e.g. https://xyz.oastify.com"))
    net.add_argument("--blind-xss",    metavar="URL",
                     help=("Blind XSS callback URL — injected into all XSS payloads. Fires when a victim (e.g. admin) loads a page with the payload. Use XSS Hunter or a custom listener. e.g. https://your.xsshunter.com"))

    # ── Detector selection ────────────────────────────────────────────────────
    det = p.add_argument_group("Detector Selection")
    det.add_argument("--detectors", metavar="LIST",
                     help="Comma-separated list of detectors to ENABLE (default: all)")
    det.add_argument("--skip",      metavar="LIST",
                     help="Comma-separated list of detectors to DISABLE (e.g. cors,jwt)")
    det.add_argument("--plugin-dir", metavar="DIR",
                     help="Directory containing custom detector plugins")
    det.add_argument("--templates",  metavar="DIR",
                     help="Directory containing Nuclei-style YAML scan templates")
    # ── Individual detector test flags (required by spec) ────────────────────
    det.add_argument("--test-csrf",          action="store_true", dest="test_csrf",
                     help="Run CSRF detector only  (shorthand: --detectors csrf)")
    det.add_argument("--test-sqli",          action="store_true", dest="test_sqli",
                     help="Run SQL injection detector only")
    det.add_argument("--test-xss",           action="store_true", dest="test_xss",
                     help="Run XSS detector only")
    det.add_argument("--test-ssrf",          action="store_true", dest="test_ssrf",
                     help="Run SSRF detector only")
    det.add_argument("--test-rce",           action="store_true", dest="test_rce",
                     help="Run RCE / OS command injection detector only")
    det.add_argument("--test-idor",          action="store_true", dest="test_idor",
                     help="Run IDOR detector only")
    det.add_argument("--test-misconfig",     action="store_true", dest="test_misconfig",
                     help="Run misconfiguration detector only")
    det.add_argument("--test-dir-traversal", action="store_true", dest="test_dir_traversal",
                     help="Run directory traversal detector only")
    det.add_argument("--test-ssti",          action="store_true", dest="test_ssti",
                     help="Run SSTI (Server-Side Template Injection) detector — math-expression canary probes for Jinja2/Twig/Freemarker/Mako")
    det.add_argument("--test-cache-poisoning", action="store_true", dest="test_cache_poisoning",
                     help="Run cache poisoning detector: test X-Forwarded-Host, X-Forwarded-For, "
                          "X-Original-URL header injection into cached HTTP responses.")
    det.add_argument("--test-smuggling",     action="store_true", dest="test_smuggling",
                     help="Run HTTP Request Smuggling detector — CL.TE and TE.CL timing probes (aggressive; targets with proxies)")
    det.add_argument("--test-all",           action="store_true", dest="test_all",
                     help="Enable all detectors (explicit; same as default)")
    # ── Shorthand performance flags ──────────────────────────────────────────
    det.add_argument("--concurrency", "-c", type=int, default=0, metavar="N",
                     help=("Max concurrent HTTP requests. 0 = adaptive AIMD auto-scaling (starts at 20, scales up to 48, backs off on 429/5xx). Set explicitly to cap throughput on fragile targets."))
    det.add_argument("--rate-limit",        type=float, default=0.0, metavar="RPS",
                     help="Max requests per second per target (0 = unlimited). Use 1-5 for stealth or fragile production apps.")
    det.add_argument("--no-dedup",          action="store_true", dest="no_dedup",
                     help="Disable request deduplication cache")
    det.add_argument("--http2",              action="store_true", dest="http2",
                     help="Use HTTP/2 for requests via httpx backend (requires: pip install httpx[http2]). "
                          "Falls back to HTTP/1.1 if httpx not installed.")
    det.add_argument("--no-verify-ssl",     action="store_true", dest="no_verify_ssl",
                     help="Disable SSL certificate verification (use for self-signed certs in test environments)")

    # ── Reconnaissance ────────────────────────────────────────────────────────
    recon = p.add_argument_group("Reconnaissance")
    recon.add_argument("--tls-analysis",  action="store_true", dest="tls_analysis",
                       help="Analyse TLS/SSL security: expired certificates, weak cipher suites, "
                            "outdated protocol versions (TLS 1.0/1.1/SSLv3), and CN/SAN mismatches.")
    recon.add_argument("--subdomain-takeover", action="store_true", dest="subdomain_takeover",
                       help="After --subdomains, check each subdomain for dangling CNAMEs pointing to "
                            "unclaimed cloud resources: GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Azure.")
    recon.add_argument("--subdomains",      action="store_true",
                       help="Enable DNS subdomain brute-force before scanning")
    recon.add_argument("--param-discovery", action="store_true",
                       help="Enable hidden parameter discovery on each endpoint")
    recon.add_argument("--no-js",           action="store_true",
                       help="Disable JavaScript endpoint extraction")

    # ── Scan modes ────────────────────────────────────────────────────────────
    mode = p.add_argument_group("Scan Modes")
    mode.add_argument("--api-mode", action="store_true",
                      help="API testing mode: JSON body fuzzing + REST endpoint discovery")
    mode.add_argument("--browser-parallel",  metavar="N", type=int, default=3, dest="browser_parallel",
                      help="Number of parallel pages during browser crawling (default: 3).")
    mode.add_argument("--browser",  action="store_true",
                      help=("Headless browser mode via Playwright — renders JavaScript, discovers dynamic forms and XHR endpoints, intercepts WebSocket URLs, and captures localStorage. Requires: pip install playwright && playwright install chromium"))
    mode.add_argument("--bypass",   action="store_true",
                      help=(
                          "Enable advanced access-control bypass testing: URL manipulation, "
                          "header spoofing (X-Forwarded-For etc.), HTTP method tampering, "
                          "encoding evasion, and parameter obfuscation. "
                          "When absent, zero bypass requests are made."
                      ))
    mode.add_argument("--fuzz",     action="store_true",
                      help=(
                          "Enable context-aware fuzzing: generates tailored payloads "
                          "(SQLi, XSS, RCE, SSRF, traversal, IDOR) per endpoint, applies "
                          "polymorphic encoding and WAF evasion, tracks evasion metrics, "
                          "and optionally chains findings into multi-step exploits."
                      ))
    mode.add_argument("--fuzz-websocket", action="store_true", dest="fuzz_websocket",
                      help="Fuzz WebSocket endpoints discovered by --browser. "
                           "Sends mutation payloads, detects abnormal disconnects and reflections. "
                           "Requires: pip install websockets")
    mode.add_argument("--fuzz-chain", action="store_true",
                      help="Enable exploit chaining within the fuzzer (links related findings).")
    mode.add_argument("--fuzz-stealth", action="store_true",
                      help="Run fuzzer in stealth mode: longer jitter, UA rotation, decoy headers.")
    mode.add_argument("--fuzz-profile", metavar="PROFILE",
                      help="Fuzzer-specific scan profile (overrides --profile for fuzzing only). "
                           "Values: safe | default | aggressive | stealth")
    mode.add_argument("--fuzz-dry-run", action="store_true",
                      help="Print all fuzz probes without sending any HTTP requests. "
                           "Use to audit payload coverage before testing.")
    mode.add_argument("--fuzz-target-param", metavar="PARAM",
                      help="Force the fuzzer to inject into this specific parameter name "
                           "instead of context-derived selection.")
    mode.add_argument("--extract-db", action="store_true",
                      help=("After confirming SQLi, auto-extract: DB version, name, all tables, and column samples from sensitive tables. Supports MySQL, PostgreSQL, MSSQL, SQLite, Oracle."))

    # ── File upload testing ───────────────────────────────────────────────────
    upload = p.add_argument_group("File Upload Testing")
    upload.add_argument("--upload", metavar="FILE",
                        help="Path to a test file for upload endpoint testing")
    upload.add_argument("--auto-upload", metavar="FILE",
                        help=(
                            "Path to a file to automatically upload whenever an upload-capable "
                            "endpoint is discovered (forms with <input type=file> or "
                            "multipart/form-data). Uses the same backend as --upload."
                        ))

    # ── Output & reporting ────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("--report", "-r", metavar="FORMATS",
                     help="Report formats, comma-separated: html,markdown,pdf")
    out.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, metavar="DIR",
                     help="Report output directory (default: %(default)s)")
    out.add_argument("--poc",       action="store_true",
                     help="Generate proof-of-concept exploit files")
    out.add_argument("--poc-dir",   default="poc_output", metavar="DIR",
                     help="PoC output directory (default: %(default)s)")
    out.add_argument("--save-scan", action="store_true",
                     help="Save completed scan as JSON for later --replay")
    out.add_argument("--scan-dir",  default="scans", metavar="DIR",
                     help="Scan storage directory (default: %(default)s)")
    out.add_argument("--jsonl", action="store_true", dest="jsonl_output", help="Stream findings as JSON Lines. CI: plasma -u URL --jsonl | jq .severity")
    out.add_argument("--output-json", metavar="FILE",
                     help="Write findings as JSON (exit code 1 if findings exist — useful as a CI/CD pipeline gate).")

    # ── Misc ──────────────────────────────────────────────────────────────────
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose/debug output")
    p.add_argument("--quiet",   "-q", action="store_true", help="Suppress banner, progress, and info output. Findings and errors still print.")
    p.add_argument("--usage",         action="store_true",
                   help="Print categorised usage examples (Quick Start, Profiles, Browser, Fuzzing, OOB, etc.) and exit.")

    return p


def setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_usage() -> None:
    """
    Print structured, beginner-friendly usage examples and exit.

    Sections:
      1. Quick Start — safe first commands for new users
      2. Scan Profiles — controlling aggressiveness
      3. Browser Mode (JS/SPA) — Playwright-powered crawling
      4. Authentication — scanning behind logins
      5. Vulnerability Detectors — per-detector flags
      6. Fuzzing & Exploit Generation — advanced active testing
      7. OOB / Blind Confirmation — Out-of-Band callbacks
      8. Output & Reporting — reports, PoC, JSON
      9. Advanced & Productivity — batch, replay, proxy, plugins
    """

    SECTIONS: list[tuple[str, list[tuple[str, str, str]]]] = [
        # (section_title, [(description, command, note), ...])
        (
            "🚀 Quick Start",
            [
                ("Passive scan — safe for production",
                 "plasma --url https://target.com --profile safe",
                 "✅ No payloads sent — safe to run anywhere"),
                ("Full active scan",
                 "plasma --url https://target.com --profile aggressive --report html",
                 "⚠ Active: sends attack payloads — authorized testing only"),
                ("Focus on SQL injection only",
                 "plasma --url https://target.com --test-sqli",
                 ""),
                ("Scan + save HTML report + PoC files",
                 "plasma --url https://target.com --report html --poc --report-dir ./results",
                 ""),
            ],
        ),
        (
            "⚡ Scan Profiles",
            [
                ("safe   — passive checks, no payloads",
                 "plasma --url https://target.com --profile safe",
                 "✅ Production-safe"),
                ("default — balanced active testing",
                 "plasma --url https://target.com --profile default",
                 "⚠ Active"),
                ("aggressive — full payloads, no delays",
                 "plasma --url https://target.com --profile aggressive",
                 "⚠ High volume — dedicated test env only"),
                ("stealth — low-rate, WAF-evasive",
                 "plasma --url https://target.com --profile stealth --rate-limit 1",
                 ""),
            ],
        ),
        (
            "🌐 Browser Mode — JavaScript / SPA Apps",
            [
                ("Passive browser crawl (JS execution)",
                 "plasma --url https://target.com --browser --profile safe",
                 "Requires: pip install playwright && playwright install chromium"),
                ("Browser + full active scan",
                 "plasma --url https://target.com --browser --profile aggressive --fuzz",
                 "⚠ Sends payloads into JS-discovered endpoints"),
                ("Browser + OOB blind confirmation",
                 "plasma --url https://target.com --browser --fuzz --collaborator https://xyz.oastify.com",
                 "OOB = Out-of-Band: detects blind vulnerabilities via DNS/HTTP callbacks"),
                ("Browser scan on SPA with auth cookie",
                 "plasma --url https://target.com --browser --auth-cookie 'session=abc123'",
                 ""),
            ],
        ),
        (
            "🔐 Authentication",
            [
                ("Form login",
                 "plasma --url https://target.com --login-url https://target.com/login --login-data 'username=admin&password=pass'",
                 ""),
                ("Cookie / session token",
                 "plasma --url https://target.com --auth-cookie 'session=abc; csrf=xyz'",
                 ""),
                ("Custom auth script (OAuth, MFA, SAML)",
                 "plasma --url https://target.com --login-script auth.py",
                 "auth.py must define: def authenticate(session): return session"),
            ],
        ),
        (
            "🔍 Vulnerability Detectors",
            [
                ("CSRF only",
                 "plasma --url https://target.com --test-csrf",
                 ""),
                ("SQL injection only",
                 "plasma --url https://target.com --test-sqli",
                 ""),
                ("XSS only",
                 "plasma --url https://target.com --test-xss",
                 ""),
                ("SSRF only",
                 "plasma --url https://target.com --test-ssrf",
                 ""),
                ("Multiple specific detectors",
                 "plasma --url https://target.com --test-sqli --test-xss --test-ssrf",
                 ""),
                ("All except CORS and JWT",
                 "plasma --url https://target.com --skip cors,jwt",
                 ""),
            ],
        ),
        (
            "💥 Fuzzing & Exploit Generation",
            [
                ("Context-aware fuzzing",
                 "plasma --url https://target.com --fuzz --profile aggressive",
                 "⚠ Generates many requests — authorized test environments only"),
                ("Exploit chain detection (SQLi→IDOR, SSRF→RCE, etc.)",
                 "plasma --url https://target.com --fuzz --fuzz-chain",
                 ""),
                ("Extract DB schema on confirmed SQLi",
                 "plasma --url https://target.com --fuzz --extract-db",
                 "--extract-db: auto-queries table names, columns, sample data"),
                ("Dry-run: print payloads without sending",
                 "plasma --url https://target.com --fuzz --fuzz-dry-run",
                 "✅ Safe — no HTTP requests made"),
                ("Stealth fuzzing (slow, evasive)",
                 "plasma --url https://target.com --fuzz --fuzz-stealth --rate-limit 2",
                 ""),
                ("Inject into a specific parameter only",
                 "plasma --url https://target.com --fuzz --fuzz-target-param id",
                 ""),
            ],
        ),
        (
            "📡 OOB / Blind Confirmation",
            [
                ("Blind SSRF/SQLi via collaborator",
                 "plasma --url https://target.com --collaborator https://YOUR.oastify.com",
                 "OOB = Out-of-Band: blind vulns confirmed via DNS/HTTP callback"),
                ("Blind XSS detection",
                 "plasma --url https://target.com --blind-xss https://YOUR.xsshunter.com",
                 "Blind XSS fires when a victim admin loads the injected page"),
                ("Full blind confirmation workflow",
                 "plasma --url https://target.com --fuzz --collaborator https://xyz.oastify.com --blind-xss https://xss.io",
                 ""),
            ],
        ),
        (
            "📄 Output & Reporting",
            [
                ("HTML report",
                 "plasma --url https://target.com --report html --report-dir ./results",
                 ""),
                ("All formats + PoC files",
                 "plasma --url https://target.com --report html,markdown,pdf --poc",
                 "PDF requires: pip install weasyprint"),
                ("JSON output for CI pipelines",
                 "plasma --url https://target.com --output-json findings.json --quiet",
                 "Exit code 1 if findings exist — use as a pipeline gate"),
                ("Web dashboard",
                 "plasma --ui",
                 "Opens at http://127.0.0.1:5001 by default"),
            ],
        ),
        (
            "⚙ Advanced & Productivity",
            [
                ("Batch scan from URL list",
                 "plasma --batch urls.txt --profile default --report html",
                 ""),
                ("Save scan for later replay",
                 "plasma --url https://target.com --profile aggressive --save-scan",
                 ""),
                ("Replay a saved scan",
                 "plasma --replay scans/scan_20240101.json --fuzz",
                 ""),
                ("Route through Burp Suite proxy",
                 "plasma --url https://target.com --proxy http://127.0.0.1:8080",
                 "All requests appear in Burp HTTP history"),
                ("Load custom detector plugins",
                 "plasma --url https://target.com --plugin-dir ./plugins",
                 "See docs/extending.md for the plugin API"),
                ("Subdomain + parameter discovery",
                 "plasma --url https://target.com --subdomains --param-discovery",
                 ""),
                ("Adaptive concurrency control",
                 "plasma --url https://target.com --concurrency 32 --rate-limit 10",
                 "--concurrency 0 = automatic AIMD scaling"),
            ],
        ),
    ]

    try:
        from rich.table import Table
        from rich.panel import Panel
        from rich.console import Console
        from rich.text import Text
        from rich import box as _box
        con = Console()

        con.print()
        con.print(
            f"[bold cyan]{'═' * 72}[/bold cyan]"
        )
        con.print(
            f"[bold cyan]  {TOOL_NAME} {TOOL_VERSION}  —  Usage Examples[/bold cyan]  "
            f"[dim](--help for full flag reference)[/dim]"
        )
        con.print(
            f"[bold cyan]{'═' * 72}[/bold cyan]"
        )
        con.print(
            "[dim]  ⚠  Always obtain written permission before scanning any target.[/dim]"
        )
        con.print()

        for section_title, entries in SECTIONS:
            table = Table(
                show_header=False,
                box=_box.SIMPLE,
                padding=(0, 1),
                expand=False,
            )
            table.add_column("desc",  style="cyan",       width=42, no_wrap=False)
            table.add_column("cmd",   style="bold white",  width=60, no_wrap=False)
            table.add_column("note",  style="dim yellow",  width=46, no_wrap=False)

            for desc, cmd, note in entries:
                table.add_row(desc, cmd, note)

            con.print(
                Panel(
                    table,
                    title=f"[bold]{section_title}[/bold]",
                    border_style="cyan",
                    padding=(0, 1),
                    expand=False,
                )
            )
        con.print()
        con.print(
            "[dim]  docs: README.md  •  docs/workflows.md  •  "
            "docs/fuzzing.md  •  docs/scan-profiles.md[/dim]"
        )
        con.print()

    except ImportError:
        # ── Plain ANSI fallback (no rich) ──────────────────────────────────
        _B = "\033[1m"; _C = "\033[36m"; _W = "\033[97m"
        _R = "\033[0m"; _D = "\033[2m";  _Y = "\033[33m"
        line = f"{_B}{_C}{'─' * 80}{_R}"

        print(f"\n{line}")
        print(f"{_B}{_C}  {TOOL_NAME} {TOOL_VERSION} — Usage Examples{_R}")
        print(f"{_D}  ⚠  Authorized testing only — obtain written permission first.{_R}")
        print(f"{line}\n")

        for section_title, entries in SECTIONS:
            print(f"  {_B}{_C}{section_title}{_R}")
            print(f"  {'─' * 60}")
            for desc, cmd, note in entries:
                print(f"  {_C}{desc:<42}{_R}  {_W}{cmd}{_R}")
                if note:
                    print(f"  {' ' * 42}  {_D}{_Y}{note}{_R}")
            print()
        print(line)
        print()

    sys.exit(0)


def _print_banner(quiet: bool) -> None:
    """Delegate to utils.banner.print_banner (imported above)."""
    print_banner(quiet=quiet)


def build_settings(args: argparse.Namespace) -> ScanSettings:
    """Convert parsed CLI arguments into a ScanSettings object."""

    # --test-* shorthand flags override --detectors
    _TEST_MAP = {
        "test_csrf":       "csrf",
        "test_sqli":       "sqli",
        "test_xss":        "xss",
        "test_ssrf":       "ssrf",
        "test_rce":        "rce",
        "test_idor":       "idor",
        "test_misconfig":  "misconfig",
        "test_dir_traversal": "directory_traversal",
        "test_ssti":       "ssti",
        "test_smuggling":  "http_smuggling",
        "test_xpath":      "xpath",
        "test_crlf":       "crlf",
        "test_cache_poisoning": "cache_poisoning",
    }
    test_selected: set[str] = {det for flag, det in _TEST_MAP.items()
                                if getattr(args, flag, False)}

    # --detectors: explicitly enabled subset (overridden by --test-* flags)
    enabled: set[str] = set()
    if test_selected:
        enabled = test_selected            # --test-* take priority
    elif getattr(args, "test_all", False):
        enabled = set()                    # empty = all detectors
    elif args.detectors:
        enabled = {d.strip() for d in args.detectors.split(",") if d.strip()}

    # --skip: detectors to disable (stored separately for the scan manager)
    skip: set[str] = set()
    if args.skip:
        skip = {d.strip() for d in args.skip.split(",") if d.strip()}

    # --report: list of format strings
    report_formats: list[str] = []
    if getattr(args, "report", None):
        report_formats = [f.strip() for f in args.report.split(",") if f.strip()]

    settings = ScanSettings(
        profile                = args.profile,
        max_depth              = args.depth,
        timeout                = args.timeout,
        enabled_detectors      = enabled,
        generate_poc           = args.poc,
        report_formats         = report_formats,
        report_dir             = args.report_dir,
        poc_dir                = args.poc_dir,
        proxy                  = getattr(args, "proxy", None),
        upload_file            = getattr(args, "auto_upload", None) or getattr(args, "upload", None),
        # Auth
        login_url              = getattr(args, "login_url", None),
        login_method           = getattr(args, "login_method", "POST"),
        login_data             = getattr(args, "login_data", None),
        login_script           = getattr(args, "login_script", None),
        auth_cookie            = getattr(args, "auth_cookie", None),
        # OOB
        collaborator_url       = getattr(args, "collaborator", None),
        blind_xss_url          = getattr(args, "blind_xss", None),
        # Recon
        enable_subdomains      = getattr(args, "subdomains", False),
        enable_js_extract      = not getattr(args, "no_js", False),
        enable_param_discovery = getattr(args, "param_discovery", False),
        # Modes
        api_mode               = getattr(args, "api_mode", False),
        browser_mode           = getattr(args, "browser", False),
        enable_bypass          = getattr(args, "bypass", False),
        enable_fuzzer          = getattr(args, "fuzz", False),
        fuzz_chain             = getattr(args, "fuzz_chain", False),
        fuzz_stealth           = getattr(args, "fuzz_stealth", False),
        fuzz_profile           = getattr(args, "fuzz_profile", None) or getattr(args, "profile", "default"),
        fuzz_dry_run           = getattr(args, "fuzz_dry_run", False),
        fuzz_target_param      = getattr(args, "fuzz_target_param", None),
        extract_db             = getattr(args, "extract_db", False),
        # Plugins & templates
        plugin_dir             = getattr(args, "plugin_dir", None),
        template_dir           = getattr(args, "templates", None),
        max_concurrency        = getattr(args, "concurrency", 0) or 0,
        rate_per_second        = getattr(args, "rate_limit", 0.0) or 0.0,
        dedup_requests         = not getattr(args, "no_dedup", False),
        # Persistence
        save_scan              = getattr(args, "save_scan", False),
        scan_dir               = getattr(args, "scan_dir", "scans"),
        # v3.3 new features
        verify_ssl             = not getattr(args, "no_verify_ssl", False),
        fuzz_websocket         = getattr(args, "fuzz_websocket", False),
        har_file               = getattr(args, "har_file", None),
        http2                  = getattr(args, "http2", False),
        browser_parallel       = getattr(args, "browser_parallel", 3),
        test_cache_poisoning   = getattr(args, "test_cache_poisoning", False),
        tls_analysis           = getattr(args, "tls_analysis", False),
        subdomain_takeover     = getattr(args, "subdomain_takeover", False),
        jsonl_output           = getattr(args, "jsonl_output", False),
    )

    # Store skip list for the scan manager to apply
    settings._skip_detectors = skip  # type: ignore[attr-defined]

    return settings


async def _run_scan(url: str, settings: ScanSettings, args: argparse.Namespace) -> None:
    """Run a full scan against a single URL."""
    # Ensure output directories exist
    os.makedirs(settings.report_dir, exist_ok=True)
    os.makedirs(settings.poc_dir, exist_ok=True)
    os.makedirs(settings.scan_dir, exist_ok=True)

    manager = ScanManager()
    context = manager.create_context(url, settings)

    if not args.quiet:
        cli_ui.show_scan_info(
            target   = url,
            profile  = settings.profile,
            depth    = settings.max_depth,
            timeout  = settings.timeout,
            proxy    = settings.proxy,
            auth_url = settings.login_url,
            skipped  = getattr(settings, "_skip_detectors", None) or None,
        )

    start = datetime.now()
    await manager.scan(context)
    elapsed = (datetime.now() - start).total_seconds()

    _print_results(context, elapsed, args.quiet)

    # JSON Lines streaming (--jsonl) — emit all findings at scan end
    if getattr(args, "jsonl_output", False):
        import json as _json
        for f in context.findings:
            fd = f.to_dict() if hasattr(f, "to_dict") else {"title": str(f)}
            print(_json.dumps(fd))

    # JSON output
    if getattr(args, "output_json", None):
        data = {
            "scan_id":    context.scan_id,
            "target":     url,
            "profile":    settings.profile,
            "duration_s": round(elapsed, 2),
            "findings":   [f.to_dict() for f in context.findings],
            "technologies": [{"name": t.name, "version": t.version}
                             for t in context.technologies],
        }
        try:
            with open(args.output_json, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            if not args.quiet:
                print(f"\n  JSON output → {args.output_json}")
        except OSError as e:
            print(f"\n  [WARN] Could not write JSON output: {e}", file=sys.stderr)

    # Report paths
    report_paths = getattr(context, "_report_paths", {})
    if report_paths and not args.quiet:
        print("\n  Reports:")
        for fmt, path in report_paths.items():
            print(f"    [{fmt.upper():8}] {path}")

    # PoC count
    poc_count = getattr(context, "_poc_count", 0)
    if poc_count and not args.quiet:
        print(f"  PoC files: {poc_count} written to {settings.poc_dir}/")

    # Risk summary
    risk = getattr(context, "_risk_summary", None)
    if risk and not args.quiet:
        print(f"\n  Risk Score : {risk.overall_score:.1f} / 10  [{risk.risk_level}]")
        if risk.top_findings:
            print("  Top issues :")
            for title in risk.top_findings[:3]:
                print(f"    • {title}")


def _print_results(context, elapsed: float, quiet: bool) -> None:
    if quiet:
        return
    findings = context.findings

    # Summary counts via cli_ui (handles both rich and plain-ANSI)
    cli_ui.show_summary(context, elapsed)

    # Findings table
    cli_ui.show_findings(findings)

    if context.technologies:
        techs = ", ".join(
            f"{t.name}" + (f" {t.version}" if t.version else "")
            for t in context.technologies
        )
        cli_ui.log_info(f"Technology stack : {techs}")

    if context.subdomains:
        cli_ui.log_info(f"Subdomains found : {len(context.subdomains)}")


async def _run_batch(args: argparse.Namespace) -> None:
    """Run scans against all URLs in a batch file."""
    try:
        with open(args.batch, encoding="utf-8") as fh:
            urls = [
                line.strip() for line in fh
                if line.strip() and not line.startswith("#")
            ]
    except OSError as e:
        print(f"[ERROR] Cannot read batch file: {e}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("[ERROR] Batch file is empty.", file=sys.stderr)
        sys.exit(1)

    settings = build_settings(args)
    manager  = ScanManager()
    contexts = [manager.create_context(u, settings) for u in urls]

    if not args.quiet:
        print(f"  Batch scan: {len(urls)} target(s)\n")

    results = await manager.batch_scan(contexts)
    for ctx in results:
        _print_results(ctx, ctx.duration_seconds or 0.0, args.quiet)


async def _run_replay(replay_file: str, args: argparse.Namespace) -> None:
    """Load and display a previously saved scan without hitting the network."""
    from core.scan_replay import ScanReplay
    replay  = ScanReplay()
    context = replay.load(replay_file)
    if not context:
        print(f"[ERROR] Failed to load replay file: {replay_file}", file=sys.stderr)
        sys.exit(1)
    print(f"  Replaying scan: {context.target_url}")
    _print_results(context, context.duration_seconds or 0.0, args.quiet)


def _launch_ui(host: str, port: int, debug: bool = False) -> None:
    """Launch the Flask web dashboard."""
    try:
        from ui.server import run_server
        print(f"""
  +---------------------------------------------+
  |  Plasma Dashboard                           |
  |  http://{host}:{port:<5}                         |
  |  Press Ctrl+C to stop                       |
  +---------------------------------------------+
""")
        run_server(host=host, port=port, debug=debug)
    except ImportError as e:
        print(f"[ERROR] Could not start UI server: {e}", file=sys.stderr)
        print("  Make sure Flask is installed: pip install flask", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[ERROR] Could not bind to {host}:{port} — {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    setup_logging(
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
    )

    _print_banner(getattr(args, "quiet", False))

    # ── Mode: diff two scan outputs ──────────────────────────────────────────
    if getattr(args, "diff_scans", None):
        from utils.scan_diff import diff_scans as _diff
        before, after = args.diff_scans
        sys.exit(_diff(before, after, jsonl=getattr(args, "jsonl_output", False)))

    # ── Mode: print usage examples ────────────────────────────────────────────
    if getattr(args, "usage", False):
        _print_usage()
        return

    # ── Mode: launch web dashboard ────────────────────────────────────────────
    if args.ui:
        _launch_ui(
            host=getattr(args, "host", UI_HOST),
            port=getattr(args, "port", UI_PORT),
            debug=getattr(args, "verbose", False),
        )
        return

    # ── Mode: replay saved scan ───────────────────────────────────────────────
    if getattr(args, "replay", None):
        asyncio.run(_run_replay(args.replay, args))
        return

    # ── Mode: batch scan ──────────────────────────────────────────────────────
    if getattr(args, "batch", None):
        asyncio.run(_run_batch(args))
        return

    # ── Mode: single URL scan ─────────────────────────────────────────────────
    if getattr(args, "url", None):
        settings = build_settings(args)
        asyncio.run(_run_scan(args.url, settings, args))
        return

    # ── No mode selected → print help ────────────────────────────────────────
    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
