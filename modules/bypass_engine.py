"""
modules/bypass_engine.py — Plasma v3
─────────────────────────────────────
Elite Web Application Security Testing & Bypass Automation Engine.

Bug fixes vs. previous version
--------------------------------
1. _fire_attempt: session.request() was called with url= appearing twice
   (once inside kwargs dict, once as explicit kwarg) → TypeError on real
   requests.Session.  Fixed: url is now the first explicit kwarg, all
   other kwargs are built in a separate dict that never contains 'url'.

2. _method_tampering: variable `p` was computed but never passed to _Attempt
   (payload= was hardcoded to the outer `payload`).  Fixed: dead `p=` line
   removed; each spec is a clean (label, method, headers) tuple.

3. BypassResult: added raw_response field for PoC generation.

4. _fire_attempt: now captures raw_response (HTTP/1.1 status + headers +
   body, truncated at RAW_RESPONSE_MAX_CHARS).

5. detect(): baseline raw HTTP responses (unauth + auth) are now captured
   and stored in Evidence.raw_response_unauth / raw_response_auth.

References
----------
  OWASP WSTG-ATHN-04 / WSTG-ATHZ-02
  PortSwigger Access Control Labs
  HackTricks — 403/401 Bypass techniques
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)
from core.vulnerability_detectors.base_detector import BaseDetector
from utils.http_client import make_session

log = logging.getLogger(__name__)

RAW_RESPONSE_MAX_CHARS: int = 5_000
_TRUNCATION_MARKER = "\n# --- RESPONSE TRUNCATED ---"


# ─── Internal data structures ─────────────────────────────────────────────────

@dataclass
class _Attempt:
    """A single bypass probe to be fired."""
    label:         str
    url:           str
    method:        str
    payload:       Optional[Any]
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class BypassResult:
    """
    Structured result for one bypass attempt.

    Implements __iter__ so the object can be unpacked as (url, status):
        for url, status in results: ...

    raw_response: raw HTTP response text (status line + headers + body),
    like curl -i output.  Truncated at RAW_RESPONSE_MAX_CHARS.
    """
    label:           str
    url:             str
    method:          str
    status_code:     int
    response_size:   int
    extra_headers:   dict[str, str]
    payload:         Optional[Any]
    notable:         bool
    baseline_status: int  = 0
    raw_response:    str  = ""

    def __iter__(self):
        yield self.url
        yield self.status_code


# ─── Raw response builder ─────────────────────────────────────────────────────

def _build_raw_response(response: requests.Response) -> str:
    """
    Build a curl -i style raw HTTP string:
        HTTP/1.1 <status> <reason>
        Header: Value
        ...
        <blank line>
        <body>

    Truncated at RAW_RESPONSE_MAX_CHARS.  Thread-safe; no side effects.
    """
    try:
        reason = response.reason or ""
        lines = [f"HTTP/1.1 {response.status_code} {reason}"]
        for name, value in response.headers.items():
            lines.append(f"{name}: {value}")
        lines.append("")   # blank separator line
        raw = "\n".join(lines) + "\n"
        try:
            raw += response.text
        except Exception:
            raw += repr(response.content[:2048])
        if len(raw) > RAW_RESPONSE_MAX_CHARS:
            raw = raw[:RAW_RESPONSE_MAX_CHARS] + _TRUNCATION_MARKER
        return raw
    except Exception as exc:
        return f"# Error capturing raw response: {exc}"


# ─── Notable-status heuristic ─────────────────────────────────────────────────

_NOTABLE_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308}


def _is_notable(status: int, baseline: int) -> bool:
    if status in _NOTABLE_STATUSES:
        return True
    if baseline in {401, 403, 404} and status not in {401, 403, 404}:
        return True
    return False


# ─── Technique helpers ────────────────────────────────────────────────────────

def _url_variations(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path.rstrip("/") or "/"
    variations = [
        ("url:suffix:.php",        f"{path}.php"),
        ("url:suffix:/index.php",  f"{path}/index.php"),
        ("url:suffix:/.html",      f"{path}/.html"),
        ("url:trailing-slash",     f"{path}/"),
        ("url:double-slash",       f"//{parsed.netloc}{path}"),
        ("url:dot-segment:/./",    f"{path}/./"),
        ("url:dot-segment:/../",   f"{path}/../{path.split('/')[-1]}"),
        ("url:semicolon",          f"{path}/;"),
        ("url:semicolon-slash",    f"{path};/"),
        ("url:null-byte",          f"{path}%00"),
        ("url:uppercase-path",     path.upper()),
        ("url:mixed-case",
         "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(path))),
    ]
    return [
        _Attempt(
            label=label,
            url=urllib.parse.urlunparse(parsed._replace(path=new_path)),
            method=method, payload=payload, extra_headers={},
        )
        for label, new_path in variations
    ]


def _encoding_variations(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    parsed          = urllib.parse.urlparse(url)
    path            = parsed.path
    encoded_path    = urllib.parse.quote(path, safe="/")
    double_enc_path = urllib.parse.quote(encoded_path, safe="/")
    unicode_path    = path.replace("/", "%c0%af")
    b64_path        = base64.b64encode(path.encode()).decode()
    return [
        _Attempt(
            label="encoding:url-encoded-path",
            url=urllib.parse.urlunparse(parsed._replace(path=encoded_path)),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="encoding:double-url-encoded",
            url=urllib.parse.urlunparse(parsed._replace(path=double_enc_path)),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="encoding:unicode-slash-overlong",
            url=urllib.parse.urlunparse(parsed._replace(path=unicode_path)),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="encoding:base64-x-rewrite-header",
            url=url, method=method, payload=payload,
            extra_headers={"X-Rewrite-URL": path, "X-Original-URL": b64_path},
        ),
        _Attempt(
            label="encoding:x-original-url",
            url=url, method=method, payload=payload,
            extra_headers={"X-Original-URL": path, "X-Rewrite-URL": path},
        ),
    ]


def _header_spoofing(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    root_url = urllib.parse.urlunparse(
        urllib.parse.urlparse(url)._replace(path="/", query="", fragment="")
    )
    spoof_sets = [
        ("header:ip-spoof-loopback",     {
            "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1",
        }),
        ("header:ip-spoof-private-10",   {"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1"}),
        ("header:ip-spoof-private-192",  {"X-Forwarded-For": "192.168.1.1", "X-Real-IP": "192.168.1.1"}),
        ("header:forwarded-for-chain",   {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"}),
        ("header:referer-self",          {"Referer": url}),
        ("header:referer-root",          {"Referer": root_url}),
        ("header:x-forwarded-host",      {"X-Forwarded-Host": "localhost"}),
        ("header:x-host-override",       {"X-Host": "localhost", "X-Forwarded-Server": "localhost"}),
        ("header:useragent-googlebot",   {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}),
        ("header:useragent-internal",    {"User-Agent": "internal-health-checker/1.0"}),
        ("header:content-type-json",     {"Content-Type": "application/json"}),
        ("header:accept-wildcard",       {"Accept": "*/*", "Accept-Encoding": "identity"}),
        ("header:cache-control-bypass",  {"Cache-Control": "no-cache", "Pragma": "no-cache"}),
        ("header:x-csrf-bypass",         {"X-CSRF-Token": "undefined", "X-Requested-With": "XMLHttpRequest"}),
    ]
    return [
        _Attempt(label=label, url=url, method=method, payload=payload, extra_headers=h)
        for label, h in spoof_sets
    ]


def _method_tampering(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    """
    HTTP method tampering.
    Bug fix: removed dead `p=` variable; each spec is (label, send_method, extra_headers).
    """
    tamper_specs = [
        ("method:OPTIONS",               "OPTIONS", {}),
        ("method:HEAD",                  "HEAD",    {}),
        ("method:TRACE",                 "TRACE",   {}),
        ("method:PATCH",                 "PATCH",   {}),
        ("method:override-POST-via-GET", "GET",     {"X-HTTP-Method-Override": "POST"}),
        ("method:override-DELETE",       "POST",    {"X-HTTP-Method-Override": "DELETE"}),
        ("method:override-PUT",          "POST",    {"X-HTTP-Method-Override": "PUT"}),
    ]
    return [
        _Attempt(label=label, url=url, method=m, payload=payload, extra_headers=h)
        for label, m, h in tamper_specs
    ]


def _param_obfuscation(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    parsed = urllib.parse.urlparse(url)
    qs     = parsed.query
    attempts = [
        _Attempt(
            label="param:null-byte-qs",
            url=urllib.parse.urlunparse(parsed._replace(query=f"{qs}&%00bypass=1")),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="param:wildcard-qs",
            url=urllib.parse.urlunparse(parsed._replace(query=f"{qs}&bypass=*")),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="param:array-pollution",
            url=urllib.parse.urlunparse(parsed._replace(query=f"{qs}&role[]=admin")),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="param:hpp-duplicate-admin",
            url=urllib.parse.urlunparse(parsed._replace(query=f"{qs}&admin=true&admin=1")),
            method=method, payload=payload, extra_headers={},
        ),
        _Attempt(
            label="param:fragment-leak",
            url=url + "#admin",
            method=method, payload=payload, extra_headers={},
        ),
    ]
    if isinstance(payload, dict) and payload:
        first_key  = next(iter(payload))
        polluted   = dict(payload)
        polluted[f"{first_key}[]"] = payload[first_key]
        attempts.append(_Attempt(
            label="param:post-key-pollution",
            url=url, method="POST", payload=polluted, extra_headers={},
        ))
    return attempts


def _path_traversal(url: str, method: str, payload, headers: dict) -> list[_Attempt]:
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path
    traversals = [
        ("traversal:dot-dot-slash",         f"{path}/../"),
        ("traversal:dot-dot-slash-encoded", f"{path}/%2e%2e/"),
        ("traversal:dot-dot-backslash",     f"{path}/..\\"),
        ("traversal:triple-dot",            f"{path}/..."),
        ("traversal:slash-dot",             f"{path}/./"),
        ("traversal:percent20-space",       f"{path}%20/"),
        ("traversal:tab-encoded",           f"{path}%09/"),
    ]
    return [
        _Attempt(
            label=label,
            url=urllib.parse.urlunparse(parsed._replace(path=new_path)),
            method=method, payload=payload, extra_headers={},
        )
        for label, new_path in traversals
    ]


# ─── Technique registry ───────────────────────────────────────────────────────

_BYPASS_TECHNIQUES: list[dict] = [
    {"name": "URL Manipulation",      "category": "url",       "fn": _url_variations},
    {"name": "Encoding Bypass",       "category": "encoding",  "fn": _encoding_variations},
    {"name": "Header Spoofing",       "category": "header",    "fn": _header_spoofing},
    {"name": "HTTP Method Tampering", "category": "method",    "fn": _method_tampering},
    {"name": "Parameter Obfuscation", "category": "param",     "fn": _param_obfuscation},
    {"name": "Path Traversal",        "category": "traversal", "fn": _path_traversal},
]


# ─── Core fire-and-record logic ───────────────────────────────────────────────

def _fire_attempt(
    session:         requests.Session,
    attempt:         _Attempt,
    timeout:         int,
    base_headers:    dict[str, str],
    jitter_range:    tuple[float, float],
    baseline_status: int,
) -> BypassResult | None:
    """
    Execute one bypass attempt synchronously (called from thread executor).

    Bug fix: url is now the first explicit kwarg to session.request().
    Previously it appeared both inside the **kwargs spread AND as an
    explicit kwarg, which raises TypeError on real requests.Session.
    """
    jitter = random.uniform(*jitter_range)
    if jitter > 0:
        time.sleep(jitter)

    merged_headers = {**base_headers, **attempt.extra_headers}
    method         = attempt.method.upper()

    # url is NOT included in req_kwargs; it is passed explicitly as the
    # first keyword argument to session.request() to avoid a duplicate-kwarg
    # TypeError.
    req_kwargs: dict[str, Any] = {
        "headers":         merged_headers,
        "timeout":         timeout,
        "allow_redirects": True,
    }
    if method in ("POST", "PUT", "PATCH"):
        if isinstance(attempt.payload, (dict, str)):
            req_kwargs["data"] = attempt.payload
    elif method == "GET" and isinstance(attempt.payload, dict):
        req_kwargs["params"] = attempt.payload

    try:
        response     = session.request(method, url=attempt.url, **req_kwargs)
        raw_response = _build_raw_response(response)

        result = BypassResult(
            label=attempt.label,
            url=attempt.url,
            method=attempt.method,
            status_code=response.status_code,
            response_size=len(response.content),
            extra_headers=attempt.extra_headers,
            payload=attempt.payload,
            notable=_is_notable(response.status_code, baseline_status),
            baseline_status=baseline_status,
            raw_response=raw_response,
        )
        log.debug(
            "[bypass] %-42s  %s  -> HTTP %d  (%d bytes)",
            attempt.label, attempt.url, response.status_code, result.response_size,
        )
        return result

    except requests.exceptions.Timeout:
        log.debug("[bypass] timeout on %s (%s)", attempt.label, attempt.url)
    except requests.exceptions.ConnectionError as exc:
        log.debug("[bypass] connection error on %s: %s", attempt.label, exc)
    except requests.exceptions.RequestException as exc:
        log.debug("[bypass] request error on %s: %s", attempt.label, exc)
    return None


def _build_all_attempts(
    url:     str,
    method:  str,
    payload: Any,
    headers: dict[str, str],
) -> list[_Attempt]:
    all_attempts: list[_Attempt] = []
    for tech in _BYPASS_TECHNIQUES:
        try:
            all_attempts.extend(tech["fn"](url, method, payload, headers))
        except Exception as exc:
            log.debug("[bypass] technique '%s' failed: %s", tech["name"], exc)
    return all_attempts


# ─── Standalone public API ────────────────────────────────────────────────────

def run_bypass_tests(
    target_url:       str,
    session:          Optional[requests.Session] = None,
    original_method:  str = "GET",
    original_payload: Any = None,
    custom_headers:   Optional[dict[str, str]] = None,
    timeout:          int   = 10,
    jitter_range:     tuple[float, float] = (0.05, 0.3),
) -> list[BypassResult]:
    """
    Standalone bypass test runner — usable independently of the scan pipeline.

    Returns list[BypassResult]; each object also unpacks as (url, status).

    Raises ValueError if target_url is empty or not http/https.
    """
    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("target_url must be a non-empty string")
    target_url = target_url.strip()

    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"target_url must use http or https scheme, got: {parsed.scheme!r}"
        )

    original_method = (original_method or "GET").strip().upper()
    headers: dict[str, str] = (
        {str(k): str(v) for k, v in custom_headers.items()}
        if isinstance(custom_headers, dict) else {}
    )

    if session is None:
        session = make_session()

    baseline_status = 0
    try:
        baseline_resp   = session.request(
            method=original_method, url=target_url,
            headers=headers, timeout=timeout, allow_redirects=True,
        )
        baseline_status = baseline_resp.status_code
        log.info("[bypass] baseline %s %s -> HTTP %d",
                 original_method, target_url, baseline_status)
    except Exception as exc:
        log.warning("[bypass] baseline request failed: %s", exc)

    attempts = _build_all_attempts(target_url, original_method, original_payload, headers)
    results: list[BypassResult] = []
    for attempt in attempts:
        result = _fire_attempt(
            session=session, attempt=attempt, timeout=timeout,
            base_headers=headers, jitter_range=jitter_range,
            baseline_status=baseline_status,
        )
        if result is not None:
            results.append(result)

    log.info("[bypass] %s — %d attempts, %d notable (baseline HTTP %d)",
             target_url, len(results), len([r for r in results if r.notable]),
             baseline_status)
    return results


# ─── BaseDetector integration ─────────────────────────────────────────────────

class BypassEngine(BaseDetector):
    """
    Access-control bypass detector — integrated with the existing scan pipeline.

    Bypass testing is COMPLETELY SILENT unless ScanSettings.enable_bypass is
    True (set by --bypass CLI flag).

    Raw HTTP response capture:
      Evidence.raw_response_unauth — unauthenticated baseline response
      Evidence.raw_response_auth   — authenticated response (when available)
    """

    NAME        = "bypass"
    VULN_TYPE   = VulnType.ACCESS_BYPASS
    DESCRIPTION = (
        "Access-control bypass via URL manipulation, header spoofing, "
        "method tampering, encoding evasion, and parameter obfuscation"
    )

    def should_test(self, endpoint: Endpoint, context: ScanContext) -> bool:
        return getattr(context.settings, "enable_bypass", False)

    async def detect(
        self,
        context:  ScanContext,
        endpoint: Endpoint,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not endpoint.url or not endpoint.url.startswith(("http://", "https://")):
            log.debug("[bypass] skipping invalid URL: %r", endpoint.url)
            return findings

        session  = make_session()
        timeout  = context.settings.timeout
        method   = endpoint.method or "GET"
        payload: Any  = endpoint.parameters or None
        headers  = {**endpoint.headers}

        # ── Unauthenticated baseline ───────────────────────────────────────
        baseline_status = 0
        raw_unauth: str = ""
        try:
            baseline = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: session.request(
                    method=method, url=endpoint.url,
                    headers=headers, timeout=timeout, allow_redirects=True,
                ),
            )
            baseline_status = baseline.status_code
            raw_unauth      = _build_raw_response(baseline)
        except Exception as exc:
            log.debug("[bypass] baseline failed for %s: %s", endpoint.url, exc)

        # ── Authenticated baseline (when auth session available) ───────────
        raw_auth: Optional[str] = None
        from utils.http_client import get_auth_session
        auth_session = get_auth_session()
        if auth_session is not None:
            try:
                auth_resp = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: auth_session.request(
                        method=method, url=endpoint.url,
                        headers=headers, timeout=timeout, allow_redirects=True,
                    ),
                )
                raw_auth = _build_raw_response(auth_resp)
            except Exception as exc:
                log.debug("[bypass] auth baseline failed for %s: %s", endpoint.url, exc)

        # ── Fire all probes concurrently ───────────────────────────────────
        attempts = _build_all_attempts(endpoint.url, method, payload, headers)

        async def _probe(attempt: _Attempt) -> BypassResult | None:
            try:
                return await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: _fire_attempt(
                        session=session, attempt=attempt, timeout=timeout,
                        base_headers=headers, jitter_range=(0.02, 0.15),
                        baseline_status=baseline_status,
                    ),
                )
            except Exception as exc:
                log.debug("[bypass] probe error %s: %s", attempt.label, exc)
                return None

        results = await asyncio.gather(*[_probe(a) for a in attempts])

        for result in results:
            if result is None or not result.notable:
                continue

            findings.append(Finding(
                vuln_type  = VulnType.ACCESS_BYPASS,
                severity   = _bypass_severity(result),
                confidence = _bypass_confidence(result, baseline_status),
                title      = f"Bypass: {result.label} → HTTP {result.status_code}",
                description=(
                    f"Access-control bypass technique '{result.label}' received "
                    f"HTTP {result.status_code} ({result.response_size} bytes) "
                    f"on {result.url}. "
                    f"Baseline was HTTP {baseline_status}. "
                    f"Extra headers sent: {result.extra_headers or 'none'}."
                ),
                evidence=Evidence(
                    request_url         = result.url,
                    request_method      = result.method,
                    request_headers     = result.extra_headers,
                    payload_used        = str(result.payload) if result.payload else "",
                    response_status     = result.status_code,
                    notes               = (
                        f"baseline={baseline_status}  "
                        f"technique={result.label}  "
                        f"body_size={result.response_size}"
                    ),
                    raw_response_unauth = raw_unauth or result.raw_response,
                    raw_response_auth   = raw_auth,
                ),
                remediation=(
                    "Enforce access control server-side, not via URL patterns or "
                    "header checks. Use a deny-by-default policy. Validate the "
                    "Origin/Referer on the server and never trust client-supplied "
                    "IP headers (X-Forwarded-For) for security decisions. "
                    "See: https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Access_Control_Cheat_Sheet.html"
                ),
                endpoint = endpoint,
                detector = self.NAME,
                owasp_id = "A01:2021",
                cwe_id   = "CWE-284",
                tags     = ["bypass", result.label.split(":")[0], "access-control"],
            ))

        if findings:
            context.log(
                f"  [bypass] {len(findings)} notable bypass(es) on {endpoint.url}"
            )
        return findings


# ─── Severity / confidence helpers ────────────────────────────────────────────

def _bypass_severity(result: BypassResult) -> Severity:
    if result.status_code in {200, 201}:
        return Severity.HIGH
    if result.status_code in {202, 204}:
        return Severity.MEDIUM
    if result.status_code in {301, 302, 307, 308}:
        return Severity.MEDIUM
    return Severity.LOW


def _bypass_confidence(result: BypassResult, baseline: int) -> Confidence:
    if baseline in {401, 403} and result.status_code in {200, 201}:
        return Confidence.HIGH
    if baseline in {401, 403, 404} and result.status_code in {200, 201, 202}:
        return Confidence.MEDIUM
    return Confidence.LOW
