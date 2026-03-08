"""
core/passive/passive_analyzer.py — WebGuard v3
─────────────────────────────────────────────────
Passive analysis that runs on every HTTP response without sending additional requests.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from requests import Response

from core.passive.security_hardening import CSPEvaluator, CookieAuditor
from core.models import Confidence, Endpoint, Evidence, Finding, Severity, VulnType

log = logging.getLogger(__name__)

# CSP check — kept here because passive_analyzer covers endpoints that
# misconfig and xss detectors may not reach (e.g. API endpoints).
# HSTS and X-Content-Type-Options are omitted to avoid duplicating
# MisconfigDetector findings on the same endpoint.
PASSIVE_HEADER_CHECKS = [
    # (header_name, title, vuln_type, severity, remediation, owasp_id, cwe_id)
    ("content-security-policy", "Missing Content-Security-Policy",
     VulnType.MISCONFIG, Severity.MEDIUM,
     "Add a Content-Security-Policy header to restrict resource loading and prevent XSS.",
     "A05:2021", "CWE-693"),
    ("x-frame-options", "Missing X-Frame-Options",
     VulnType.MISCONFIG, Severity.LOW,
     "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
     "A05:2021", "CWE-1021"),
    ("x-content-type-options", "Missing X-Content-Type-Options",
     VulnType.MISCONFIG, Severity.LOW,
     "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
     "A05:2021", "CWE-693"),
    ("strict-transport-security", "Missing Strict-Transport-Security (HSTS)",
     VulnType.MISCONFIG, Severity.MEDIUM,
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to enforce HTTPS.",
     "A02:2021", "CWE-319"),
    ("referrer-policy", "Missing Referrer-Policy",
     VulnType.MISCONFIG, Severity.LOW,
     "Add Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage.",
     "A05:2021", "CWE-200"),
    ("permissions-policy", "Missing Permissions-Policy",
     VulnType.MISCONFIG, Severity.LOW,
     "Add Permissions-Policy to restrict browser feature access (camera, microphone, etc.).",
     "A05:2021", "CWE-693"),
    ("cross-origin-opener-policy", "Missing Cross-Origin-Opener-Policy",
     VulnType.MISCONFIG, Severity.LOW,
     "Add Cross-Origin-Opener-Policy: same-origin to isolate browsing context.",
     "A05:2021", "CWE-346"),
    ("cross-origin-embedder-policy", "Missing Cross-Origin-Embedder-Policy",
     VulnType.MISCONFIG, Severity.LOW,
     "Add Cross-Origin-Embedder-Policy: require-corp alongside COOP for full isolation.",
     "A05:2021", "CWE-693"),
    ("cross-origin-resource-policy", "Missing Cross-Origin-Resource-Policy",
     VulnType.MISCONFIG, Severity.LOW,
     "Add Cross-Origin-Resource-Policy: same-site to prevent cross-origin resource leakage.",
     "A05:2021", "CWE-346"),
]

# Framework/debug indicators in headers
DEBUG_HEADER_PATTERNS = [
    ("x-debug-token", "Symfony Debug Token Exposed"),
    ("x-debug-token-link", "Symfony Debug Profiler Link Exposed"),
    ("x-powered-by", "Technology Disclosed in X-Powered-By"),
    ("x-aspnet-version", "ASP.NET Version Disclosed"),
    ("x-aspnetmvc-version", "ASP.NET MVC Version Disclosed"),
    ("server", None),  # version checked elsewhere
]

# Stack trace / error patterns in response body
ERROR_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python Stack Trace"),
    (re.compile(r"at \w+[\.\w]+\([\w.]+\.java:\d+\)", re.I),  "Java Stack Trace"),
    (re.compile(r"System\.NullReferenceException", re.I),      "C# NullReferenceException"),
    (re.compile(r"ORA-\d{5}:", re.I),                          "Oracle Database Error"),
    (re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),        "MySQL JDBC Error"),
    (re.compile(r"Parse error:.*on line \d+", re.I),           "PHP Parse Error"),
    (re.compile(r"SyntaxError:", re.I),                        "JavaScript Syntax Error"),
    (re.compile(r"<b>Warning</b>:.*on line <b>\d+", re.I),    "PHP Warning"),
    (re.compile(r"Rails\.application", re.I),                  "Rails Application Exposed"),
    (re.compile(r"DEBUG =\s*True", re.I),                      "Django Debug Mode On"),
]


class PassiveAnalyzer:
    _csp_eval    = CSPEvaluator()
    _cookie_audit = CookieAuditor()

    """
    Runs passive checks on an HTTP response.

    Instantiate once and call .analyse(response, endpoint) for each response.
    Returns a list of Findings — empty if nothing notable found.
    """

    def analyse(
        self,
        response: Response,
        endpoint: Optional[Endpoint] = None,
        context  = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if response is None:
            return findings

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # 1. Missing security headers
        for header, title, vuln, sev, fix, owasp, cwe in PASSIVE_HEADER_CHECKS:
            if header not in headers_lower:
                findings.append(Finding(
                    vuln_type=vuln, severity=sev, confidence=Confidence.CONFIRMED,
                    title=title,
                    description=f"Response from {response.url} is missing the '{header}' header.",
                    evidence=Evidence(
                        request_url=str(response.url),
                        matched_pattern=f"missing: {header}",
                        response_status=response.status_code,
                    ),
                    remediation=fix, endpoint=endpoint, detector="passive",
                    owasp_id=owasp, cwe_id=cwe,
                    tags=["passive", "headers"],
                ))

        # 2. Debug / framework disclosure headers
        for debug_header, debug_title in DEBUG_HEADER_PATTERNS:
            val = headers_lower.get(debug_header, "")
            if not val or debug_title is None:
                continue
            findings.append(Finding(
                vuln_type=VulnType.INFORMATION_DISC, severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                title=debug_title,
                description=f"Header '{debug_header}: {val}' reveals internal technology.",
                evidence=Evidence(
                    request_url=str(response.url),
                    matched_pattern=f"{debug_header}: {val}",
                    response_headers=dict(response.headers),
                ),
                remediation=f"Remove or suppress the '{debug_header}' response header.",
                endpoint=endpoint, detector="passive",
                owasp_id="A05:2021", cwe_id="CWE-200",
                tags=["passive", "info-disclosure"],
            ))

        # 3. Error messages / stack traces
        body = response.text
        for pattern, label in ERROR_PATTERNS:
            if pattern.search(body):
                findings.append(Finding(
                    vuln_type=VulnType.INFORMATION_DISC, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Debug Output Exposed: {label}",
                    description=f"{label} found in response from {response.url}.",
                    evidence=Evidence(
                        request_url=str(response.url),
                        matched_pattern=pattern.pattern,
                        response_status=response.status_code,
                        response_body=body[:400],
                    ),
                    remediation="Disable debug mode and suppress detailed error messages in production.",
                    endpoint=endpoint, detector="passive",
                    owasp_id="A05:2021", cwe_id="CWE-209",
                    tags=["passive", "debug"],
                ))
                break  # one stack trace finding per response

        # CSP evaluation
        csp = headers.get("content-security-policy", "")
        findings.extend(self._csp_eval.evaluate(csp, endpoint))

        # Cookie security audit
        findings.extend(self._cookie_audit.audit(dict(headers), endpoint))

        return findings
