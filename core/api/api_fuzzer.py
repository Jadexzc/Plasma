"""
core/api/api_fuzzer.py — WebGuard v3
──────────────────────────────────────
REST API fuzzer: JSON body fuzzing, parameter injection, and endpoint discovery.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from config import DEFAULT_TIMEOUT, SCAN_PROFILES
from core.models import Confidence, Endpoint, Evidence, Finding, Severity, VulnType
from utils.http_client import make_session
from utils.response_diff import ResponseDiff

log = logging.getLogger(__name__)

# Common REST API path patterns
API_PATH_PATTERNS = [
    re.compile(r'/api/v?\d+/[\w/-]+'),
    re.compile(r'/rest/[\w/-]+'),
    re.compile(r'/graphql'),
    re.compile(r'/v\d+/[\w/-]+'),
]

# Fuzzing values that often reveal issues
JSON_FUZZ_VALUES = [
    "' OR '1'='1",          # SQLi
    "<script>alert(1)</script>",  # XSS
    "../../../etc/passwd",  # Traversal
    "null",
    "true", "false",
    0, -1, 9999999,
    [],
    {},
    "{{7*7}}",              # SSTI
    "${7*7}",               # EL injection
    "aaaa" * 1000,          # Buffer / DoS
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


class APIFuzzer:
    """
    Fuzzes REST API endpoints for common vulnerabilities.

    Works in two modes:
    1. Parameter fuzzing on discovered API endpoints
    2. Method enumeration (IDOR via PUT/DELETE)
    """

    def __init__(
        self,
        session:  Optional[requests.Session] = None,
        profile:  str = "default",
    ) -> None:
        self._session = session or make_session()
        self._profile = profile
        self._cfg     = SCAN_PROFILES.get(profile, SCAN_PROFILES["default"])

    async def fuzz_endpoint(self, endpoint: Endpoint, context) -> list[Finding]:
        """Fuzz a single API endpoint and return findings."""
        findings: list[Finding] = []

        if not self._is_api_endpoint(endpoint.url):
            return findings

        # Method enumeration
        method_findings = await self._enumerate_methods(endpoint, context)
        findings.extend(method_findings)

        # JSON body fuzzing (if POST/PUT endpoint)
        if endpoint.method.upper() in ("POST", "PUT", "PATCH") and endpoint.parameters:
            body_findings = await self._fuzz_json_body(endpoint, context)
            findings.extend(body_findings)

        return findings

    async def _enumerate_methods(self, endpoint: Endpoint, ctx) -> list[Finding]:
        """Test HTTP methods not used by the application."""
        findings = []
        try:
            # Get baseline with correct method
            baseline = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self._session.request(
                    endpoint.method, endpoint.url,
                    timeout=ctx.settings.timeout, allow_redirects=False)
            )
            if baseline is None or baseline.status_code in (404, 500):
                return findings

            # Try alternative methods
            for method in HTTP_METHODS:
                if method == endpoint.method.upper():
                    continue
                try:
                    resp = await asyncio.get_running_loop().run_in_executor(
                        None, lambda m=method: self._session.request(
                            m, endpoint.url,
                            json=endpoint.parameters or {},
                            timeout=ctx.settings.timeout,
                            allow_redirects=False)
                    )
                    if resp and resp.status_code == 200:
                        diff = ResponseDiff.compare(baseline, resp)
                        if diff.significant:
                            findings.append(Finding(
                                vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                title=f"Unexpected HTTP Method Allowed: {method} on {endpoint.url}",
                                description=(
                                    f"HTTP {method} returns a different 200 response "
                                    f"on {endpoint.url} (expected {endpoint.method})."
                                ),
                                evidence=Evidence(
                                    request_url=endpoint.url, request_method=method,
                                    response_status=resp.status_code,
                                    notes=f"Baseline: {baseline.status_code}, test: {resp.status_code}",
                                ),
                                remediation="Restrict HTTP methods using Allow headers or WAF rules.",
                                endpoint=endpoint, detector="api-fuzzer",
                                owasp_id="A05:2021", cwe_id="CWE-16",
                                tags=["api", "method-enum"],
                            ))
                except Exception:
                    pass
        except Exception as exc:
            log.debug("Method enum failed: %s", exc)
        return findings

    async def _fuzz_json_body(self, endpoint: Endpoint, ctx) -> list[Finding]:
        """Fuzz JSON fields with injection payloads."""
        findings: list[Finding] = []
        max_p = self._cfg.get("max_payloads", 5)

        try:
            baseline = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self._session.request(
                    endpoint.method, endpoint.url,
                    json=endpoint.parameters,
                    headers={"Content-Type": "application/json"},
                    timeout=ctx.settings.timeout, allow_redirects=False)
            )
        except Exception:
            return findings

        for field in list(endpoint.parameters.keys())[:3]:
            for value in JSON_FUZZ_VALUES[:max_p]:
                mutated = {**endpoint.parameters, field: value}
                try:
                    resp = await asyncio.get_running_loop().run_in_executor(
                        None, lambda m=mutated: self._session.request(
                            endpoint.method, endpoint.url,
                            json=m,
                            headers={"Content-Type": "application/json"},
                            timeout=ctx.settings.timeout, allow_redirects=False)
                    )
                    if resp and resp.status_code == 500:
                        findings.append(Finding(
                            vuln_type=VulnType.INFORMATION_DISC, severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            title=f"API Server Error on JSON Fuzz: Field '{field}'",
                            description=(
                                f"Field '{field}' with value {value!r} caused HTTP 500 on "
                                f"{endpoint.url}. May indicate insufficient input validation."
                            ),
                            evidence=Evidence(
                                request_url=endpoint.url, request_method=endpoint.method,
                                payload_used=json.dumps({field: value}),
                                response_status=500,
                                response_body=resp.text[:300],
                            ),
                            remediation="Validate and sanitise all API input. Handle exceptions gracefully.",
                            endpoint=endpoint, detector="api-fuzzer",
                            owasp_id="A03:2021", cwe_id="CWE-20",
                            tags=["api", "fuzz", "500"],
                        ))
                        break
                except Exception:
                    pass

        return findings

    @staticmethod
    def _is_api_endpoint(url: str) -> bool:
        return any(p.search(url) for p in API_PATH_PATTERNS)
