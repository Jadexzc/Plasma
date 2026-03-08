"""
core/recon/parameter_discovery.py — WebGuard v3
─────────────────────────────────────────────────
Hidden parameter discovery for each endpoint.
Tests wordlist parameters by appending them to requests
and using the ResponseDiff engine to detect anomalies.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse

import requests

from config import PARAMETER_WORDLIST, PARAMETER_CONCURRENCY, DEFAULT_TIMEOUT
from core.models import Confidence, Endpoint, Evidence, Finding, Severity, VulnType
from utils.response_diff import ResponseDiff
from utils.http_client import make_session

log = logging.getLogger(__name__)

BUILTIN_PARAMS = [
    "debug", "admin", "test", "dev", "preview", "redirect", "callback",
    "file", "path", "url", "mode", "action", "id", "user", "page",
    "format", "output", "type", "lang", "locale", "version", "v",
    "token", "key", "secret", "password", "username", "email",
    "sort", "order", "filter", "search", "q", "query",
    "return", "next", "continue", "back",
    "limit", "offset", "page_size", "per_page",
    "format", "json", "xml", "csv",
    "verbose", "log", "trace", "profile", "benchmark",
    "proxy", "forward", "target", "host",
    "include", "exclude", "fields", "columns",
]


class ParameterDiscovery:
    """
    Tests endpoints for hidden/undocumented parameters.

    Usage:
        disc = ParameterDiscovery(session=session)
        findings = await disc.discover(endpoint, context)
    """

    def __init__(
        self,
        session:     Optional[requests.Session] = None,
        wordlist:    Optional[str]              = None,
        concurrency: int                        = PARAMETER_CONCURRENCY,
    ) -> None:
        self._session     = session or make_session()
        self._wordlist    = wordlist or PARAMETER_WORDLIST
        self._concurrency = concurrency
        self._params      = self._load_params()

    def _load_params(self) -> list[str]:
        path = Path(self._wordlist)
        if path.exists():
            lines = path.read_text(errors="ignore").splitlines()
            extra = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            return list(dict.fromkeys(BUILTIN_PARAMS + extra))[:500]
        return BUILTIN_PARAMS

    async def discover(self, endpoint: Endpoint, context) -> list[Finding]:
        """Probe for hidden parameters and return anomaly findings."""
        findings: list[Finding] = []
        existing_params = set(endpoint.param_names)
        sem = asyncio.Semaphore(self._concurrency)

        # Baseline: fetch the endpoint as-is
        baseline = await asyncio.get_running_loop().run_in_executor(
            None, lambda: self._request(endpoint, {}, context)
        )
        if baseline is None:
            return findings

        new_params = [p for p in self._params if p not in existing_params]

        async def _test(param: str) -> Optional[Finding]:
            async with sem:
                return await self._test_param(endpoint, param, baseline, context)

        results = await asyncio.gather(*[_test(p) for p in new_params])
        return [r for r in results if r is not None]

    async def _test_param(
        self, endpoint: Endpoint, param: str,
        baseline: requests.Response, ctx,
    ) -> Optional[Finding]:
        test_params = dict(endpoint.parameters)
        test_params[param] = "1"

        try:
            test_resp = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self._request(endpoint, test_params, ctx)
            )
            if test_resp is None:
                return None

            diff = ResponseDiff.compare(baseline, test_resp, strict=True)
            if diff.significant:
                return Finding(
                    vuln_type=VulnType.INFORMATION_DISC, severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title=f"Hidden Parameter Discovered: '{param}'",
                    description=(
                        f"Adding parameter '{param}=1' to {endpoint.url} produced a "
                        f"significantly different response "
                        f"(status: {baseline.status_code}→{test_resp.status_code}, "
                        f"length delta: {diff.length_delta} bytes). "
                        "This parameter may be undocumented or trigger non-standard behaviour."
                    ),
                    evidence=Evidence(
                        request_url=endpoint.url,
                        payload_used=f"{param}=1",
                        matched_pattern=f"length_delta={diff.length_delta}",
                        response_status=test_resp.status_code,
                    ),
                    remediation=(
                        "Audit all accepted parameters. "
                        "Remove debug/test parameters from production code."
                    ),
                    endpoint=endpoint, detector="parameter-discovery",
                    owasp_id="A05:2021", cwe_id="CWE-200",
                    tags=["recon", "parameter"],
                )
        except Exception as exc:
            log.debug("Param discovery failed for %s=%s: %s", endpoint.url, param, exc)
        return None

    def _request(
        self, endpoint: Endpoint,
        extra_params: dict,
        ctx,
    ) -> Optional[requests.Response]:
        merged = {**endpoint.parameters, **extra_params}
        try:
            t = ctx.settings.timeout
            if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
                return self._session.post(endpoint.url, data=merged, timeout=t)
            return self._session.get(endpoint.url, params=merged, timeout=t)
        except Exception:
            return None
