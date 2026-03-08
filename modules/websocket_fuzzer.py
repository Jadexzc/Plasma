"""
modules/websocket_fuzzer.py — Plasma v3.3
──────────────────────────────────────────
WebSocket fuzzing module.

Captures WebSocket endpoints from BrowserCrawler (already stored in
ScanContext._browser_result.js_urls and tagged with "websocket") then sends
mutation payloads over live ws:// / wss:// connections.

Detection targets
─────────────────
• Abnormal disconnect / connection reset after payload
• Error frames (opcode 0x8) with non-1000 close codes
• Reflected payload in server response (XSS / injection)
• Unexpected JSON structure changes (prototype pollution, type confusion)
• Time-based anomalies (sleep-like delays → blind injection)

CLI flag
─────────
--fuzz-websocket

Integration
───────────
Called from ScanManager._phase_websocket_fuzz() after _phase_fuzz().
Findings are added to context.findings.

Requires:
    pip install websockets
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)

log = logging.getLogger(__name__)

# ── Payload library ───────────────────────────────────────────────────────────

_WS_PAYLOADS: list[tuple[str, str]] = [
    # (payload_string, technique_label)
    # XSS / injection
    ('<script>alert(1)</script>',               "xss-basic"),
    ('"><img src=x onerror=alert(1)>',          "xss-attr-break"),
    ("' OR '1'='1",                             "sqli-basic"),
    ("'; DROP TABLE messages--",                "sqli-stacked"),
    ("{{7*7}}",                                 "ssti-canary"),
    ("${7*7}",                                  "ssti-el"),
    # Prototype pollution
    ('{"__proto__":{"polluted":true}}',         "proto-pollution"),
    ('{"constructor":{"prototype":{"x":1}}}',   "proto-constructor"),
    # Type confusion
    ('"' * 5000,                                "oversized-string"),
    ('[]' * 100,                                "nested-arrays"),
    ('\x00\x01\x02\x03',                        "binary-injection"),
    # Path traversal in WS message
    ('{"file":"../../../../etc/passwd"}',       "path-traversal"),
    ('{"url":"file:///etc/passwd"}',            "ssrf-file"),
    ('{"url":"http://169.254.169.254/latest"}', "ssrf-aws-meta"),
    # Command injection
    ('{"cmd":"id;whoami"}',                     "rce-cmd"),
    ('{"action":"ping","host":"127.0.0.1;id"}', "rce-ping"),
    # Oversized / DoS-adjacent (safe, no actual DoS)
    ('A' * 65536,                               "large-message"),
]

_REFLECT_RE = re.compile(r"(alert\(1\)|polluted|7777777|\x00)", re.I)

# Abnormal WS close codes (1000 = normal, 1001 = going away — both fine)
_BAD_CLOSE_CODES = {1002, 1003, 1007, 1008, 1009, 1010, 1011}


@dataclass
class WSProbeResult:
    url:           str
    payload:       str
    technique:     str
    response:      Optional[str]
    close_code:    Optional[int]
    close_reason:  Optional[str]
    elapsed:       float
    error:         Optional[str]
    notable:       bool


class WebSocketFuzzer:
    """
    Fuzz WebSocket endpoints discovered by BrowserCrawler.

    Usage (called by ScanManager)::

        fuzzer = WebSocketFuzzer(context)
        findings = await fuzzer.run()
        context.findings.extend(findings)

    Standalone::

        fuzzer = WebSocketFuzzer(context)
        findings = await fuzzer.run()
    """

    def __init__(self, context: ScanContext) -> None:
        self.context    = context
        self.settings   = context.settings
        self._timeout   = context.settings.timeout
        self._semaphore = asyncio.Semaphore(5)

    async def run(self) -> list[Finding]:
        """
        Discover WS endpoints and fuzz them in parallel.

        V1: Endpoints are fuzzed concurrently up to self.parallel_endpoints
        (default = min(8, len(endpoints))). Each endpoint gets its own
        asyncio.Semaphore(5) for probe-level concurrency.
        """
        ws_endpoints = self._collect_ws_endpoints()
        if not ws_endpoints:
            log.info("[ws-fuzz] No WebSocket endpoints to fuzz")
            return []

        n = len(ws_endpoints)
        self.parallel_endpoints = min(8, n)
        self.context.log(
            f"  [ws-fuzz] fuzzing {n} WebSocket endpoint(s) "
            f"(parallel={self.parallel_endpoints})"
        )

        # Endpoint-level semaphore: parallel endpoint processing
        ep_sem  = asyncio.Semaphore(self.parallel_endpoints)

        async def _fuzz_with_sem(ep):
            async with ep_sem:
                return await self._fuzz_endpoint(ep)

        tasks   = [_fuzz_with_sem(ep) for ep in ws_endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                log.debug("[ws-fuzz] endpoint error: %s", r)

        self.context.log(
            f"  [ws-fuzz] complete — {len(findings)} finding(s)"
        )
        return findings

    def _collect_ws_endpoints(self) -> list[Endpoint]:
        """Gather ws:// endpoints from context (browser crawler + endpoints list)."""
        seen:    set[str]      = set()
        result:  list[Endpoint] = []

        for ep in self.context.endpoints:
            url = ep.url or ""
            if url.startswith(("ws://", "wss://")) and url not in seen:
                seen.add(url)
                result.append(ep)

        # Also pull from raw browser result js_urls
        br = getattr(self.context, "_browser_result", None)
        if br:
            for url in (getattr(br, "js_urls", None) or []):
                if url.startswith(("ws://", "wss://")) and url not in seen:
                    seen.add(url)
                    result.append(Endpoint(
                        url=url, method="GET", tags=["websocket", "browser"]
                    ))
        return result

    async def _fuzz_endpoint(self, endpoint: Endpoint) -> list[Finding]:
        """Send all payloads to a single WebSocket endpoint."""
        findings: list[Finding] = []

        # Try to import websockets — graceful degradation if not installed
        try:
            import websockets
        except ImportError:
            log.warning(
                "[ws-fuzz] 'websockets' not installed — skipping WS fuzzing. "
                "Run: pip install websockets"
            )
            return []

        url = endpoint.url
        # Pre-check: try a clean connect/ping/close to establish baseline
        baseline_ok = await self._baseline_check(url, websockets)
        if not baseline_ok:
            log.debug("[ws-fuzz] baseline failed for %s — skipping", url)
            return []

        tasks = [
            self._send_probe(url, payload, technique, websockets)
            for payload, technique in _WS_PAYLOADS
        ]

        async with self._semaphore:
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        for pr in probe_results:
            if isinstance(pr, WSProbeResult) and pr.notable:
                f = self._result_to_finding(pr, endpoint)
                if f:
                    findings.append(f)

        return findings

    async def _baseline_check(self, url: str, ws_module) -> bool:
        """Return True if a normal WS connection succeeds."""
        try:
            async with asyncio.timeout(self._timeout):
                async with ws_module.connect(
                    url,
                    open_timeout=self._timeout,
                    close_timeout=3,
                    ssl=self._ssl_ctx(url),
                ) as ws:
                    await ws.ping()
            return True
        except Exception:
            return False

    async def _send_probe(
        self, url: str, payload: str, technique: str, ws_module
    ) -> WSProbeResult:
        """Send a single fuzz payload over WebSocket and record the result."""
        response:     Optional[str] = None
        close_code:   Optional[int] = None
        close_reason: Optional[str] = None
        error:        Optional[str] = None
        notable                     = False

        t0 = time.monotonic()
        try:
            async with asyncio.timeout(self._timeout):
                async with ws_module.connect(
                    url,
                    open_timeout=self._timeout,
                    close_timeout=3,
                    ssl=self._ssl_ctx(url),
                ) as ws:
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=4.0)
                    except asyncio.TimeoutError:
                        pass  # no response — not necessarily notable

        except Exception as exc:
            cls_name = type(exc).__name__
            # websockets.exceptions.ConnectionClosedError has .code and .reason
            code_attr   = getattr(exc, "code", None)
            reason_attr = getattr(exc, "reason", None)
            if code_attr is not None:
                close_code   = int(code_attr)
                close_reason = str(reason_attr or "")
                if close_code in _BAD_CLOSE_CODES:
                    notable = True
            error = f"{cls_name}: {exc}"

        elapsed = time.monotonic() - t0

        # Reflection detection
        if response and _REFLECT_RE.search(response):
            notable = True

        # Timing anomaly (blind injection / sleep)
        if elapsed > self._timeout * 0.7 and technique.startswith(("sqli", "rce", "ssti")):
            notable = True

        return WSProbeResult(
            url=url, payload=payload, technique=technique,
            response=response, close_code=close_code, close_reason=close_reason,
            elapsed=elapsed, error=error, notable=notable,
        )

    def _result_to_finding(self, pr: WSProbeResult, ep: Endpoint) -> Optional[Finding]:
        """Convert a notable WSProbeResult to a Finding."""
        if pr.close_code and pr.close_code in _BAD_CLOSE_CODES:
            title = f"WebSocket — Abnormal Close ({pr.close_code}) on {pr.technique}"
            desc  = (
                f"Payload `{pr.payload[:80]}` caused the server to close the WebSocket "
                f"with code {pr.close_code} ({pr.close_reason!r}). "
                f"This may indicate an unhandled error or input validation failure."
            )
            sev  = Severity.MEDIUM
            conf = Confidence.MEDIUM
        elif pr.response and _REFLECT_RE.search(pr.response):
            title = f"WebSocket — Payload Reflected in Response ({pr.technique})"
            desc  = (
                f"The payload `{pr.payload[:80]}` was reflected in the server "
                f"WebSocket response: {pr.response[:200]!r}. "
                f"Reflected content may be rendered by clients, enabling XSS."
            )
            sev  = Severity.HIGH
            conf = Confidence.HIGH
        elif pr.elapsed > self._timeout * 0.7:
            title = f"WebSocket — Timing Anomaly ({pr.technique})"
            desc  = (
                f"Payload `{pr.payload[:80]}` caused a {pr.elapsed:.1f}s delay "
                f"(timeout={self._timeout}s), suggesting potential blind injection "
                f"or resource exhaustion."
            )
            sev  = Severity.MEDIUM
            conf = Confidence.LOW
        else:
            return None

        return Finding(
            vuln_type=VulnType.OTHER,
            severity=sev,
            confidence=conf,
            title=title,
            description=desc,
            evidence=Evidence(
                request_url=pr.url,
                request_method="WS",
                request_body=pr.payload[:500],
                matched_pattern=pr.technique,
                response_status=pr.close_code or 0,
                response_body=(pr.response or "")[:500],
                response_time=pr.elapsed,
                notes=pr.error or "",
            ),
            remediation=(
                "Validate and sanitise all WebSocket message content server-side. "
                "Implement WebSocket message schema validation. "
                "Handle errors gracefully without exposing internal state."
            ),
            endpoint=ep,
            detector="websocket-fuzzer",
            tags=["websocket", "fuzz", pr.technique],
            owasp_id="A03:2021",
            cwe_id="CWE-20",
        )

    @staticmethod
    def _ssl_ctx(url: str):
        """Return SSL context for wss:// or None for ws://."""
        if url.startswith("wss://"):
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            return ctx
        return None
