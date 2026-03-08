"""
plugins/example_plugin.py — WebGuard v3 Plugin Example
────────────────────────────────────────────────────────
This file demonstrates how to write a custom WebGuard detector plugin.
Run with: python main.py --url https://example.com --plugin-dir plugins/
"""
from __future__ import annotations

import asyncio
import logging

from core.models import Confidence, Endpoint, Evidence, Finding, ScanContext, Severity, VulnType
from core.vulnerability_detectors.base_detector import BaseDetector

log = logging.getLogger(__name__)


class ExamplePluginDetector(BaseDetector):
    """
    Example custom detector plugin.
    Detects server responses that mention "TODO" in the body (demo only).
    """

    NAME        = "example-plugin"
    VULN_TYPE   = VulnType.INFORMATION_DISC
    DESCRIPTION = "Example plugin: detects TODO comments in responses (demo)"

    def should_test(self, endpoint: Endpoint, ctx: ScanContext) -> bool:
        return True

    async def detect(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings = []
        try:
            import requests
            resp = await asyncio.get_running_loop().run_in_executor(
                None, lambda: requests.get(endpoint.url, timeout=5))
            if resp and "TODO" in resp.text:
                findings.append(Finding(
                    vuln_type=VulnType.INFORMATION_DISC,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    title="TODO Comment Found in Response",
                    description=f"The response from {endpoint.url} contains a 'TODO' comment.",
                    evidence=Evidence(request_url=endpoint.url, matched_pattern="TODO"),
                    remediation="Remove TODO comments before deploying to production.",
                    endpoint=endpoint, detector=self.NAME,
                    tags=["plugin", "info-disclosure"],
                ))
        except Exception as exc:
            log.debug("Plugin detector failed: %s", exc)
        return findings
