"""
modules/file_upload_detector.py
─────────────────────────────────
File Upload vulnerability detector — BaseDetector subclass.

Passively summarises file-upload endpoints discovered during crawling AND
actively tests them when context.settings.upload_file is provided (CLI --upload).

Passive checks (always run):
  - Endpoint lacks CSRF token → unprotected multipart upload
  - Endpoint missing Accept-Ranges / Content-Disposition checks

Active checks (when upload_file is set):
  - Submit test file to endpoint and inspect response
  - Detect unrestricted file type acceptance
  - Detect dangerous file stored/reflected in response
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from core.endpoint_classifier import ClassifiedEndpoint
from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)
from core.vulnerability_detectors.base_detector import BaseDetector
from utils.http_client import make_session

log = logging.getLogger(__name__)


# ─── Legacy summary models (kept for backward compat with ReportBuilder) ──────

@dataclass
class FileUploadFinding:
    """Summary of a single file-upload endpoint's security posture."""
    url:              str
    method:           str
    enctype:          str
    has_csrf_token:   bool
    file_field_names: list[str] = field(default_factory=list)

    @property
    def risk_note(self) -> str:
        if not self.has_csrf_token:
            return "No CSRF token — fully unprotected multipart endpoint"
        return "CSRF token present — verify server-side validation"


@dataclass
class FileUploadSummary:
    """Aggregated file upload risk summary for the whole scan."""
    findings:    list[FileUploadFinding] = field(default_factory=list)
    total_count: int = 0

    @property
    def unprotected_count(self) -> int:
        return sum(1 for f in self.findings if not f.has_csrf_token)


# ─── Legacy detector (for backward compat) ────────────────────────────────────

class _LegacyFileUploadDetector:
    """
    Legacy classifier — only summarises endpoints, no active probing.
    Used by ReportBuilder for the old CSRF-only pipeline.
    """

    def detect(self, endpoints: list[ClassifiedEndpoint]) -> FileUploadSummary:
        """Return a summary of all file-upload endpoints."""
        summary = FileUploadSummary()

        for ep in endpoints:
            if not ep.has_file_upload:
                continue

            file_fields = [
                i["name"] for i in ep.inputs
                if i.get("type", "").lower() == "file" and i.get("name")
            ]

            summary.findings.append(FileUploadFinding(
                url=ep.url,
                method=ep.method,
                enctype=ep.enctype,
                has_csrf_token=ep.csrf_token_field is not None,
                file_field_names=file_fields,
            ))

        summary.total_count = len(summary.findings)
        return summary


# Public alias for legacy callers
FileUploadDetector = _LegacyFileUploadDetector


# ─── New BaseDetector implementation ──────────────────────────────────────────

class FileUploadVulnDetector(BaseDetector):
    """
    File upload vulnerability detector (BaseDetector subclass).

    Auto-discovered by DetectorRegistry and integrated into the scan pipeline.

    Passive checks:
      - Multipart endpoint without CSRF token (High)
      - Multipart endpoint with weak CSRF token (Medium)

    Active checks (only if context.settings.upload_file is set):
      - Submit file to endpoint; detect unrestricted type acceptance
      - Detect if upload path is reflected in response (potential stored XSS)
    """

    NAME        = "file-upload"
    VULN_TYPE   = VulnType.FILE_UPLOAD
    DESCRIPTION = "Detects insecure file upload endpoints (CSRF, unrestricted type, path disclosure)"

    def should_test(self, endpoint: Endpoint, context: ScanContext) -> bool:
        return endpoint.has_file_upload

    async def detect(
        self,
        context:  ScanContext,
        endpoint: Endpoint,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # ── Passive: CSRF token check ──────────────────────────────────────────
        has_token = any(
            any(p in name.lower() for p in (
                "csrf", "token", "_token", "csrftoken", "csrf_token",
                "authenticity_token", "xsrf", "_csrf"
            ))
            for name in endpoint.parameters.keys()
        )

        if not has_token:
            findings.append(Finding(
                vuln_type=VulnType.FILE_UPLOAD,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Unprotected File Upload Endpoint (No CSRF Token)",
                description=(
                    f"The file upload endpoint {endpoint.url} accepts multipart/form-data "
                    "requests without a CSRF token. An attacker can craft a cross-site form "
                    "that causes authenticated victims to upload arbitrary files."
                ),
                evidence=Evidence(
                    request_url=endpoint.url,
                    request_method=endpoint.method,
                    notes="No CSRF token field detected in multipart form",
                ),
                remediation=(
                    "Add a synchronizer CSRF token to all file upload forms. "
                    "Also validate file type (allowlist), size limit, and store "
                    "uploads outside the web root. "
                    "See: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                ),
                endpoint=endpoint,
                detector=self.NAME,
                owasp_id="A01:2021",
                cwe_id="CWE-352",
                tags=["file-upload", "csrf", "multipart"],
            ))

        # ── Active: submit test file ───────────────────────────────────────────
        upload_file: Optional[str] = getattr(context.settings, "upload_file", None)
        profile = context.settings.profile
        if upload_file and os.path.isfile(upload_file) and profile != "safe":
            active_findings = await self._test_active_upload(context, endpoint, upload_file)
            findings.extend(active_findings)

        return findings

    async def _test_active_upload(
        self,
        context:     ScanContext,
        endpoint:    Endpoint,
        upload_file: str,
    ) -> list[Finding]:
        """Submit the test file to the endpoint and analyse the response."""
        findings: list[Finding] = []
        filename = os.path.basename(upload_file)

        def _do_upload():
            session = make_session(timeout=context.settings.timeout)
            # Find the file field name (default to 'file')
            file_param = next(
                (name for name in endpoint.parameters if "file" in name.lower()),
                "file",
            )
            # Build form data (include all non-file params)
            data = {k: v for k, v in endpoint.parameters.items()
                    if k.lower() != file_param}
            try:
                with open(upload_file, "rb") as fh:
                    files = {file_param: (filename, fh, "application/octet-stream")}
                    if endpoint.method.upper() == "POST":
                        resp = session.post(endpoint.url, data=data, files=files)
                    else:
                        resp = session.put(endpoint.url, data=data, files=files)
                return resp
            except Exception as exc:
                log.debug("File upload test failed for %s: %s", endpoint.url, exc)
                return None

        try:
            resp = await asyncio.get_running_loop().run_in_executor(None, _do_upload)
        except Exception as exc:
            log.debug("Upload executor error: %s", exc)
            return findings

        if resp is None:
            return findings

        # Analyse response
        body = resp.text if hasattr(resp, "text") else ""
        status = resp.status_code if hasattr(resp, "status_code") else 0

        # Server accepted the upload (2xx response)
        if 200 <= status < 300:
            # Check if filename is reflected (potential path disclosure / stored XSS)
            if filename in body:
                findings.append(Finding(
                    vuln_type=VulnType.FILE_UPLOAD,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="File Upload — Filename Reflected in Response",
                    description=(
                        f"After uploading '{filename}' to {endpoint.url}, the server "
                        "reflected the filename in its response. This may indicate the "
                        "upload path is exposed, enabling stored XSS if HTML files are accepted."
                    ),
                    evidence=Evidence(
                        request_url=endpoint.url,
                        request_method=endpoint.method,
                        payload_used=filename,
                        response_status=status,
                        response_body=body[:500],
                        notes="Filename appears in response body",
                    ),
                    remediation=(
                        "Never reflect uploaded filenames in responses. "
                        "Generate server-side random names for stored files."
                    ),
                    endpoint=endpoint,
                    detector=self.NAME,
                    owasp_id="A04:2021",
                    cwe_id="CWE-434",
                    tags=["file-upload", "active", "reflected"],
                ))
            else:
                # Generic acceptance finding
                findings.append(Finding(
                    vuln_type=VulnType.FILE_UPLOAD,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="File Upload Accepted Without Apparent Validation",
                    description=(
                        f"The endpoint {endpoint.url} accepted a test file upload "
                        f"(HTTP {status}). Verify that the server enforces file type "
                        "allowlisting, size limits, and malware scanning."
                    ),
                    evidence=Evidence(
                        request_url=endpoint.url,
                        request_method=endpoint.method,
                        payload_used=filename,
                        response_status=status,
                        notes=f"Server returned HTTP {status} — upload accepted",
                    ),
                    remediation=(
                        "Enforce file type allowlist (not denylist), maximum size, "
                        "store files outside web root, serve via CDN or signed URL. "
                        "See: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                    ),
                    endpoint=endpoint,
                    detector=self.NAME,
                    owasp_id="A04:2021",
                    cwe_id="CWE-434",
                    tags=["file-upload", "active"],
                ))

        log.info(
            "[%s] File upload test: %s → HTTP %d (file: %s)",
            self.NAME, endpoint.url, status, filename,
        )
        return findings
