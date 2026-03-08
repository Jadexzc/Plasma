"""
core/passive/security_hardening.py — Plasma v3.3
──────────────────────────────────────────────────
Security hardening checks that run passively against the target.

Modules
───────
  1. CSPEvaluator     — rates Content-Security-Policy strength, flags bypasses
  2. CookieAuditor    — checks cookie flags: __Host-, __Secure-, SameSite, HttpOnly
  3. ScanAuditLog     — immutable append-only log of all HTTP requests made
  4. ReportHasher     — SHA-256 hash of final report for integrity verification

These run after passive_analyzer and produce low/medium/info findings.
They never block or modify the scan flow.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# 1. CSP Evaluator
# ═══════════════════════════════════════════════════════════════════════════

# Bypass-enabling directives
_CSP_UNSAFE     = re.compile(r"'unsafe-inline'|'unsafe-eval'", re.I)
_CSP_WILDCARD   = re.compile(r"script-src\s+[^;]*\*", re.I)
_CSP_DATA_URI   = re.compile(r"'data:'|data:", re.I)
_CSP_HTTP_SRC   = re.compile(r"(script|style|img|font|connect|object|frame)-src[^;]*http:", re.I)


class CSPEvaluator:
    """Evaluate Content-Security-Policy header strength."""

    def evaluate(self, csp: str, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        url = endpoint.url

        if not csp:
            findings.append(Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="CSP — Content-Security-Policy Header Missing",
                description=(
                    f"{url} does not send a Content-Security-Policy header. "
                    "Without CSP, XSS attacks can load arbitrary scripts."
                ),
                evidence=Evidence(request_url=url, matched_pattern="no CSP header"),
                remediation=(
                    "Implement a strict CSP: "
                    "Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'"
                ),
                endpoint=endpoint, detector="csp-evaluator",
                tags=["csp", "missing"], owasp_id="A05:2021", cwe_id="CWE-693",
            ))
            return findings

        # unsafe-inline / unsafe-eval
        if _CSP_UNSAFE.search(csp):
            match = _CSP_UNSAFE.search(csp).group(0)
            findings.append(Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title=f"CSP — {match!r} Allows XSS Bypass",
                description=(
                    f"The CSP for {url} contains {match!r}, which allows inline scripts "
                    "and eval(). XSS payloads can execute without CSP protection."
                ),
                evidence=Evidence(request_url=url, matched_pattern=match, notes=csp[:300]),
                remediation=(
                    f"Remove {match!r} from CSP. Use nonces or hashes for legitimate inline scripts. "
                    "Replace eval() with safer alternatives."
                ),
                endpoint=endpoint, detector="csp-evaluator",
                tags=["csp", "unsafe"], owasp_id="A05:2021", cwe_id="CWE-693",
            ))

        # Wildcard in script-src
        if _CSP_WILDCARD.search(csp):
            findings.append(Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="CSP — Wildcard (*) in script-src Bypasses XSS Protection",
                description=f"CSP on {url} uses a wildcard in script-src, defeating XSS protection.",
                evidence=Evidence(request_url=url, matched_pattern="script-src *", notes=csp[:300]),
                remediation="Replace wildcards with explicit trusted domains.",
                endpoint=endpoint, detector="csp-evaluator",
                tags=["csp", "wildcard"], owasp_id="A05:2021", cwe_id="CWE-693",
            ))

        # No script-src at all (relies on default-src)
        if "script-src" not in csp.lower() and "default-src" not in csp.lower():
            findings.append(Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                title="CSP — No script-src or default-src Directive",
                description=f"CSP on {url} has no script-src or default-src — scripts unrestricted.",
                evidence=Evidence(request_url=url, matched_pattern="missing script-src"),
                remediation="Add: Content-Security-Policy: default-src 'self'; script-src 'nonce-...'",
                endpoint=endpoint, detector="csp-evaluator",
                tags=["csp", "incomplete"], owasp_id="A05:2021", cwe_id="CWE-693",
            ))

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 2. Cookie Auditor
# ═══════════════════════════════════════════════════════════════════════════

class CookieAuditor:
    """
    Audit Set-Cookie headers for missing security flags.
    Checks: Secure, HttpOnly, SameSite, __Host- / __Secure- prefixes.
    """

    def audit(self, response_headers: dict, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        url = endpoint.url

        set_cookies = []
        for k, v in response_headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)

        if not set_cookies:
            return findings

        for cookie_str in set_cookies:
            cookie_name = cookie_str.split("=")[0].strip()
            lower = cookie_str.lower()

            # Sensitive cookie names (session, auth, token, jwt)
            is_sensitive = bool(re.search(
                r"\b(session|sess|auth|token|jwt|csrf|xsrf|login|user)\b",
                cookie_name, re.I
            ))

            if "secure" not in lower and (
                url.startswith("https://") or is_sensitive
            ):
                findings.append(Finding(
                    vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    title=f"Cookie — Missing Secure Flag: {cookie_name!r}",
                    description=(
                        f"Cookie {cookie_name!r} on {url} lacks the Secure flag. "
                        "It can be transmitted over HTTP, enabling interception."
                    ),
                    evidence=Evidence(request_url=url, matched_pattern="no Secure flag",
                                     notes=cookie_str[:200]),
                    remediation=f"Set-Cookie: {cookie_name}=...; Secure; HttpOnly; SameSite=Lax",
                    endpoint=endpoint, detector="cookie-auditor",
                    tags=["cookie", "no-secure"], owasp_id="A02:2021", cwe_id="CWE-614",
                ))

            if "httponly" not in lower and is_sensitive:
                findings.append(Finding(
                    vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    title=f"Cookie — Missing HttpOnly Flag: {cookie_name!r}",
                    description=(
                        f"Sensitive cookie {cookie_name!r} lacks HttpOnly. "
                        "JavaScript can read it, enabling XSS-based session theft."
                    ),
                    evidence=Evidence(request_url=url, matched_pattern="no HttpOnly",
                                     notes=cookie_str[:200]),
                    remediation="Add HttpOnly to all session and auth cookies.",
                    endpoint=endpoint, detector="cookie-auditor",
                    tags=["cookie", "no-httponly"], owasp_id="A02:2021", cwe_id="CWE-1004",
                ))

            if "samesite" not in lower and is_sensitive:
                findings.append(Finding(
                    vuln_type=VulnType.MISCONFIG, severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    title=f"Cookie — Missing SameSite Attribute: {cookie_name!r}",
                    description=(
                        f"Sensitive cookie {cookie_name!r} has no SameSite attribute. "
                        "This can enable CSRF attacks from cross-site requests."
                    ),
                    evidence=Evidence(request_url=url, matched_pattern="no SameSite"),
                    remediation="Add SameSite=Lax (or Strict for high-security sessions).",
                    endpoint=endpoint, detector="cookie-auditor",
                    tags=["cookie", "no-samesite", "csrf"], owasp_id="A01:2021", cwe_id="CWE-352",
                ))

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 3. Scan Audit Log
# ═══════════════════════════════════════════════════════════════════════════

class ScanAuditLog:
    """
    Immutable append-only log of all HTTP requests made during a scan.
    Written to: {scan_dir}/{scan_id}.audit.log

    Each line is a JSON object: {"ts": ..., "method": ..., "url": ..., "status": ...}
    File is append-only; existing entries are never modified.
    """

    def __init__(self, scan_dir: str, scan_id: str) -> None:
        os.makedirs(scan_dir, exist_ok=True)
        self._path   = Path(scan_dir) / f"{scan_id}.audit.log"
        self._fh     = open(self._path, "a", encoding="utf-8", buffering=1)
        self._closed = False

    def __del__(self) -> None:
        """Ensure the file is closed even if close() was never explicitly called."""
        if not getattr(self, "_closed", True):
            try:
                self._fh.flush()
                self._fh.close()
                self._closed = True
            except Exception:
                pass

    def log_request(
        self,
        method:  str,
        url:     str,
        status:  Optional[int] = None,
        payload: Optional[str] = None,
        source:  str = "scan",
    ) -> None:
        """Append one request to the audit log."""
        entry = {
            "ts":      datetime.utcnow().isoformat(),
            "method":  method.upper(),
            "url":     url,
            "status":  status,
            "source":  source,
        }
        if payload:
            entry["payload"] = payload[:200]
        try:
            self._fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def close(self) -> None:
        """Flush and close the log file."""
        if not getattr(self, "_closed", False):
            try:
                self._fh.flush()
                self._fh.close()
                self._closed = True
            except Exception:
                pass

    @property
    def path(self) -> str:
        return str(self._path)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Report Hasher
# ═══════════════════════════════════════════════════════════════════════════

class ReportHasher:
    """
    Compute and verify SHA-256 hash of report files for integrity verification.
    Writes a .sha256 sidecar file next to each report.
    """

    @staticmethod
    def hash_file(report_path: str) -> str:
        """Compute SHA-256 of a file and write .sha256 sidecar."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Report not found: {report_path}")

        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        digest = sha.hexdigest()

        sidecar = path.with_suffix(path.suffix + ".sha256")
        sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        log.info("[hasher] %s  →  %s", path.name, digest[:16] + "…")
        return digest

    @staticmethod
    def verify_file(report_path: str) -> bool:
        """Verify a report against its .sha256 sidecar. Returns True if intact."""
        path    = Path(report_path)
        sidecar = path.with_suffix(path.suffix + ".sha256")

        if not sidecar.exists():
            log.warning("[hasher] No .sha256 sidecar for %s", path.name)
            return False

        stored = sidecar.read_text().split()[0].strip()

        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        actual = sha.hexdigest()

        if actual == stored:
            log.info("[hasher] ✓ Integrity verified: %s", path.name)
            return True
        else:
            log.warning("[hasher] ✗ Integrity FAILED: %s (expected %s, got %s)",
                        path.name, stored[:16], actual[:16])
            return False
