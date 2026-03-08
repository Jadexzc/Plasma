"""
core/tech_detection.py — WebGuard v3
──────────────────────────────────────
Technology fingerprinting from HTTP headers, cookies, meta tags, and paths.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

import requests

from config import TECH_FINGERPRINTS, DEFAULT_TIMEOUT
from core.models import TechFingerprint
from utils.http_client import make_session

log = logging.getLogger(__name__)


class TechDetector:
    """
    Detects the technology stack of a web application.

    Usage:
        detector = TechDetector()
        techs = detector.detect("https://example.com")
        for t in techs:
            print(t.name, t.version)
    """

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._session = session or make_session()

    def detect(self, url: str) -> list[TechFingerprint]:
        """Synchronously detect technologies for a URL."""
        results: list[TechFingerprint] = []
        try:
            resp = self._session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception as exc:
            log.debug("TechDetector: failed to fetch %s: %s", url, exc)
            return results

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        html          = resp.text.lower()
        cookies_lower = {k.lower(): v.lower() for k, v in resp.cookies.items()}

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            found, version = self._match(fingerprint, headers_lower, html, cookies_lower, resp.headers)
            if found:
                results.append(TechFingerprint(
                    name=tech_name,
                    version=version,
                    source="fingerprint",
                ))

        # Version extraction from headers
        self._extract_versions(results, resp.headers)
        log.info("TechDetector: %d technologies detected on %s", len(results), url)
        return results

    def _match(
        self,
        fingerprint: dict,
        headers: dict[str, str],
        html: str,
        cookies: dict[str, str],
        raw_headers,
    ) -> tuple[bool, Optional[str]]:
        """Returns (matched, version_string)."""

        # Header patterns
        for h_pattern in fingerprint.get("headers", []):
            header_name, _, header_value = h_pattern.partition(": ")
            if header_name.lower() in headers:
                if not header_value or header_value.lower() in headers.get(header_name.lower(), ""):
                    return True, None

        # Cookie names
        for cookie in fingerprint.get("cookies", []):
            if cookie.lower() in cookies:
                return True, None

        # Meta tags / HTML patterns
        for meta in fingerprint.get("meta", []):
            if meta.lower() in html:
                return True, None

        # Paths (skip — path testing done by SensitiveFiles detector)
        return False, None

    @staticmethod
    def _extract_versions(results: list[TechFingerprint], headers) -> None:
        """Try to extract version from Server/X-Powered-By headers."""
        server = headers.get("Server", "") + " " + headers.get("X-Powered-By", "")
        patterns = [
            (r"nginx/([\d.]+)", "nginx"),
            (r"Apache/([\d.]+)", "apache"),
            (r"PHP/([\d.]+)", "php"),
            (r"IIS/([\d.]+)", "iis"),
        ]
        for pattern, tech in patterns:
            m = re.search(pattern, server, re.I)
            if m:
                for fp in results:
                    if fp.name == tech and fp.version is None:
                        fp.version = m.group(1)
