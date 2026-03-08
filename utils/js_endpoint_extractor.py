"""
utils/js_endpoint_extractor.py — WebGuard v3
──────────────────────────────────────────────
Extracts API endpoints and hidden paths from JavaScript source files.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger(__name__)

# Patterns that indicate API endpoints in JS code
JS_FETCH_PATTERNS = [
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios(?:\.\w+)?\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'XMLHttpRequest[^;]*?\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'(?:url|endpoint|path|href)\s*[=:]\s*["\']([/][^"\'<>\s]{2,})["\']', re.I),
    re.compile(r'["\'](/(?:api|v\d|rest|graphql)[^"\'<>\s]{0,100})["\']'),
]

JS_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


class JSEndpointExtractor:
    """
    Fetches linked JavaScript files and extracts endpoint URLs.

    Usage:
        extractor = JSEndpointExtractor(base_url="https://example.com")
        endpoints = extractor.extract_from_html(page_html)
        endpoints += extractor.extract_from_url("https://example.com/app.js")
    """

    def __init__(self, base_url: str, session: requests.Session | None = None) -> None:
        self.base_url = base_url
        self._session = session or requests.Session()
        self._session.headers.setdefault("User-Agent", "WebGuard/3.0")

    def extract_from_html(self, html: str) -> list[str]:
        """Find all <script src> tags, fetch each JS file, and extract endpoints."""
        endpoints: list[str] = []

        # Inline script content
        inline = re.findall(r'<script(?![^>]*src)[^>]*>([\s\S]*?)</script>', html, re.I)
        for snippet in inline:
            endpoints.extend(self._extract_from_js(snippet))

        # External scripts
        for src in JS_SCRIPT_SRC_RE.findall(html):
            full_url = urljoin(self.base_url, src)
            if not full_url.startswith(("http://", "https://")):
                continue
            endpoints.extend(self.extract_from_url(full_url))

        return self._deduplicate_and_filter(endpoints)

    def extract_from_url(self, js_url: str) -> list[str]:
        """Fetch a JS URL and extract endpoint patterns."""
        try:
            resp = self._session.get(js_url, timeout=8, allow_redirects=True)
            if resp.status_code == 200:
                return self._extract_from_js(resp.text)
        except Exception as exc:
            log.debug("JS extraction failed for %s: %s", js_url, exc)
        return []

    def _extract_from_js(self, js_code: str) -> list[str]:
        endpoints = []
        for pattern in JS_FETCH_PATTERNS:
            for match in pattern.finditer(js_code):
                path = match.group(1).strip()
                if self._is_valid_endpoint(path):
                    full = urljoin(self.base_url, path)
                    endpoints.append(full)
        return endpoints

    def _deduplicate_and_filter(self, endpoints: list[str]) -> list[str]:
        seen   = set()
        result = []
        base_host = urlparse(self.base_url).netloc

        for ep in endpoints:
            ep = ep.strip()
            if ep in seen:
                continue
            seen.add(ep)

            parsed = urlparse(ep)
            # Only same-origin endpoints
            if parsed.netloc and parsed.netloc != base_host:
                continue
            result.append(ep)

        return result

    @staticmethod
    def _is_valid_endpoint(path: str) -> bool:
        """Basic sanity check for an endpoint path."""
        if not path or len(path) < 2:
            return False
        if path.startswith(("data:", "javascript:", "mailto:", "#")):
            return False
        if path.endswith((".png", ".jpg", ".gif", ".css", ".ico", ".woff", ".svg")):
            return False
        return True
