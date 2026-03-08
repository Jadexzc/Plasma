"""
utils/har_parser.py — Plasma v3.3
───────────────────────────────────
HTTP Archive (HAR) file parser.

Parses a browser-recorded .har file and extracts:
  • Every unique URL + HTTP method
  • Query parameters
  • POST body parameters (application/x-www-form-urlencoded and application/json)
  • Request headers (auth headers, content-type)

The results are returned as Endpoint objects ready for the AttackSurfaceMapper.

Usage::

    parser  = HARParser("session.har")
    endpoints = parser.parse()
    # → list[Endpoint]

CLI::

    plasma -u https://example.com --har session.har

References
──────────
  HAR 1.2 spec: http://www.softwareishard.com/blog/har-12-spec/
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse, urlencode

from core.models import Endpoint

log = logging.getLogger(__name__)

# Headers that are interesting for security testing
_AUTH_HEADER_NAMES = frozenset({
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "cookie", "x-csrf-token", "x-xsrf-token",
})

# Headers to drop (binary / irrelevant)
_DROP_HEADERS = frozenset({
    "accept-encoding", "accept-language", "accept", "cache-control",
    "connection", "host", "upgrade-insecure-requests", "sec-fetch-*",
    "sec-ch-ua*", "if-none-match", "if-modified-since",
})


class HARParser:
    """
    Parse a .har file and return Endpoint objects for scanning.

    Args:
        har_path: Path to the .har file (exported from Chrome/Firefox DevTools,
                  Burp Suite, or Charles Proxy).
        target_filter: If set, only include entries whose URL starts with this
                       prefix (useful for limiting to the target origin).
    """

    def __init__(
        self,
        har_path:      str,
        target_filter: Optional[str] = None,
    ) -> None:
        self.har_path      = Path(har_path)
        self.target_filter = target_filter
        self._endpoints:   list[Endpoint] = []

    def parse(self) -> list[Endpoint]:
        """Parse the HAR file and return deduplicated Endpoints."""
        if not self.har_path.exists():
            raise FileNotFoundError(f"HAR file not found: {self.har_path}")

        try:
            data = json.loads(self.har_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid HAR file (JSON error): {e}") from e

        entries = data.get("log", {}).get("entries", [])
        if not entries:
            log.warning("[har] No entries found in %s", self.har_path)
            return []

        seen:    set[tuple[str, str, str]] = set()   # (url_norm, method, body_key)
        result:  list[Endpoint]            = []

        for entry in entries:
            ep = self._parse_entry(entry)
            if ep is None:
                continue

            # Apply target filter
            if self.target_filter and not ep.url.startswith(self.target_filter):
                continue

            # Deduplicate by (normalised_url, method, sorted_params)
            param_key = ",".join(sorted(ep.parameters.keys())) if ep.parameters else ""
            key = (self._normalise_url(ep.url), ep.method.upper(), param_key)
            if key in seen:
                continue
            seen.add(key)
            result.append(ep)

        log.info("[har] Parsed %d unique endpoints from %s", len(result), self.har_path)
        return result

    def _parse_entry(self, entry: dict) -> Optional[Endpoint]:
        """Convert a single HAR entry to an Endpoint."""
        req = entry.get("request", {})
        url     = req.get("url", "")
        method  = req.get("method", "GET").upper()

        if not url or not url.startswith(("http://", "https://")):
            return None

        # ── Extract parameters ─────────────────────────────────────────────
        params: dict[str, str] = {}

        # 1. Query string params
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        for k, vs in qs.items():
            params[k] = vs[0] if vs else ""

        # Remove query string from URL (params already extracted)
        clean_url = parsed._replace(query="").geturl()

        # 2. POST body params
        post_data = req.get("postData", {}) or {}
        mime_type = (post_data.get("mimeType", "") or "").lower()
        body_text = post_data.get("text", "") or ""

        body_raw: Optional[str] = None

        if "application/json" in mime_type and body_text:
            try:
                body_json = json.loads(body_text)
                if isinstance(body_json, dict):
                    params.update({k: str(v) for k, v in body_json.items()})
                body_raw = body_text
            except json.JSONDecodeError:
                pass
        elif "x-www-form-urlencoded" in mime_type:
            # Parse from postData.params array if available
            for pf in (post_data.get("params") or []):
                params[pf.get("name", "")] = pf.get("value", "")
            if not params and body_text:
                for k, vs in parse_qs(body_text, keep_blank_values=True).items():
                    params[k] = vs[0] if vs else ""
            body_raw = body_text or urlencode(params)
        elif "multipart/form-data" in mime_type:
            for pf in (post_data.get("params") or []):
                params[pf.get("name", "")] = pf.get("value", "")

        # ── Extract useful headers ──────────────────────────────────────────
        headers: dict[str, str] = {}
        for h in (req.get("headers") or []):
            name  = (h.get("name") or "").lower()
            value = (h.get("value") or "")
            if name in _AUTH_HEADER_NAMES:
                headers[name] = value
            elif "content-type" in name:
                headers["content-type"] = value

        # ── Build tags ──────────────────────────────────────────────────────
        tags = ["har"]
        if headers.get("authorization"):
            tags.append("authenticated")
        if "application/json" in mime_type:
            tags.append("json-body")
        if "multipart" in mime_type:
            tags.append("multipart")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            tags.append("state-changing")

        return Endpoint(
            url=clean_url,
            method=method,
            parameters=params,
            headers=headers,
            body=body_raw,
            tags=tags,
        )

    @staticmethod
    def _normalise_url(url: str) -> str:
        """Strip query string and fragment for dedup."""
        p = urlparse(url)
        return p._replace(query="", fragment="").geturl()
