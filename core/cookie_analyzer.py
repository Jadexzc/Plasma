"""
core/cookie_analyzer.py
─────────────────────────
Evaluates cookies against the three core security attributes:
  Secure    → HTTPS-only transmission
  HttpOnly  → JavaScript access blocked
  SameSite  → primary browser-level CSRF defence
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from config import SESSION_COOKIE_PATTERNS
from core.crawler import RawCookie

log = logging.getLogger(__name__)


@dataclass
class CookieAnalysisResult:
    """Security findings for a single cookie."""
    name:                 str
    source_url:           str
    is_secure:            bool
    is_http_only:         bool
    same_site:            Optional[str]
    is_session_candidate: bool
    issues:               list[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        n = len(self.issues)
        if n == 0: return "Low"
        if n == 1: return "Medium"
        if n == 2: return "High"
        return "Critical"


class CookieAnalyzer:
    """
    Runs three security checks on every cookie:
      1. Secure flag   2. HttpOnly flag   3. SameSite policy
    """

    def analyze(self, cookies: list[RawCookie]) -> list[CookieAnalysisResult]:
        results = []
        for cookie in cookies:
            result = self._check(cookie)
            results.append(result)
            log.debug("%s  secure=%s  httponly=%s  samesite=%s  issues=%d",
                      cookie.name, result.is_secure, result.is_http_only,
                      result.same_site, len(result.issues))
        return results

    def _check(self, cookie: RawCookie) -> CookieAnalysisResult:
        issues: list[str] = []
        if not cookie.secure:
            issues.append("Missing Secure flag — cookie transmitted over HTTP")
        if not cookie.http_only:
            issues.append("Missing HttpOnly flag — cookie accessible via JavaScript")
        if cookie.same_site is None:
            issues.append("SameSite absent — browser default behaviour varies")
        elif cookie.same_site.lower() == "none":
            issues.append("SameSite=None — cookie sent on all cross-site requests")

        return CookieAnalysisResult(
            name=cookie.name, source_url=cookie.source_url,
            is_secure=cookie.secure, is_http_only=cookie.http_only,
            same_site=cookie.same_site,
            is_session_candidate=self._is_session(cookie.name),
            issues=issues,
        )

    @staticmethod
    def _is_session(name: str) -> bool:
        lower = name.lower()
        return any(p in lower for p in SESSION_COOKIE_PATTERNS)
