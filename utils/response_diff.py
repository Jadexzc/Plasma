"""
utils/response_diff.py — WebGuard v3
──────────────────────────────────────
Response comparison engine for reducing false positives.
Used by IDOR, SQLi boolean detection, parameter discovery, access control.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Optional

from requests import Response


@dataclass
class DiffResult:
    """Comparison result between two HTTP responses."""
    status_changed:   bool  = False
    length_delta:     int   = 0           # byte delta
    length_pct:       float = 0.0         # % change in body length
    content_ratio:    float = 1.0         # 0.0=completely different, 1.0=identical
    json_keys_diff:   list[str] = None    # keys present in resp2 but not resp1
    redirect_changed: bool  = False
    content_type_changed: bool = False
    significant:      bool  = False       # summary flag

    def __post_init__(self):
        if self.json_keys_diff is None:
            self.json_keys_diff = []


class ResponseDiff:
    """
    Compare two HTTP responses to detect meaningful differences.

    Usage:
        diff = ResponseDiff.compare(baseline_response, test_response)
        if diff.significant:
            # likely vulnerability
    """

    # Thresholds
    LENGTH_CHANGE_THRESHOLD = 0.05     # 5% body size change = significant
    MIN_SIGNIFICANT_DELTA   = 50       # bytes — ignore tiny changes
    SIMILARITY_THRESHOLD    = 0.85     # content ratio below this = different page

    @classmethod
    def compare(
        cls,
        baseline: Optional[Response],
        test:     Optional[Response],
        strict:   bool = False,
    ) -> DiffResult:
        """
        Compare two responses. Returns DiffResult with .significant flag.

        Args:
            baseline: the reference response (e.g., original request)
            test:     the injected/modified request response
            strict:   if True, even small changes are flagged
        """
        result = DiffResult()

        if baseline is None or test is None:
            return result

        # ── Status code ─────────────────────────────────────────────────────
        result.status_changed = (baseline.status_code != test.status_code)

        # ── Body length ──────────────────────────────────────────────────────
        b_len = len(baseline.content)
        t_len = len(test.content)
        result.length_delta = abs(t_len - b_len)
        result.length_pct   = (result.length_delta / max(b_len, 1)) * 100

        # ── Content similarity ────────────────────────────────────────────────
        # Fast path: if length delta alone already exceeds both thresholds we
        # know the result is significant and can skip the O(n²) SequenceMatcher.
        if (result.length_pct > cls.LENGTH_CHANGE_THRESHOLD * 100
                and result.length_delta > cls.MIN_SIGNIFICANT_DELTA):
            result.content_ratio = 0.0   # conservative: treat as completely different
        else:
            b_text = _normalise(baseline.text)
            t_text = _normalise(test.text)
            result.content_ratio = SequenceMatcher(None, b_text[:4000], t_text[:4000]).ratio()

        # ── Redirect ─────────────────────────────────────────────────────────
        b_loc = baseline.headers.get("Location", "")
        t_loc = test.headers.get("Location", "")
        result.redirect_changed = (b_loc != t_loc)

        # ── Content-Type ──────────────────────────────────────────────────────
        b_ct = baseline.headers.get("Content-Type", "").split(";")[0].strip()
        t_ct = test.headers.get("Content-Type", "").split(";")[0].strip()
        result.content_type_changed = (b_ct != t_ct)

        # ── JSON structure ────────────────────────────────────────────────────
        if "json" in b_ct:
            result.json_keys_diff = _json_new_keys(baseline.text, test.text)

        # ── Significance decision ─────────────────────────────────────────────
        result.significant = cls._is_significant(result, strict)

        return result

    @classmethod
    def _is_significant(cls, r: DiffResult, strict: bool) -> bool:
        if r.status_changed:
            return True
        if r.redirect_changed:
            return True
        if r.content_ratio < cls.SIMILARITY_THRESHOLD:
            return True
        if strict:
            return r.length_delta > 20
        return (
            r.length_pct > cls.LENGTH_CHANGE_THRESHOLD * 100
            and r.length_delta > cls.MIN_SIGNIFICANT_DELTA
        )

    @classmethod
    def same_content(cls, r1: Optional[Response], r2: Optional[Response]) -> bool:
        """Quick check: are two responses functionally identical?"""
        if r1 is None or r2 is None:
            return False
        if r1.status_code != r2.status_code:
            return False
        t1 = _normalise(r1.text)
        t2 = _normalise(r2.text)
        return SequenceMatcher(None, t1[:3000], t2[:3000]).ratio() > 0.97

    @classmethod
    def body_contains_new_content(cls, baseline: Optional[Response], test: Optional[Response], keyword: str) -> bool:
        """Return True if keyword appears in test response but NOT in baseline."""
        if baseline is None or test is None:
            return False
        kw = keyword.lower()
        return kw in test.text.lower() and kw not in baseline.text.lower()


def _normalise(text: str) -> str:
    """Remove dynamic tokens (CSRF, nonces, timestamps) before comparison."""
    # Remove UUIDs
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', text, flags=re.I)
    # Remove CSRF-style tokens (long hex/base64 in hidden inputs)
    text = re.sub(r'value="[A-Za-z0-9+/=]{20,}"', 'value="TOKEN"', text)
    # Remove timestamps / epoch values
    text = re.sub(r'\b\d{10,13}\b', 'TS', text)
    return text


def _json_new_keys(baseline_text: str, test_text: str) -> list[str]:
    """Return keys present in test JSON but absent from baseline JSON."""
    try:
        b = json.loads(baseline_text)
        t = json.loads(test_text)
        if isinstance(b, dict) and isinstance(t, dict):
            return [k for k in t if k not in b]
    except Exception:
        pass
    return []
