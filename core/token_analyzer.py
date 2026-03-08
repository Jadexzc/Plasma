"""
core/token_analyzer.py
───────────────────────
Evaluates CSRF token quality on every state-changing endpoint:
  Presence  — token field detected?
  Length    — meets minimum?
  Entropy   — sufficiently random? (Shannon, via utils.entropy)
  Reuse     — same value on multiple forms?
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from config import MIN_TOKEN_LENGTH, MIN_TOKEN_ENTROPY
from core.endpoint_classifier import ClassifiedEndpoint
from utils.entropy import shannon_entropy, classify_token_strength

log = logging.getLogger(__name__)


@dataclass
class TokenAnalysisResult:
    """CSRF token findings for one state-changing endpoint."""
    endpoint_url: str
    method:       str
    token_field:  Optional[str]
    token_value:  Optional[str]
    token_length: int
    entropy:      float
    strength:     str   # "Strong" | "Adequate" | "Weak" | "Absent"
    is_reused:    bool = False
    issues:       list[str] = field(default_factory=list)

    @property
    def has_token(self) -> bool:
        return self.token_field is not None

    @property
    def entropy_display(self) -> str:
        return f"{self.entropy:.2f} bits/char" if self.entropy > 0 else "N/A"


class TokenAnalyzer:
    """
    Two-pass analysis:
      Pass 1 — collect all token values to detect reuse across forms
      Pass 2 — evaluate each endpoint's token individually
    """

    def analyze(self, endpoints: list[ClassifiedEndpoint]) -> list[TokenAnalysisResult]:
        """Analyze state-changing endpoints only (GET endpoints skipped)."""
        targets = [e for e in endpoints if e.is_state_changing]

        # Pass 1: build reuse map
        value_counts: Counter[str] = Counter(
            v for e in targets if (v := self._token_value(e))
        )

        # Pass 2: evaluate
        results = []
        for ep in targets:
            result = self._evaluate(ep, value_counts)
            results.append(result)
            log.debug("[%s] %s  field=%s  strength=%s  entropy=%.2f",
                      ep.method, ep.url, result.token_field or "NONE",
                      result.strength, result.entropy)
        return results

    def _evaluate(self, ep: ClassifiedEndpoint, value_counts: Counter) -> TokenAnalysisResult:
        field_name = ep.csrf_token_field
        token_val  = self._token_value(ep)
        issues: list[str] = []

        if field_name is None:
            return TokenAnalysisResult(
                endpoint_url=ep.url, method=ep.method,
                token_field=None, token_value=None,
                token_length=0, entropy=0.0, strength="Absent",
                issues=["No CSRF token field detected in form"],
            )

        length   = len(token_val) if token_val else 0
        entropy  = shannon_entropy(token_val) if token_val else 0.0
        strength = classify_token_strength(length, entropy)
        reused   = token_val is not None and value_counts.get(token_val, 0) > 1

        if length < MIN_TOKEN_LENGTH:
            issues.append(f"Token too short ({length} chars; minimum {MIN_TOKEN_LENGTH})")
        if entropy < MIN_TOKEN_ENTROPY and length > 0:
            issues.append(f"Low entropy ({entropy:.2f} bits/char; minimum {MIN_TOKEN_ENTROPY})")
        if reused:
            issues.append("Token value reused across multiple forms")
        if strength == "Weak":
            issues.append("Token classified as Weak — may be guessable or sequential")

        return TokenAnalysisResult(
            endpoint_url=ep.url, method=ep.method,
            token_field=field_name, token_value=token_val,
            token_length=length, entropy=entropy,
            strength=strength, is_reused=reused, issues=issues,
        )

    @staticmethod
    def _token_value(ep: ClassifiedEndpoint) -> Optional[str]:
        if ep.csrf_token_field is None:
            return None
        for inp in ep.inputs:
            if inp.get("name") == ep.csrf_token_field:
                return inp.get("value") or None
        return None
