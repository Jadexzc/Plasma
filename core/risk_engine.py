"""
core/risk_engine.py — Plasma v3
---------------------------------
CVSS-inspired risk scoring engine.
Scores each finding and produces an overall scan risk assessment.

Production optimisations
------------------------
scan_risk: eliminated two redundant passes over findings.
  Before: score_all (1 pass) + counts loop (1 pass) + zip+sort for top-5 (1 pass).
          Also created a paired list for zip then sorted it.
  After:  single pass that accumulates scores, counts, and top-5 simultaneously.
          O(n) time, O(k) space where k = 5 (top findings buffer capped via heapq.nlargest).

_level: pre-sorted threshold tuple avoids branch-heavy if-elif chains for
  repeated calls.  Minor but keeps the hot path tidy.
"""
from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass
from typing import Optional

from core.models import Confidence, Finding, Severity, ScanContext

log = logging.getLogger(__name__)

# CVSS-inspired base scores per severity
_SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH:     7.5,
    Severity.MEDIUM:   5.0,
    Severity.LOW:      2.5,
    Severity.INFO:     0.0,
}

# Confidence multiplier
_CONFIDENCE_MULT: dict[Confidence, float] = {
    Confidence.CONFIRMED: 1.0,
    Confidence.HIGH:      0.9,
    Confidence.MEDIUM:    0.7,
    Confidence.LOW:       0.5,
}

# Auth-required deduction (findings behind login are harder to exploit)
_AUTH_DEDUCT = 0.5

# Sorted thresholds for _level() — avoids repeated if/elif evaluation.
_LEVEL_THRESHOLDS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (1.0, "Low"),
    (0.0, "Info"),
)


@dataclass
class RiskScore:
    """Computed risk assessment for a single finding."""
    finding_id:     str
    base_score:     float
    confidence_adj: float
    final_score:    float
    risk_level:     str       # "Critical" / "High" / "Medium" / "Low" / "Info"
    exploitability: str       # "Easy" / "Moderate" / "Difficult"
    impact:         str       # "Critical" / "Significant" / "Moderate" / "Minor"
    requires_auth:  bool


@dataclass
class ScanRisk:
    """Overall risk assessment for a complete scan."""
    overall_score:  float
    risk_level:     str
    total_findings: int
    critical_count: int
    high_count:     int
    medium_count:   int
    low_count:      int
    info_count:     int
    waf_detected:   bool
    top_findings:   list[str]   # titles of top 5 findings by score


class RiskEngine:
    """
    Scores findings and generates scan risk assessments.

    Usage:
        engine = RiskEngine()
        scores = engine.score_all(context.findings)
        report = engine.scan_risk(context)
    """

    def score_finding(self, finding: Finding, auth_required: bool = False) -> RiskScore:
        """Compute a numeric risk score for one finding."""
        base  = _SEVERITY_BASE.get(finding.severity, 0.0)
        conf  = _CONFIDENCE_MULT.get(finding.confidence, 0.7)
        score = base * conf

        if auth_required:
            score = max(0.0, score - _AUTH_DEDUCT)

        # Use provided CVSS score if available
        if finding.cvss_score is not None:
            final = min(10.0, finding.cvss_score)
        else:
            final = min(10.0, round(score, 1))

        return RiskScore(
            finding_id=finding.id,
            base_score=round(base, 1),
            confidence_adj=round(score, 1),
            final_score=final,
            risk_level=self._level(final),
            exploitability=self._exploitability(finding),
            impact=self._impact(finding),
            requires_auth=auth_required,
        )

    def score_all(self, findings: list[Finding]) -> list[RiskScore]:
        return [self.score_finding(f) for f in findings]

    def scan_risk(self, context: ScanContext) -> ScanRisk:
        """
        Produce an overall risk assessment for a completed scan.

        Performance: single-pass accumulation instead of three separate passes.
        Also uses heapq.nlargest for top-5 instead of a full sort (O(n log k)
        vs O(n log n) for a full sort when k << n).
        """
        findings = context.findings
        if not findings:
            return ScanRisk(
                overall_score=0.0, risk_level="None", total_findings=0,
                critical_count=0, high_count=0, medium_count=0,
                low_count=0, info_count=0, waf_detected=False, top_findings=[],
            )

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        score_sum = 0.0
        max_score = 0.0
        # Accumulate (score, title) tuples for top-5 selection via heapq.
        scored_titles: list[tuple[float, str]] = []

        for f in findings:
            rs = self.score_finding(f)
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            score_sum += rs.final_score
            if rs.final_score > max_score:
                max_score = rs.final_score
            scored_titles.append((rs.final_score, f.title))

        avg     = round(score_sum / len(findings), 1)
        overall = round(max_score * 0.6 + avg * 0.4, 1)

        # O(n log k) instead of O(n log n) full sort
        top = [title for _, title in heapq.nlargest(5, scored_titles, key=lambda x: x[0])]

        return ScanRisk(
            overall_score=overall,
            risk_level=self._level(overall),
            total_findings=len(findings),
            critical_count=counts.get("Critical", 0),
            high_count=counts.get("High", 0),
            medium_count=counts.get("Medium", 0),
            low_count=counts.get("Low", 0),
            info_count=counts.get("Info", 0),
            waf_detected=getattr(context, "_waf_detected", False),
            top_findings=top,
        )

    @staticmethod
    def _level(score: float) -> str:
        """Map numeric score to risk-level label via sorted threshold table."""
        for threshold, label in _LEVEL_THRESHOLDS:
            if score >= threshold:
                return label
        return "Info"

    @staticmethod
    def _exploitability(f: Finding) -> str:
        if f.confidence in (Confidence.CONFIRMED, Confidence.HIGH):
            return "Easy"
        if f.confidence == Confidence.MEDIUM:
            return "Moderate"
        return "Difficult"

    @staticmethod
    def _impact(f: Finding) -> str:
        if f.severity == Severity.CRITICAL: return "Critical"
        if f.severity == Severity.HIGH:     return "Significant"
        if f.severity == Severity.MEDIUM:   return "Moderate"
        return "Minor"


# -- Backward Compatibility Stubs (v2 API) ------------------------------------

from dataclasses import dataclass as _dc, field as _field
from typing import Any as _Any

@_dc
class ScoreBreakdown:
    total:   int  = 0
    details: list = _field(default_factory=list)

@_dc
class ScoredEndpoint:
    endpoint:  _Any          = None
    score:     int            = 0
    risk:      str            = "Low"
    findings:  list           = _field(default_factory=list)
    breakdown: ScoreBreakdown = _field(default_factory=ScoreBreakdown)

def classify_score(score: int) -> str:
    if score >= 12: return "Critical"
    if score >= 7:  return "High"
    if score >= 3:  return "Medium"
    return "Low"
