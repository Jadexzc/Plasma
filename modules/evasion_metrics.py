"""
modules/evasion_metrics.py — Plasma v3
──────────────────────────────────────
Evasion metrics tracker and reporter.

Provides:
  EvasionMetricsReport   — dataclass wrapping a completed session's metrics
  EvasionMetricsReporter — formats metrics for CLI or log output

Usage:
    from modules.evasion_metrics import EvasionMetricsReporter
    reporter = EvasionMetricsReporter()
    reporter.ingest(fuzz_engine._evasion.get_metrics())
    reporter.ingest_feedback(fuzz_engine._feedback.top_techniques())
    print(reporter.summary_text())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EvasionMetricsReport:
    """Snapshot of evasion effectiveness for a single scan."""
    total_probes:       int                   = 0
    notable_hits:       int                   = 0
    waf_detections:     int                   = 0
    waf_names:          list[str]             = field(default_factory=list)
    technique_hits:     dict[str, int]        = field(default_factory=dict)
    technique_misses:   dict[str, int]        = field(default_factory=dict)
    top_techniques:     list[tuple[str,float]]= field(default_factory=list)

    @property
    def hit_rate(self) -> float:
        return self.notable_hits / max(self.total_probes, 1)

    @property
    def best_technique(self) -> Optional[str]:
        return self.top_techniques[0][0] if self.top_techniques else None


class EvasionMetricsReporter:
    """
    Aggregates raw metric dicts (from EvasionLayer.get_metrics() and
    FeedbackLoop.top_techniques()) into a clean EvasionMetricsReport,
    and renders human-readable summaries.
    """

    def __init__(self) -> None:
        self._raw:      dict[str, int]         = {}
        self._feedback: list[tuple[str, float]] = []

    def ingest(self, metrics: dict[str, int]) -> None:
        """Ingest raw metric dict from EvasionLayer.get_metrics()."""
        self._raw.update(metrics)

    def ingest_feedback(self, top: list[tuple[str, float]]) -> None:
        """Ingest top techniques from FeedbackLoop.top_techniques()."""
        self._feedback = top

    def build_report(self) -> EvasionMetricsReport:
        report = EvasionMetricsReport(top_techniques=self._feedback)
        for key, count in self._raw.items():
            if ":hit" in key:
                tech = key.replace(":hit", "")
                report.technique_hits[tech] = count
                report.notable_hits        += count
            elif ":miss" in key:
                tech = key.replace(":miss", "")
                report.technique_misses[tech] = count
            elif key == "headers_built":
                report.total_probes += count
        return report

    def summary_text(self) -> str:
        r = self.build_report()
        lines = [
            "── Evasion Metrics ─────────────────────────────────",
            f"  Total probes      : {r.total_probes}",
            f"  Notable hits      : {r.notable_hits}",
            f"  Hit rate          : {r.hit_rate:.1%}",
            f"  WAF detections    : {r.waf_detections}",
        ]
        if r.top_techniques:
            lines.append("  Top techniques    :")
            for tech, score in r.top_techniques[:5]:
                lines.append(f"    {tech:<40}  score={score:.3f}")
        lines.append("─" * 52)
        return "\n".join(lines)
