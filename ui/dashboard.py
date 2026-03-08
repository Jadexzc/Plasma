"""
ui/dashboard.py
────────────────
Dashboard data layer — transforms ScanContext/Finding objects into
structured dicts for the REST API and the UI frontend.

All serialisation for the dashboard lives here, keeping server.py clean.
"""

from __future__ import annotations

from core.models import ScanContext, Finding, Severity


def scan_summary(ctx: ScanContext) -> dict:
    """Return a complete dashboard summary for one scan."""
    by_sev: dict[str, list] = {s.value: [] for s in Severity}
    for f in ctx.findings:
        by_sev[f.severity.value].append({
            "id":        f.id,
            "title":     f.title,
            "vuln_type": f.vuln_type.value,
            "url":       f.endpoint.url if f.endpoint else "",
        })

    return {
        **ctx.to_summary_dict(),
        "findings_by_severity": by_sev,
        "recent_log":  list(ctx.history)[-20:],
        "endpoints":   len(ctx.endpoints),
    }


def finding_detail(f: Finding) -> dict:
    """Return full detail for one finding (used in the findings drawer)."""
    return {
        **f.to_dict(),
        "remediation": f.remediation,
        "evidence": {
            "request_url":     f.evidence.request_url,
            "request_method":  f.evidence.request_method,
            "request_body":    f.evidence.request_body,
            "payload_used":    f.evidence.payload_used,
            "matched_pattern": f.evidence.matched_pattern,
            "response_status": f.evidence.response_status,
            "response_body":   f.evidence.response_body[:1000],
            "notes":           f.evidence.notes,
        },
    }
