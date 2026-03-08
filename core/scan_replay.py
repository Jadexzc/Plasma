"""
core/scan_replay.py — WebGuard v3
────────────────────────────────────
Scan persistence and replay system.
Saves completed scan state as JSON; can replay without hitting the target.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, ScanSettings, ScanState, Severity, VulnType,
)

log = logging.getLogger(__name__)


class ScanReplay:
    """
    Save and load scan contexts.

    Usage (save):
        replay = ScanReplay(scan_dir="scans/")
        path = replay.save(context)

    Usage (load/replay):
        ctx = replay.load("scans/scan_20240101.json")
        # ctx.findings, ctx.endpoints etc. fully populated
    """

    def __init__(self, scan_dir: str = "scans") -> None:
        self.scan_dir = scan_dir
        os.makedirs(scan_dir, exist_ok=True)

    def save(self, context: ScanContext) -> str:
        """Serialize and save a ScanContext to JSON. Returns the file path."""
        filename = (
            f"scan_{context.target_url.replace('://', '_').replace('/', '_')}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        path = os.path.join(self.scan_dir, filename)
        data = self._serialise(context)
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.info("Scan saved → %s", path)
        return path

    def load(self, path: str) -> Optional[ScanContext]:
        """Load a previously saved ScanContext from JSON."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return self._deserialise(data)
        except Exception as exc:
            log.error("Failed to load scan from %s: %s", path, exc)
            return None

    def list_scans(self) -> list[dict]:
        """List all saved scans with metadata."""
        scans = []
        for f in sorted(Path(self.scan_dir).glob("scan_*.json")):
            try:
                data = json.loads(f.read_text())
                scans.append({
                    "file":       str(f),
                    "target":     data.get("target_url"),
                    "findings":   len(data.get("findings", [])),
                    "timestamp":  data.get("end_time"),
                    "state":      data.get("state"),
                })
            except Exception:
                pass
        return scans

    # ── Private serialisation ──────────────────────────────────────────────────

    @staticmethod
    def _serialise(ctx: ScanContext) -> dict:
        return {
            "scan_id":    ctx.scan_id,
            "target_url": ctx.target_url,
            "state":      ctx.state.value,
            "start_time": ctx.start_time.isoformat() if ctx.start_time else None,
            "end_time":   ctx.end_time.isoformat() if ctx.end_time else None,
            "history":    list(ctx.history),
            "error":      ctx.error,
            "settings": {
                "profile":  ctx.settings.profile,
                "max_depth": ctx.settings.max_depth,
            },
            "findings": [ScanReplay._serialise_finding(f) for f in ctx.findings],
            "endpoints": [
                {"url": e.url, "method": e.method, "parameters": e.parameters}
                for e in ctx.endpoints
            ],
            "technologies": [
                {"name": t.name, "version": t.version}
                for t in ctx.technologies
            ],
        }

    @staticmethod
    def _serialise_finding(f: Finding) -> dict:
        return {
            "id":          f.id,
            "vuln_type":   f.vuln_type.value,
            "severity":    f.severity.value,
            "confidence":  f.confidence.value,
            "title":       f.title,
            "description": f.description,
            "remediation": f.remediation,
            "detector":    f.detector,
            "tags":        f.tags,
            "owasp_id":    f.owasp_id,
            "cwe_id":      f.cwe_id,
            "cvss_score":  f.cvss_score,
            "timestamp":   f.timestamp.isoformat(),
            "endpoint_url": f.endpoint.url if f.endpoint else "",
            "endpoint_method": f.endpoint.method if f.endpoint else "GET",
            "evidence": {
                "request_url":    f.evidence.request_url,
                "payload_used":   f.evidence.payload_used,
                "matched_pattern": f.evidence.matched_pattern,
                "response_status": f.evidence.response_status,
                "notes":          f.evidence.notes,
            },
        }

    @staticmethod
    def _deserialise(data: dict) -> ScanContext:
        settings = ScanSettings(
            profile=data.get("settings", {}).get("profile", "default")
        )
        ctx = ScanContext(
            target_url=data["target_url"],
            settings=settings,
            state=ScanState(data.get("state", "completed")),
            scan_id=data.get("scan_id", ""),
            history=data.get("history", []),
            error=data.get("error"),
        )
        if data.get("start_time"):
            ctx.start_time = datetime.fromisoformat(data["start_time"])
        if data.get("end_time"):
            ctx.end_time = datetime.fromisoformat(data["end_time"])

        for fd in data.get("findings", []):
            try:
                ep = Endpoint(
                    url=fd.get("endpoint_url", ""),
                    method=fd.get("endpoint_method", "GET"),
                )
                ev_data = fd.get("evidence", {})
                ev = Evidence(
                    request_url=ev_data.get("request_url", ""),
                    payload_used=ev_data.get("payload_used", ""),
                    matched_pattern=ev_data.get("matched_pattern", ""),
                    response_status=ev_data.get("response_status", 0),
                    notes=ev_data.get("notes", ""),
                )
                finding = Finding(
                    id=fd["id"],
                    vuln_type=VulnType(fd["vuln_type"]),
                    severity=Severity(fd["severity"]),
                    confidence=Confidence(fd["confidence"]),
                    title=fd["title"],
                    description=fd["description"],
                    remediation=fd.get("remediation", ""),
                    detector=fd.get("detector", ""),
                    tags=fd.get("tags", []),
                    owasp_id=fd.get("owasp_id", ""),
                    cwe_id=fd.get("cwe_id", ""),
                    cvss_score=fd.get("cvss_score"),
                    endpoint=ep,
                    evidence=ev,
                )
                ctx.findings.append(finding)
            except Exception as exc:
                log.warning("Failed to deserialise finding: %s", exc)

        for ep_data in data.get("endpoints", []):
            ctx.endpoints.append(Endpoint(
                url=ep_data["url"],
                method=ep_data.get("method", "GET"),
                parameters=ep_data.get("parameters", {}),
            ))

        return ctx
