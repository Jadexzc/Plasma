"""
core/attack_surface.py — Plasma v3
────────────────────────────────────
Attack surface mapper.

Aggregates endpoint data from all discovery sources and produces a
prioritised, deduplicated view of what should be tested.

Sources
───────
  1. Static crawler         (BFS HTML parser)
  2. Browser crawler        (Playwright JS execution)
  3. JS endpoint extraction (inline script URL mining)
  4. Subdomain discovery    (DNS brute-force)
  5. Parameter discovery    (hidden param brute-force)
  6. Nuclei templates       (path-based probing)
  7. User-supplied endpoints (--url, --batch, --replay)

Output
──────
  • Prioritised EndpointQueue ready for the detector pipeline
  • AttackSurfaceSummary with per-source counts and coverage stats
  • Technology fingerprints (affects which detectors run)
  • Discovered technologies feed WAF detection and payload selection

Usage
─────
    mapper = AttackSurfaceMapper(context)
    surface = await mapper.build()

    # surface.queue     → prioritised EndpointQueue
    # surface.summary   → dict of source → endpoint counts
    # surface.techs     → list[TechDetection]
    # surface.waf       → detected WAF name or None
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from core.endpoint_queue import EndpointQueue, Priority
from core.models import Endpoint, ScanContext

log = logging.getLogger(__name__)


@dataclass
class AttackSurfaceSummary:
    """Per-source endpoint count breakdown and overall coverage stats."""
    source_counts:   dict[str, int] = field(default_factory=dict)
    total_unique:    int             = 0
    total_deduped:   int             = 0
    state_changing:  int             = 0   # POST/PUT/DELETE/PATCH endpoints
    file_upload:     int             = 0
    api_endpoints:   int             = 0   # tagged 'xhr' or 'js-extracted'
    waf_detected:    Optional[str]   = None
    technologies:    list[str]       = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sources":          self.source_counts,
            "total_unique":     self.total_unique,
            "total_deduped":    self.total_deduped,
            "state_changing":   self.state_changing,
            "file_upload":      self.file_upload,
            "api_endpoints":    self.api_endpoints,
            "waf":              self.waf_detected,
            "technologies":     self.technologies,
        }


class AttackSurface:
    """
    Fully-built attack surface ready for scanning.

    Attributes
    ──────────
    queue    : EndpointQueue, priority-ordered and deduplicated
    summary  : AttackSurfaceSummary
    techs    : List of detected technology names
    waf      : Detected WAF name, or None
    """

    def __init__(
        self,
        queue:   EndpointQueue,
        summary: AttackSurfaceSummary,
    ) -> None:
        self.queue   = queue
        self.summary = summary
        self.techs:  list[str]       = summary.technologies
        self.waf:    Optional[str]   = summary.waf_detected

    def log_summary(self, logger=None) -> None:
        """Print a human-readable summary to the scan log."""
        l = logger or log
        s = self.summary
        l.info(
            "[attack_surface] %d unique endpoints  "
            "(%d state-changing, %d file-upload, %d API/XHR)  "
            "sources: %s",
            s.total_unique, s.state_changing, s.file_upload, s.api_endpoints,
            ", ".join(f"{src}={n}" for src, n in s.source_counts.items()),
        )
        if s.waf_detected:
            l.info("[attack_surface] WAF detected: %s", s.waf_detected)
        if s.technologies:
            l.info("[attack_surface] Technologies: %s", ", ".join(s.technologies))


class AttackSurfaceMapper:
    """
    Aggregates all endpoint sources into a single prioritised queue.

    The mapper runs after Phase 1 (crawl) and Phase 1.5 (recon) have
    completed, consuming whatever was discovered and adding context-aware
    priority scoring before handing off to the detector pipeline.
    """

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    async def build(self) -> AttackSurface:
        """
        Build the attack surface from all available context data.

        This is called at the start of Phase 3 (detect), after crawl
        and recon phases have populated context.endpoints and related fields.
        """
        queue   = EndpointQueue()
        summary = AttackSurfaceSummary()

        # ── Source 1: Already-discovered endpoints in context ─────────────────
        raw_eps = list(self.context.endpoints or [])
        for ep in raw_eps:
            prio = self._priority_for(ep)
            src  = self._source_label(ep)
            queue.push(ep, priority=prio, source=src)
            summary.source_counts[src] = summary.source_counts.get(src, 0) + 1

        # ── Source 2: Browser crawl result (if present) ───────────────────────
        browser_result = getattr(self.context, "_browser_result", None)
        if browser_result:
            added = queue.push_browser_result(browser_result)
            if added:
                summary.source_counts["browser"] = added

            # Surface storage findings as context metadata
            if browser_result.storage:
                self.context._browser_storage = browser_result.storage
                n_stores = sum(
                    len(v.get("localStorage", {})) + len(v.get("sessionStorage", {}))
                    for v in browser_result.storage.values()
                )
                if n_stores:
                    self.context.log(f"  [surface] {n_stores} localStorage/sessionStorage entries captured")

            # Surface console output (may contain API keys, debug info)
            if browser_result.console:
                self.context._browser_console = browser_result.console
                log.debug("[surface] %d console messages captured", len(browser_result.console))

        # ── Source 3: Subdomain endpoints ─────────────────────────────────────
        for sub in getattr(self.context, "subdomains", []):
            ep = Endpoint(url=sub, method="GET", tags=["subdomain"])
            queue.push(ep, priority=Priority.LOW, source="subdomain")
            summary.source_counts["subdomain"] = \
                summary.source_counts.get("subdomain", 0) + 1

        # ── Metadata aggregation ──────────────────────────────────────────────
        qs = queue.stats()
        summary.total_unique   = qs["queued"]
        summary.total_deduped  = qs["dedup_hits"]

        # Count endpoint types
        for ep in queue:
            if ep.is_state_changing:
                summary.state_changing += 1
            if ep.has_file_upload:
                summary.file_upload += 1
            if any(t in (ep.tags or []) for t in ("xhr", "js-extracted", "api")):
                summary.api_endpoints += 1

        # Technology names from context
        techs = getattr(self.context, "technologies", [])
        summary.technologies = [t.name for t in techs] if techs else []

        # WAF detection from evasion module if available
        summary.waf_detected = await self._detect_waf()

        surface = AttackSurface(queue=queue, summary=summary)
        surface.log_summary(logger=log)

        # Persist on context for access by later phases
        self.context._attack_surface = surface
        return surface

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _priority_for(self, ep: Endpoint) -> Priority:
        """Assign priority based on endpoint characteristics."""
        tags = set(ep.tags or [])

        # Admin / auth endpoints always highest priority
        if any(kw in ep.url.lower() for kw in
               ("/admin", "/login", "/auth", "/oauth", "/api/v", "/graphql",
                "/upload", "/file", "/import", "/export", "/debug")):
            return Priority.CRITICAL

        # State-changing operations
        if ep.is_state_changing:
            return Priority.HIGH

        # File upload
        if ep.has_file_upload:
            return Priority.HIGH

        # JS-discovered or XHR endpoints
        if tags & {"xhr", "js-extracted", "browser", "api"}:
            return Priority.NORMAL

        # Endpoints with parameters
        if ep.parameters:
            return Priority.NORMAL

        # Subdomains, no-parameter pages
        if "subdomain" in tags:
            return Priority.LOW

        return Priority.NORMAL

    def _source_label(self, ep: Endpoint) -> str:
        """Return the most descriptive source label for an endpoint."""
        tags = set(ep.tags or [])
        if "subdomain" in tags:     return "subdomain"
        if "js-extracted" in tags:  return "js"
        if "browser" in tags:       return "browser"
        if "xhr" in tags:           return "xhr"
        if "websocket" in tags:     return "websocket"
        return "crawler"

    async def _detect_waf(self) -> Optional[str]:
        """Probe for WAF presence using known fingerprints."""
        try:
            from core.evasion.waf_detector import WAFDetector
            detector = WAFDetector()
            return await asyncio.get_running_loop().run_in_executor(
                None, lambda: detector.detect(self.context.target_url)
            )
        except Exception as exc:
            log.debug("[surface] WAF detection failed: %s", exc)
        return None
