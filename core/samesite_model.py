"""
core/samesite_model.py
───────────────────────
Models real-world CSRF impact of each SameSite cookie policy.

  Strict → never sent cross-site               ✅ full protection
  Lax    → sent on top-level GET only          ⚠️ partial
  None   → always sent (requires Secure)       ❌ no protection
  Absent → browser-dependent                   ⚠️ unreliable
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.cookie_analyzer import CookieAnalysisResult
from core.endpoint_classifier import ClassifiedEndpoint

log = logging.getLogger(__name__)


@dataclass
class SameSiteFinding:
    """One SameSite-related security observation."""
    severity:           str
    title:              str
    detail:             str
    affected_cookies:   list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)

    SEVERITY_COLORS = {
        "Info": "\033[36m", "Low": "\033[32m", "Medium": "\033[33m",
        "High": "\033[31m", "Critical": "\033[35m",
    }

    @property
    def color(self) -> str:
        return self.SEVERITY_COLORS.get(self.severity, "\033[0m")


@dataclass
class SameSiteEvaluation:
    """Aggregated output from the SameSite model."""
    findings:                 list[SameSiteFinding] = field(default_factory=list)
    unprotected_cookie_count: int  = 0
    file_upload_risk:         bool = False
    overall_samesite_risk:    str  = "Low"


class SameSiteModel:
    """
    Generates SameSite findings by cross-referencing:
      - Cookie policies (absent / Lax / None)
      - Endpoint types  (state-changing, file-upload)
    """

    def evaluate(
        self,
        cookie_results: list[CookieAnalysisResult],
        endpoints:      list[ClassifiedEndpoint],
    ) -> SameSiteEvaluation:
        ev         = SameSiteEvaluation()
        state_eps  = [e for e in endpoints if e.is_state_changing]
        upload_eps = [e for e in state_eps  if e.has_file_upload]

        # Finding 1: SameSite absent
        absent = [c for c in cookie_results if c.same_site is None]
        if absent:
            ev.unprotected_cookie_count = len(absent)
            ev.findings.append(SameSiteFinding(
                severity="High",
                title="Cookies Missing SameSite Attribute",
                detail=(
                    f"{len(absent)} cookie(s) have no SameSite attribute. "
                    "Older browsers default to None; modern browsers (Chrome 80+) "
                    "default to Lax, but relying on this is fragile."
                ),
                affected_cookies=[c.name for c in absent],
            ))

        # Finding 2: SameSite=None with state-changing endpoints
        none_cookies = [c for c in cookie_results if c.same_site == "None"]
        if none_cookies and state_eps:
            ev.findings.append(SameSiteFinding(
                severity="Critical",
                title="SameSite=None With State-Changing Endpoints",
                detail=(
                    f"{len(none_cookies)} cookie(s) use SameSite=None — sent on ALL "
                    f"cross-site requests. With {len(state_eps)} state-changing "
                    "endpoint(s) present, a forged request is all an attacker needs."
                ),
                affected_cookies=[c.name for c in none_cookies],
                affected_endpoints=[e.url for e in state_eps[:5]],
            ))

        # Finding 3: SameSite=Lax — limited POST protection
        lax_cookies = [c for c in cookie_results if c.same_site == "Lax"]
        post_eps    = [e for e in state_eps if e.method == "POST"]
        if lax_cookies and post_eps:
            ev.findings.append(SameSiteFinding(
                severity="Medium",
                title="SameSite=Lax Does Not Fully Protect POST Endpoints",
                detail=(
                    "Lax blocks cross-site sub-resource requests but some "
                    "top-level navigation POST scenarios may still send the cookie "
                    "in older browsers."
                ),
                affected_cookies=[c.name for c in lax_cookies],
                affected_endpoints=[e.url for e in post_eps[:3]],
            ))

        # Finding 4: file upload endpoints
        if upload_eps:
            ev.file_upload_risk = True
            ev.findings.append(SameSiteFinding(
                severity="High",
                title="File Upload Endpoints — Elevated CSRF Risk",
                detail=(
                    f"{len(upload_eps)} multipart endpoint(s) detected. "
                    "Multipart CSRF attacks bypass Content-Type checks and require "
                    "explicit token protection regardless of SameSite policy."
                ),
                affected_endpoints=[e.url for e in upload_eps],
            ))

        # Finding 5: no cookies at all
        if not cookie_results:
            ev.findings.append(SameSiteFinding(
                severity="Info",
                title="No Session Cookies Detected",
                detail="Application may use header-based auth (JWT); SameSite analysis does not apply.",
            ))

        ev.overall_samesite_risk = self._overall_risk(ev.findings)
        log.debug("SameSite evaluation: %d findings, risk=%s",
                  len(ev.findings), ev.overall_samesite_risk)
        return ev

    @staticmethod
    def _overall_risk(findings: list[SameSiteFinding]) -> str:
        rank   = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        labels = ["Low", "Low", "Medium", "High", "Critical"]
        return labels[max((rank.get(f.severity, 0) for f in findings), default=0)]
