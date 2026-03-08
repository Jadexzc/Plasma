"""
reporting/report_builder.py
────────────────────────────
Security report generation.

Two builders:
  ReportBuilder            — original CSRF-only Markdown builder (backward compat)
  MultiFormatReportBuilder — full multi-vulnerability builder (Markdown, HTML, PDF)

The public generate() method assembles and saves the report.
A content-hash guard prevents writing duplicate files with identical content.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime

log = logging.getLogger(__name__)

# ── Legacy imports (backward compat) ─────────────────────────────────────────
# These are only needed by the v2 ReportBuilder class.  Guard them so that a
# missing or broken legacy module does not prevent MultiFormatReportBuilder
# from loading in a pure-v3 deployment.
try:
    from core.cookie_analyzer     import CookieAnalysisResult
    from core.endpoint_classifier import ClassifiedEndpoint
    from core.risk_engine         import ScoredEndpoint, classify_score, ScoreBreakdown
    from core.samesite_model      import SameSiteEvaluation
    from core.token_analyzer      import TokenAnalysisResult
    _LEGACY_AVAILABLE = True
except ImportError:
    _LEGACY_AVAILABLE = False
    CookieAnalysisResult = ClassifiedEndpoint = ScoredEndpoint = None    # type: ignore
    classify_score = ScoreBreakdown = SameSiteEvaluation = TokenAnalysisResult = None  # type: ignore


class ReportBuilder:
    """
    Original CSRF-only Markdown report builder.

    Kept for backward compatibility with the legacy pipeline.
    For full multi-vulnerability scans, use MultiFormatReportBuilder below.

    Usage:
        builder = ReportBuilder(output_dir="reports")
        path    = builder.generate(
            target, scored_endpoints, cookie_results, token_results,
            samesite, poc_report, output_file
        )
    """

    WIDTH = 80

    def __init__(self, output_dir: str = "reports", verbose: bool = False) -> None:
        self.output_dir = output_dir
        self.verbose    = verbose
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        target:           str,
        scored_endpoints: list[ScoredEndpoint],
        cookie_results:   list[CookieAnalysisResult],
        token_results:    list[TokenAnalysisResult],
        samesite:         SameSiteEvaluation,
        poc_report=None,
        output_file:      str | None = None,
    ) -> str:
        """Generate and save the CSRF-only Markdown report. Returns file path."""
        from config import TOOL_NAME, TOOL_VERSION, DISCLAIMER

        ts       = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        slug     = target.replace("://", "_").replace("/", "_").replace(":", "_")[:40]
        filename  = output_file or f"csrfguard_report_{slug}.md"
        filepath  = os.path.join(self.output_dir, filename)

        lines = [
            f"# {TOOL_NAME} v{TOOL_VERSION} — CSRF Security Report\n\n",
            f"**Target:** {target}  \n",
            f"**Generated:** {ts}  \n",
            f"> ⚠ {DISCLAIMER}\n\n---\n\n",
        ]

        lines += [self._header(target, ts, self._overall_risk(scored_endpoints, samesite))]
        lines += [self._executive_summary(scored_endpoints, cookie_results, token_results, samesite)]
        lines += [self._endpoint_findings(scored_endpoints)]
        if scored_endpoints:
            lines += [self._endpoint_detail(e) for e in scored_endpoints]
        lines += [self._cookie_analysis(cookie_results)]
        lines += [self._token_analysis(token_results)]
        lines += [self._file_upload_risk(scored_endpoints)]
        lines += [self._score_breakdown(scored_endpoints)]
        lines += [self._remediation(scored_endpoints, token_results, samesite)]
        if poc_report:
            lines += [self._poc_inventory(poc_report)]
        lines += [self._references(ts)]

        content = "".join(lines)
        return _write_deduped(filepath, content)

    # ── Section renderers ─────────────────────────────────────────────────────

    def _header(self, target: str, ts: str, risk: str) -> str:
        from core.risk_engine import classify_score
        from config import TOOL_NAME, TOOL_VERSION
        return (
            f"## Overview\n\n"
            f"| Field | Value |\n|---|---|\n"
            f"| **Tool** | {TOOL_NAME} v{TOOL_VERSION} |\n"
            f"| **Target** | `{target}` |\n"
            f"| **Timestamp** | {ts} |\n"
            f"| **Overall Risk** | **{risk}** |\n\n"
        )

    def _toc(self) -> str:
        return (
            "## Table of Contents\n\n"
            "1. [Overview](#overview)\n"
            "2. [Executive Summary](#executive-summary)\n"
            "3. [Endpoint Risk Findings](#endpoint-risk-findings)\n"
            "4. [Cookie Security Analysis](#cookie-security-analysis)\n"
            "5. [CSRF Token Analysis](#csrf-token-analysis)\n"
            "6. [File Upload Risk](#file-upload-risk)\n"
            "7. [Score Breakdown](#score-breakdown)\n"
            "8. [Remediation Priority](#remediation-priority)\n"
            "9. [PoC File Inventory](#poc-file-inventory)\n"
            "10. [References](#references)\n\n"
        )

    def _executive_summary(
        self,
        scored:  list[ScoredEndpoint],
        cookies: list[CookieAnalysisResult],
        tokens:  list[TokenAnalysisResult],
        ss:      SameSiteEvaluation,
    ) -> str:
        total_ep    = len(scored)
        high_risk   = sum(1 for e in scored if e.classification in ("Critical", "High"))
        missing_tok = sum(1 for t in tokens if not t.has_token)
        weak_tok    = sum(1 for t in tokens if t.has_token and t.strength in ("Weak", "Absent"))
        no_ss       = ss.unprotected_cookie_count
        upload_ep   = sum(1 for e in scored if e.endpoint.has_file_upload)
        poc_count   = 0

        lines = [
            "## Executive Summary\n\n",
            "| Metric | Value |\n|---|:---:|\n",
            f"| State-changing endpoints | {total_ep} |\n",
            f"| High / Critical endpoints | {high_risk} |\n",
            f"| Endpoints missing CSRF token | {missing_tok} |\n",
            f"| Endpoints with weak token | {weak_tok} |\n",
            f"| Cookies without SameSite | {no_ss} |\n",
            f"| File upload endpoints | {upload_ep} |\n",
            f"| PoC files generated | {poc_count} |\n\n",
        ]
        if ss.findings:
            lines.append("**SameSite Findings:**\n\n")
            for f in ss.findings:
                lines.append(f"- **{f.severity}** — {f.title}: {f.detail}\n")
            lines.append("\n")
        return "".join(lines)

    def _endpoint_findings(self, scored: list[ScoredEndpoint]) -> str:
        if not scored:
            return "## Endpoint Risk Findings\n\n_No state-changing endpoints found._\n\n"
        lines = [
            "## Endpoint Risk Findings\n\n",
            "| Method | URL | Score | Risk | CSRF Token |\n|---|---|:---:|---|---|\n",
        ]
        for e in scored:
            lines.append(
                f"| `{e.method}` | `{e.url}` | {e.score} | {e.classification} "
                f"| {'❌ Absent' if not e.endpoint.csrf_token_field else '⚠️ Present'} |\n"
            )
        return "".join(lines) + "\n"

    def _endpoint_detail(self, e: ScoredEndpoint) -> str:
        token  = f"`{e.endpoint.csrf_token_field}`" if e.endpoint.csrf_token_field \
                 else "❌ Not found"
        return (
            f"### `{e.method}` {e.url}\n\n"
            f"- **Risk Score:** {e.score}  **Classification:** {e.classification}\n"
            f"- **Encoding:** `{e.endpoint.enctype}`\n"
            f"- **CSRF Token Field:** {token}\n"
            f"- **File Upload:** {'Yes' if e.endpoint.has_file_upload else 'No'}\n\n"
        )

    def _cookie_analysis(self, cookies: list[CookieAnalysisResult]) -> str:
        if not cookies:
            return "## Cookie Security Analysis\n\n_No cookies detected._\n\n"
        lines = [
            "## Cookie Security Analysis\n\n",
            "| Cookie | Secure | HttpOnly | SameSite | Session | Risk |\n"
            "|---|:---:|:---:|---|:---:|---|\n",
        ]
        for c in cookies:
            ss = c.same_site or "❌ None"
            lines.append(
                f"| `{c.name}` | {'✅' if c.is_secure else '❌'} "
                f"| {'✅' if c.is_http_only else '❌'} "
                f"| {ss} | {'✅' if c.is_session_candidate else '—'} "
                f"| {c.risk_level} |\n"
            )
        return "".join(lines) + "\n"

    def _token_analysis(self, tokens: list[TokenAnalysisResult]) -> str:
        if not tokens:
            return "## CSRF Token Analysis\n\n_No state-changing endpoints found._\n\n"
        lines = [
            "## CSRF Token Analysis\n\n",
            "| Endpoint | Token Field | Length | Entropy | Strength | Reused |\n"
            "|---|---|:---:|:---:|---|:---:|\n",
        ]
        for t in tokens:
            field  = f"`{t.token_field}`" if t.token_field else "❌ Absent"
            reused = "⚠️ Yes" if t.is_reused else "No"
            lines.append(
                f"| `{t.endpoint_url}` | {field} "
                f"| {t.token_length or '—'} | {t.entropy_display} "
                f"| {t.strength} | {reused} |\n"
            )
        return "".join(lines) + "\n"

    def _file_upload_risk(self, scored: list[ScoredEndpoint]) -> str:
        uploads = [e for e in scored if e.endpoint.has_file_upload]
        if not uploads:
            return "## File Upload Risk\n\n_No file upload endpoints detected._\n\n"
        lines = [
            "## File Upload Risk\n\n",
            "| Method | URL | Enctype | CSRF Token |\n|---|---|---|---|\n",
        ]
        for e in uploads:
            lines.append(
                f"| `{e.method}` | `{e.url}` | `{e.endpoint.enctype}` "
                f"| {e.endpoint.csrf_token_field or '❌ None'} |\n"
            )
        lines.append(
            "\n> Multipart PoC files using `Fetch + FormData + Blob` were generated "
            "for each unprotected file upload endpoint.\n\n"
        )
        return "".join(lines)

    def _score_breakdown(self, scored: list[ScoredEndpoint]) -> str:
        hot = [e for e in scored if e.classification in ("Critical", "High")]
        if not hot:
            return "## Score Breakdown\n\n_No high-risk endpoints._\n\n"
        lines = ["## Score Breakdown\n\n"]
        for e in hot:
            lines.append(f"### `{e.method}` {e.url}  (Score: {e.score})\n\n")
            lines.append("| Factor | Weight | Detail |\n|---|:---:|---|\n")
            for bd in e.breakdown:
                lines.append(f"| {bd.factor} | +{bd.weight} | {bd.detail} |\n")
            lines.append("\n")
        return "".join(lines)

    def _remediation(
        self,
        scored:  list[ScoredEndpoint],
        tokens:  list[TokenAnalysisResult],
        ss:      SameSiteEvaluation,
    ) -> str:
        from config import (
            STRONG_TOKEN_LENGTH, STRONG_TOKEN_ENTROPY,
            MIN_TOKEN_LENGTH, MIN_TOKEN_ENTROPY,
        )
        lines = ["## Remediation Priority\n\n"]

        missing = [t for t in tokens if not t.has_token]
        if missing:
            lines += [
                "### 🔴 Critical — Add Synchronizer Tokens\n\n",
                "The following endpoints are missing CSRF tokens entirely:\n\n",
                "".join(f"- `{t.endpoint_url}`\n" for t in missing),
                "\n**Fix:** Add a cryptographically random token (≥128 bits) as a hidden "
                "field in every form. Validate on the server before processing.\n\n",
            ]

        weak = [t for t in tokens if t.has_token and t.strength in ("Weak", "Absent")]
        if weak:
            lines += [
                "### 🟠 High — Strengthen Weak Tokens\n\n",
                f"Tokens must be ≥{STRONG_TOKEN_LENGTH} chars and "
                f"≥{STRONG_TOKEN_ENTROPY} bits/char entropy.\n\n",
            ]

        if ss.unprotected_cookie_count:
            lines += [
                "### 🟡 Medium — Set SameSite Cookie Attribute\n\n",
                "Add `SameSite=Lax` (minimum) or `SameSite=Strict` to all session cookies.\n\n",
            ]

        uploads = [e for e in scored if e.endpoint.has_file_upload]
        if uploads:
            lines += [
                "### 🟡 Medium — Secure File Upload Endpoints\n\n",
                "Add CSRF tokens, enforce file-type allowlist, size caps, "
                "and store outside web root.\n\n",
            ]

        if not (missing or weak or ss.unprotected_cookie_count or uploads):
            lines.append("_No critical remediations required at this time._\n\n")

        return "".join(lines)

    def _poc_inventory(self, poc) -> str:
        if poc is None or not hasattr(poc, "total"):
            return ""
        if poc.total == 0:
            return "## PoC File Inventory\n\n_No PoC files generated. Pass `--poc` to enable._\n\n"
        lines = [
            "## PoC File Inventory\n\n",
            f"**{poc.total} PoC file(s)** generated in `{poc.output_dir}/`\n\n",
            "| Method | File | Type |\n|---|---|---|\n",
        ]
        lines += [
            f"| `{p.method}` | `{p.filename}` | {p.poc_type} |\n"
            for p in poc.generated
        ]
        return "".join(lines) + "\n"

    def _references(self, ts: str) -> str:
        return (
            "## References\n\n"
            "- [OWASP CSRF Prevention Cheat Sheet]"
            "(https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)\n"
            "- [OWASP Testing Guide — WSTG-SESS-05]"
            "(https://owasp.org/www-project-web-security-testing-guide/)\n"
            "- [File Upload Cheat Sheet]"
            "(https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)\n"
            f"\n---\n_Generated {ts}_\n"
        )

    @staticmethod
    def _overall_risk(scored: list[ScoredEndpoint], samesite: SameSiteEvaluation) -> str:
        if not scored:
            return samesite.overall_samesite_risk
        return scored[0].classification


# ── Helper: deduplicated file writer ──────────────────────────────────────────

def _write_deduped(filepath: str, content: str) -> str:
    """
    Write content to filepath only if the file doesn't already exist with
    the identical content (prevents generating duplicate reports).
    Returns the path.
    """
    new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if os.path.exists(filepath):
        existing_hash = hashlib.sha256(
            open(filepath, encoding="utf-8").read().encode("utf-8")
        ).hexdigest()
        if existing_hash == new_hash:
            log.debug("Report unchanged — skipping write: %s", filepath)
            return filepath
    open(filepath, "w", encoding="utf-8").write(content)
    return filepath


# ── Multi-format builder ──────────────────────────────────────────────────────

class MultiFormatReportBuilder:
    """
    Generates security reports in Markdown, HTML, and PDF formats
    from a ScanContext produced by ScanManager.

    Usage:
        builder = MultiFormatReportBuilder(output_dir="reports")
        paths = builder.generate(context, formats=["html"])

    Deduplication: identical reports are never overwritten (content-hash guard).
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        context,
        formats: list[str] | None = None,
    ) -> dict[str, str]:
        """
        Generate reports in the requested formats only.

        Args:
            context: completed ScanContext
            formats: list of "markdown", "html", "pdf"
                     (default: ["html"] — a single, useful report)

        Returns:
            dict of {format_name: output_path}
        """
        formats = formats or ["html"]
        # Normalise and deduplicate format list
        formats = list(dict.fromkeys(f.lower() for f in formats))
        paths   = {}

        md_content = self._render_markdown(context)

        if "markdown" in formats:
            md_path = self._write(f"report_{context.scan_id[:8]}.md", md_content)
            paths["markdown"] = md_path

        if "html" in formats:
            html_content = self._render_html(context, md_content)
            html_path    = self._write(f"report_{context.scan_id[:8]}.html", html_content)
            paths["html"] = html_path

        if "pdf" in formats:
            html_path_for_pdf = paths.get("html") or ""
            if not html_path_for_pdf:
                # Need html temporarily
                html_content = self._render_html(context, md_content)
                html_path_for_pdf = self._write_path(f"_tmp_{context.scan_id[:8]}.html")
                open(html_path_for_pdf, "w", encoding="utf-8").write(html_content)
            pdf_path = self._render_pdf(context, html_path_for_pdf)
            if pdf_path:
                paths["pdf"] = pdf_path
            # Clean up temp
            if html_path_for_pdf.startswith(os.path.join(self.output_dir, "_tmp_")):
                try:
                    os.remove(html_path_for_pdf)
                except OSError:
                    pass

        log.info("Reports generated: %s", paths)
        return paths

    def _render_markdown(self, context) -> str:
        """Build a full Markdown report from a ScanContext."""
        from core.models import Severity
        from config import TOOL_NAME, TOOL_VERSION, DISCLAIMER

        duration_str = "N/A"
        if getattr(context, "start_time", None) and getattr(context, "end_time", None):
            dur = (context.end_time - context.start_time).total_seconds()
            duration_str = f"{dur:.1f}s"
        elif getattr(context, "start_time", None):
            from datetime import datetime
            dur = (datetime.now() - context.start_time).total_seconds()
            duration_str = f"{dur:.1f}s (scan in progress)"

        lines = [
            f"# {TOOL_NAME} v{TOOL_VERSION} — Security Report\n",
            f"\n**Target:** {context.target_url}  \n",
            f"**Scan ID:** {context.scan_id}  \n",
            f"**Duration:** {duration_str}  \n",
            f"**Profile:** {getattr(getattr(context, 'settings', None), 'profile', 'default')}  \n",
            f"**Profile:** {context.settings.profile}  \n",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n",
            f"\n> ⚠ {DISCLAIMER}\n",
            "\n---\n",
            "\n## Executive Summary\n\n",
        ]

        breakdown = context.finding_count_by_severity
        total     = len(context.findings)
        highest   = context.highest_severity

        lines.append(
            f"**{total} finding(s)** across {len(context.endpoints)} endpoint(s).  \n"
            f"Highest severity: **{highest.value if highest else 'None'}**\n\n"
        )
        lines.append(
            "| Severity | Count |\n|---|:---:|\n" +
            "".join(f"| {sev} | {breakdown.get(sev, 0)} |\n"
                    for sev in ["Critical", "High", "Medium", "Low", "Info"])
        )

        lines.append("\n---\n\n## Findings Summary\n\n")
        if not context.findings:
            lines.append("_No findings detected._\n")
        else:
            lines.append("| Severity | Type | Title | Endpoint |\n|---|---|---|---|\n")
            for f in context.findings:
                url = f.endpoint.url if f.endpoint else "N/A"
                lines.append(
                    f"| {f.severity.value} | {f.vuln_type.value} "
                    f"| {f.title} | `{url}` |\n"
                )

        lines.append("\n---\n\n## Detailed Findings\n")
        for f in context.findings:
            lines.append(f"\n### [{f.severity.value}] {f.title}\n\n")
            lines.append(f"**Type:** {f.vuln_type.value}  \n")
            lines.append(f"**Confidence:** {f.confidence.value}  \n")
            lines.append(f"**OWASP:** {f.owasp_id or 'N/A'}  **CWE:** {f.cwe_id or 'N/A'}\n\n")
            lines.append(f"{f.description}\n\n")
            if f.evidence and f.evidence.payload_used:
                lines.append(f"**Payload:** `{f.evidence.payload_used}`  \n")
            if f.evidence and f.evidence.matched_pattern:
                lines.append(f"**Matched:** `{f.evidence.matched_pattern}`\n\n")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}\n")

        # Fuzzing summary section (only present if fuzzer was active)
        if getattr(context.settings, "enable_fuzzer", False):
            lines.append(self._fuzz_summary_md(context))

        return "".join(lines)

    # ── Fuzz summary section ───────────────────────────────────────────────────

    @staticmethod
    def _fuzz_summary_md(context) -> str:
        """Build a Markdown Fuzzing Summary section from scan context."""
        from collections import Counter
        from core.models import VulnType

        fuzz_findings = [f for f in context.findings if "fuzz" in (f.detector or "")]
        chain_findings = [f for f in fuzz_findings if "chain" in str(getattr(f, "tags", []))]
        oob_findings   = [f for f in fuzz_findings if "oob" in (f.evidence.notes or "").lower()]

        # Technique frequency from evidence notes
        technique_counts: Counter = Counter()
        waf_names: Counter = Counter()
        for f in fuzz_findings:
            notes = f.evidence.notes or ""
            for part in notes.split():
                if part.startswith("technique="):
                    technique_counts[part[10:].split(":")[0]] += 1
                if part.startswith("waf=") and part[4:] != "none":
                    waf_names[part[4:]] += 1

        # Severity heatmap for fuzz findings
        sev_counts: Counter = Counter(f.severity.value for f in fuzz_findings)

        lines = [
            "\n---\n",
            "\n## Fuzzing Summary\n\n",
            f"| Metric | Value |\n|---|:---:|\n",
            f"| Fuzz probes generated | — |\n",
            f"| Fuzz findings | {len(fuzz_findings)} |\n",
            f"| Exploit chains identified | {len(chain_findings)} |\n",
            f"| OOB-confirmed findings | {len(oob_findings)} |\n",
            f"| WAF detections | {sum(waf_names.values())} |\n\n",
        ]

        # Severity heatmap
        if sev_counts:
            lines.append("### Finding Severity Heatmap\n\n")
            lines.append("| Severity | Count | Bar |\n|---|:---:|---|\n")
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                count = sev_counts.get(sev, 0)
                bar   = "█" * min(count, 20)
                lines.append(f"| {sev} | {count} | {bar} |\n")
            lines.append("\n")

        # Top techniques
        if technique_counts:
            lines.append("### Top Techniques\n\n")
            lines.append("| Technique | Findings |\n|---|:---:|\n")
            for tech, cnt in technique_counts.most_common(10):
                lines.append(f"| `{tech}` | {cnt} |\n")
            lines.append("\n")

        # WAF detections
        if waf_names:
            lines.append("### WAF Detections\n\n")
            lines.append("| WAF | Count |\n|---|:---:|\n")
            for waf, cnt in waf_names.most_common():
                lines.append(f"| {waf} | {cnt} |\n")
            lines.append("\n")

        # Exploit chains
        if chain_findings:
            lines.append("### Exploit Chains\n\n")
            for f in chain_findings:
                lines.append(f"- **{f.title}** — {f.description[:120]}...\n")
            lines.append("\n")

        return "".join(lines)

    def _render_html(self, context, md_content: str) -> str:
        duration_str = "N/A"
        if getattr(context, "start_time", None) and getattr(context, "end_time", None):
            dur = (context.end_time - context.start_time).total_seconds()
            duration_str = f"{dur:.1f}s"
        """Render the HTML report using the template file."""
        tpl_path = os.path.join(
            os.path.dirname(__file__), "..", "templates", "report_template.html"
        )
        try:
            template = open(tpl_path, encoding="utf-8").read()
        except FileNotFoundError:
            template = "<html><body>{{ FINDINGS_TABLE }}</body></html>"

        breakdown = context.finding_count_by_severity
        total     = len(context.findings)

        exec_summary = (
            f"<p>Found <strong>{total} finding(s)</strong> across "
            f"<strong>{len(context.endpoints)}</strong> endpoints.</p>"
            "<table><tr><th>Severity</th><th>Count</th></tr>"
            + "".join(
                f"<tr class='{s}'><td>{s}</td><td>{breakdown.get(s, 0)}</td></tr>"
                for s in ["Critical", "High", "Medium", "Low", "Info"]
            )
            + "</table>"
        )

        def _esc(s: str) -> str:
            return (s.replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))

        findings_table = (
            "<table><tr><th>Severity</th><th>Type</th><th>Title</th><th>URL</th></tr>"
            + "".join(
                f"<tr class='{f.severity.value}'>"
                f"<td><span class='badge {f.severity.value}'>{f.severity.value}</span></td>"
                f"<td>{_esc(f.vuln_type.value)}</td>"
                f"<td>{_esc(f.title)}</td>"
                f"<td><code>{_esc(f.endpoint.url if f.endpoint else '')}</code></td>"
                "</tr>"
                for f in context.findings
            )
            + "</table>"
        )

        findings_detail = "".join(
            f"<div class='finding-detail'>"
            f"<h3 class='{f.severity.value}'>[{f.severity.value}] {_esc(f.title)}</h3>"
            f"<p><b>Type:</b> {_esc(f.vuln_type.value)} &nbsp;|&nbsp; "
            f"<b>Confidence:</b> {_esc(f.confidence.value)} &nbsp;|&nbsp; "
            f"<b>OWASP:</b> {_esc(f.owasp_id or 'N/A')} &nbsp;|&nbsp; "
            f"<b>CWE:</b> {_esc(f.cwe_id or 'N/A')}</p>"
            f"<p>{_esc(f.description)}</p>"
            f"<p><b>Remediation:</b> {_esc(f.remediation or '')}</p>"
            f"</div>"
            for f in context.findings
        )

        return (
            template
            .replace("{{ TARGET }}", _esc(context.target_url))
            .replace("{{ TIMESTAMP }}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            .replace("{{ PROFILE }}", _esc(context.settings.profile))
            .replace("{{ SCAN_ID }}", context.scan_id)
            .replace("{{ EXEC_SUMMARY }}", exec_summary)
            .replace("{{ FINDINGS_TABLE }}", findings_table)
            .replace("{{ FINDINGS_DETAIL }}", findings_detail)
            .replace("{{ REMEDIATION_MATRIX }}",
                     "<p><em>See the Markdown report for the full priority matrix.</em></p>")
            .replace("{{ POC_INVENTORY }}",
                     "<p><em>PoC files in poc_output/ (if --poc was used)</em></p>")
            .replace("{{ DISCLAIMER }}", "For Authorized Testing Only")
        )

    def _render_pdf(self, context, html_path: str) -> str | None:
        """Convert HTML report to PDF. Returns path or None if no library available."""
        pdf_path = self._write_path(f"report_{context.scan_id[:8]}.pdf")

        try:
            import weasyprint
            if html_path and os.path.exists(html_path):
                weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            else:
                weasyprint.HTML(string=self._render_html(context, "")).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            pass

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4
            c = canvas.Canvas(pdf_path, pagesize=A4)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 800, "Plasma Security Report")
            c.setFont("Helvetica", 11)
            c.drawString(50, 780, f"Target: {context.target_url}")
            c.drawString(50, 764, f"Findings: {len(context.findings)}")
            y = 740
            for f in context.findings[:30]:
                c.drawString(50, y, f"[{f.severity.value}] {f.title[:80]}")
                y -= 16
                if y < 60:
                    c.showPage()
                    y = 800
            c.save()
            return pdf_path
        except ImportError:
            pass

        log.warning("No PDF library (weasyprint/reportlab) — skipping PDF generation")
        return None

    def _write(self, filename: str, content: str) -> str:
        path = self._write_path(filename)
        return _write_deduped(path, content)

    def _write_path(self, filename: str) -> str:
        return os.path.join(self.output_dir, filename)
