"""
reporting/formatter.py
───────────────────────
CLI output formatter for CSRFGuard.

All terminal print statements in the tool flow through this module.
Using a dedicated formatter keeps main.py and all analysis modules
free of any print() calls, making them independently testable.

ANSI colours are defined in the inner C class so any module can do:
    from reporting.formatter import C
    print(f"{C.RED}error{C.RESET}")
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from core.cookie_analyzer import CookieAnalysisResult
from core.samesite_model import SameSiteFinding, SameSiteEvaluation
from core.token_analyzer import TokenAnalysisResult
from core.risk_engine import ScoredEndpoint

if TYPE_CHECKING:
    from modules.poc_generator import PoCReport


# ─── ANSI Colour Palette ──────────────────────────────────────────────────────

class C:
    """Minimal ANSI colour helpers — import anywhere that needs colour output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[90m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"

    @staticmethod
    def risk(label: str) -> str:
        palette = {"Low": C.GREEN, "Medium": C.YELLOW, "High": C.RED, "Critical": C.MAGENTA}
        return f"{palette.get(label, C.RESET)}{label}{C.RESET}"

    @staticmethod
    def tick(value: bool, yes: str = "Yes", no: str = "No") -> str:
        return f"{C.GREEN}✓ {yes}{C.RESET}" if value else f"{C.RED}✗ {no}{C.RESET}"


# ─── Formatter ────────────────────────────────────────────────────────────────

class Formatter:
    """
    Centralised, presentation-quality CLI output for CSRFGuard.

    All methods are standalone — call in any order from main.py.
    """

    WIDTH = 64

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ── Layout ────────────────────────────────────────────────────────────────

    def section(self, title: str) -> None:
        bar = "─" * self.WIDTH
        print(f"\n{C.CYAN}{bar}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
        print(f"{C.CYAN}{bar}{C.RESET}")

    def info(self, label: str, value: str = "") -> None:
        if value:
            print(f"  {C.DIM}›{C.RESET} {label:<34} {value}")
        else:
            print(f"  {C.DIM}›{C.RESET} {label}")

    # ── Per-Phase Summaries ───────────────────────────────────────────────────

    def cookie_row(self, result: CookieAnalysisResult) -> None:
        tag = f" {C.YELLOW}[session?]{C.RESET}" if result.is_session_candidate else ""
        print(f"\n  {C.BOLD}Cookie: {result.name}{C.RESET}{tag}")
        print(f"    Secure   : {C.tick(result.is_secure)}")
        print(f"    HttpOnly : {C.tick(result.is_http_only)}")
        samesite = result.same_site or f"{C.RED}Absent{C.RESET}"
        print(f"    SameSite : {samesite}")
        print(f"    Risk     : {C.risk(result.risk_level)}")
        for issue in result.issues:
            print(f"    {C.YELLOW}⚠{C.RESET}  {issue}")

    def token_row(self, result: TokenAnalysisResult) -> None:
        mc = C.RED if result.method in ("POST", "PUT", "PATCH", "DELETE") else C.DIM
        print(f"\n  {mc}[{result.method}]{C.RESET} {result.endpoint_url}")
        if not result.has_token:
            print(f"    Token    : {C.RED}✗ ABSENT{C.RESET}")
        else:
            print(f"    Token    : {C.GREEN}✓ {result.token_field}{C.RESET}")
            print(f"    Length   : {result.token_length} chars")
            print(f"    Entropy  : {result.entropy_display}")
            print(f"    Strength : {C.risk(result.strength)}")
            if result.is_reused:
                print(f"    {C.YELLOW}⚠  Token value reused across forms{C.RESET}")
        for issue in result.issues:
            print(f"    {C.YELLOW}⚠{C.RESET}  {issue}")

    def samesite_finding(self, finding: SameSiteFinding) -> None:
        print(f"\n  {finding.color}[{finding.severity}]{C.RESET} {C.BOLD}{finding.title}{C.RESET}")
        print(f"  {C.DIM}{self._wrap(finding.detail)}{C.RESET}")
        if finding.affected_cookies:
            print(f"  {C.DIM}Cookies: {', '.join(finding.affected_cookies)}{C.RESET}")
        for ep in finding.affected_endpoints:
            print(f"  {C.DIM}  → {ep}{C.RESET}")

    def poc_row(self, poc_report: "PoCReport") -> None:
        if poc_report.total == 0:
            print(f"  {C.YELLOW}[!] No PoC files generated{C.RESET}")
            return
        print(f"\n  {C.BOLD}PoC files → {poc_report.output_dir}/{C.RESET}")
        for p in poc_report.generated:
            badge = f"{C.MAGENTA}[multipart]{C.RESET}" if p.poc_type == "multipart" \
                    else f"{C.CYAN}[post]{C.RESET}"
            print(f"  {C.RED}⚠{C.RESET}  {badge}  {p.filename}")
        if poc_report.skipped:
            print(f"  {C.DIM}Skipped (GET/non-state): {len(poc_report.skipped)}{C.RESET}")

    # ── Final Summary ─────────────────────────────────────────────────────────

    def final_summary(
        self,
        target:           str,
        scored_endpoints: list[ScoredEndpoint],
        cookie_results:   list[CookieAnalysisResult],
        samesite_results: SameSiteEvaluation,
    ) -> None:
        dbl = "═" * self.WIDTH
        print(f"\n{C.CYAN}{dbl}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  FINAL REPORT  —  CSRFGuard Analysis{C.RESET}")
        print(f"{C.CYAN}{dbl}{C.RESET}")
        print(f"  Target    : {C.BOLD}{target}{C.RESET}")
        print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # counts
        print(f"\n  {C.BOLD}Scan Summary{C.RESET}")
        self.info("State-changing endpoints", str(len(scored_endpoints)))
        self.info("Cookies analyzed",         str(len(cookie_results)))
        self.info("SameSite findings",        str(len(samesite_results.findings)))

        # endpoint risk table
        if scored_endpoints:
            print(f"\n  {C.BOLD}Endpoint Risk Table{C.RESET}")
            print(f"  {'METHOD':<8} {'SCORE':<7} {'RISK':<12} URL")
            print(f"  {'──────':<8} {'─────':<7} {'────':<12} ───")
            for ep in scored_endpoints:
                mc = C.RED if ep.method == "POST" else C.DIM
                print(
                    f"  {mc}{ep.method:<8}{C.RESET} "
                    f"{ep.score:<7} "
                    f"{ep.color}{ep.classification:<12}{C.RESET} "
                    f"{ep.url}"
                )

        # breakdown for high/critical
        hot = [e for e in scored_endpoints if e.classification in ("Critical", "High")]
        if hot:
            print(f"\n  {C.BOLD}{C.RED}⚠  High / Critical — Score Breakdown{C.RESET}")
            for ep in hot:
                print(f"\n  {ep.color}[{ep.classification}]{C.RESET} {ep.method} {ep.url}")
                for item in ep.breakdown:
                    print(f"    {C.RED}+{item.weight}{C.RESET}  {item.factor}")
                    print(f"         {C.DIM}{item.detail}{C.RESET}")

        # overall
        overall = scored_endpoints[0].classification if scored_endpoints \
                  else samesite_results.overall_samesite_risk
        print(f"\n  {C.BOLD}Overall CSRF Risk : {C.risk(overall)}{C.RESET}")
        print(
            f"\n  {C.DIM}Legend: "
            f"{C.GREEN}Low (0–3){C.RESET}  │  "
            f"{C.YELLOW}Medium (4–7){C.RESET}  │  "
            f"{C.RED}High (8–12){C.RESET}  │  "
            f"{C.MAGENTA}Critical (13+){C.RESET}"
        )
        print(f"\n{C.CYAN}{dbl}{C.RESET}")
        print(f"{C.DIM}  CSRFGuard — Academic use only. Authorized testing only.{C.RESET}")
        print(f"{C.CYAN}{dbl}{C.RESET}\n")

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _wrap(text: str, width: int = 70) -> str:
        words, lines, line, n = text.split(), [], [], 0
        for word in words:
            if n + len(word) + 1 > width:
                lines.append(" ".join(line))
                line, n = [word], len(word)
            else:
                line.append(word)
                n += len(word) + 1
        if line:
            lines.append(" ".join(line))
        return "\n  ".join(lines)
