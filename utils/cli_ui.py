"""
utils/cli_ui.py — WebGuard v3
───────────────────────────────
Terminal UI helpers for structured, colourful CLI output.

Style inspired by Nmap / Metasploit:
  [INFO]    neutral context
  [WARNING] caution
  [ERROR]   failure
  [SUCCESS] completion / positive result
  [+]       finding discovered

Works in two modes:
  - Enhanced : rich installed → panels, tables, progress bars
  - Fallback  : stdlib ANSI   → same information, plaintext formatting

Public API
----------
    from utils.cli_ui import (
        show_scan_info, log_info, log_warning,
        log_error, log_success, show_findings, show_progress,
    )
"""
from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:
    from core.models import Finding, ScanContext

# ── Optional rich probe ───────────────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn,
    )
    from rich.text import Text
    from rich import box
    _RICH = True
    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    _RICH = False
    _console = None       # type: ignore[assignment]
    _err_console = None   # type: ignore[assignment]

# ── ANSI colour codes (fallback) ──────────────────────────────────────────────

_R = "\033[0m"        # reset
_BOLD = "\033[1m"
_DIM  = "\033[2m"

_CYAN    = "\033[36m"
_GREEN   = "\033[92m"
_YELLOW  = "\033[93m"
_RED     = "\033[91m"
_MAGENTA = "\033[95m"
_WHITE   = "\033[97m"
_BLUE    = "\033[94m"

_SEV_ANSI = {
    "Critical": f"{_BOLD}{_RED}",
    "High":     f"{_BOLD}{_MAGENTA}",
    "Medium":   f"{_BOLD}{_YELLOW}",
    "Low":      f"{_BOLD}{_CYAN}",
    "Info":     f"{_DIM}{_WHITE}",
}

_SEV_RICH = {
    "Critical": "bold red",
    "High":     "bold magenta",
    "Medium":   "bold yellow",
    "Low":      "cyan",
    "Info":     "dim white",
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ts() -> str:
    """HH:MM:SS timestamp for log lines."""
    return time.strftime("%H:%M:%S")


def _ansi_log(prefix_color: str, prefix: str, message: str) -> None:
    print(f"{_DIM}{_ts()}{_R}  {_BOLD}{prefix_color}{prefix}{_R}  {message}")


def _rich_log(prefix: str, style: str, message: str) -> None:
    _console.print(f"[dim]{_ts()}[/dim]  [{style}]{prefix}[/{style}]  {message}")


# ── Public log functions ──────────────────────────────────────────────────────

def log_info(message: str) -> None:
    """[INFO] Neutral informational message."""
    if _RICH:
        _rich_log("[INFO]", "cyan", message)
    else:
        _ansi_log(_CYAN, "[INFO]", message)


def log_warning(message: str) -> None:
    """[WARNING] Caution — non-fatal anomaly."""
    if _RICH:
        _rich_log("[WARNING]", "bold yellow", message)
    else:
        _ansi_log(_YELLOW, "[WARNING]", message)


def log_error(message: str) -> None:
    """[ERROR] Failure message — printed to stderr."""
    if _RICH:
        _err_console.print(f"[dim]{_ts()}[/dim]  [bold red][ERROR][/bold red]  {message}")
    else:
        print(
            f"{_DIM}{_ts()}{_R}  {_BOLD}{_RED}[ERROR]{_R}  {message}",
            file=sys.stderr,
        )


def log_success(message: str) -> None:
    """[SUCCESS] Positive completion message."""
    if _RICH:
        _rich_log("[SUCCESS]", "bold green", message)
    else:
        _ansi_log(_GREEN, "[SUCCESS]", message)


def log_finding(message: str) -> None:
    """[+] A vulnerability was discovered."""
    if _RICH:
        _rich_log("[+]", "bold magenta", message)
    else:
        _ansi_log(_MAGENTA, "[+]", message)


# ── Scan info panel ───────────────────────────────────────────────────────────

def show_scan_info(
    target:   str,
    profile:  str,
    depth:    int,
    timeout:  int,
    proxy:    Optional[str] = None,
    auth_url: Optional[str] = None,
    skipped:  Optional[set[str]] = None,
) -> None:
    """
    Print a structured scan configuration panel before scanning starts.

    Rich mode   → framed panel with aligned rows.
    Fallback    → plain indented lines.
    """
    rows = [
        ("Target",   target),
        ("Profile",  profile),
        ("Depth",    str(depth)),
        ("Timeout",  f"{timeout}s"),
    ]
    if proxy:
        rows.append(("Proxy", proxy))
    if auth_url:
        rows.append(("Auth", auth_url))
    if skipped:
        rows.append(("Skipping", ", ".join(sorted(skipped))))

    if _RICH:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim cyan", justify="right")
        table.add_column(style="white")
        for key, val in rows:
            table.add_row(key, val)
        panel = Panel(
            table,
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
        _console.print(panel)
        _console.print()
    else:
        border = f"{_BOLD}{_CYAN}{'─' * 50}{_R}"
        print(border)
        print(f"{_BOLD}{_CYAN}  Scan Configuration{_R}")
        print(border)
        for key, val in rows:
            print(f"  {_CYAN}{key:<10}{_R}  {val}")
        print(border)
        print()


# ── Findings table ────────────────────────────────────────────────────────────

def show_findings(findings: list["Finding"], max_rows: int = 20) -> None:
    """
    Print a structured findings table after the scan completes.

    Rich mode   → coloured table with severity, type, title, URL columns.
    Fallback    → aligned plain-text table.
    """
    if not findings:
        log_info("No findings recorded.")
        return

    displayed = findings[:max_rows]
    truncated = len(findings) - len(displayed)

    if _RICH:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            box=box.SIMPLE_HEAVY,
            expand=False,
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type",     style="dim white", width=22)
        table.add_column("Title",    style="white",     width=38)
        table.add_column("URL",      style="dim cyan",  width=40, no_wrap=True)

        for f in displayed:
            sev_style = _SEV_RICH.get(f.severity.value, "white")
            url = (f.endpoint.url if f.endpoint else "—")[:40]
            table.add_row(
                Text(f.severity.value, style=sev_style),
                f.vuln_type.value,
                f.title[:38],
                url,
            )

        _console.print()
        _console.print(table)
        if truncated:
            _console.print(
                f"[dim]  … {truncated} more finding(s) not shown. "
                "Use --report for the full list.[/dim]"
            )
        _console.print()
    else:
        # Plain-text aligned table
        COL = (10, 22, 38, 40)
        header = (
            f"{'Severity':<{COL[0]}}  {'Type':<{COL[1]}}  "
            f"{'Title':<{COL[2]}}  {'URL':<{COL[3]}}"
        )
        sep = "  ".join("─" * w for w in COL)
        print(f"\n{_BOLD}{_CYAN}{header}{_R}")
        print(f"{_CYAN}{sep}{_R}")
        for f in displayed:
            sev_c = _SEV_ANSI.get(f.severity.value, "")
            url = (f.endpoint.url if f.endpoint else "—")[:COL[3]]
            print(
                f"{sev_c}{f.severity.value:<{COL[0]}}{_R}  "
                f"{f.vuln_type.value:<{COL[1]}}  "
                f"{f.title[:COL[2]]:<{COL[2]}}  "
                f"{_DIM}{url}{_R}"
            )
        if truncated:
            print(f"\n{_DIM}  … {truncated} more finding(s) not shown.{_R}")
        print()


# ── Summary counts ────────────────────────────────────────────────────────────

def show_summary(context: "ScanContext", elapsed: float) -> None:
    """
    Print the post-scan severity count summary.
    Called by main._print_results if cli_ui is wired in.
    """
    counts = context.finding_count_by_severity
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    icons     = {"Critical": "●", "High": "●", "Medium": "●", "Low": "●", "Info": "○"}
    non_zero  = [(s, counts.get(s, 0)) for s in sev_order if counts.get(s, 0)]

    if _RICH:
        _console.print(
            f"\n[bold]Scan complete[/bold]  [dim]│[/dim]  "
            f"[cyan]{elapsed:.1f}s[/cyan]  [dim]│[/dim]  "
            f"[bold]{len(context.findings)} finding(s)[/bold]"
        )
        for sev, n in non_zero:
            style = _SEV_RICH.get(sev, "white")
            _console.print(f"  [{style}]{icons[sev]} {sev:<10}  {n}[/{style}]")
        _console.print()
    else:
        print(
            f"\n{_BOLD}Scan complete{_R}  │  "
            f"{_CYAN}{elapsed:.1f}s{_R}  │  "
            f"{_BOLD}{len(context.findings)} finding(s){_R}"
        )
        for sev, n in non_zero:
            c = _SEV_ANSI.get(sev, "")
            print(f"  {c}{icons[sev]} {sev:<10}  {n}{_R}")
        print()


# ── Progress bar ──────────────────────────────────────────────────────────────

class ScanProgress:
    """
    Context-manager progress indicator.

    Usage:
        with ScanProgress("Crawling target") as p:
            p.update("Phase 1: crawling…")
            # … work …
            p.update("Phase 2: detecting…")
    """

    def __init__(self, description: str = "Scanning") -> None:
        self._desc = description
        self._progress: Optional[Progress] = None
        self._task_id = None

    def __enter__(self) -> "ScanProgress":
        if _RICH:
            self._progress = Progress(
                SpinnerColumn(style="bold cyan"),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                TextColumn("[dim]{task.fields[status]}"),
                TimeElapsedColumn(),
                console=_console,
                transient=True,
            )
            self._progress.__enter__()
            self._task_id = self._progress.add_task(
                self._desc, total=100, status="initialising…"
            )
        else:
            print(f"{_CYAN}[~]{_R} {self._desc}…", flush=True)
        return self

    def update(self, status: str, advance: int = 5) -> None:
        """Update the status text and optionally advance the progress bar."""
        if _RICH and self._progress and self._task_id is not None:
            self._progress.update(self._task_id, advance=advance, status=status)
        else:
            print(f"  {_DIM}→ {status}{_R}", flush=True)

    def __exit__(self, *_) -> None:
        if _RICH and self._progress:
            self._progress.__exit__(*_)


def show_progress(description: str) -> ScanProgress:
    """Return a ScanProgress context manager for the given description."""
    return ScanProgress(description)
