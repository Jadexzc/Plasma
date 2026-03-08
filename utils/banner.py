"""
utils/banner.py -- Plasma v3
------------------------------
Professional CLI startup banner.

Renders a clean ASCII header with a rainbow gradient.
Two modes:
  - Enhanced : rich + pyfiglet installed  -> figlet title + Rich markup colours
  - Fallback  : stdlib only               -> hand-crafted ANSI banner, no dependencies

All characters are standard 7-bit ASCII -- no Unicode required.

Public API
----------
    from utils.banner import print_banner
    print_banner()             # safe to call unconditionally
    print_banner(quiet=True)   # suppressed in --quiet mode
"""
from __future__ import annotations

import sys

# -- Optional dependency probes -----------------------------------------------

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    _RICH = True
except ImportError:
    _RICH = False

try:
    import pyfiglet
    _FIGLET = True
except ImportError:
    _FIGLET = False

# -- Constants ----------------------------------------------------------------

_TOOL      = "Plasma"
_SUBTITLE  = "Advanced Web Vulnerability Scanner"
_AUTHOR    = "Created by Crypt0nymz"
_VERSION   = "v3.0.0"
_WEBSITE   = "github.com/Crypt0nymz/plasma"

# ANSI rainbow palette (6-colour cycle, all standard terminals)
_ANSI_RAINBOW = [
    "\033[91m",   # bright red
    "\033[93m",   # bright yellow
    "\033[92m",   # bright green
    "\033[96m",   # bright cyan
    "\033[94m",   # bright blue
    "\033[95m",   # bright magenta
]
_ANSI_BOLD  = "\033[1m"
_ANSI_DIM   = "\033[2m"
_ANSI_WHITE = "\033[97m"
_ANSI_RESET = "\033[0m"

# Pure standard-ASCII logo for Plasma (Option B -- clean modern, 4 rows, 37 chars).
# Every character is in the 7-bit printable ASCII range [0x20-0x7E].
# Verified width: 37 chars per line.
_ASCII_LOGO = (
    r" ___ _      _   ___ __  __   _ ",
    r"| _ \ |    /_\ / __|  \/  | /_\ ",
    r"|  _/ |__ / _ \\__ \ |\/| |/ _ \ ",
    r"|_| |____/_/ \_\___/_|  |_/_/ \_\ ",
)

# Width of the logo block (visible chars in widest row)
_LOGO_WIDTH = max(len(row) for row in _ASCII_LOGO)

# Overall banner width (capped at 80 for terminal compatibility)
_BANNER_WIDTH = 80


# -- Helpers ------------------------------------------------------------------

def _centre_ansi(text: str, width: int = _BANNER_WIDTH) -> str:
    """Centre *text*, accounting for invisible ANSI escape sequences."""
    import re
    visible_len = len(re.sub(r"\033\[[0-9;]*m", "", text))
    pad = max(0, (width - visible_len) // 2)
    return " " * pad + text


def _hr(char: str = "=", width: int = _BANNER_WIDTH) -> str:
    return char * width


# -- Fallback renderer (stdlib ANSI only) ------------------------------------

def _print_fallback() -> None:
    """Render banner using only ANSI escape codes -- no third-party packages."""
    print()
    print(f"{_ANSI_BOLD}{_ANSI_RAINBOW[2]}{_hr('=')}{_ANSI_RESET}")
    print()

    for i, row in enumerate(_ASCII_LOGO):
        color = _ANSI_RAINBOW[i % len(_ANSI_RAINBOW)]
        # Centre each logo row within the banner width
        pad = " " * max(0, (_BANNER_WIDTH - len(row)) // 2)
        print(f"{_ANSI_BOLD}{color}{pad}{row}{_ANSI_RESET}")

    print()
    print(_centre_ansi(f"{_ANSI_BOLD}{_ANSI_WHITE}{_SUBTITLE}{_ANSI_RESET}"))
    print(_centre_ansi(f"{_ANSI_DIM}{_ANSI_WHITE}{_AUTHOR}  *  {_VERSION}{_ANSI_RESET}"))
    print(_centre_ansi(f"{_ANSI_DIM}{_ANSI_RAINBOW[4]}{_WEBSITE}{_ANSI_RESET}"))
    print()
    print(f"{_ANSI_BOLD}{_ANSI_RAINBOW[4]}{_hr('=')}{_ANSI_RESET}")
    print()


# -- Rich renderer (rich + optional pyfiglet) --------------------------------

def _print_rich() -> None:
    """Render banner using rich for panels and colour markup."""
    console = Console(width=_BANNER_WIDTH)

    # Use pyfiglet for a larger title when available; else fall back to the
    # hand-crafted logo (which is already good).
    if _FIGLET:
        try:
            figlet_lines = pyfiglet.figlet_format(_TOOL, font="slant").splitlines()
        except Exception:
            figlet_lines = _ASCII_LOGO   # tuple — iterate directly, no copy needed
    else:
        figlet_lines = _ASCII_LOGO

    rainbow_colors = [
        "bright_red", "yellow", "bright_green",
        "cyan",        "bright_blue", "magenta",
    ]

    title_text = Text(justify="center")
    for i, line in enumerate(figlet_lines):
        title_text.append(line + "\n", style=f"bold {rainbow_colors[i % len(rainbow_colors)]}")

    subtitle_text = Text(justify="center")
    subtitle_text.append(f"\n{_SUBTITLE}\n", style="bold white")
    subtitle_text.append(f"{_AUTHOR}  *  {_VERSION}\n", style="dim white")
    subtitle_text.append(f"{_WEBSITE}", style="dim cyan")

    content = Text(justify="center")
    content.append_text(title_text)
    content.append_text(subtitle_text)

    panel = Panel(
        Align(content, align="center"),
        border_style="bright_green",
        padding=(0, 2),
        width=_BANNER_WIDTH,
    )
    console.print()
    console.print(panel)
    console.print()


# -- Public API ---------------------------------------------------------------

def print_banner(quiet: bool = False) -> None:
    """
    Print the Plasma startup banner.

    Uses rich + pyfiglet when available; falls back to ANSI-only rendering.
    Silently suppressed when *quiet* is True or stdout is not a TTY.
    Never raises -- scanner must not crash due to banner issues.
    """
    if quiet:
        return
    if not sys.stdout.isatty():
        return
    try:
        if _RICH:
            _print_rich()
        else:
            _print_fallback()
    except Exception:
        pass

