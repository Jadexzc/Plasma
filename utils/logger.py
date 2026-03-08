"""
utils/logger.py
────────────────
Centralised logging configuration for WebGuard.

All modules use logging.getLogger(__name__) — this module configures
the root "webguard" logger once, so the entire framework logs consistently.

Usage:
    from utils.logger import setup_logging
    setup_logging(verbose=True, log_file="logs/scan.log")
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path


class ColorFormatter(logging.Formatter):
    """
    ANSI-coloured log formatter for console output.
    Colors by level: DEBUG=grey, INFO=cyan, WARNING=yellow, ERROR=red, CRITICAL=magenta.
    """

    LEVEL_COLORS = {
        logging.DEBUG:    "\033[90m",
        logging.INFO:     "\033[36m",
        logging.WARNING:  "\033[33m",
        logging.ERROR:    "\033[31m",
        logging.CRITICAL: "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color  = self.LEVEL_COLORS.get(record.levelno, "")
        prefix = f"{color}[{record.levelname[0]}]{self.RESET}"
        msg    = super().format(record)
        return f"{prefix} {msg}"


def setup_logging(
    verbose:  bool         = False,
    log_file: str | None   = None,
    log_name: str          = "webguard",
) -> logging.Logger:
    """
    Configure the root WebGuard logger.

    Args:
        verbose:  if True, set level to DEBUG; else WARNING
        log_file: optional path to write logs to (in addition to console)
        log_name: root logger name (default: "webguard")

    Returns:
        Configured Logger instance.
    """
    level = logging.DEBUG if verbose else logging.WARNING

    # Console handler with colours
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(ColorFormatter(
        fmt="%(asctime)s  %(name)-30s  %(message)s",
        datefmt="%H:%M:%S",
    ))

    handlers: list[logging.Handler] = [console]

    # Optional file handler (plain text, full detail)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handlers.append(fh)

    # Configure root logger and all framework sub-loggers
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # individual handlers filter by their own level
    for h in handlers:
        root.addHandler(h)

    return logging.getLogger(log_name)
