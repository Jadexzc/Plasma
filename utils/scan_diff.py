"""
utils/scan_diff.py — Plasma v3.3
──────────────────────────────────
Scan diff tool — compare two Plasma JSON scan outputs.

Usage::

    plasma --diff-scans before.json after.json

Output:
  • NEW findings (in after, not in before) — potential regressions
  • FIXED findings (in before, not in after) — patched vulnerabilities
  • UNCHANGED findings (in both)

A finding is considered the same if its (title, url, method) tuple matches.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _load_scan(path: str) -> list[dict]:
    """Load findings from a scan JSON file."""
    p = Path(path)
    if not p.exists():
        print(f"[diff] ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[diff] ERROR: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)

    # Support both {"findings": [...]} and a bare list
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return []


def _finding_key(f: dict) -> tuple:
    """Canonical identity key for a finding."""
    ep = f.get("endpoint") or {}
    url = (ep.get("url") or f.get("url") or "").rstrip("/")
    return (
        f.get("title", "").strip(),
        url,
        f.get("severity", ""),
    )


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        sev.lower(), 5
    )


def diff_scans(before_path: str, after_path: str, jsonl: bool = False) -> int:
    """
    Compare two scan outputs.

    Args:
        before_path: JSON file from first (earlier) scan
        after_path:  JSON file from second (later) scan
        jsonl:       If True, emit JSON Lines instead of human-readable output

    Returns:
        Exit code: 0 = no new findings, 1 = new findings exist
    """
    before = _load_scan(before_path)
    after  = _load_scan(after_path)

    before_keys = {_finding_key(f): f for f in before}
    after_keys  = {_finding_key(f): f for f in after}

    new_keys       = set(after_keys)  - set(before_keys)
    fixed_keys     = set(before_keys) - set(after_keys)
    unchanged_keys = set(before_keys) & set(after_keys)

    new_findings       = sorted([after_keys[k]  for k in new_keys],       key=lambda f: _severity_order(f.get("severity", "")))
    fixed_findings     = sorted([before_keys[k] for k in fixed_keys],     key=lambda f: _severity_order(f.get("severity", "")))
    unchanged_findings = sorted([after_keys[k]  for k in unchanged_keys], key=lambda f: _severity_order(f.get("severity", "")))

    if jsonl:
        for f in new_findings:
            print(json.dumps({"status": "new",       "finding": f}))
        for f in fixed_findings:
            print(json.dumps({"status": "fixed",     "finding": f}))
        for f in unchanged_findings:
            print(json.dumps({"status": "unchanged", "finding": f}))
        return 1 if new_findings else 0

    # ── Human-readable output ─────────────────────────────────────────────────
    _SEV_COLOUR = {
        "critical": "\033[91m", "high": "\033[31m",
        "medium": "\033[33m",   "low": "\033[32m",
        "info": "\033[36m",
    }
    RESET = "\033[0m"

    def _fmt(f: dict, prefix: str, colour: str) -> str:
        sev   = f.get("severity", "?").upper()
        title = f.get("title", "Untitled")
        ep    = (f.get("endpoint") or {})
        url   = ep.get("url") or f.get("url") or "?"
        sev_c = _SEV_COLOUR.get(sev.lower(), "")
        return f"  {colour}{prefix} [{sev_c}{sev}{RESET}{colour}] {title}{RESET}\n        {url}"

    print(f"\n{'='*65}")
    print(f"  PLASMA SCAN DIFF  {before_path}  →  {after_path}")
    print(f"{'='*65}")
    print(f"  Before: {len(before)} findings  |  After: {len(after)} findings")
    print(f"  New: {len(new_findings)}  Fixed: {len(fixed_findings)}  Unchanged: {len(unchanged_findings)}\n")

    if new_findings:
        print(f"\033[91m{'─'*30} NEW FINDINGS ({len(new_findings)}) {'─'*30}\033[0m")
        for f in new_findings:
            print(_fmt(f, "►", "\033[91m"))

    if fixed_findings:
        print(f"\n\033[32m{'─'*30} FIXED FINDINGS ({len(fixed_findings)}) {'─'*30}\033[0m")
        for f in fixed_findings:
            print(_fmt(f, "✓", "\033[32m"))

    if unchanged_findings:
        print(f"\n\033[33m{'─'*30} UNCHANGED ({len(unchanged_findings)}) {'─'*30}\033[0m")
        for f in unchanged_findings[:10]:  # cap display at 10
            print(_fmt(f, "·", "\033[33m"))
        if len(unchanged_findings) > 10:
            print(f"  … and {len(unchanged_findings) - 10} more")

    print()
    return 1 if new_findings else 0
