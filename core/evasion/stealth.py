"""
core/evasion/stealth.py
────────────────────────
EvasionMiddleware: the top-level coordinator that selects and applies
evasion techniques based on the active scan profile.

ScanManager calls EvasionMiddleware.apply() before every request.
The pipeline:
  1. RequestObfuscator  → modify headers / params
  2. WAFBypass          → transform payloads if profile is aggressive/stealth
  3. Throttle           → enforce per-profile request delays + jitter
"""

from __future__ import annotations

import asyncio
import logging
import random

from config import JITTER_RANGE, SCAN_PROFILES
from core.evasion.request_obfuscation import RequestObfuscator
from core.evasion.waf_bypass import WAFBypass

log = logging.getLogger(__name__)


class EvasionMiddleware:
    """
    Applies the full evasion pipeline to outbound requests.

    This class is the only evasion entrypoint ScanManager needs to know about.
    All technique selection is encapsulated here, driven by the profile name.
    """

    def __init__(self, profile: str = "default") -> None:
        self.profile     = profile
        self.obfuscator  = RequestObfuscator(profile=profile)
        self._cfg        = SCAN_PROFILES.get(profile, SCAN_PROFILES["default"])

    async def throttle(self) -> None:
        """
        Enforce the profile's request delay, plus optional random jitter.
        Call this between requests in the detector loop.
        """
        base_delay = self._cfg.get("request_delay", 0.3)
        if base_delay > 0:
            jitter = random.uniform(*JITTER_RANGE) if self._cfg.get("evasion") else 0.0
            await asyncio.sleep(base_delay + jitter)

    def apply_to_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Apply header-level obfuscation based on profile."""
        if not self._cfg.get("evasion"):
            return headers
        return self.obfuscator.apply(headers)

    def transform_payload(self, payload: str) -> list[str]:
        """
        Return one or more transformed variants of a payload.
        - safe/default: return [payload] unchanged
        - aggressive:   return all WAFBypass variants
        - stealth:      return a single randomly selected variant
        """
        if not self._cfg.get("evasion"):
            return [payload]
        variants = WAFBypass.apply_all(payload)
        if self.profile == "stealth":
            return [random.choice(variants)]
        return variants

    def should_apply(self) -> bool:
        return self._cfg.get("evasion", False)
