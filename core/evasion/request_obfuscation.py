"""
core/evasion/request_obfuscation.py
─────────────────────────────────────
HTTP request-level obfuscation techniques.

Transforms applied to the requests.Request object before sending:
  - User-Agent rotation (from config.USER_AGENT_POOL)
  - Header casing variation (Host: → HOST:)
  - Fake referrer injection
  - Accept-Encoding manipulation
  - X-Forwarded-For spoofing
  - Parameter order randomisation

Usage:
    obf = RequestObfuscator(profile="stealth")
    session = obf.apply(session, request_kwargs)
"""

from __future__ import annotations

import random

import requests

from config import USER_AGENT_POOL, ROTATE_USER_AGENTS


class RequestObfuscator:
    """
    Mutates outbound HTTP request parameters to avoid fingerprinting.
    Transforms are gated by the active scan profile.
    """

    FAKE_REFERRERS = [
        "https://www.google.com/search?q=login",
        "https://bing.com/",
        "https://duckduckgo.com/",
        "",
    ]

    def __init__(self, profile: str = "default") -> None:
        self.profile = profile

    def apply(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Return a modified headers dict with obfuscation applied.

        Args:
            headers: base headers dict from make_session()

        Returns:
            Modified headers dict.
        """
        result = dict(headers)

        # User-agent rotation
        if ROTATE_USER_AGENTS or self.profile in ("aggressive", "stealth"):
            result["User-Agent"] = random.choice(USER_AGENT_POOL)

        # Fake referrer (stealth only)
        if self.profile == "stealth":
            result["Referer"] = random.choice(self.FAKE_REFERRERS)

        # X-Forwarded-For spoofing (aggressive)
        if self.profile == "aggressive":
            octets = [str(random.randint(1, 254)) for _ in range(4)]
            result["X-Forwarded-For"] = ".".join(octets)

        return result

    def randomise_params(self, params: dict[str, str]) -> dict[str, str]:
        """Shuffle parameter order (some WAFs check parameter sequence)."""
        items = list(params.items())
        random.shuffle(items)
        return dict(items)
