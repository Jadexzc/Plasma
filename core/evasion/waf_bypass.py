"""
core/evasion/waf_bypass.py
───────────────────────────
WAF bypass encoding and transformation techniques.

These transforms are applied to payloads before they are sent,
allowing detectors to probe through common WAF signature filters.

Techniques:
  - Double URL encoding          %27 → %2527
  - HTML entity encoding         ' → &#x27;
  - Mixed case                   SELECT → SeLeCt
  - SQL comment insertion        SE/**/LECT
  - Unicode lookalike characters (for WAFs that normalise poorly)
  - Case variation and whitespace substitution
"""

from __future__ import annotations

import random
import re
import urllib.parse


class WAFBypass:
    """
    Applies WAF evasion transforms to a payload string.
    Transforms are selected based on the active evasion profile.
    """

    @staticmethod
    def double_encode(payload: str) -> str:
        """Double URL-encode the payload: % → %25."""
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Replace single quotes with HTML entities."""
        return payload.replace("'", "&#x27;").replace('"', "&quot;")

    @staticmethod
    def mixed_case(payload: str) -> str:
        """Randomise character case (effective against case-sensitive WAF rules)."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in payload
        )

    @staticmethod
    def sql_comment_injection(payload: str) -> str:
        """
        Insert SQL inline comments between keywords to break signature matching.
        SELECT → SE/**/LECT
        """
        keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM"]
        result = payload
        for kw in keywords:
            mid = len(kw) // 2
            obfuscated = kw[:mid] + "/**/" + kw[mid:]
            result = re.sub(kw, obfuscated, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def url_encode_special(payload: str) -> str:
        """URL-encode only the special characters attackers typically inject."""
        mapping = {
            "'": "%27", '"': "%22", "<": "%3C", ">": "%3E",
            "(": "%28", ")": "%29", ";": "%3B", "=": "%3D",
            "&": "%26", "|": "%7C",
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def apply_all(payload: str) -> list[str]:
        """
        Return a list of WAF-bypass variants for a given payload.
        Use in aggressive/stealth profiles to maximise coverage.
        """
        return [
            payload,
            WAFBypass.double_encode(payload),
            WAFBypass.html_entity_encode(payload),
            WAFBypass.sql_comment_injection(payload),
            WAFBypass.url_encode_special(payload),
        ]
