"""
core/evasion/
──────────────
Evasion and stealth module package.

ScanManager calls EvasionMiddleware.apply(request, profile) before every
outbound HTTP request. The middleware chain applies transforms based on the
active scan profile (safe / default / aggressive / stealth).
"""

from .stealth import EvasionMiddleware
