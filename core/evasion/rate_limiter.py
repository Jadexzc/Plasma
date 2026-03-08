"""
core/evasion/rate_limiter.py — Plasma V1
WAF fingerprinting, rate-limit calibration, exponential backoff.
"""
from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from requests import Response

from config import (
    RATE_LIMIT_CODES, WAF_BLOCK_CODES, WAF_SLOWDOWN_FACTOR,
    WAF_SIGNATURES, JITTER_RANGE,
)

log = logging.getLogger(__name__)

_RETRY_AFTER_RE = re.compile(r"(\d+)")


@dataclass
class WAFProvider:
    name:         str
    headers:      list       = field(default_factory=list)
    body_re:      object     = None
    status_codes: list       = field(default_factory=list)
    bypass_hint:  str        = ""


_WAF_PROVIDERS = [
    WAFProvider("Cloudflare",
        headers=[("cf-ray",""),("server","cloudflare")],
        body_re=re.compile(r"cloudflare|cf-ray|ray id:", re.I),
        status_codes=[403,429,503],
        bypass_hint="Cloudflare detected. Use --rate-limit to stay under threshold."),
    WAFProvider("AWS WAF",
        headers=[("x-amzn-requestid",""),("x-amz-cf-id","")],
        body_re=re.compile(r"aws.*403|request blocked", re.I),
        status_codes=[403],
        bypass_hint="AWS WAF detected. Use --rate-limit 2."),
    WAFProvider("Akamai",
        headers=[("x-check-cacheable",""),("akamai-origin-hop","")],
        body_re=re.compile(r"akamai|reference #", re.I),
        status_codes=[403],
        bypass_hint="Akamai detected. Use --fuzz-stealth."),
    WAFProvider("ModSecurity",
        headers=[],
        body_re=re.compile(r"mod.?security|not acceptable", re.I),
        status_codes=[406,403],
        bypass_hint="ModSecurity detected. Enable --fuzz-stealth."),
    WAFProvider("F5 BIG-IP",
        headers=[("TS","")],
        body_re=re.compile(r"requested url was rejected|big.?ip", re.I),
        status_codes=[403],
        bypass_hint="F5 BIG-IP ASM detected."),
    WAFProvider("Imperva",
        headers=[("x-iinfo",""),("incap-ses","")],
        body_re=re.compile(r"incapsula|imperva", re.I),
        status_codes=[403],
        bypass_hint="Imperva detected."),
    WAFProvider("Sucuri",
        headers=[("x-sucuri-id",""),("x-sucuri-cache","")],
        body_re=re.compile(r"sucuri", re.I),
        status_codes=[403],
        bypass_hint="Sucuri CloudProxy detected."),
    WAFProvider("Fastly",
        headers=[("x-fastly-request-id","")],
        body_re=re.compile(r"varnish", re.I),
        status_codes=[429,503],
        bypass_hint="Fastly CDN detected."),
]


class RateLimiter:
    """
    Adaptive rate limiter with WAF fingerprinting and auto-calibration.

    Usage::

        limiter = RateLimiter(base_delay=0.3)
        await limiter.throttle()
        limiter.observe(response)
        report = limiter.fingerprint_report()
    """

    def __init__(self, base_delay: float = 0.3) -> None:
        self.base_delay           = base_delay
        self._current_delay       = base_delay
        self._waf_detected        = False
        self._waf_provider: Optional[str] = None
        self._rate_limited        = False
        self._violations          = deque(maxlen=20)
        self._last_request        = 0.0
        self._request_times: deque = deque(maxlen=60)
        self._detected_rps_limit: Optional[float] = None
        self._retry_after_s       = 0.0
        self._429_count           = 0
        self._consecutive_429s    = 0

    async def throttle(self) -> None:
        if self._retry_after_s > 0:
            remaining = self._retry_after_s - (time.monotonic() - self._last_request)
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._retry_after_s = 0.0
        elapsed = time.monotonic() - self._last_request
        jitter  = random.uniform(*JITTER_RANGE)
        wait    = max(0.0, self._current_delay + jitter - elapsed)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()
        self._request_times.append(self._last_request)

    def observe(self, response: Optional[Response]) -> None:
        if response is None:
            return
        status  = response.status_code
        headers = response.headers

        if status in RATE_LIMIT_CODES:
            self._429_count        += 1
            self._consecutive_429s += 1
            self._violations.append("rate_limit")
            self._rate_limited = True
            retry_hdr = headers.get("Retry-After") or headers.get("X-RateLimit-Reset")
            if retry_hdr:
                m = _RETRY_AFTER_RE.search(str(retry_hdr))
                if m:
                    self._retry_after_s = float(m.group(1))
            backoff = min(self.base_delay * (2 ** self._consecutive_429s), 30.0)
            self._current_delay = backoff + random.uniform(0, backoff * 0.2)
            self._estimate_rps_limit(headers)
            log.warning("[ratelimit] HTTP 429 (#%d) backoff=%.1fs", self._429_count, self._current_delay)
            return

        if status < 400:
            self._consecutive_429s = max(0, self._consecutive_429s - 1)

        if status in WAF_BLOCK_CODES:
            self._violations.append("waf_block")
            self._current_delay = min(self._current_delay * WAF_SLOWDOWN_FACTOR, 30.0)
            log.warning("[ratelimit] WAF block HTTP %d delay=%.1fs", status, self._current_delay)

        if not self._waf_provider:
            provider = self._identify_waf_provider(response)
            if provider:
                self._waf_detected  = True
                self._waf_provider  = provider.name
                self._current_delay = max(self._current_delay, 1.0)
                log.info("[ratelimit] WAF: %s  hint=%s", provider.name, provider.bypass_hint)

        recent_viol = sum(1 for v in self._violations if v in ("rate_limit","waf_block"))
        if recent_viol < 3 and len(self._violations) >= 5:
            self._current_delay = max(self.base_delay, self._current_delay * 0.9)

    def _identify_waf_provider(self, response) -> Optional[WAFProvider]:
        headers = response.headers
        body    = (response.text or "")[:2000]
        for provider in _WAF_PROVIDERS:
            for hdr_name, hdr_contains in provider.headers:
                val = headers.get(hdr_name, "").lower()
                if val and (not hdr_contains or hdr_contains.lower() in val):
                    return provider
            if provider.body_re and provider.body_re.search(body):
                return provider
        return None

    def _estimate_rps_limit(self, headers) -> None:
        limit_hdr  = headers.get("X-RateLimit-Limit") or headers.get("RateLimit-Limit")
        window_hdr = headers.get("X-RateLimit-Window") or "60"
        if limit_hdr:
            try:
                limit  = float(_RETRY_AFTER_RE.search(str(limit_hdr)).group(1))
                window = float(_RETRY_AFTER_RE.search(str(window_hdr)).group(1))
                if window > 0:
                    self._detected_rps_limit = limit / window
                    safe = 1.0 / (self._detected_rps_limit * 0.7)
                    self._current_delay = max(self._current_delay, safe)
                    log.info("[ratelimit] Detected %.1f req/%ds -> safe delay %.2fs", limit, window, safe)
            except Exception:
                pass

    def calibrate(self, target_rps: float) -> None:
        if target_rps <= 0:
            return
        self._current_delay = 1.0 / target_rps
        self.base_delay     = self._current_delay
        log.info("[ratelimit] Calibrated to %.1f RPS (%.3fs)", target_rps, self._current_delay)

    def estimated_rps(self) -> float:
        times = list(self._request_times)
        if len(times) < 2:
            return 0.0
        w = times[-1] - times[0]
        return len(times) / w if w > 0 else 0.0

    @property
    def waf_detected(self) -> bool:
        return self._waf_detected

    @property
    def waf_provider(self) -> Optional[str]:
        return self._waf_provider

    @property
    def is_throttled(self) -> bool:
        return self._rate_limited

    @property
    def current_delay(self) -> float:
        return self._current_delay

    def fingerprint_report(self) -> dict:
        return {
            "waf_detected":       self._waf_detected,
            "waf_provider":       self._waf_provider or "Unknown",
            "rate_limited":       self._rate_limited,
            "total_429s":         self._429_count,
            "detected_rps_limit": self._detected_rps_limit,
            "current_delay_s":    round(self._current_delay, 3),
            "estimated_rps":      round(self.estimated_rps(), 2),
        }

    def status_report(self) -> dict:
        return self.fingerprint_report()


# ═══════════════════════════════════════════════════════════════════════════════
# Active Rate-Limit Prober
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimitProber:
    """
    Actively probes a target URL to measure its rate limit.

    Algorithm
    ─────────
    1. Send probes at exponentially increasing RPS: 1, 2, 4, 8, 16 ... req/s
    2. Stop on first HTTP 429 or WAF block
    3. Safe ceiling = (last_safe_rps * 0.7) — 30% headroom
    4. Returns a calibrated RateLimiter instance

    This runs only in "aggressive" profile mode and only when explicitly
    requested (--rate-limit 0 means auto-calibrate).
    """

    def __init__(self, target_url: str, timeout: int = 8) -> None:
        self.target_url = target_url
        self.timeout    = timeout

    def probe(self, max_rps: float = 20.0) -> "RateLimiter":
        """
        Probe synchronously.  Returns a calibrated RateLimiter.
        Safe to call from sync or async code (blocking).
        """
        import requests as _req
        session = _req.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; probe)"})

        rps       = 1.0
        last_safe = 1.0
        probes    = 0
        log.info("[ratelimit-probe] Starting rate limit probe on %s", self.target_url)

        while rps <= max_rps:
            delay = 1.0 / rps
            # Send 3 probes at this rate, check all succeed
            ok = True
            for _ in range(3):
                try:
                    r = session.get(
                        self.target_url, timeout=self.timeout, allow_redirects=False
                    )
                    probes += 1
                    if r.status_code in (429, 503, 403):
                        # Check for WAF/rate-limit signatures
                        ok = False
                        break
                except Exception:
                    ok = False
                    break
                import time as _t; _t.sleep(delay)

            if not ok:
                break
            last_safe = rps
            rps *= 2.0

        # Apply 30% safety margin
        safe_rps = last_safe * 0.7
        log.info(
            "[ratelimit-probe] Ceiling detected: %.1f RPS — safe rate: %.1f RPS (%d probes sent)",
            last_safe, safe_rps, probes
        )
        limiter = RateLimiter(base_delay=1.0 / max(safe_rps, 0.1))
        limiter.calibrate(safe_rps)
        return limiter

    async def probe_async(self, max_rps: float = 20.0) -> "RateLimiter":
        """Async wrapper for probe()."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.probe(max_rps))
