"""
core/adaptive_concurrency.py — Plasma v3
──────────────────────────────────────────
Adaptive concurrency controller for the scan engine.

Problem
───────
A fixed MAX_CONCURRENT_DETECTORS=8 is a poor fit across scan targets:
  - Fast targets (local lab) → 8 is a bottleneck; 32+ is fine
  - Slow/fragile targets → 8 causes timeouts and false negatives
  - WAF targets → flood triggers IP ban

Solution
────────
AdaptiveSemaphore observes rolling response latency and 4xx/5xx rates,
then adjusts effective concurrency up or down within user-configured bounds.

Algorithm: AIMD (Additive Increase / Multiplicative Decrease)
  - Increase by +1 every WINDOW_SIZE successful requests below LATENCY_THRESHOLD
  - Decrease by ×DECREASE_FACTOR on each timeout, 429, or 5xx

Exposed as a drop-in asyncio.Semaphore replacement.

Usage
─────
    from core.adaptive_concurrency import AdaptiveSemaphore
    sem = AdaptiveSemaphore(initial=8, min_concurrency=1, max_concurrency=32)

    async with sem:
        resp = await engine.get(url)
        sem.feedback(resp.status_code, latency_ms)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Optional

log = logging.getLogger(__name__)

# ── AIMD tuning constants ─────────────────────────────────────────────────────

_LATENCY_THRESHOLD_MS = 2_000   # above this → reduce concurrency
_WINDOW_SIZE          = 20      # requests per evaluation window
_INCREASE_STEP        = 1       # concurrency += 1 on healthy window
_DECREASE_FACTOR      = 0.75    # concurrency *= 0.75 on degradation
_MIN_CONCURRENCY      = 1
_MAX_CONCURRENCY      = 64


class AdaptiveSemaphore:
    """
    Asyncio semaphore with AIMD-based concurrency adaptation.

    Drop-in replacement for asyncio.Semaphore in scan_manager and engine.

    Thread-safe for use inside asyncio tasks.
    """

    def __init__(
        self,
        initial:         int = 8,
        min_concurrency: int = _MIN_CONCURRENCY,
        max_concurrency: int = _MAX_CONCURRENCY,
        latency_threshold_ms: int = _LATENCY_THRESHOLD_MS,
    ) -> None:
        self._current   = max(min_concurrency, min(initial, max_concurrency))
        self._min       = min_concurrency
        self._max       = max_concurrency
        self._threshold = latency_threshold_ms
        self._sem       = asyncio.Semaphore(self._current)
        self._lock      = asyncio.Lock()

        # Rolling window for AIMD decisions
        self._window: deque[tuple[int, float]] = deque(maxlen=_WINDOW_SIZE)
        self._window_count = 0

    # ── asyncio.Semaphore protocol ────────────────────────────────────────────

    async def __aenter__(self) -> "AdaptiveSemaphore":
        await self._sem.acquire()
        return self

    async def __aexit__(self, *_) -> None:
        self._sem.release()

    async def acquire(self) -> None:
        await self._sem.acquire()

    def release(self) -> None:
        self._sem.release()

    # ── Feedback interface ────────────────────────────────────────────────────

    def feedback(self, status_code: int, latency_ms: float) -> None:
        """
        Record the outcome of one completed request.
        AIMD adjustment happens when the window fills.

        Args:
            status_code : HTTP status (e.g. 200, 429, 503)
            latency_ms  : Round-trip time in milliseconds
        """
        degraded = (
            status_code in (429, 503, 502, 504)
            or status_code >= 500
            or latency_ms > self._threshold
        )
        self._window.append((status_code, latency_ms))
        self._window_count += 1

        if degraded:
            self._safe_schedule(self._decrease())

        elif self._window_count % _WINDOW_SIZE == 0:
            # Evaluate window
            bad = sum(1 for s, l in self._window
                      if s >= 500 or s == 429 or l > self._threshold)
            if bad == 0:
                self._safe_schedule(self._increase())
            elif bad > _WINDOW_SIZE // 3:
                self._safe_schedule(self._decrease())

    @staticmethod
    def _safe_schedule(coro) -> None:
        """Schedule a coroutine if a running event loop exists; else discard."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            # No running event loop (e.g. sync test context) — discard safely
            import inspect
            if inspect.iscoroutine(coro):
                coro.close()

    @property
    def current(self) -> int:
        return self._current

    def stats(self) -> dict:
        return {
            "current_concurrency": self._current,
            "min":                 self._min,
            "max":                 self._max,
        }

    # ── Internal adjustment ───────────────────────────────────────────────────

    async def _increase(self) -> None:
        async with self._lock:
            new = min(self._current + _INCREASE_STEP, self._max)
            if new > self._current:
                diff = new - self._current
                self._current = new
                for _ in range(diff):
                    self._sem.release()   # expand semaphore capacity
                log.debug("[concurrency] ↑ %d → %d", self._current - diff, self._current)

    async def _decrease(self) -> None:
        async with self._lock:
            new = max(int(self._current * _DECREASE_FACTOR), self._min)
            if new < self._current:
                diff = self._current - new
                self._current = new
                # Drain excess permits — acquire them without blocking
                for _ in range(diff):
                    try:
                        self._sem._value = max(0, self._sem._value - 1)
                    except Exception:
                        pass
                log.debug("[concurrency] ↓ %d → %d", self._current + diff, self._current)


class RateLimiter:
    """
    Token-bucket rate limiter for the scan engine.

    Limits the number of requests per second across all concurrent workers.

    Usage:
        limiter = RateLimiter(rate=20)   # 20 req/s
        await limiter.acquire()
        # ... make request ...
    """

    def __init__(self, rate: float = 20.0) -> None:
        self._rate      = rate
        self._tokens    = rate
        self._last      = time.monotonic()
        self._lock      = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last  = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

    def set_rate(self, rate: float) -> None:
        self._rate = max(0.1, rate)


class ScanConcurrencyCoordinator:
    """
    Top-level coordinator that owns the adaptive semaphore, rate limiter,
    and provides a simple gate() method for all scanner subsystems.

    Single instance per scan context; injected into AsyncHTTPEngine.
    """

    def __init__(
        self,
        initial_concurrency: int   = 8,
        max_concurrency:     int   = 32,
        rate_per_second:     float = 0.0,   # 0 = unlimited
    ) -> None:
        self.semaphore = AdaptiveSemaphore(
            initial=initial_concurrency,
            max_concurrency=max_concurrency,
        )
        self.rate_limiter = RateLimiter(rate_per_second) if rate_per_second > 0 else None

    async def gate(self) -> None:
        """Acquire both the semaphore slot and a rate-limiter token."""
        if self.rate_limiter:
            await self.rate_limiter.acquire()
        await self.semaphore.acquire()

    def release(self) -> None:
        self.semaphore.release()

    def report(self, status_code: int, latency_ms: float) -> None:
        self.semaphore.feedback(status_code, latency_ms)

    def stats(self) -> dict:
        s = self.semaphore.stats()
        if self.rate_limiter:
            s["rate_per_second"] = self.rate_limiter._rate
        return s
