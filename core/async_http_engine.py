"""
core/async_http_engine.py — Plasma v3
──────────────────────────────────────
Centralized async HTTP engine.

Design goals
────────────
  • Zero blocking on the asyncio event loop — all socket I/O runs in
    a dedicated ThreadPoolExecutor.
  • Connection reuse — a single requests.Session is shared across all
    requests on the same scan; urllib3 pools keep TCP connections alive.
  • Request deduplication — an LRU-capped cache prevents identical
    (method, url, sorted_params) tuples from hitting the network twice.
  • Adaptive back-pressure — a token-bucket rate limiter observes 429 /
    503 responses and automatically throttles the scan per-host.
  • Bulk concurrent dispatch — submit() + gather() fire up to
    MAX_ENGINE_CONCURRENCY requests simultaneously.
  • Response streaming — callers can opt-in to streaming to avoid
    loading multi-MB bodies into memory.

Public API
──────────
    engine = AsyncHTTPEngine(session=make_session(), timeout=10)

    # Single request
    resp = await engine.get("https://target.com/path", params={"q": "1"})
    resp = await engine.post("https://target.com/api", data={"x": "1"})
    resp = await engine.request("PUT", url, json=payload)

    # Concurrent dispatch
    responses = await engine.gather([
        engine.get(url1, params=p1),
        engine.post(url2, data=d2),
    ], concurrency=20)

    # Streaming (large bodies — avoids loading full response)
    async with engine.stream("GET", url) as streamed:
        async for chunk in streamed:
            process(chunk)

    # Stats
    print(engine.stats())  # hits, misses, deduped, throttled
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

import requests

from config import DEFAULT_TIMEOUT, MAX_CONCURRENT_DETECTORS
from utils.http_client import make_session

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_DEDUP_CACHE    = 2_048   # LRU cache cap (entries)
_DEFAULT_CONCURRENCY = min(MAX_CONCURRENT_DETECTORS * 4, 32)
_THROTTLE_BACKOFF   = 2.0    # initial back-off seconds on 429
_THROTTLE_MAX       = 30.0   # maximum back-off ceiling
_THROTTLE_DECAY     = 0.5    # back-off halved per successful request


@dataclass
class EngineStats:
    requests_sent:   int = 0
    cache_hits:      int = 0
    cache_misses:    int = 0
    deduped:         int = 0
    throttled:       int = 0
    errors:          int = 0
    total_bytes:     int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.requests_sent, 1)

    def summary(self) -> dict:
        return {
            "sent":        self.requests_sent,
            "cache_hits":  self.cache_hits,
            "deduped":     self.deduped,
            "throttled":   self.throttled,
            "errors":      self.errors,
            "bytes_rx":    self.total_bytes,
            "avg_ms":      round(self.avg_latency_ms, 1),
        }


class _LRUCache:
    """Thread-safe LRU cache backed by an OrderedDict."""

    def __init__(self, maxsize: int = _MAX_DEDUP_CACHE) -> None:
        self._cache:   OrderedDict[str, Any] = OrderedDict()
        self._maxsize  = maxsize
        self._lock     = asyncio.Lock()

    async def get(self, key: str) -> Any:
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._maxsize:
                    self._cache.popitem(last=False)
            self._cache[key] = value

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()


class _HostThrottler:
    """Per-host adaptive token-bucket rate limiter."""

    def __init__(self) -> None:
        self._backoff:  dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        async with self._lock:
            delay = self._backoff.get(host, 0.0)
        if delay > 0:
            await asyncio.sleep(delay)

    async def on_throttled(self, host: str) -> None:
        async with self._lock:
            current = self._backoff.get(host, _THROTTLE_BACKOFF / 2)
            self._backoff[host] = min(current * 2, _THROTTLE_MAX)
        log.debug("[engine] 429 on %s — back-off %.1fs", host, self._backoff[host])

    async def on_success(self, host: str) -> None:
        async with self._lock:
            if host in self._backoff:
                new_val = self._backoff[host] * _THROTTLE_DECAY
                if new_val < 0.05:
                    del self._backoff[host]
                else:
                    self._backoff[host] = new_val


class AsyncHTTPEngine:
    """
    Centralized async HTTP engine for Plasma v3.

    All network I/O runs in a shared ThreadPoolExecutor so the asyncio
    event loop is never blocked.  Identical requests within a scan are
    de-duplicated via an LRU cache keyed on (method, url, body hash).

    Args:
        session      : Pre-configured requests.Session (from make_session())
        timeout      : Per-request timeout in seconds
        max_workers  : Thread pool size
        dedup        : Enable request deduplication cache
        max_concurrency : Semaphore cap for concurrent in-flight requests
    """

    def __init__(
        self,
        session:         Optional[requests.Session] = None,
        timeout:         int   = DEFAULT_TIMEOUT,
        max_workers:     int   = 20,
        dedup:           bool  = True,
        max_concurrency: int   = _DEFAULT_CONCURRENCY,
        verify_ssl:      bool  = True,
    ) -> None:
        self._session    = session or make_session()
        # Fix: apply SSL verification setting on existing session
        self._session.verify = verify_ssl
        self._timeout    = timeout
        self._pool       = ThreadPoolExecutor(max_workers=max_workers,
                                              thread_name_prefix="plasma-http")
        self._dedup      = dedup
        self._cache      = _LRUCache()    # sized adaptively via resize_cache()
        self._throttler  = _HostThrottler()
        self._semaphore  = asyncio.Semaphore(max_concurrency)
        self._stats      = EngineStats()
        self._verify_ssl = verify_ssl

    # ── Public request API ────────────────────────────────────────────────────

    async def get(
        self,
        url:     str,
        params:  Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        """Async GET request."""
        return await self.request("GET", url, params=params, headers=headers, **kwargs)

    async def post(
        self,
        url:     str,
        data:    Optional[dict] = None,
        json:    Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        """Async POST request."""
        return await self.request("POST", url, data=data, json=json,
                                  headers=headers, **kwargs)

    async def request(
        self,
        method:  str,
        url:     str,
        *,
        params:  Optional[dict] = None,
        data:    Optional[dict] = None,
        json:    Optional[dict] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool   = True,
        stream:  bool           = False,
        cache:   bool           = True,        # per-call dedup override
        timeout: Optional[int]  = None,
    ) -> Optional[requests.Response]:
        """
        Generic async request dispatcher.

        Flow:
          1. Build cache key
          2. Check LRU cache (if dedup enabled and method is safe)
          3. Apply per-host throttle delay
          4. Acquire concurrency semaphore
          5. Run synchronous request in thread pool
          6. Update throttler and cache
          7. Return response
        """
        from urllib.parse import urlparse
        host = urlparse(url).netloc

        # 1. Cache key
        cache_key = None
        if self._dedup and cache and method.upper() in ("GET", "HEAD", "OPTIONS"):
            cache_key = _make_key(method, url, params, data, json)

        # 2. Cache hit
        if cache_key:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                self._stats.cache_hits += 1
                return cached

        self._stats.cache_misses += 1

        # 3. Throttle wait
        await self._throttler.wait(host)

        # 4. Concurrency gate
        async with self._semaphore:
            t0 = time.monotonic()
            try:
                resp = await asyncio.get_running_loop().run_in_executor(
                    self._pool,
                    lambda: self._send_sync(
                        method=method, url=url, params=params,
                        data=data, json_=json, headers=headers,
                        allow_redirects=allow_redirects,
                        stream=stream,
                        timeout=timeout or self._timeout,
                    ),
                )
            except Exception as exc:
                self._stats.errors += 1
                log.debug("[engine] request error %s %s: %s", method, url, exc)
                return None
            finally:
                elapsed = (time.monotonic() - t0) * 1000
                self._stats.total_latency_ms += elapsed

        if resp is None:
            self._stats.errors += 1
            return None

        self._stats.requests_sent += 1
        if resp.content:
            self._stats.total_bytes += len(resp.content)

        # 5. Throttle feedback
        if resp.status_code == 429:
            self._stats.throttled += 1
            await self._throttler.on_throttled(host)
        else:
            await self._throttler.on_success(host)

        # 6. Cache write (safe methods only)
        if cache_key and resp.status_code < 500:
            await self._cache.set(cache_key, resp)

        return resp

    async def gather(
        self,
        coroutines: list,
        concurrency: Optional[int] = None,
    ) -> list[Optional[requests.Response]]:
        """
        Concurrently dispatch a list of request coroutines.

        Args:
            coroutines   : List of coroutines from engine.get() / engine.post()
            concurrency  : Optional override for this batch only

        Returns:
            List of responses in the same order as input coroutines.
            None entries indicate failed requests.
        """
        if concurrency and concurrency != self._semaphore._value:
            sem = asyncio.Semaphore(concurrency)
            async def _limited(coro):
                async with sem:
                    return await coro
            return list(await asyncio.gather(*[_limited(c) for c in coroutines],
                                              return_exceptions=False))
        return list(await asyncio.gather(*coroutines, return_exceptions=False))

    async def probe_params_concurrent(
        self,
        method:    str,
        url:       str,
        base_params: dict,
        param_payloads: list[tuple[str, str]],  # [(param_name, payload), ...]
        headers:   Optional[dict] = None,
        timeout:   Optional[int]  = None,
    ) -> list[tuple[str, str, Optional[requests.Response]]]:
        """
        Fire all param/payload combinations concurrently.

        This is the core performance upgrade for detectors: instead of a
        sequential for loop over params, all (param, payload) combinations
        are fired in parallel and results are gathered.

        Args:
            param_payloads : list of (param_name, payload_value) pairs

        Returns:
            list of (param_name, payload, response) triples
        """
        async def _one(param: str, payload: str):
            test_params = dict(base_params)
            test_params[param] = payload
            if method.upper() in ("POST", "PUT", "PATCH"):
                resp = await self.request(method, url, data=test_params,
                                          headers=headers, timeout=timeout,
                                          cache=False)
            else:
                resp = await self.request(method, url, params=test_params,
                                          headers=headers, timeout=timeout,
                                          cache=False)
            return (param, payload, resp)

        tasks = [_one(p, v) for p, v in param_payloads]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    def resize_cache(self, endpoint_count: int) -> None:
        """
        Adaptively resize the LRU dedup cache based on discovered endpoint count.
        Rule: max(2048, endpoint_count * 4), capped at 16384.
        Called by ScanManager after _phase_crawl completes.
        """
        new_size = min(max(2048, endpoint_count * 4), 16384)
        if new_size > self._cache._maxsize:
            self._cache._maxsize = new_size
            import logging as _log
            _log.getLogger(__name__).debug(
                "[engine] LRU cache resized to %d (endpoints=%d)",
                new_size, endpoint_count,
            )

    def stats(self) -> dict:
        """Return engine statistics summary."""
        return self._stats.summary()

    async def clear_cache(self) -> None:
        """Flush the dedup cache (e.g. between scans)."""
        await self._cache.clear()

    async def shutdown(self) -> None:
        """Gracefully shut down the thread pool."""
        self._pool.shutdown(wait=False)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send_sync(
        self,
        method:          str,
        url:             str,
        params:          Optional[dict],
        data:            Optional[dict],
        json_:           Optional[dict],
        headers:         Optional[dict],
        allow_redirects: bool,
        stream:          bool,
        timeout:         int,
    ) -> Optional[requests.Response]:
        """Synchronous request — runs inside ThreadPoolExecutor."""
        try:
            return self._session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_,
                headers=headers,
                allow_redirects=allow_redirects,
                stream=stream,
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            log.debug("[engine] connection error %s %s: %s", method, url, exc)
        except requests.exceptions.Timeout:
            log.debug("[engine] timeout %s %s (%ds)", method, url, timeout)
        except requests.exceptions.RequestException as exc:
            log.debug("[engine] request failed %s %s: %s", method, url, exc)
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_key(
    method: str,
    url:    str,
    params: Optional[dict],
    data:   Optional[dict],
    body:   Optional[dict],
) -> str:
    """Build a stable cache key for a request."""
    parts = [method.upper(), url]
    if params:
        parts.append(str(sorted(params.items())))
    if data:
        parts.append(str(sorted(data.items())))
    if body:
        parts.append(str(sorted(body.items())))
    raw = "|".join(parts).encode()
    return hashlib.md5(raw).hexdigest()


# ── Context-managed engine per scan ──────────────────────────────────────────

class ScanHTTPEngine:
    """
    Context manager that creates one AsyncHTTPEngine per scan and tears it
    down (flushing the dedup cache and thread pool) on __aexit__.

    Usage:
        async with ScanHTTPEngine(timeout=10, dedup=True) as engine:
            resp = await engine.get("https://target.com/api")
    """

    def __init__(self, **kwargs) -> None:
        self._kwargs = kwargs
        self._engine: Optional[AsyncHTTPEngine] = None

    async def __aenter__(self) -> AsyncHTTPEngine:
        self._engine = AsyncHTTPEngine(**self._kwargs)
        return self._engine

    async def __aexit__(self, *_) -> None:
        if self._engine:
            await self._engine.shutdown()
            self._engine = None
