"""
core/endpoint_queue.py — Plasma v3
────────────────────────────────────
Thread-safe, priority-ordered endpoint queue for the scan pipeline.

The EndpointQueue is the central coordination point between all discovery
sources (static crawler, browser, JS extraction, subdomain scan, param
discovery) and the detection + fuzzing consumers.

Design
──────
  • Priority levels: CRITICAL (0) > HIGH (1) > NORMAL (2) > LOW (3)
  • Deduplication by (url, method, frozenset(params.keys()))
  • Tag-based filtering (e.g. 'browser', 'js-extracted', 'subdomain')
  • Thread-safe — all sources can push concurrently
  • Async-compatible — async_drain() yields batches for asyncio consumers
  • Statistics: tracks source counts, dedup hits, priority distribution

Usage
─────
    queue = EndpointQueue()

    # Producers (any thread / coroutine)
    queue.push(endpoint, priority=Priority.HIGH, source="browser")
    queue.push_many(endpoints, source="crawler")

    # Consumers
    async for batch in queue.async_drain(batch_size=10):
        await run_detectors(batch)

    # Filter view
    browser_eps = queue.filter(tags=["browser"])

    # Stats
    print(queue.stats())
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Iterable, Iterator, Optional

from core.models import Endpoint

log = logging.getLogger(__name__)


class Priority(IntEnum):
    """Endpoint processing priority — lower number = higher priority."""
    CRITICAL = 0   # Login/admin endpoints, confirmed attack surface
    HIGH     = 1   # State-changing (POST/PUT/DELETE), file upload endpoints
    NORMAL   = 2   # Standard GET endpoints with parameters
    LOW      = 3   # Static assets, no-parameter pages, subdomains


@dataclass(order=True)
class _QueueEntry:
    """Internal priority queue entry."""
    priority:  int
    seq:       int                  # tie-breaker: insertion order
    endpoint:  Endpoint = field(compare=False)
    source:    str       = field(compare=False, default="unknown")
    tags:      list[str] = field(compare=False, default_factory=list)


def _endpoint_key(ep: Endpoint) -> str:
    """Stable deduplication key for an endpoint."""
    param_sig = "|".join(sorted(ep.parameters.keys() if ep.parameters else []))
    raw = f"{ep.method.upper()}|{ep.url}|{param_sig}"
    return hashlib.md5(raw.encode()).hexdigest()


class EndpointQueue:
    """
    Priority-ordered, deduplicated endpoint queue.

    Thread-safe: all public methods acquire a lock.
    Async-compatible: async_drain() wraps get operations in run_in_executor.
    """

    def __init__(self) -> None:
        self._entries:   list[_QueueEntry]  = []
        self._seen:      set[str]            = set()
        self._lock:      threading.Lock      = threading.Lock()
        self._seq:       int                 = 0

        # Statistics
        self._total_pushed: int              = 0
        self._dedup_hits:   int              = 0
        self._source_counts: dict[str, int]  = {}
        self._priority_counts: dict[int, int] = {p.value: 0 for p in Priority}

    # ── Producer API ──────────────────────────────────────────────────────────

    def push(
        self,
        endpoint:  Endpoint,
        priority:  Priority = Priority.NORMAL,
        source:    str       = "unknown",
        extra_tags: list[str] = None,
    ) -> bool:
        """
        Add an endpoint to the queue.

        Returns True if the endpoint was added, False if it was a duplicate.
        """
        key = _endpoint_key(endpoint)
        with self._lock:
            if key in self._seen:
                self._dedup_hits += 1
                return False

            self._seen.add(key)
            tags = list(endpoint.tags or []) + (extra_tags or [])
            entry = _QueueEntry(
                priority=int(priority),
                seq=self._seq,
                endpoint=endpoint,
                source=source,
                tags=tags,
            )
            # Insert in sorted position (maintain heap property via bisect)
            import bisect
            bisect.insort(self._entries, entry)
            self._seq += 1
            self._total_pushed += 1
            self._source_counts[source] = self._source_counts.get(source, 0) + 1
            self._priority_counts[int(priority)] = \
                self._priority_counts.get(int(priority), 0) + 1
            return True

    def push_many(
        self,
        endpoints: Iterable[Endpoint],
        priority:  Priority = Priority.NORMAL,
        source:    str       = "unknown",
    ) -> int:
        """Push multiple endpoints. Returns count of new (non-duplicate) entries."""
        added = 0
        for ep in endpoints:
            added += int(self.push(ep, priority=priority, source=source))
        return added

    def push_browser_result(self, result) -> int:
        """
        Ingest a BrowserCrawler CrawlResult into the queue.

        Tags endpoints by source type (browser, xhr, websocket, js-extracted).
        State-changing endpoints get HIGH priority; others NORMAL.
        """
        added = 0
        for ep in result.endpoints:
            tags = list(ep.tags or [])
            prio = Priority.HIGH if ep.is_state_changing else Priority.NORMAL
            added += int(self.push(ep, priority=prio, source="browser", extra_tags=tags))
        return added

    # ── Consumer API ──────────────────────────────────────────────────────────

    def pop(self) -> Optional[Endpoint]:
        """Remove and return the highest-priority endpoint, or None if empty."""
        with self._lock:
            if not self._entries:
                return None
            return self._entries.pop(0).endpoint

    def peek(self) -> Optional[Endpoint]:
        """Return the highest-priority endpoint without removing it."""
        with self._lock:
            return self._entries[0].endpoint if self._entries else None

    def pop_batch(self, n: int) -> list[Endpoint]:
        """Remove and return up to n highest-priority endpoints."""
        with self._lock:
            batch = self._entries[:n]
            self._entries = self._entries[n:]
            return [e.endpoint for e in batch]

    async def async_drain(
        self,
        batch_size: int = 20,
        loop:       Optional[asyncio.AbstractEventLoop] = None,
    ) -> "AsyncGenerator[list[Endpoint], None]":
        """
        Async generator that yields batches of endpoints until the queue is empty.

        Usage:
            async for batch in queue.async_drain(batch_size=20):
                await process(batch)
        """
        while True:
            batch = self.pop_batch(batch_size)
            if not batch:
                break
            yield batch
            await asyncio.sleep(0)   # yield control to event loop

    def drain(self) -> list[Endpoint]:
        """Return all endpoints in priority order and clear the queue."""
        with self._lock:
            result = [e.endpoint for e in self._entries]
            self._entries.clear()
            return result

    def __iter__(self) -> Iterator[Endpoint]:
        """Iterate all endpoints in priority order (non-destructive)."""
        with self._lock:
            return iter([e.endpoint for e in list(self._entries)])

    # ── Query API ─────────────────────────────────────────────────────────────

    def filter(
        self,
        tags:          Optional[list[str]] = None,
        source:        Optional[str]       = None,
        min_priority:  Optional[Priority]  = None,
        predicate:     Optional[Callable[[Endpoint], bool]] = None,
    ) -> list[Endpoint]:
        """
        Return endpoints matching all specified criteria (non-destructive).

        Args:
            tags         : Endpoint must have ALL listed tags
            source       : Endpoint must come from this source
            min_priority : Only return endpoints at or above this priority
            predicate    : Arbitrary filter function
        """
        with self._lock:
            results = []
            for entry in self._entries:
                if tags and not all(t in entry.tags for t in tags):
                    continue
                if source and entry.source != source:
                    continue
                if min_priority is not None and entry.priority > int(min_priority):
                    continue
                if predicate and not predicate(entry.endpoint):
                    continue
                results.append(entry.endpoint)
            return results

    @property
    def size(self) -> int:
        """Current number of queued endpoints."""
        with self._lock:
            return len(self._entries)

    def __len__(self) -> int:
        return self.size

    def is_empty(self) -> bool:
        return self.size == 0

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return a statistics summary."""
        with self._lock:
            return {
                "queued":         len(self._entries),
                "total_pushed":   self._total_pushed,
                "dedup_hits":     self._dedup_hits,
                "unique_ratio":   round(
                    (self._total_pushed - self._dedup_hits) / max(self._total_pushed, 1), 3
                ),
                "by_source":      dict(self._source_counts),
                "by_priority":    {
                    Priority(k).name: v
                    for k, v in self._priority_counts.items()
                },
            }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"EndpointQueue(queued={s['queued']}, "
            f"total={s['total_pushed']}, dedup={s['dedup_hits']})"
        )
