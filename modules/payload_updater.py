"""
modules/payload_updater.py — Plasma v3
───────────────────────────────────────
PayloadUpdater: auto-fetch and cache external payload lists.

Fetches from FUZZ_PAYLOAD_UPDATE_URL (config) or any custom URL.
Cache is stored in payloads/_remote_cache/ with mtime-based daily refresh.

Usage
─────
    from modules.payload_updater import PayloadUpdater
    updater = PayloadUpdater()
    payloads = updater.get("sqli")   # returns list[str], auto-refreshes if stale

    # Custom remote source
    payloads = updater.fetch_url("https://raw.githubusercontent.com/.../sqli.txt")

    # Force refresh all cached lists
    updater.refresh_all()

Supported auto-sources
──────────────────────
  Built-in aliases map short names to known raw URLs from PayloadsAllTheThings / SecLists.
  Add entries to _KNOWN_SOURCES to register new remote lists.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from config import FUZZ_PAYLOAD_UPDATE_URL

log = logging.getLogger(__name__)

# Cache TTL: 24 hours
_CACHE_TTL_SECONDS = 86_400

_CACHE_DIR = Path(__file__).parent.parent / "payloads" / "_remote_cache"

# Known remote payload sources (short-name → raw URL)
_KNOWN_SOURCES: dict[str, str] = {
    "sqli":        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_ErrorBased.txt",
    "xss":         "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
    "ssrf":        "https://raw.githubusercontent.com/payloadbox/ssrf-payload-list/master/SSRF-Payloads.txt",
    "traversal":   "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
    "rce":         "https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/Generic-Payloads.txt",
    "parameters":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
}

# Register custom URL from config if set
if FUZZ_PAYLOAD_UPDATE_URL:
    _KNOWN_SOURCES["custom"] = FUZZ_PAYLOAD_UPDATE_URL


class PayloadUpdater:
    """
    Manages remote payload list fetching, caching, and auto-refresh.

    Thread-safe reads; writes are guarded by a simple file-lock pattern
    (atomic rename on write).
    """

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self._cache_dir = cache_dir or _CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._mem: dict[str, list[str]] = {}   # in-process cache

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, source: str, force: bool = False) -> list[str]:
        """
        Return payloads for a known source alias, refreshing if stale.

        Args:
            source : alias from _KNOWN_SOURCES (e.g. "sqli", "xss")
            force  : bypass TTL and re-fetch

        Returns:
            list[str] — deduplicated, comment-stripped payload lines.
            Empty list if source is unknown or network unavailable.
        """
        if source in self._mem and not force:
            return self._mem[source]

        url = _KNOWN_SOURCES.get(source)
        if not url:
            log.debug("[payload_updater] unknown source: %s", source)
            return []

        return self._load_or_fetch(source, url, force=force)

    def fetch_url(self, url: str, alias: Optional[str] = None) -> list[str]:
        """
        Fetch payloads from any URL (not limited to known sources).

        Args:
            url   : full HTTPS URL pointing to a text payload list
            alias : optional cache key; defaults to URL hash

        Returns:
            list[str] — lines from the remote file (comments stripped).
        """
        import hashlib
        key = alias or hashlib.md5(url.encode()).hexdigest()[:12]
        return self._load_or_fetch(key, url, force=False)

    def refresh_all(self) -> dict[str, int]:
        """
        Force-refresh every known source.
        Returns {source: count} mapping.
        """
        results: dict[str, int] = {}
        for alias in _KNOWN_SOURCES:
            payloads = self.get(alias, force=True)
            results[alias] = len(payloads)
            log.info("[payload_updater] refreshed %-14s → %d payloads", alias, len(payloads))
        return results

    def list_sources(self) -> dict[str, str]:
        """Return the registered source alias → URL mapping."""
        return dict(_KNOWN_SOURCES)

    def add_source(self, alias: str, url: str) -> None:
        """Register a custom remote source at runtime."""
        _KNOWN_SOURCES[alias] = url
        log.debug("[payload_updater] registered source: %s → %s", alias, url)

    def cache_stats(self) -> dict[str, dict]:
        """Return cache file stats (size, age) for each known source."""
        stats: dict[str, dict] = {}
        for alias in _KNOWN_SOURCES:
            path = self._cache_path(alias)
            if path.exists():
                age   = time.time() - path.stat().st_mtime
                lines = sum(1 for _ in path.open())
                stats[alias] = {
                    "path":       str(path),
                    "age_hours":  round(age / 3600, 1),
                    "stale":      age > _CACHE_TTL_SECONDS,
                    "payload_count": lines,
                }
            else:
                stats[alias] = {"cached": False}
        return stats

    # ── Internal ───────────────────────────────────────────────────────────────

    def _cache_path(self, alias: str) -> Path:
        safe = alias.replace("/", "_").replace(":", "_")
        return self._cache_dir / f"{safe}.txt"

    def _is_stale(self, path: Path) -> bool:
        if not path.exists():
            return True
        return (time.time() - path.stat().st_mtime) > _CACHE_TTL_SECONDS

    def _load_or_fetch(self, alias: str, url: str, force: bool) -> list[str]:
        path = self._cache_path(alias)

        if not force and not self._is_stale(path):
            payloads = self._read_cache(path)
            if payloads:
                self._mem[alias] = payloads
                return payloads

        # Attempt network fetch
        try:
            raw = self._http_get(url, timeout=15)
            payloads = self._parse_lines(raw)
            if payloads:
                self._write_cache(path, payloads)
                self._mem[alias] = payloads
                log.info("[payload_updater] fetched %-14s → %d payloads", alias, len(payloads))
                return payloads
        except Exception as exc:
            log.warning("[payload_updater] fetch failed for %s (%s): %s", alias, url, exc)

        # Fallback: stale cache is better than nothing
        if path.exists():
            payloads = self._read_cache(path)
            if payloads:
                log.debug("[payload_updater] using stale cache for %s", alias)
                self._mem[alias] = payloads
                return payloads

        return []

    @staticmethod
    def _http_get(url: str, timeout: int = 15) -> str:
        """Minimal HTTP GET — no external dependency beyond stdlib."""
        req = urllib.request.Request(url, headers={"User-Agent": "Plasma/3 PayloadUpdater"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    @staticmethod
    def _parse_lines(raw: str) -> list[str]:
        """Strip blank lines and comments; deduplicate while preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                seen.add(line)
                result.append(line)
        return result

    @staticmethod
    def _read_cache(path: Path) -> list[str]:
        try:
            return [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except Exception:
            return []

    @staticmethod
    def _write_cache(path: Path, payloads: list[str]) -> None:
        """Atomic write via temp-file + rename."""
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text("\n".join(payloads), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            log.debug("[payload_updater] write failed: %s", exc)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
