"""
core/recon/subdomain_discovery.py — WebGuard v3
─────────────────────────────────────────────────
DNS-based subdomain enumeration using a wordlist.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from config import SUBDOMAIN_WORDLIST, SUBDOMAIN_CONCURRENCY, SUBDOMAIN_TIMEOUT

log = logging.getLogger(__name__)


class SubdomainDiscovery:
    """
    Discovers subdomains by brute-forcing a wordlist of prefixes.

    Usage:
        disc = SubdomainDiscovery("https://example.com")
        subdomains = await disc.discover()
        # → ["admin.example.com", "api.example.com", ...]
    """

    def __init__(
        self,
        target_url: str,
        wordlist:   Optional[str] = None,
        concurrency: int = SUBDOMAIN_CONCURRENCY,
    ) -> None:
        parsed = urlparse(target_url)
        self.base_domain  = parsed.netloc.split(":")[0]
        self.scheme       = parsed.scheme
        self.wordlist     = wordlist or SUBDOMAIN_WORDLIST
        self.concurrency  = concurrency
        self._found: list[str] = []

    async def discover(self) -> list[str]:
        """Return a list of discovered live subdomains."""
        prefixes = self._load_wordlist()
        if not prefixes:
            log.warning("SubdomainDiscovery: no wordlist loaded from %s", self.wordlist)
            return []

        log.info("SubdomainDiscovery: testing %d subdomains for %s",
                 len(prefixes), self.base_domain)

        sem = asyncio.Semaphore(self.concurrency)

        async def _check(prefix: str) -> Optional[str]:
            hostname = f"{prefix}.{self.base_domain}"
            async with sem:
                if await self._resolves(hostname):
                    url = f"{self.scheme}://{hostname}"
                    log.info("  Found subdomain: %s", url)
                    return url
            return None

        results = await asyncio.gather(*[_check(p) for p in prefixes])
        found = [r for r in results if r is not None]
        self._found = found
        log.info("SubdomainDiscovery: %d live subdomains found", len(found))
        return found

    @staticmethod
    async def _resolves(hostname: str) -> bool:
        """Non-blocking DNS lookup."""
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, hostname),
                timeout=SUBDOMAIN_TIMEOUT,
            )
            return True
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            return False

    def _load_wordlist(self) -> list[str]:
        try:
            path = Path(self.wordlist)
            if not path.exists():
                # Fallback built-in mini wordlist
                return self._builtin_wordlist()
            lines = path.read_text(errors="ignore").splitlines()
            return [l.strip() for l in lines if l.strip() and not l.startswith("#")][:5000]
        except Exception:
            return self._builtin_wordlist()

    @staticmethod
    def _builtin_wordlist() -> list[str]:
        return [
            "www", "api", "admin", "mail", "ftp", "dev", "staging", "test",
            "portal", "app", "mobile", "beta", "cdn", "static", "assets",
            "auth", "login", "dashboard", "secure", "vpn", "remote", "uat",
            "preprod", "qa", "demo", "support", "helpdesk", "shop",
        ]
