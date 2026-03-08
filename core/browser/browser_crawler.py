"""
core/browser/browser_crawler.py — Plasma v3.2
───────────────────────────────────────────────
Headless browser crawler using Playwright for JavaScript-heavy SPAs.

Upgrades vs v3.1
─────────────────
• Auth cookie / header injection before crawl
• Custom user-agent (stealth support)
• localStorage + sessionStorage capture (secrets, tokens)
• Console.log capture (debug info disclosure)
• WebSocket URL interception
• JS endpoint extraction from inline <script> blocks
• Graceful CAPTCHA / error recovery with configurable timeout
• Background request recorder feeds into endpoint queue
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from core.models import Endpoint

log = logging.getLogger(__name__)

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    log.debug(
        "Playwright not installed — browser mode unavailable. "
        "Install: pip install playwright && playwright install chromium"
    )

# Patterns that identify API / endpoint URLs in intercepted traffic
_API_URL_RE = re.compile(
    r"/api/|/v\d+/|/rest/|/graphql|\.json|/search|/query|/submit|/upload",
    re.I,
)
# JS endpoint patterns extracted from page source
_JS_URL_RE  = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post)|XMLHttpRequest)\s*\(\s*[\'\"]((?:/|https?://)[^\'\"\ ]+)""",
    re.I,
)


class BrowserCrawler:
    """
    Playwright-based crawler for JavaScript-heavy applications.

    Capabilities
    ─────────────
    - Full JS execution (React, Vue, Angular, vanilla)
    - Dynamic form detection (post-JS-render)
    - XHR / fetch / axios request interception
    - WebSocket URL capture
    - Auth cookie + header injection
    - localStorage / sessionStorage capture
    - Console.log capture (info disclosure)
    - JS endpoint URL extraction from <script> blocks
    - Screenshot per page
    - CAPTCHA / WAF block detection with graceful fallback
    - Custom user-agent (stealth mode)

    Usage
    ──────
        crawler = BrowserCrawler(
            "https://target.com",
            auth_cookies={"session": "abc123"},
            user_agent="Mozilla/5.0 ...",
        )
        if BrowserCrawler.is_available():
            result = await crawler.crawl()
            # result.endpoints  → list[Endpoint]
            # result.js_urls    → raw intercepted URLs
            # result.storage    → localStorage/sessionStorage data
            # result.console    → captured console.log output
    """

    def __init__(
        self,
        target_url:     str,
        max_pages:      int               = 20,
        screenshot_dir: str               = "screenshots",
        auth_cookies:   Optional[dict]    = None,
        auth_headers:   Optional[dict]    = None,
        user_agent:     Optional[str]     = None,
        timeout_ms:     int               = 20_000,
        stealth:        bool              = False,
        page_delay_ms:  int               = 500,
    ) -> None:
        self.target_url     = target_url
        self.max_pages      = max_pages
        self.screenshot_dir = screenshot_dir
        self.auth_cookies   = auth_cookies or {}
        self.auth_headers   = auth_headers or {}
        self.user_agent     = user_agent or _DEFAULT_USER_AGENT
        self.timeout_ms     = timeout_ms
        self.stealth        = stealth
        # Rate limiting: minimum delay between page navigations (ms)
        # Stealth mode triples this to reduce fingerprinting
        self.page_delay_ms  = page_delay_ms * 3 if stealth else page_delay_ms
        # Parallel page count (default 1 = sequential, safe; set via --browser-parallel)
        self.parallel_pages = 1  # set externally by ScanManager

        # Collected during crawl
        self._intercepted_urls:  list[str]       = []
        self._websocket_urls:    list[str]        = []
        self._console_messages:  list[str]        = []
        self._storage_data:      dict[str, dict]  = {}

    # ── Public API ────────────────────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        return PLAYWRIGHT_AVAILABLE

    async def crawl(self) -> "CrawlResult":
        """
        Crawl the target and return a CrawlResult.

        Returns a CrawlResult even on failure (empty, with error recorded).
        Never raises — all errors are captured and logged.
        """
        result = CrawlResult()
        if not PLAYWRIGHT_AVAILABLE:
            log.warning(
                "Browser mode unavailable: Playwright not installed. "
                "Fix: pip install playwright && playwright install chromium"
            )
            result.error = "Playwright not installed"
            return result

        try:
            await self._run_crawl(result)
        except Exception as exc:
            log.warning("BrowserCrawler: crawl failed: %s", exc)
            result.error = str(exc)
        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _run_crawl(self, result: "CrawlResult") -> None:
        visited: set[str] = set()

        async with async_playwright() as pw:
            launch_opts: dict = {"headless": True}
            if self.stealth:
                launch_opts["args"] = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ]

            browser = await pw.chromium.launch(**launch_opts)
            context = await browser.new_context(
                user_agent=self.user_agent,
                extra_http_headers=self.auth_headers,
            )

            # Inject auth cookies before first navigation
            if self.auth_cookies:
                parsed = urlparse(self.target_url)
                base   = f"{parsed.scheme}://{parsed.netloc}"
                await context.add_cookies([
                    {"name": k, "value": v, "url": base}
                    for k, v in self.auth_cookies.items()
                ])

            page = await context.new_page()

            # Wire up interceptors
            await page.route("**/*", self._intercept_route)
            page.on("websocket", lambda ws: self._websocket_urls.append(ws.url))
            page.on("console",   lambda msg: self._console_messages.append(
                f"[{msg.type}] {msg.text}"))

            # ── Parallel BFS crawl ─────────────────────────────────────────
            # parallel_pages=1 → sequential (default/safe); N>1 → parallel.
            n_parallel = max(1, getattr(self, "parallel_pages", 1))
            queue: list[str] = [self.target_url]
            sem   = asyncio.Semaphore(n_parallel)

            async def _visit(page_ctx, url: str) -> tuple[list, list, dict, str | None]:
                """Visit one URL, return (endpoints, links, storage, error)."""
                async with sem:
                    try:
                        page_eps, links = await self._crawl_page(page_ctx, url)
                        storage = await self._capture_storage(page_ctx)
                        if self.page_delay_ms > 0:
                            await asyncio.sleep(self.page_delay_ms / 1000)
                        return page_eps, links, storage, None
                    except Exception as exc:
                        return [], [], {}, str(exc)

            while queue and len(visited) < self.max_pages:
                # Take a batch of up to n_parallel URLs
                batch: list[str] = []
                while queue and len(batch) < n_parallel and len(visited) < self.max_pages:
                    candidate = queue.pop(0)
                    if candidate not in visited:
                        visited.add(candidate)
                        batch.append(candidate)

                if not batch:
                    break

                if n_parallel > 1:
                    # Open separate pages for parallel crawling
                    pages_ctx = [
                        await context.new_page() for _ in range(len(batch))
                    ]
                    for p in pages_ctx:
                        await p.route("**/*", self._intercept_route)
                        p.on("websocket", lambda ws: self._websocket_urls.append(ws.url))
                else:
                    pages_ctx = [page]

                tasks = [
                    _visit(pages_ctx[min(i, len(pages_ctx)-1)], url)
                    for i, url in enumerate(batch)
                ]
                batch_results = await asyncio.gather(*tasks)

                if n_parallel > 1:
                    for p in pages_ctx:
                        try: await p.close()
                        except Exception: pass

                for (page_eps, links, storage, error), url in zip(batch_results, batch):
                    if error:
                        log.debug("BrowserCrawler: page error %s: %s", url, error)
                        result.errors.append(f"{url}: {error}")
                        continue
                    result.endpoints.extend(page_eps)
                    if storage:
                        result.storage[url] = storage
                    for link in links:
                        if urlparse(link).netloc == urlparse(self.target_url).netloc:
                            if link not in visited:
                                queue.append(link)

            await browser.close()

        # Dedup and attach intercepted API endpoints
        known = {ep.url for ep in result.endpoints}
        for api_url in self._intercepted_urls:
            if api_url not in known:
                result.endpoints.append(
                    Endpoint(url=api_url, method="GET", tags=["browser", "xhr"]))
                known.add(api_url)
        for ws_url in self._websocket_urls:
            if ws_url not in known:
                result.endpoints.append(
                    Endpoint(url=ws_url, method="GET", tags=["browser", "websocket"]))
                known.add(ws_url)

        result.console    = list(self._console_messages)
        result.js_urls    = list(self._intercepted_urls) + list(self._websocket_urls)

        log.info(
            "BrowserCrawler: %d endpoints, %d XHR, %d WS from %d pages visited",
            len(result.endpoints),
            len(self._intercepted_urls),
            len(self._websocket_urls),
            len(visited),
        )

    async def _crawl_page(
        self, page, url: str
    ) -> tuple[list[Endpoint], list[str]]:
        """Navigate to a page, extract forms + links + inline JS endpoints."""
        endpoints: list[Endpoint] = []

        # Navigate with timeout + graceful CAPTCHA detection
        try:
            resp = await page.goto(
                url, wait_until="networkidle", timeout=self.timeout_ms
            )
        except Exception as exc:
            # domcontentloaded fallback for slow pages
            try:
                resp = await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.timeout_ms
                )
            except Exception:
                raise exc

        # Check for CAPTCHA / WAF block
        title = await page.title()
        if any(w in title.lower() for w in ("captcha", "blocked", "access denied", "cloudflare")):
            log.warning("BrowserCrawler: possible CAPTCHA/WAF block on %s (title: %s)", url, title)

        # Extract forms
        forms = await page.query_selector_all("form")
        for form in forms:
            action   = await form.get_attribute("action") or url
            method   = (await form.get_attribute("method") or "GET").upper()
            full_url = urljoin(url, action)
            params: dict[str, str] = {}
            inputs = await form.query_selector_all("input, select, textarea")
            for inp in inputs:
                name  = await inp.get_attribute("name") or ""
                value = await inp.get_attribute("value") or ""
                if name:
                    params[name] = value
            endpoints.append(Endpoint(
                url=full_url, method=method, parameters=params,
                source_page=url,
                is_state_changing=method in ("POST", "PUT", "PATCH", "DELETE"),
                tags=["browser"],
            ))

        # Extract JS-referenced endpoints from <script> blocks
        scripts = await page.eval_on_selector_all(
            "script:not([src])", "els => els.map(e => e.textContent)"
        )
        for script_text in scripts:
            for js_url in _JS_URL_RE.findall(script_text or ""):
                full = urljoin(url, js_url)
                endpoints.append(Endpoint(
                    url=full, method="GET", tags=["browser", "js-extracted"]
                ))

        # Extract navigation links
        hrefs = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)"
        )

        # Screenshot
        await self.screenshot(page, url)

        return endpoints, hrefs

    async def _intercept_route(self, route) -> None:
        """Capture XHR/fetch URLs matching API patterns."""
        url = route.request.url
        if _API_URL_RE.search(url):
            self._intercepted_urls.append(url)
        await route.continue_()

    async def _capture_storage(self, page) -> dict:
        """Capture localStorage and sessionStorage (may contain tokens/secrets)."""
        try:
            return await page.evaluate("""() => {
                const ls = {};
                const ss = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    ls[k] = localStorage.getItem(k);
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    ss[k] = sessionStorage.getItem(k);
                }
                return {localStorage: ls, sessionStorage: ss};
            }""")
        except Exception:
            return {}

    async def screenshot(self, page, url: str) -> Optional[str]:
        """Take a full-page screenshot; returns path or None on failure."""
        try:
            os.makedirs(self.screenshot_dir, exist_ok=True)
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", url)[:80]
            path = os.path.join(self.screenshot_dir, f"{safe}.png")
            await page.screenshot(path=path, full_page=True)
            return path
        except Exception as exc:
            log.debug("Screenshot failed for %s: %s", url, exc)
        return None


# ── Result container ──────────────────────────────────────────────────────────

class CrawlResult:
    """
    Output from BrowserCrawler.crawl().

    Attributes
    ──────────
    endpoints : All Endpoint objects discovered (forms + XHR + WS + JS-extracted)
    js_urls   : Raw intercepted URL strings (XHR + WebSocket)
    storage   : {page_url: {localStorage: {...}, sessionStorage: {...}}}
    console   : List of console.log messages captured during crawl
    errors    : Non-fatal page-level errors
    error     : Top-level error string (set if crawl failed entirely)
    """
    def __init__(self) -> None:
        self.endpoints: list[Endpoint]       = []
        self.js_urls:   list[str]            = []
        self.storage:   dict[str, dict]      = {}
        self.console:   list[str]            = []
        self.errors:    list[str]            = []
        self.error:     Optional[str]        = None


# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
