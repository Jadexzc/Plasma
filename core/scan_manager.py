"""
core/scan_manager.py — Plasma v3
-----------------------------------
Extended scan orchestrator with auth, recon, passive analysis, templates, and plugins.
Preserves all v2 architecture: async pipeline, per-scan queues, SSE streaming.

Production optimisations
------------------------
1. _phase_detect: early cancelled-state check inside the task loop avoids
   submitting work that will never be used.

2. _phase_detect: task count for progress is computed once up-front instead
   of calling max(n_tasks, 1) in the inner loop on every completion.

3. _extract_js_endpoints: duplicate URL check changed from O(n) linear scan
   to O(1) set lookup.  A local set `_existing_urls` is built once (O(n))
   then reused for every newly extracted endpoint (O(1) per check).

4. Registry.disable() race on batch scans: each scan now takes a per-scan
   snapshot of disabled detector names and disables them on a fresh list
   derived per-context, avoiding mutation of the shared registry state.
   (Full fix requires per-scan registry copies; the safe minimal fix is to
   re-enable any detectors disabled for a scan when that scan finishes,
   which is implemented in _phase_auth via a finally-style approach.)

5. import time moved to module level (was inside _test_time_based in sqli).

6. _phase_risk_engine: sorting findings by severity uses the pre-computed
   _SEVERITY_RANK constant (imported from models) instead of rebuilding a
   dict literal on every sort key evaluation.
"""
from __future__ import annotations

import asyncio
import logging
import queue as _queue
from datetime import datetime
from typing import Optional

from core.endpoint_queue import EndpointQueue, Priority
from core.attack_surface import AttackSurfaceMapper
from config import (
    DEFAULT_CRAWL_DEPTH, DEFAULT_TIMEOUT, DEFAULT_SCAN_PROFILE,
    MAX_CONCURRENT_DETECTORS, SCAN_PROFILES,
)
from core.crawler import Crawler
from core.cookie_analyzer import CookieAnalyzer
from core.detector_registry import DetectorRegistry
from core.endpoint_classifier import EndpointClassifier
from core.models import (
    _SEVERITY_RANK,           # re-use the already-allocated rank map
    Endpoint, Finding, ScanContext, ScanSettings, ScanState,
)
from core.samesite_model import SameSiteModel
from core.token_analyzer import TokenAnalyzer

log = logging.getLogger(__name__)


class ScanManager:
    """
    Plasma v3 scan orchestrator.

    New phases vs v2:
      - Phase 0:   Auth (login before crawling if configured)
      - Phase 1.5: Recon (subdomains, JS extraction, tech detection)
      - Phase 4.5: Passive analysis + template scanning
      - Phase 4.7: Plugin/template checks
    """

    def __init__(
        self,
        registry:    DetectorRegistry | None = None,
        event_queue  = None,
    ) -> None:
        self._registry    = registry or DetectorRegistry()
        self._registry.load_all()
        self._event_queue = event_queue
        self._scan_queues: dict[str, _queue.SimpleQueue] = {}
        # Semaphore is created lazily on first scan inside a running event loop
        self._semaphore: asyncio.Semaphore | None = None
        self._active_scans: dict[str, ScanContext] = {}

    # -- Public API -----------------------------------------------------------

    def create_context(
        self,
        target_url: str,
        settings:   ScanSettings | None = None,
    ) -> ScanContext:
        ctx = ScanContext(
            target_url=target_url,
            settings=settings or ScanSettings(),
        )
        self._active_scans[ctx.scan_id] = ctx
        self._scan_queues[ctx.scan_id]  = _queue.SimpleQueue()
        return ctx

    def get_scan_queue(self, scan_id: str) -> _queue.SimpleQueue | None:
        return self._scan_queues.get(scan_id)

    async def scan(self, context: ScanContext) -> ScanContext:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_DETECTORS)
        context.state      = ScanState.RUNNING
        context.start_time = datetime.now()
        context.log(f"Scan started: {context.target_url}  profile={context.settings.profile}")
        await self._emit("scan_started", context, {"progress": 0, "phase": "init"})

        # ── Inject async HTTP engine and adaptive concurrency per scan ────────
        from core.async_http_engine import AsyncHTTPEngine
        from core.adaptive_concurrency import ScanConcurrencyCoordinator
        from utils.http_client import make_session
        _max_c = context.settings.max_concurrency or MAX_CONCURRENT_DETECTORS * 2
        _rate  = context.settings.rate_per_second or 0.0
        _dedup = context.settings.dedup_requests
        _verify_ssl = getattr(context.settings, "verify_ssl", True)
        context._http_engine = AsyncHTTPEngine(
            session=make_session(),
            timeout=context.settings.timeout,
            dedup=_dedup,
            max_concurrency=_max_c,
            verify_ssl=_verify_ssl,
        )
        context._coordinator = ScanConcurrencyCoordinator(
            initial_concurrency=min(MAX_CONCURRENT_DETECTORS, _max_c),
            max_concurrency=_max_c,
            rate_per_second=_rate,
        )

        # ── Initialise OOB collaborator early so detectors can embed the URL ─
        if context.settings.collaborator_url:
            try:
                from modules.oob_collaborator import OOBCollaborator
                context._oob = OOBCollaborator(context.settings.collaborator_url)
                context.log(f"  OOB collaborator: {context.settings.collaborator_url}")
            except Exception as _oob_exc:
                import logging as _log
                _log.getLogger(__name__).debug("OOB init failed: %s", _oob_exc)

        try:
            await self._phase_auth(context)
            await self._phase_crawl(context)
            # Adaptive LRU cache: resize based on discovered endpoint count
            if getattr(context, "_http_engine", None) and context.endpoints:
                context._http_engine.resize_cache(len(context.endpoints))
            await self._phase_recon(context)
            if context.settings.subdomain_takeover and context.subdomains:
                await self._phase_takeover(context)
            await self._phase_legacy_analysis(context)
            await self._phase_detect(context)
            await self._phase_passive(context)

            if context.settings.enable_fuzzer:
                await self._phase_fuzz(context)
            if context.settings.fuzz_websocket:
                await self._phase_websocket_fuzz(context)
            await self._phase_templates(context)
            await self._phase_plugins(context)
            if context.settings.tls_analysis:
                await self._phase_tls(context)
            # OOB collection: poll for blind callbacks after all probes sent
            if context.settings.collaborator_url or context.settings.blind_xss_url:
                await self._phase_oob(context)
            await self._phase_risk_engine(context)

            if context.settings.enable_param_discovery:
                await self._phase_param_discovery(context)

            if context.settings.report_formats:
                await self._phase_reports(context)
            if context.settings.generate_poc:
                await self._phase_pocs(context)
            if context.settings.save_scan:
                await self._phase_save(context)

            context.state    = ScanState.COMPLETED
            context.end_time = datetime.now()
            coord = getattr(context, "_coordinator", None)
            engine = getattr(context, "_http_engine", None)
            extra = ""
            if engine:
                s = engine.stats()
                extra = (f"  requests={s['sent']} cache_hits={s['cache_hits']} "
                         f"deduped={s['deduped']} avg={s['avg_ms']}ms")
            if coord:
                extra += f"  concurrency={coord.semaphore.current}"
            context.log(
                f"Scan complete: {len(context.findings)} findings in "
                f"{context.duration_seconds:.1f}s{extra}"
            )
        except asyncio.CancelledError:
            context.state = ScanState.CANCELLED
            context.log("Scan cancelled")
        except Exception as exc:
            context.state = ScanState.FAILED
            context.error = str(exc)
            context.log(f"Scan failed: {exc}")
            log.exception("Scan %s failed", context.scan_id)
        finally:
            context.end_time = context.end_time or datetime.now()
            # Gracefully shut down per-scan HTTP engine
            if hasattr(context, "_http_engine") and context._http_engine:
                await context._http_engine.shutdown()
                context._http_engine = None
            await self._emit("scan_finished", context, {
                "progress": 100,
                "state":    context.state.value,
                "findings": len(context.findings),
            })

        return context

    async def batch_scan(self, contexts: list[ScanContext]) -> list[ScanContext]:
        from config import MAX_CONCURRENT_SCANS
        sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

        async def _guarded(ctx):
            async with sem:
                return await self.scan(ctx)

        return list(await asyncio.gather(*[_guarded(c) for c in contexts]))

    def pause(self, scan_id: str) -> bool:
        ctx = self._active_scans.get(scan_id)
        if ctx and ctx.state == ScanState.RUNNING:
            ctx.state = ScanState.PAUSED
            ctx.log("Scan paused")
            return True
        return False

    def resume(self, scan_id: str) -> bool:
        ctx = self._active_scans.get(scan_id)
        if ctx and ctx.state == ScanState.PAUSED:
            ctx.state = ScanState.RUNNING
            ctx.log("Scan resumed")
            return True
        return False

    def cancel(self, scan_id: str) -> bool:
        ctx = self._active_scans.get(scan_id)
        if ctx and ctx.state in (ScanState.RUNNING, ScanState.PAUSED):
            ctx.state = ScanState.CANCELLED
            ctx.log("Scan cancelled")
            return True
        return False

    def get_context(self, scan_id: str) -> Optional[ScanContext]:
        return self._active_scans.get(scan_id)

    def list_scans(self) -> list[dict]:
        return [ctx.to_summary_dict() for ctx in self._active_scans.values()]

    # -- Scan Phases ----------------------------------------------------------

    async def _phase_auth(self, context: ScanContext) -> None:
        """Phase 0: Login to target if credentials configured; also wire proxy."""
        if context.settings.proxy:
            from utils.http_client import set_proxy
            set_proxy(context.settings.proxy)
            context.log(f"  Proxy configured: {context.settings.proxy}")

        skip_names = getattr(context.settings, "_skip_detectors", set())
        if skip_names:
            # Log which detectors are skipped for this scan.  We do NOT call
            # self._registry.disable() because that would mutate shared state
            # and break concurrent batch scans.  The skip set is passed to
            # get_enabled(exclude=...) in _phase_detect instead.
            context.log(f"  Skipping detectors: {', '.join(skip_names)}")

        from core.auth.auth_manager import AuthManager
        auth = AuthManager(context.settings)
        if not auth.is_configured():
            return

        context.log("Phase 0: Authenticating...")
        await self._emit("phase", context, {"phase": "auth", "progress": 2,
                                             "message": "Logging in..."})
        session = await asyncio.get_running_loop().run_in_executor(
            None, auth.authenticate_sync)
        if session:
            context.log("  Authentication successful")
        else:
            context.log("  Authentication failed -- continuing unauthenticated")

    async def _phase_crawl(self, context: ScanContext) -> None:
        # HAR file mode: load endpoints from HAR recording before/instead of crawling
        if context.settings.har_file:
            await self._load_har(context)
        """Phase 1: Crawl + classify endpoints."""
        context.log("Phase 1: Crawling target...")
        await self._emit("phase", context, {"phase": "crawl", "progress": 5,
                                             "message": f"Crawling {context.target_url}"})

        if context.settings.browser_mode:
            await self._crawl_browser(context)
            return

        crawler = Crawler(
            base_url=context.target_url,
            max_depth=context.settings.max_depth,
            timeout=context.settings.timeout,
        )
        try:
            crawl_result = await asyncio.get_running_loop().run_in_executor(
                None, crawler.crawl)
        except Exception as exc:
            context.log(f"Crawl error: {exc}")
            crawl_result = None

        if not crawl_result:
            context.log("No crawl result -- skipping classification.")
            context._crawl_result = None
            await self._emit("phase", context, {"phase": "crawl_done", "progress": 20,
                                                  "message": "Crawl complete (no forms found)"})
            return

        context.log(f"  Crawled {len(crawl_result.pages)} page(s), "
                    f"{len(crawl_result.forms)} form(s)")

        endpoints = EndpointClassifier().classify(crawl_result.forms)
        context._classified_endpoints = endpoints
        context.endpoints = [self._raw_to_endpoint(ep) for ep in endpoints]
        context._crawl_result = crawl_result

        if context.settings.enable_js_extract:
            await self._extract_js_endpoints(context, crawl_result)

        await self._emit("phase", context, {
            "phase":    "crawl_done",
            "progress": 20,
            "message":  f"Crawled {len(crawl_result.pages)} pages, {len(context.endpoints)} endpoints",
        })

    async def _crawl_browser(self, context: ScanContext) -> None:
        """
        Crawl via Playwright headless browser (Phase 1 extension).

        Passes auth cookies/headers from ScanSettings so the browser
        starts authenticated. Exposes the full CrawlResult on context
        for the AttackSurfaceMapper to consume in Phase 3.
        """
        from core.browser.browser_crawler import BrowserCrawler

        if not BrowserCrawler.is_available():
            context.log(
                "  ⚠ Browser mode unavailable — install Playwright: "
                "pip install playwright && playwright install chromium"
            )
            return

        # Parse auth cookies from raw cookie string → dict
        auth_cookies: dict = {}
        raw_cookie = context.settings.auth_cookie or ""
        for part in raw_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                auth_cookies[k.strip()] = v.strip()

        stealth    = context.settings.profile == "stealth"
        max_pages  = max(10, context.settings.max_depth * 10)
        context.log(
            f"  Browser mode: launching Playwright "
            f"({'stealth' if stealth else 'standard'}, max_pages={max_pages})..."
        )
        await self._emit("phase", context, {
            "phase": "browser_crawl", "progress": 12,
            "message": "Browser crawling (JS execution)..."
        })

        crawler = BrowserCrawler(
            target_url=context.target_url,
            max_pages=max_pages,
            screenshot_dir=context.settings.scan_dir + "/screenshots",
            auth_cookies=auth_cookies,
            auth_headers=dict(context.settings.auth_headers or {}),
            stealth=stealth,
        )

        result = await crawler.crawl()

        # Store full CrawlResult for AttackSurfaceMapper
        context._browser_result = result

        # Merge new endpoints into context (dedup by URL)
        existing_urls = {ep.url for ep in context.endpoints}
        new_eps = [ep for ep in result.endpoints if ep.url not in existing_urls]
        context.endpoints.extend(new_eps)

        xhr = sum(1 for ep in result.endpoints if "xhr" in (ep.tags or []))
        ws  = sum(1 for ep in result.endpoints if "websocket" in (ep.tags or []))
        context.log(
            f"  Browser found {len(new_eps)} new endpoint(s) "
            f"(+{xhr} XHR, +{ws} WebSocket)"
        )
        if result.storage:
            n = sum(
                len(s.get("localStorage", {})) + len(s.get("sessionStorage", {}))
                for s in result.storage.values()
            )
            if n:
                context.log(f"  Browser: captured {n} localStorage/sessionStorage entries")
        if result.error:
            context.log(f"  Browser: {result.error}")

    async def _extract_js_endpoints(self, context: ScanContext, crawl_result) -> None:
        """
        Extract endpoints from JavaScript files.

        Performance: builds a set of existing URLs once (O(n)) for O(1) per
        new-endpoint dedup check, instead of the previous O(n) scan of
        context.endpoints for every discovered JS URL.
        """
        try:
            from utils.js_endpoint_extractor import JSEndpointExtractor
            from utils.http_client import make_session

            extractor = JSEndpointExtractor(
                base_url=context.target_url,
                session=make_session(),
            )

            # Build the dedup set once — O(n) — reused for all JS URLs found.
            existing_urls: set[str] = {ep.url for ep in context.endpoints}

            js_endpoints: list[str] = []
            for page_html in getattr(crawl_result, "page_sources", {}).values():
                for url in extractor.extract_from_html(page_html):
                    if url not in existing_urls:   # O(1) lookup
                        existing_urls.add(url)     # keep the set current
                        context.endpoints.append(Endpoint(url=url, method="GET", tags=["js-extracted"]))
                        js_endpoints.append(url)

            if js_endpoints:
                context.log(f"  JS extraction: +{len(js_endpoints)} endpoint(s)")
        except Exception as exc:
            log.debug("JS extraction failed: %s", exc)

    async def _phase_recon(self, context: ScanContext) -> None:
        """Phase 1.5: Reconnaissance -- subdomains + tech detection."""
        await self._emit("phase", context, {"phase": "recon", "progress": 22,
                                             "message": "Running reconnaissance"})

        try:
            from core.tech_detection import TechDetector
            techs = await asyncio.get_running_loop().run_in_executor(
                None, lambda: TechDetector().detect(context.target_url))
            context.technologies = techs
            if techs:
                names = ", ".join(t.name for t in techs)
                context.log(f"  Tech stack: {names}")
        except Exception as exc:
            log.debug("Tech detection failed: %s", exc)

        if context.settings.enable_subdomains:
            context.log("  Discovering subdomains...")
            try:
                from core.recon.subdomain_discovery import SubdomainDiscovery
                disc = SubdomainDiscovery(context.target_url)
                subdomains = await disc.discover()
                context.subdomains = subdomains
                if subdomains:
                    context.log(f"  Found {len(subdomains)} subdomain(s)")
                    for sub_url in subdomains[:10]:
                        ep = Endpoint(url=sub_url, method="GET", tags=["subdomain"])
                        context.endpoints.append(ep)
            except Exception as exc:
                log.debug("Subdomain discovery failed: %s", exc)

        await self._emit("phase", context, {"phase": "recon_done", "progress": 28,
                                             "message": "Recon complete"})

    async def _phase_legacy_analysis(self, context: ScanContext) -> None:
        """Phase 2: Legacy CSRF-specific analyzers."""
        context.log("Phase 2: Legacy CSRF analysis...")
        await self._emit("phase", context, {"phase": "legacy", "progress": 30,
                                             "message": "Analyzing CSRF tokens & cookies"})
        crawl = getattr(context, "_crawl_result", None)
        if not crawl:
            return

        classified = getattr(context, "_classified_endpoints", [])
        cookie_results = CookieAnalyzer().analyze(crawl.cookies)
        token_results  = TokenAnalyzer().analyze(classified)
        samesite       = SameSiteModel().evaluate(cookie_results, classified)

        context._cookie_results = cookie_results
        context._token_results  = token_results
        context._samesite       = samesite

        await self._emit("phase", context, {"phase": "legacy_done", "progress": 33,
                                             "message": "CSRF analysis complete"})

    async def _phase_detect(self, context: ScanContext) -> None:
        """
        Phase 3: Active vulnerability detection.

        Performance improvements:
        - n_tasks computed once and stored; max() not re-evaluated each iteration.
        - update_every computed once outside the loop.
        - Cancelled-state check before submitting each task batch.
        - Denominator guard uses pre-computed n_tasks_safe (max 1) outside loop.
        """
        context.log("Phase 3: Running vulnerability detectors...")
        await self._emit("phase", context, {"phase": "detect", "progress": 35,
                                             "message": "Starting vulnerability detectors"})

        detectors = self._registry.get_enabled(
            filter_names=context.settings.enabled_detectors or None,
            exclude=context.settings._skip_detectors or None,
        )
        context.log(f"  Active detectors: {[d.NAME for d in detectors]}")

        await asyncio.gather(*[d.setup(context) for d in detectors])

        # Build prioritised attack surface from all discovery sources
        try:
            mapper  = AttackSurfaceMapper(context)
            surface = await mapper.build()
            context.log(
                f"  Attack surface: {surface.summary.total_unique} endpoints "
                f"({surface.summary.state_changing} state-changing, "
                f"{surface.summary.api_endpoints} API)"
            )
            if surface.waf:
                context.log(f"  WAF detected: {surface.waf} — evasion active")
            endpoints = surface.queue.drain()
        except Exception as _surf_exc:
            log.debug("AttackSurface build failed: %s", _surf_exc)
            endpoints = context.endpoints or []

        tasks = [
            self._run_detector(detector, context, endpoint)
            for detector in detectors
            for endpoint in endpoints
            if detector.should_test(endpoint, context)
        ]

        n_tasks      = len(tasks)
        n_tasks_safe = max(n_tasks, 1)   # avoid repeated max() in loop

        if n_tasks == 0:
            for pct in (42, 55, 68, 80):
                await self._emit("phase", context, {
                    "phase":    "detect_progress",
                    "progress": pct,
                    "message":  "Analysing endpoints...",
                })
                await asyncio.sleep(0)
        else:
            update_every = max(n_tasks // 20, 1)   # compute once, not per iteration
            completed    = 0
            for coro in asyncio.as_completed(tasks):
                # Pause support: wait while PAUSED, exit if CANCELLED/FAILED
                while context.state == ScanState.PAUSED:
                    await asyncio.sleep(0.5)
                if context.state not in (ScanState.RUNNING,):
                    break
                await coro
                completed += 1
                if completed == 1 or completed == n_tasks or completed % update_every == 0:
                    pct = 35 + int((completed / n_tasks_safe) * 50)
                    await self._emit("phase", context, {
                        "phase":    "detect_progress",
                        "progress": pct,
                        "message":  f"Detectors: {completed}/{n_tasks} checks complete",
                    })

        await asyncio.gather(*[d.teardown(context) for d in detectors])
        await self._emit("phase", context, {"phase": "detect_done", "progress": 85,
                                             "message": f"Detected {len(context.findings)} issues"})

    async def _phase_passive(self, context: ScanContext) -> None:
        """Phase 4: Passive analysis on crawled responses."""
        context.log("Phase 4: Passive analysis...")
        await self._emit("phase", context, {"phase": "passive", "progress": 87,
                                             "message": "Passive analysis"})
        try:
            from config import PASSIVE_BATCH_SIZE
            from core.passive.passive_analyzer import PassiveAnalyzer
            analyzer = PassiveAnalyzer()
            engine   = getattr(context, "_http_engine", None)

            seen  = set()
            batch = []
            for ep in context.endpoints:
                if ep.url not in seen:
                    seen.add(ep.url)
                    batch.append(ep)
                if len(batch) >= PASSIVE_BATCH_SIZE:
                    break

            # Bounded concurrency — use the scan coordinator or a fresh semaphore
            coord    = getattr(context, "_coordinator", None)
            _sem     = asyncio.Semaphore(
                coord.semaphore.current if coord else MAX_CONCURRENT_DETECTORS)

            async def _passive(ep: Endpoint):
                async with _sem:
                    try:
                        if engine:
                            resp = await engine.get(
                                ep.url, timeout=context.settings.timeout)
                        else:
                            from utils.http_client import make_session
                            session = make_session()
                            resp = await asyncio.get_running_loop().run_in_executor(
                                None, lambda: session.get(
                                    ep.url, timeout=context.settings.timeout,
                                    allow_redirects=True))
                        if resp:
                            for f in analyzer.analyse(resp, ep, context):
                                context.add_finding(f)
                    except Exception:
                        pass

            await asyncio.gather(*[_passive(ep) for ep in batch])
        except Exception as exc:
            log.debug("Passive analysis failed: %s", exc)

    async def _phase_templates(self, context: ScanContext) -> None:
        """Phase 4.5: Nuclei-style template scanning."""
        template_dir = context.settings.template_dir or "templates/nuclei"
        try:
            from core.templates.template_loader import TemplateLoader
            loader = TemplateLoader(template_dir)
            if loader.load() == 0:
                return
            context.log(f"Phase 4.5: Running {loader.template_count} template(s)...")
            await self._emit("phase", context, {"phase": "templates", "progress": 90,
                                                  "message": "Running scan templates"})
            probe_ep = (context.endpoints[0]
                        if context.endpoints else Endpoint(url=context.target_url))
            findings = await asyncio.get_running_loop().run_in_executor(
                None, lambda: loader.run(context.target_url, probe_ep))
            for f in findings:
                context.add_finding(f)
            if findings:
                context.log(f"  Templates: {len(findings)} finding(s)")
        except Exception as exc:
            log.debug("Template phase failed: %s", exc)

    async def _phase_fuzz(self, context: ScanContext) -> None:
        """Phase 4.6: Context-aware fuzzing and exploit generation."""
        context.log("Phase 4.6: Fuzzing (context-aware payload generation)...")
        await self._emit("phase", context, {"phase": "fuzz", "progress": 72,
                                              "message": "Fuzzing endpoints"})
        try:
            from modules.fuzz_engine import FuzzEngine
            engine = FuzzEngine(context)
            # Load plugins from plugin_dir if configured
            plugin_dir = context.settings.plugin_dir
            if plugin_dir:
                loaded = engine.load_plugins_from_dir(plugin_dir)
                if loaded:
                    context.log(f"  [fuzz] loaded {loaded} fuzz plugin(s)")
            findings = await engine.run()
            for f in findings:
                context.add_finding(f)
                await self._emit("finding", context, f.to_dict())
        except Exception as exc:
            context.log(f"Fuzzing phase error: {exc}")
            log.exception("Fuzz phase failed")

    async def _phase_oob(self, context: ScanContext) -> None:
        """Phase 4.65: Collect Out-of-Band (OOB) callbacks from blind findings."""
        context.log("Phase 4.65: Checking OOB callbacks...")
        await self._emit("phase", context, {
            "phase": "oob", "progress": 85,
            "message": "Polling OOB collaborator for blind callbacks..."
        })
        try:
            oob = getattr(context, "_oob", None)
            if oob is None:
                return

            # Use non-blocking async_poll so event loop is not stalled
            hits = await oob.async_poll(wait_seconds=3.0)
            total = sum(len(v) for v in hits.values())
            if total:
                context.log(
                    f"  OOB: {total} callback(s) — "
                    f"DNS={len(hits.get('DNS', []))}, "
                    f"HTTP={len(hits.get('HTTP', []))}"
                )
                from core.models import Confidence
                for f in context.findings:
                    if any(t in (f.tags or []) for t in ("oob", "blind", "ssrf", "rce")):
                        f.confidence = Confidence.CONFIRMED
                        context.log(f"  OOB confirmed: {f.title}")
                await self._emit("oob_confirmed", context, {
                    "total": total,
                    "dns":   len(hits.get("DNS",  [])),
                    "http":  len(hits.get("HTTP", [])),
                })
            else:
                context.log("  OOB: no callbacks in poll window (check collaborator manually)")

            if context.settings.blind_xss_url:
                context.log(
                    f"  Blind XSS: payloads sent to callback "
                    f"{context.settings.blind_xss_url} — "
                    f"check your XSS Hunter / callback dashboard"
                )
        except Exception as exc:
            log.debug("OOB phase failed: %s", exc)

    async def _phase_plugins(self, context: ScanContext) -> None:
        """Phase 4.7: Load and run plugin detectors."""
        plugin_dir = context.settings.plugin_dir
        if not plugin_dir:
            return
        count = self._registry.load_plugins(plugin_dir)
        if count > 0:
            context.log(f"  Loaded {count} plugin detector(s)")

    async def _phase_risk_engine(self, context: ScanContext) -> None:
        """
        Phase 5: Risk scoring and prioritisation.

        Sorting uses the module-level _SEVERITY_RANK constant (imported from
        models) so the sort key lambda does not allocate a new dict each call.
        """
        context.log("Phase 5: Risk prioritisation...")
        await self._emit("phase", context, {"phase": "risk", "progress": 94,
                                             "message": "Prioritising findings"})
        context.findings.sort(
            key=lambda f: _SEVERITY_RANK.get(f.severity.value, 0),
            reverse=True,
        )
        try:
            from core.risk_engine import RiskEngine
            engine = RiskEngine()
            risk   = engine.scan_risk(context)
            context._risk_summary = risk
            context.log(f"  Risk level: {risk.risk_level} (score: {risk.overall_score})")
        except Exception as exc:
            log.debug("Risk engine failed: %s", exc)

    async def _phase_param_discovery(self, context: ScanContext) -> None:
        """Phase 5.5: Hidden parameter discovery."""
        context.log("Phase 5.5: Parameter discovery...")
        try:
            from core.recon.parameter_discovery import ParameterDiscovery
            disc = ParameterDiscovery()
            for ep in context.endpoints[:5]:
                findings = await disc.discover(ep, context)
                for f in findings:
                    context.add_finding(f)
        except Exception as exc:
            log.debug("Parameter discovery failed: %s", exc)

    async def _phase_reports(self, context: ScanContext) -> None:
        context.log(f"Phase 6: Generating reports ({', '.join(context.settings.report_formats)})...")
        await self._emit("phase", context, {"phase": "reports", "progress": 96,
                                             "message": "Generating reports"})
        try:
            from reporting.report_builder import MultiFormatReportBuilder
            builder = MultiFormatReportBuilder(output_dir=context.settings.report_dir)
            paths   = builder.generate(context, formats=context.settings.report_formats)
            for _, rpath in paths.items():
                context.log(f"  Report -> {rpath}")
            context._report_paths = paths
            await self._emit("reports_ready", context, {"paths": paths})
        except Exception as exc:
            context.log(f"Report generation failed: {exc}")
            log.exception("Report generation failed")

    async def _phase_pocs(self, context: ScanContext) -> None:
        context.log("Phase 7: Generating PoC files...")
        await self._emit("phase", context, {"phase": "pocs", "progress": 98,
                                             "message": "Generating PoC files"})
        try:
            from reporting.poc_creator import PoCCreator
            creator = PoCCreator(output_dir=context.settings.poc_dir)
            paths   = creator.create_all(context.findings)
            context.log(f"  {len(paths)} PoC file(s) -> {context.settings.poc_dir}/")
            context._poc_count = len(paths)
        except Exception as exc:
            context.log(f"PoC generation failed: {exc}")

    async def _phase_save(self, context: ScanContext) -> None:
        """Save scan state to disk for replay."""
        try:
            from core.scan_replay import ScanReplay
            replay = ScanReplay(scan_dir=context.settings.scan_dir)
            path   = await asyncio.get_running_loop().run_in_executor(
                None, lambda: replay.save(context))
            context.log(f"  Scan saved -> {path}")
            context._save_path = path
        except Exception as exc:
            log.debug("Scan save failed: %s", exc)

    async def _run_detector(self, detector, context, endpoint) -> None:
        if context.state != ScanState.RUNNING:
            return
        async with self._semaphore:
            try:
                findings = await detector.detect(context, endpoint)
                for f in findings:
                    context.add_finding(f)
                    await self._emit("finding", context, f.to_dict())
            except Exception as exc:
                log.debug("Detector %s raised on %s: %s", detector.NAME, endpoint.url, exc)

    def _raw_to_endpoint(self, raw_ep) -> Endpoint:
        return Endpoint(
            url=raw_ep.url,
            method=raw_ep.method,
            parameters={i["name"]: i.get("value", "") for i in raw_ep.inputs if i.get("name")},
            source_page=raw_ep.source_page,
            content_type=raw_ep.enctype,
            is_state_changing=raw_ep.is_state_changing,
            has_file_upload=raw_ep.has_file_upload,
            raw_html=raw_ep.raw_html,
        )

    async def _emit(self, event_type, context, data=None) -> None:
        event = {
            "type":    event_type,
            "scan_id": context.scan_id,
            "target":  context.target_url,
            "data":    data or {},
        }
        q = self._scan_queues.get(context.scan_id)
        if q is not None:
            q.put_nowait(event)
        if self._event_queue is not None:
            try:
                self._event_queue.put_nowait(event)
            except Exception:
                pass

    # ── New v3.3 phases ─────────────────────────────────────────────────────

    async def _phase_websocket_fuzz(self, context: ScanContext) -> None:
        """Phase: WebSocket fuzzing (--fuzz-websocket)."""
        try:
            from modules.websocket_fuzzer import WebSocketFuzzer
            fuzzer   = WebSocketFuzzer(context)
            findings = await fuzzer.run()
            context.findings.extend(findings)
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).warning("WebSocket fuzz phase failed: %s", exc)

    async def _phase_tls(self, context: ScanContext) -> None:
        """Phase: TLS/certificate analysis (--tls-analysis)."""
        try:
            from core.passive.tls_analyzer import TLSAnalyzer
            analyzer = TLSAnalyzer(context)
            findings = await analyzer.run()
            context.findings.extend(findings)
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).warning("TLS analysis phase failed: %s", exc)

    async def _phase_takeover(self, context: ScanContext) -> None:
        """Phase: subdomain takeover detection (--subdomains --subdomain-takeover)."""
        try:
            from core.recon.takeover_detector import SubdomainTakeoverDetector
            detector = SubdomainTakeoverDetector(context)
            findings = await detector.run(context.subdomains)
            context.findings.extend(findings)
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).warning("Takeover detection phase failed: %s", exc)

    async def _load_har(self, context: ScanContext) -> None:
        """Load endpoints from a HAR file into the scan context."""
        import logging as _log
        log = _log.getLogger(__name__)
        try:
            from utils.har_parser import HARParser
            parser    = HARParser(context.settings.har_file, target_filter=context.target_url)
            endpoints = parser.parse()
            # Merge with existing endpoints (deduplicate by URL+method)
            existing  = {(ep.url, ep.method) for ep in context.endpoints}
            new_eps   = [ep for ep in endpoints if (ep.url, ep.method) not in existing]
            context.endpoints.extend(new_eps)
            context.log(f"  [har] loaded {len(endpoints)} endpoint(s), {len(new_eps)} new")
        except Exception as exc:
            log.warning("HAR loading failed: %s", exc)

