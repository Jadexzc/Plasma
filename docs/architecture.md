# Architecture

Plasma is built around an async scan pipeline with a centralized HTTP engine and adaptive concurrency.

---

## Scan Pipeline

```
plasma --url https://target.com

  ScanManager.scan(context)
    │
    ├─ Phase 0:   Auth         Login, proxy setup
    ├─ Phase 1:   Crawl        BFS crawler → form classification → JS endpoint extraction
    ├─ Phase 1.5: Recon        Tech detection, subdomain discovery
    ├─ Phase 2:   CSRF Legacy  Token analysis, cookie analysis, SameSite evaluation
    ├─ Phase 3:   Detect       15 detectors × N endpoints (adaptive concurrent)
    │               │
    │               └── AsyncHTTPEngine.probe_params_concurrent()
    │                      ├── LRU dedup cache check  (O(1))
    │                      ├── Per-host adaptive throttle  (AIMD)
    │                      ├── AdaptiveSemaphore gate
    │                      └── ThreadPoolExecutor  (20 workers)
    │
    ├─ Phase 4:   Passive      Security header analysis, 50-endpoint batch
    ├─ Phase 4.5: Templates    Nuclei-style YAML template scanning
    ├─ Phase 4.6: Fuzz         Context-aware fuzzer (--fuzz)
    ├─ Phase 5:   Risk         CVSS-like scoring, severity ranking
    ├─ Phase 6:   Reports      HTML / Markdown / PDF generation
    └─ Phase 7:   PoC          Per-finding exploit script generation
```

---

## Core Components

| Module | Location | Purpose |
|---|---|---|
| `ScanManager` | `core/scan_manager.py` | Orchestrates all scan phases |
| `Crawler` | `core/crawler.py` | BFS web crawler |
| `EndpointClassifier` | `core/endpoint_classifier.py` | Classifies forms into `Endpoint` objects |
| `DetectorRegistry` | `core/detector_registry.py` | Loads and manages all detectors |
| `AsyncHTTPEngine` | `core/async_http_engine.py` | Centralized async HTTP client |
| `AdaptiveSemaphore` | `core/adaptive_concurrency.py` | AIMD concurrency control |
| `FuzzEngine` | `modules/fuzz_engine.py` | Context-aware fuzzer |
| `MultiFormatReportBuilder` | `reporting/report_builder.py` | Report generation |

---

## Async HTTP Engine

All HTTP I/O flows through a single `AsyncHTTPEngine` per scan:

```
AsyncHTTPEngine
  ├── requests.Session  (shared, connection pooled)
  ├── ThreadPoolExecutor  (20 workers — sync requests run here)
  ├── LRU dedup cache  (2048 entries, O(1) key lookup)
  ├── _HostThrottler  (AIMD per-host back-off on 429/5xx)
  └── asyncio.Semaphore  (adaptive concurrency gate)
```

Detectors call `engine.probe_params_concurrent()` to fire all parameter × payload combinations simultaneously, giving approximately 10× throughput over sequential probing.

---

## Adaptive Concurrency (AIMD)

Concurrency adjusts automatically based on observed response quality:

| Signal | Action |
|---|---|
| 20 clean requests, all < 2s | +1 concurrent slot |
| 429 / 5xx received | × 0.75 (multiplicative decrease) |
| Timeout | × 0.75 |
| Bounds | Configurable: `--concurrency N` sets ceiling |

---

## Detector Lifecycle

Each detector inherits from `BaseDetector` and follows this lifecycle per scan:

```
registry.load_all()          → instantiate all detector classes
detector.setup(context)      → per-scan initialisation (load wordlists, etc.)
detector.should_test(ep)     → decide whether to test this endpoint
detector.detect(context, ep) → run tests, return list[Finding]
detector.teardown(context)   → release resources
```

Detectors are stateless between calls. All state lives in `ScanContext`.

---

## Request Deduplication

Identical GET requests (same method + URL + sorted params) are cached in an LRU store. When multiple detectors probe the same endpoint, the second hit returns a cached response rather than making a new HTTP request.

Disable with `--no-dedup` for maximum coverage at the cost of more requests.

---

## Directory Structure

```
plasma/
  main.py                        CLI entry point (invoked via `plasma` command)
  config.py                      Global configuration and scan profiles
  core/
    scan_manager.py              Scan orchestrator
    models.py                    Data models (Endpoint, Finding, ScanSettings, etc.)
    crawler.py                   BFS web crawler
    detector_registry.py         Loads and manages detectors
    async_http_engine.py         Centralized async HTTP engine
    adaptive_concurrency.py      AIMD concurrency controller
    vulnerability_detectors/     All detector modules
    auth/                        Authentication (form, cookie, script)
    passive/                     Passive analysis modules
    recon/                       Subdomain discovery, parameter discovery
    templates/                   Nuclei-style YAML template runner
    browser/                     Playwright headless browser crawler
    evasion/                     WAF bypass / request obfuscation
  modules/
    fuzz_engine.py               Context-aware fuzzer
    bypass_engine.py             Evasion and bypass techniques
    oob_collaborator.py          OOB / blind confirmation
    db_extractor.py              DB schema extraction
    payload_updater.py           Remote payload list sync
    file_upload_detector.py      File upload vulnerability detection
  reporting/
    report_builder.py            Multi-format report generation
    poc_creator.py               PoC exploit script generation
  payloads/                      Static payload libraries
  plugins/                       Plugin API and sample plugins
  templates/nuclei/              YAML scan templates
  utils/
    http_client.py               Session factory + retry adapter
    parser.py                    HTML parsing helpers
    response_diff.py             Response differential analysis
    js_endpoint_extractor.py     JavaScript URL extraction
  docs/                          This documentation
```
