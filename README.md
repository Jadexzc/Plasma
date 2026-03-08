<!-- Plasma — Web Application Security Testing Framework -->

<div align="center">

# Plasma

**Web Application Security Testing Framework**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![CI](https://img.shields.io/github/actions/workflow/status/Jadexzc/plasma/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Jadexzc/plasma/actions)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-V1-crimson?style=flat-square)](CHANGELOG.md)
[![Coverage](https://img.shields.io/badge/tests-52%20passing-brightgreen?style=flat-square)](tests/)
[![Docker](https://img.shields.io/badge/docker-ready-0db7ed?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

</div>

---

Plasma is a modular, async Python framework for web application penetration testing and security research. It combines a high-performance async HTTP engine with a multi-phase scan pipeline covering passive analysis, active vulnerability detection, fuzzing, exploit chaining, and professional report generation.

> **Legal notice:** Plasma is designed for authorized security testing only. Do not run it against any system without explicit written permission from the system owner. Unauthorized use may violate applicable laws.

---

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [CLI Reference](#cli-reference)
5. [Scan Profiles](#scan-profiles)
6. [Detectors](#detectors)
7. [Fuzzing and Exploit Chaining](#fuzzing-and-exploit-chaining)
8. [Reporting](#reporting)
9. [Web Dashboard](#web-dashboard)
10. [Architecture](#architecture)
11. [Docker](#docker)
12. [Testing](#testing)
13. [Contributing](#contributing)
14. [License](#license)

---

## Features

- **18 vulnerability detectors** — CSRF, XSS, SQLi, SSRF, RCE, IDOR, SSTI, HTTP Smuggling, GraphQL, JWT, CORS, CRLF, XPath, cache poisoning, directory traversal, open redirect, misconfiguration, sensitive file exposure
- **Full-surface fuzzer** with exploit chaining — SSTI to RCE OOB, SSRF to RCE, SQLi to IDOR, traversal to LFI
- **Playwright headless browser crawler** for JavaScript-heavy single-page applications
- **WebSocket fuzzing** with 17 mutation payload categories across XSS, SQLi, SSTI, prototype pollution, SSRF, and command injection
- **JWT algorithm confusion** — RS256/HS256 key confusion, JKU/JWK/kid header injection, alg:none bypass
- **GraphQL security testing** — introspection, nested mutation fuzzing, depth/complexity DoS, batch query abuse
- **HAR file import** — replay authenticated browser sessions directly into the scan pipeline
- **Subdomain takeover detection** — 13 provider fingerprints (GitHub Pages, S3, Heroku, Netlify, Vercel, Azure, Fastly, and more) with CNAME confirmation
- **TLS/SSL analysis** — certificate expiry, weak ciphers, outdated protocol versions, CVE correlation
- **Cache poisoning detection** — six header injection vectors (X-Forwarded-Host, X-Original-URL, Forwarded, and others)
- **Scan diff tool** — compare two scan outputs to detect security regressions in CI/CD pipelines
- **Adaptive concurrency** — AIMD rate control with WAF fingerprinting and automatic rate limit calibration
- **32 Nuclei-compatible detection templates**
- **HTML, Markdown, and PDF report generation** with SHA-256 integrity verification
- **Real-time web dashboard** with Server-Sent Events streaming, dark-theme UI, and JSON export

---

## Installation

**Requirements:** Python 3.10 or later.

```bash
git clone https://github.com/Jadexzc/plasma.git
cd plasma
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate.bat   # Windows Command Prompt
pip install -r requirements.txt
pip install -e .
```

After installation, you can run Plasma from anywhere using the `plasma` command instead of `python main.py`.

```bash
plasma --help
```

### Optional Dependencies

| Feature | Package | Install Command |
|---------|---------|-----------------|
| Browser crawling (`--browser`) | `playwright` | `pip install playwright && playwright install chromium` |
| HTTP/2 (`--http2`) | `httpx` | `pip install httpx[http2]` |
| WebSocket fuzzing (`--fuzz-websocket`) | `websockets` | `pip install websockets` |
| Subdomain takeover DNS (`--subdomain-takeover`) | `dnspython` | `pip install dnspython` |
| PDF reports (`--report pdf`) | `weasyprint` | See below |

**PDF report generation** requires system-level graphics libraries before installing the Python package:

```bash
# Linux (Debian / Ubuntu)
sudo apt-get install python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0
pip install weasyprint

# macOS
brew install pango gdk-pixbuf libffi
pip install weasyprint
```

---

## Quick Start

```bash
# Basic scan — default profile, all detectors
plasma -u https://target.example.com

# Full scan with browser crawling, fuzzing, and HTML report
plasma -u https://target.example.com --browser --fuzz -r html

# Aggressive scan — full payload coverage, TLS analysis, subdomain takeover
plasma -u https://target.example.com --profile aggressive \
  --browser --fuzz --fuzz-websocket --tls-analysis \
  --subdomains --subdomain-takeover -r html,pdf

# Authenticated scan via HAR recording (preserves session cookies and headers)
plasma -u https://app.example.com --har session.har --fuzz

# Blind OOB testing with a Collaborator or interactsh server
plasma -u https://target.example.com --fuzz --fuzz-chain \
  --collaborator https://YOUR_ID.oastify.com

# Scan diff for CI/CD regression detection
plasma -u https://staging.example.com --output-json scan-after.json
plasma --diff-scans scan-before.json scan-after.json

# Stream findings as JSON Lines for pipeline filtering
plasma -u https://example.com --jsonl | jq 'select(.severity == "CRITICAL")'
```

---

## CLI Reference

### Target

| Flag | Description |
|------|-------------|
| `-u URL`, `--url URL` | Single target URL |
| `-b FILE`, `--batch FILE` | File containing one URL per line |
| `--har FILE` | Import all requests from a browser HAR recording |
| `--replay FILE` | Replay a scan saved with `--save-scan` |
| `--diff-scans A B` | Compare two Plasma JSON scan outputs |

### Scan Profile

| Flag | Description |
|------|-------------|
| `-p PROFILE`, `--profile PROFILE` | `safe`, `default`, `aggressive`, `stealth` |
| `-d N`, `--depth N` | Crawl depth (default: `2`) |
| `-t N`, `--timeout N` | Request timeout in seconds (default: `10`) |

### Detectors

| Flag | Description |
|------|-------------|
| `--test-csrf` | CSRF — token absence, SameSite weaknesses |
| `--test-sqli` | SQL injection — error-based, time-based, OOB |
| `--test-xss` | Cross-site scripting — reflected, DOM, stored indicators |
| `--test-ssrf` | Server-side request forgery |
| `--test-rce` | Remote code execution |
| `--test-idor` | Insecure direct object reference |
| `--test-misconfig` | Security misconfiguration |
| `--test-dir-traversal` | Directory and path traversal |
| `--test-ssti` | Server-side template injection with RCE OOB chain |
| `--test-smuggling` | HTTP request smuggling — CL.TE and TE.CL |
| `--test-xpath` | XPath injection |
| `--test-crlf` | CRLF injection and response splitting |
| `--test-jwt` | JWT: alg:none, RS256/HS256 confusion, JKU/JWK/kid injection |
| `--test-cache-poisoning` | HTTP cache poisoning via header injection |
| `--test-all` | Enable all detectors |
| `--detectors LIST` | Comma-separated list of detector names to enable |
| `--skip LIST` | Comma-separated list of detectors to disable |

### Scan Modes

| Flag | Description |
|------|-------------|
| `--browser` | Playwright headless crawl for JavaScript-heavy applications |
| `--browser-parallel N` | Parallel browser pages during crawl (default: `3`) |
| `--fuzz` | Enable the fuzz engine |
| `--fuzz-websocket` | Fuzz discovered WebSocket endpoints |
| `--fuzz-chain` | Enable multi-step exploit chain detection |
| `--fuzz-stealth` | Add timing jitter and user-agent rotation between probes |
| `--fuzz-profile PROFILE` | Override the fuzzer profile independently of `--profile` |
| `--fuzz-dry-run` | Print all generated payloads without sending any requests |
| `--fuzz-target-param PARAM` | Restrict fuzzing to a single named parameter |
| `--api-mode` | API testing — JSON body injection, REST endpoint discovery |
| `--bypass` | Access control bypass — header spoofing, method tampering |
| `--http2` | Use HTTP/2 via httpx (falls back to HTTP/1.1 automatically) |

### Reconnaissance

| Flag | Description |
|------|-------------|
| `--subdomains` | DNS subdomain brute-force enumeration |
| `--subdomain-takeover` | Check discovered subdomains for dangling CNAMEs |
| `--param-discovery` | Hidden parameter discovery |
| `--tls-analysis` | TLS/SSL — certificates, ciphers, protocol versions, CVE correlation |
| `--no-js` | Disable JavaScript endpoint extraction |

### Authentication

| Flag | Description |
|------|-------------|
| `--auth-cookie VALUE` | Inject session cookie string |
| `--login-url URL` | Form-based login endpoint |
| `--login-data JSON` | Login POST body as JSON |
| `--login-script FILE` | Python script for complex authentication flows (OAuth, MFA) |
| `--collaborator URL` | OOB callback server for blind SSRF, RCE, and SSTI |
| `--blind-xss URL` | Blind XSS callback URL |

### Output

| Flag | Description |
|------|-------------|
| `-r FORMATS`, `--report FORMATS` | Report formats: `html`, `markdown`, `pdf` (comma-separated) |
| `--report-dir DIR` | Report output directory (default: `reports/`) |
| `--poc` | Generate proof-of-concept exploit files |
| `--poc-dir DIR` | PoC output directory (default: `poc_output/`) |
| `--output-json FILE` | Write all findings as JSON; exits with code `1` if findings exist |
| `--jsonl` | Stream findings as JSON Lines to stdout |
| `--save-scan` | Save scan state for later replay or diff |
| `--scan-dir DIR` | Scan storage directory (default: `scans/`) |

### Performance

| Flag | Description |
|------|-------------|
| `--concurrency N` | Maximum concurrent requests |
| `--rate-limit RPS` | Target requests per second (`0` = auto-calibrate) |
| `--no-dedup` | Disable request deduplication |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `--proxy URL` | HTTP/HTTPS proxy (e.g. `http://127.0.0.1:8080`) |

---

## Scan Profiles

Profiles control payload volume, request rate, and whether evasion techniques are active.

| Profile | Payload Volume | Delay | Evasion | Production-Safe |
|---------|---------------|-------|---------|-----------------|
| `safe` | Passive only | 1.0 s | Off | Yes |
| `default` | Moderate (10 per param) | 0.3 s | Off | Usually |
| `aggressive` | Full (50 per param) | None | On | No |
| `stealth` | Reduced (5 per param) | 3.0 s | On | Depends |

```bash
# Stealth profile for the main scan; aggressive fuzzer profile on discovered endpoints
plasma -u https://target.example.com --profile stealth --fuzz --fuzz-profile aggressive

# Cap request rate on aggressive profile
plasma -u https://target.example.com --profile aggressive --rate-limit 5

# Use a specific proxy and suppress SSL errors in a test environment
plasma -u https://target.example.com --proxy http://127.0.0.1:8080 --no-verify-ssl
```

See [docs/scan-profiles.md](docs/scan-profiles.md) for complete profile specifications.

---

## Detectors

All 18 detectors implement `BaseDetector` from `core/vulnerability_detectors/base_detector.py` and are registered in `core/detector_registry.py`. Run `plasma --test-all` to enable all detectors simultaneously.

| Detector | `--test-*` flag | Internal NAME | Primary Techniques |
|----------|-----------------|---------------|--------------------|
| CSRF | `--test-csrf` | `csrf` | Token absence, SameSite=None, preflight bypass |
| SQL Injection | `--test-sqli` | `sqli` | Error-based, boolean-blind, time-based, OOB |
| XSS | `--test-xss` | `xss` | Reflected, DOM sink analysis, attribute context |
| SSRF | `--test-ssrf` | `ssrf` | Internal IP probing, cloud metadata, OOB DNS |
| RCE | `--test-rce` | `rce` | Command injection, deserialization patterns |
| IDOR | `--test-idor` | `idor` | Numeric ID enumeration, UUID traversal |
| Misconfiguration | `--test-misconfig` | `misconfig` | Security headers, CORS policy, exposed admin paths |
| Directory Traversal | `--test-dir-traversal` | `directory_traversal` | `../` sequences, URL-encoded and null-byte variants |
| SSTI | `--test-ssti` | `ssti` | 7 engine fingerprints, RCE OOB chain |
| HTTP Smuggling | `--test-smuggling` | `http_smuggling` | CL.TE, TE.CL timing probes |
| XPath Injection | `--test-xpath` | `xpath` | Error-based XPath injection |
| CRLF | `--test-crlf` | `crlf` | Header injection, log injection |
| JWT | `--test-jwt` | `jwt` | alg:none, RS256/HS256 confusion, JKU/JWK/kid injection |
| GraphQL | *(enabled by default)* | `graphql` | Introspection, mutation fuzzing, depth/complexity DoS |
| CORS | *(enabled by default)* | `cors` | Origin reflection, null origin, credentialed misconfiguration |
| Cache Poisoning | `--test-cache-poisoning` | `cache_poisoning` | X-Forwarded-Host, X-Original-URL, Forwarded |
| Open Redirect | *(enabled by default)* | `open-redirect` | Parameter-based, header-based |
| Sensitive Files | *(enabled by default)* | `sensitive-files` | .env, .git, backup files, credential exposure |

---

## Fuzzing and Exploit Chaining

The fuzz engine (`modules/fuzz_engine.py`) runs after standard detectors and tests all discovered parameters with context-aware payloads across five attack categories: SQL injection, XSS, SSTI, path traversal, and SSRF.

### Exploit Chains

Enable with `--fuzz-chain`. Plasma links confirmed findings into multi-step attacks:

| Chain | Trigger Condition | Escalation |
|-------|-------------------|------------|
| `sqli→idor` | SQLi confirmed | Extracted IDs used for IDOR enumeration |
| `ssrf→rce` | SSRF confirmed | Internal service probed for command execution |
| `traversal→lfi→rce` | Path traversal confirmed | File read escalated to code execution |
| `xss→csrf` | XSS confirmed | CSRF token exfiltration attempt |
| `ssti→rce-oob` | SSTI confirmed + `--collaborator` set | OOB RCE via Freemarker/Velocity payload |

### WebSocket Fuzzing

```bash
plasma -u https://target.example.com --fuzz --fuzz-websocket \
  --collaborator https://your.oob.server
```

Sends 17 payload categories over live `ws://` and `wss://` connections. Detects abnormal close codes (1002, 1003, 1007–1011), payload reflection, and time-based anomalies.

### DB Extraction

When SQL injection is confirmed, `--extract-db` automatically retrieves the database version, table names, and sample rows from sensitive tables (users, credentials, tokens):

```bash
plasma -u https://target.example.com --fuzz --extract-db
```

Supports MySQL/MariaDB, PostgreSQL, MSSQL, SQLite, and Oracle.

See [docs/fuzzing.md](docs/fuzzing.md) for full fuzzer documentation including WAF evasion, dry-run mode, and the plugin API.

---

## Reporting

Plasma generates reports in four formats:

| Format | Flag | Description |
|--------|------|-------------|
| HTML | `-r html` | Self-contained interactive report with severity grouping and evidence |
| Markdown | `-r markdown` | Portable text report for Jira, Confluence, or GitHub Issues |
| PDF | `-r pdf` | Formal deliverable (requires WeasyPrint) |
| JSON | `--output-json FILE` | Machine-readable findings; exits with code `1` if findings exist |
| JSON Lines | `--jsonl` | One finding per line, streamed to stdout |

```bash
# Generate all formats with PoC files
plasma -u https://target.example.com -r html,markdown,pdf --poc --report-dir ./results

# CI pipeline — fail build if any findings are detected
plasma -u https://staging.internal --profile default --output-json results.json
echo "Exit code: $?"
```

All reports include a SHA-256 integrity hash written to a `.sha256` sidecar file alongside the report. See [docs/reporting.md](docs/reporting.md) for the full output structure and JSON schema.

---

## Web Dashboard

The web dashboard provides a real-time GUI equivalent of the CLI. All V1 features are accessible through the interface — browser crawl, WebSocket fuzzing, TLS analysis, HAR import, subdomain takeover, JSON Lines output, and more.

```bash
plasma --ui
# Dashboard available at http://127.0.0.1:5000
```

The dashboard connects to the scan engine via Server-Sent Events and streams progress, phase transitions, severity counts, and individual findings in real time. Findings can be exported as JSON from the interface.

---

## Architecture

```
plasma/
  main.py                           CLI entry point and argument parser
  config.py                         Global constants and scan profiles
  core/
    scan_manager.py                 Scan phase orchestrator
    async_http_engine.py            Adaptive async HTTP engine with LRU deduplication cache
    adaptive_concurrency.py         AIMD concurrency controller
    models.py                       ScanContext, ScanSettings, Finding, Endpoint data models
    detector_registry.py            Detector loader and registry
    crawler.py                      BFS web crawler (sync and async)
    passive/
      passive_analyzer.py           Security headers, error messages, CSP, cookie analysis
      tls_analyzer.py               TLS/SSL analysis with CVE correlation
      security_hardening.py         CSP evaluator, cookie auditor, audit log, report hasher
    recon/
      subdomain_discovery.py        DNS brute-force enumeration
      parameter_discovery.py        Hidden parameter discovery
      takeover_detector.py          Subdomain takeover (13 provider fingerprints)
    browser/
      browser_crawler.py            Playwright headless crawler with parallel page support
    vulnerability_detectors/        18 detector implementations
    templates/
      template_loader.py            Parallel async Nuclei template execution
    evasion/
      rate_limiter.py               WAF fingerprinting and rate limit auto-calibration
  modules/
    fuzz_engine.py                  FuzzEngine and ExploitChainer
    websocket_fuzzer.py             WebSocket mutation fuzzer
    oob_collaborator.py             Out-of-band callback server integration
    poc_generator.py                Proof-of-concept file generation
  utils/
    har_parser.py                   Browser HAR recording importer
    scan_diff.py                    Scan output comparison tool
  reporting/
    report_builder.py               HTML, Markdown, and PDF generation
  ui/
    server.py                       Flask API server
    static/
      index.html                    Web dashboard
      style.css                     Dark red theme (IBM Plex Mono + IBM Plex Sans)
      app.js                        SSE-based real-time client
  tests/
    test_detectors.py               Unit tests for all detectors and utilities
    test_integration.py             Integration tests for the scan pipeline
  templates/
    nuclei/                         32 YAML detection templates
  docs/                             Extended documentation
```

The scan pipeline runs in numbered phases: Auth (0) → Crawl (1) → Recon (1.5) → Legacy CSRF analysis (2) → Detection (3) → Passive analysis (4) → Templates (4.5) → Fuzzing (4.6) → Risk scoring (5) → Reports (6) → PoC generation (7).

See [docs/architecture.md](docs/architecture.md) for a complete description of the scan pipeline, async HTTP engine, AIMD concurrency controller, and detector lifecycle.

---

## Docker

Plasma ships with a `Dockerfile` and `docker-compose.yml` for containerised scanning without a local Python installation.

### Build the Image

```bash
docker build -t plasma:v1 .
```

### Run a Scan

```bash
# Basic scan — output reports to host filesystem
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  plasma:v1 --url https://target.example.com --profile default -r html

# Aggressive scan with fuzzing and PoC generation
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/poc_output:/app/poc_output \
  plasma:v1 --url https://target.example.com --profile aggressive --fuzz --poc -r html

# Authenticated scan via session cookie
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  plasma:v1 \
  --url https://target.example.com \
  --auth-cookie "session=abc123" \
  --profile default -r html

# Route traffic through Burp Suite
docker run --rm \
  --network host \
  -v $(pwd)/reports:/app/reports \
  plasma:v1 \
  --url https://target.example.com \
  --proxy http://127.0.0.1:8080 --no-verify-ssl
```

### Docker Compose

```bash
# Single scan using the TARGET_URL environment variable
TARGET_URL=https://target.example.com docker compose up plasma

# Launch the web dashboard on http://localhost:5001
docker compose up plasma-ui
```

Output directories (`reports/`, `poc_output/`, `scans/`) are bind-mounted to the host so results persist after the container exits.

### Container Notes

| Concern | Detail |
|---------|--------|
| Browser mode | Not included in the base image. Add `RUN pip install playwright && playwright install chromium --with-deps` to the Dockerfile to enable `--browser`. |
| PDF reports | Add `libcairo2 libpango-1.0-0 libpangocairo-1.0-0` to the `apt-get` line in the Dockerfile if PDF output is required. |
| Non-root user | The container runs as root by default. Pass `--user $(id -u):$(id -g)` to `docker run` if required by your security policy. |
| Networking | Use `--network host` on Linux when scanning `localhost` or when routing through a local proxy. |

---

## Testing

```bash
# Run the full test suite (52 tests)
python -m unittest discover tests/ -v

# Run a single test class
python -m unittest tests.test_detectors.TestCSPEvaluator -v

# Print all fuzzer payloads without sending any requests
plasma -u https://example.com --fuzz --fuzz-dry-run --verbose
```

### Test Coverage

The suite covers 52 tests across the following areas:

| Area | Tests |
|------|-------|
| HAR parser | GET/POST parsing, JSON body, deduplication, target filter |
| Scan diff | NEW/FIXED/UNCHANGED detection, exit code behaviour |
| CSP evaluator | Missing CSP, unsafe-inline, wildcards, strong CSP baseline |
| Cookie auditor | Secure/HttpOnly/SameSite flag detection, non-sensitive exemption |
| Rate limiter | WAF fingerprinting (Cloudflare, AWS, Akamai), 429 backoff, calibration |
| GraphQL helpers | Type unwrapping (NON_NULL, LIST), SQL error regex |
| Report hasher | SHA-256 hash/verify cycle, tamper detection |
| Adaptive LRU cache | Resize growth, minimum floor, no-shrink invariant |
| ScanSettings | All V1 fields present, safe default values |
| CLI flags | All V1 flags registered and visible in `--help` output |
| Fuzz engine | Instantiation, payload coverage, SSTI→RCE chain presence |
| Detector registry | All 18 detectors loadable, no duplicates |
| Template loader | 32 templates load, required fields present, no duplicate names |
| Build settings | All CLI args correctly wired to ScanSettings fields |
| WebSocket fuzzer | Payload count, XSS and SQLi categories covered |

---

## Contributing

Contributions are welcome. Please follow these guidelines before opening a pull request.

1. **Code style** — Python 3.10+. Use type annotations throughout. No bare `except:` clauses. Follow existing module conventions.
2. **Async** — Use `asyncio.get_running_loop()` in async contexts. The deprecated `asyncio.get_event_loop()` is not permitted.
3. **New detector** — Implement `BaseDetector`, register the class in `core/detector_registry.py`, and add unit tests in `tests/test_detectors.py`. All 52 existing tests must continue to pass.
4. **Security** — Do not log request payloads at `INFO` level. All finding data is written to the append-only scan audit log.
5. **Tests** — All new features require unit tests. Run `python -m unittest discover tests/ -v` and confirm zero failures before submitting.
6. **Documentation** — Update the relevant file in `docs/` when adding or modifying features. Update the CLI reference table in this README when adding or removing flags.
7. **Pull requests** — Keep pull requests focused on a single change. Include a description of what was changed and why.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full text.

---

*Plasma V1 — For authorized security testing only.*
