# Reporting

Plasma generates structured reports and executable PoC files for every finding.

---

## Report Formats

| Format | Flag | Description |
|---|---|---|
| HTML | `--report html` | Self-contained interactive report with severity grouping |
| Markdown | `--report markdown` | Portable text report; suitable for Jira, Confluence, GitHub |
| PDF | `--report pdf` | Formal deliverable (requires WeasyPrint) |
| JSON | `--output-json FILE` | Machine-readable raw findings for custom tooling |

```bash
# Generate all formats
plasma --url https://target.com \
  --report html,markdown,pdf \
  --output-json results.json \
  --report-dir ./results
```

---

## Output Directory Structure

```
results/
  scan_2024-01-15_143022.html
  scan_2024-01-15_143022.md
  scan_2024-01-15_143022.pdf
  poc/
    sqli_api_users_id_1.py
    xss_search_q.html
    ssrf_redirect_url.py
```

Reports are named `scan_YYYY-MM-DD_HHMMSS.FORMAT` by default.

---

## PoC Files

Use `--poc` to generate a standalone exploit script for every confirmed finding.

```bash
plasma --url https://target.com --poc --poc-dir ./poc
```

PoC files are self-contained Python or HTML files that reproduce the vulnerability:

**SQLi PoC (`sqli_api_users_id.py`):**
```python
# Plasma PoC — SQL Injection
# Endpoint: GET /api/users?id=1
# Payload:  ' OR '1'='1
import requests

resp = requests.get(
    "https://target.com/api/users",
    params={"id": "' OR '1'='1"},
)
print(resp.status_code, resp.text[:200])
```

**XSS PoC (`xss_search_q.html`):**
```html
<!-- Plasma PoC — Reflected XSS -->
<!-- Endpoint: GET /search?q=test -->
<a href="https://target.com/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E">
  Click to trigger XSS
</a>
```

---

## Findings Structure (JSON)

```json
{
  "scan_id": "abc123",
  "target": "https://target.com",
  "started": "2024-01-15T14:30:22",
  "duration_seconds": 87.4,
  "findings": [
    {
      "vuln_type": "SQLI",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "title": "SQL Injection — Error-Based (id)",
      "endpoint": "/api/users",
      "method": "GET",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "owasp_id": "A03:2021",
      "cwe_id": "CWE-89",
      "evidence": {
        "request_url": "https://target.com/api/users?id=%27+OR+%271%27%3D%271",
        "response_status": 500,
        "matched_pattern": "you have an error in your sql syntax"
      },
      "remediation": "Use parameterised queries or prepared statements."
    }
  ]
}
```

---

## Report Sections (HTML / Markdown)

1. **Executive Summary** — scan metadata, total findings by severity
2. **Findings by Severity** — CRITICAL → HIGH → MEDIUM → LOW
3. **Finding Detail** — endpoint, payload, evidence, remediation, OWASP/CWE reference
4. **Fuzz Summary** (if `--fuzz` was used) — technique heatmap, WAF detections, exploit chains
5. **Scan Metadata** — profile, timing, detectors used, request statistics

---

## PDF Generation

PDF output requires WeasyPrint and its system dependencies.

```bash
pip install weasyprint
plasma --url https://target.com --report pdf --report-dir ./results
```

See [docs/installation.md](installation.md) for system library requirements per platform.

---

## Customising Reports

Report templates are in `reporting/`:

- `report_builder.py` — orchestrates all format generation
- `poc_creator.py` — generates per-finding PoC files

To add a custom section, extend `MultiFormatReportBuilder` or add a PoC handler in `poc_creator.py`.
