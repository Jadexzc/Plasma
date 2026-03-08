# Extending Plasma

Plasma supports three extension points: custom detectors, fuzz plugins, and YAML scan templates.

---

## Writing a Custom Detector

All detectors inherit from `BaseDetector` in `core/vulnerability_detectors/base_detector.py`.

**Minimal example (`plugins/my_detector.py`):**

```python
from __future__ import annotations
import logging
from core.models import Confidence, Endpoint, Evidence, Finding, ScanContext, Severity, VulnType
from core.vulnerability_detectors.base_detector import BaseDetector

log = logging.getLogger(__name__)


class MyDetector(BaseDetector):
    NAME        = "my-check"                    # unique detector identifier
    VULN_TYPE   = VulnType.OTHER
    DESCRIPTION = "Detects my custom vulnerability class"

    def should_test(self, endpoint: Endpoint, ctx: ScanContext) -> bool:
        # Return True to test this endpoint, False to skip
        return bool(endpoint.parameters)

    async def detect(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings = []
        session  = self._get_engine(context)    # use shared async HTTP engine

        for param in endpoint.param_names:
            resp = await session.get(endpoint.url, params={param: "PROBE"})
            if resp and "vulnerable-string" in resp.text:
                findings.append(Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"My Vulnerability in '{param}'",
                    description=f"Probe reflected in {endpoint.url}.",
                    evidence=Evidence(
                        request_url=endpoint.url,
                        request_method=endpoint.method,
                        payload_used="PROBE",
                        matched_pattern="vulnerable-string",
                        response_status=resp.status_code,
                        response_body=resp.text[:500],
                    ),
                    remediation="Fix the vulnerability.",
                    endpoint=endpoint,
                    detector=self.NAME,
                    owasp_id="A03:2021",
                    cwe_id="CWE-20",
                    tags=["custom"],
                ))
        return findings
```

**Load at runtime:**
```bash
plasma --url https://target.com --plugin-dir plugins/
```

Plasma auto-discovers all `BaseDetector` subclasses in the plugin directory.

---

## Detector Contract

| Requirement | Detail |
|---|---|
| `NAME` | Unique lowercase string (e.g. `"sqli"`, `"my-check"`) |
| `VULN_TYPE` | A `VulnType` enum member |
| `detect()` | Must return `list[Finding]` — never raise exceptions; catch internally |
| Stateless | No instance state shared between `detect()` calls |
| Logging | Use `self._log` or `logging.getLogger(__name__)` — never `print()` |

---

## Writing a Fuzz Plugin

Fuzz plugins extend payload sets and evasion logic for the `FuzzEngine`.

```python
from plugins.fuzz_plugin_api import FuzzPlugin, PluginMetadata

class MyWAFBypass(FuzzPlugin):
    meta = PluginMetadata(
        name="my-waf-bypass",
        version="1.0",
        description="Bypass rules for TargetCorp WAF",
    )

    def get_payloads(self, vuln_type: str) -> list[str]:
        """Return additional payloads for the given vulnerability type."""
        if vuln_type == "sqli":
            return [
                "' /*!50000UNION*/ /*!50000SELECT*/ 1--",
                "' OR/**/ 1=1--",
            ]
        return []

    def apply_evasion(self, payload: str) -> str:
        """Transform a payload before sending."""
        return payload.replace(" ", "/**/")
```

```bash
plasma --url https://target.com --fuzz --plugin-dir plugins/
```

---

## YAML Scan Templates

Plasma supports a Nuclei-compatible YAML template format for lightweight checks.

**Example (`templates/nuclei/exposed-env.yaml`):**

```yaml
id: exposed-dotenv
info:
  name: Exposed .env File
  severity: high
  description: Checks for publicly accessible .env files
  tags:
    - exposure
    - config

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.backup"
    matchers:
      - type: word
        words:
          - "APP_KEY="
          - "DB_PASSWORD="
        condition: or
```

```bash
plasma --url https://target.com --templates templates/nuclei/
```

Templates are loaded and run in Phase 4.5 of the scan pipeline.

---

## Adding a New VulnType

If your detector introduces a new vulnerability class:

1. Add a member to the `VulnType` enum in `core/models.py`:
   ```python
   MY_VULN = "My Custom Vulnerability"
   ```

2. Add a PoC handler in `reporting/poc_creator.py` if you want PoC generation.

3. Add it to `ENABLED_DETECTORS` in `config.py` if it should be on by default.

---

## Testing Your Detector

Add a test in `tests/`:

```python
import asyncio
from unittest.mock import MagicMock, patch
from core.async_http_engine import AsyncHTTPEngine
from plugins.my_detector import MyDetector

def test_my_detector_flags_vulnerability():
    detector = MyDetector()
    ctx      = MagicMock()
    ctx._http_engine = None
    ctx.settings.timeout = 5

    endpoint = MagicMock()
    endpoint.url = "https://target.com/page"
    endpoint.method = "GET"
    endpoint.param_names = ["q"]
    endpoint.parameters = {"q": "test"}

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.text = "vulnerable-string found here"
    fake_resp.content = b"ok"

    with patch.object(AsyncHTTPEngine, 'get', return_value=fake_resp):
        findings = asyncio.run(detector.detect(ctx, endpoint))

    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
```
