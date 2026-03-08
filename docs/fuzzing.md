# Fuzzing & Exploit Generation

Plasma's fuzzing engine (`modules/fuzz_engine.py`) performs context-aware vulnerability testing beyond the standard detectors.

---

## Enabling the Fuzzer

```bash
plasma --url https://target.com --fuzz
```

The fuzzer runs as Phase 4.6 of the scan pipeline, after standard detectors have completed.

---

## Fuzzer Capabilities

| Feature | Description |
|---|---|
| Context-aware payloads | Selects payload sets based on endpoint type (API, form, numeric param, string param) |
| Polymorphic encoding | Applies raw, URL, double-URL, HTML entity, base64, unicode, and hex encoding variants |
| WAF detection | Identifies Cloudflare, Akamai, AWS WAF, ModSecurity, and Sucuri from response signatures |
| Adaptive feedback | EMA scoring tracks which payload/evasion combinations are most effective per target |
| Exploit chaining | Detects multi-step chains: SQLi→IDOR, SSRF→RCE, Traversal→LFI→RCE |
| OOB confirmation | Integrates with Burp Collaborator, interactsh, and custom listeners for blind issues |
| DB extraction | Auto-extracts schema on confirmed SQLi (MySQL, PostgreSQL, MSSQL, SQLite, Oracle) |

---

## Fuzzer Flags

```bash
--fuzz               Enable the fuzzer
--fuzz-chain         Enable multi-step exploit chain detection
--fuzz-stealth       Add random jitter + user-agent rotation between probes
--fuzz-dry-run       Print all generated probes without sending any HTTP requests
--fuzz-target-param  Restrict injection to a single named parameter
--fuzz-profile P     Set the fuzzer's scan profile independently of --profile
--extract-db         Auto-extract DB schema when SQLi is confirmed
--collaborator URL   OOB collaborator URL for blind confirmation
```

---

## Dry Run Mode

Before a real scan, use `--fuzz-dry-run` to review what payloads would be sent:

```bash
plasma --url https://target.com --fuzz --fuzz-dry-run
```

No HTTP requests are made. All generated probes are printed to stdout. Useful for auditing payload coverage and verifying parameter targeting.

---

## OOB / Blind Confirmation

For vulnerabilities that produce no visible response (blind SQLi, blind SSRF, blind XSS):

```bash
# Using Burp Collaborator
plasma --url https://target.com --fuzz \
  --collaborator https://abc123.oastify.com

# Using interactsh
plasma --url https://target.com --fuzz \
  --collaborator https://xyz.interactsh.com

# Blind XSS
plasma --url https://target.com --fuzz \
  --blind-xss https://your.xsshunter.com
```

The collaborator URL is embedded in SSRF, SQLi out-of-band, and XSS payloads as a callback. Check your collaborator dashboard for DNS/HTTP hits.

---

## DB Schema Extraction

When SQLi is confirmed, `--extract-db` automatically queries:

- Database version and name
- All table names
- Column names for high-value tables (users, credentials, tokens, sessions)
- Sample rows from sensitive tables

```bash
plasma --url https://target.com --fuzz --extract-db
```

Supports: MySQL/MariaDB, PostgreSQL, MSSQL, SQLite, Oracle.

---

## WAF Evasion

The fuzzer automatically detects WAF signatures and applies evasion techniques:

| Technique | Example |
|---|---|
| Encoding variants | `%27` instead of `'` |
| Case randomisation | `sElEcT` instead of `SELECT` |
| Comment injection | `SELECT/**/1` |
| Null byte injection | `param%00value` |
| Header manipulation | Spoofed `X-Forwarded-For`, `X-Real-IP` |
| Chunked encoding | Splits payloads across multiple requests |

---

## Plugin System

Custom payload sets and evasion techniques can be loaded as plugins.

**Plugin file structure (`plugins/my_plugin.py`):**

```python
from plugins.fuzz_plugin_api import FuzzPlugin, PluginMetadata

class MyPlugin(FuzzPlugin):
    meta = PluginMetadata(
        name="my-plugin",
        version="1.0",
        description="Custom SQLi bypass for target WAF",
    )

    def get_payloads(self, vuln_type: str) -> list[str]:
        if vuln_type == "sqli":
            return ["' /*!UNION*/ /*!SELECT*/ 1--"]
        return []

    def apply_evasion(self, payload: str) -> str:
        return payload.replace(" ", "/**/")
```

```bash
plasma --url https://target.com --fuzz --plugin-dir plugins/
```

---

## Exploit Chains

With `--fuzz-chain`, Plasma attempts to link vulnerabilities into multi-step attacks:

| Chain | Description |
|---|---|
| SQLi → IDOR | Extracted user IDs used to probe IDOR endpoints |
| SSRF → RCE | Internal service URLs probed for command execution |
| Traversal → LFI → RCE | File read → config leak → code execution |

Chains are reported as multi-step findings with each step documented in the PoC output.
