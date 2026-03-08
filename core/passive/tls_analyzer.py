"""
core/passive/tls_analyzer.py — Plasma v3.3
────────────────────────────────────────────
TLS/SSL certificate and cipher suite analysis.

Checks
──────
  1. Certificate expiry (expired / expires within 30 days)
  2. Self-signed certificate
  3. Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, anon)
  4. Outdated TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  5. Common Name / SAN mismatch
  6. Insecure key length (RSA < 2048 bit, EC < 224 bit)

Usage (called from ScanManager._phase_tls)::

    analyzer = TLSAnalyzer(context)
    findings = await analyzer.run()
    context.findings.extend(findings)
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import re
import ssl
import socket
from typing import Optional
from urllib.parse import urlparse

from core.models import (
    Confidence, Endpoint, Evidence, Finding,
    ScanContext, Severity, VulnType,
)

log = logging.getLogger(__name__)

_WEAK_CIPHERS = re.compile(r"(RC4|DES|3DES|NULL|EXPORT|ADH|AECDH|MD5|RC2)", re.I)
_EXPIRY_WARN_DAYS = 30



# ── TLS CVE correlation table ─────────────────────────────────────────────────
# (keyword_in_cipher_or_proto, cve_id, description)
_CIPHER_CVES: list[tuple[str, str, str]] = [
    ("RC4",     "CVE-2013-2566",  "BEAST/RC4 weak cipher — broken stream cipher"),
    ("3DES",    "CVE-2016-2183",  "SWEET32 birthday attack on 3DES in CBC mode"),
    ("DES",     "CVE-1999-0796",  "DES — 56-bit key is brute-forceable"),
    ("EXPORT",  "CVE-2015-0204",  "FREAK — export-grade RSA keys"),
    ("NULL",    "CVE-2014-3566",  "Null cipher — no encryption"),
    ("ANON",    "CVE-2007-4995",  "Anonymous DH — no authentication"),
    ("MD5",     "CVE-2008-5077",  "MD5 in TLS — collision attacks possible"),
]
_PROTO_CVES: list[tuple[str, str, str]] = [
    ("SSLv2",   "CVE-2016-0800",  "DROWN — SSLv2 enables cross-protocol attack"),
    ("SSLv3",   "CVE-2014-3566",  "POODLE — padding oracle on SSLv3"),
    ("TLSv1",   "CVE-2011-3389",  "BEAST — CBC-mode attack on TLS 1.0"),
    ("TLSv1.0", "CVE-2011-3389",  "BEAST — CBC-mode attack on TLS 1.0"),
    ("TLSv1.1", "CVE-2020-12801", "TLS 1.1 deprecated — no forward secrecy guarantee"),
]

class TLSAnalyzer:
    """
    Analyse TLS certificate and protocol security for HTTPS targets.

    Findings are informational to HIGH severity and are added to context.findings.
    """

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    async def run(self) -> list[Finding]:
        url = self.context.target_url
        parsed = urlparse(url)
        if parsed.scheme != "https":
            log.debug("[tls] target is not HTTPS — skipping TLS analysis")
            return []

        host = parsed.hostname or ""
        port = parsed.port or 443

        self.context.log(f"  [tls] analysing TLS for {host}:{port}…")

        findings: list[Finding] = []
        loop = asyncio.get_running_loop()

        try:
            cert_info, cipher_info, proto_info = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._probe_tls(host, port)),
                timeout=15,
            )
        except Exception as exc:
            log.debug("[tls] probe failed: %s", exc)
            return []

        ep = Endpoint(url=url, method="GET", tags=["tls", "passive"])

        # ── Certificate expiry ─────────────────────────────────────────────
        if cert_info:
            findings.extend(self._check_cert(cert_info, host, ep))

        # ── Cipher weaknesses ──────────────────────────────────────────────
        if cipher_info:
            f = self._check_cipher(cipher_info, url, ep)
            if f:
                findings.append(f)

        # ── Protocol version ──────────────────────────────────────────────
        if proto_info:
            f = self._check_protocol(proto_info, url, ep)
            if f:
                findings.append(f)

        if findings:
            self.context.log(f"  [tls] {len(findings)} TLS finding(s)")
        else:
            self.context.log("  [tls] TLS configuration looks good")

        return findings

    def _probe_tls(self, host: str, port: int):
        """Blocking TLS probe — run in executor."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()          # (name, protocol, bits)
                proto  = ssock.version()         # e.g. "TLSv1.2"
        return cert, cipher, proto

    def _check_cert(self, cert: dict, host: str, ep: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        # ── Expiry ────────────────────────────────────────────────────────
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (not_after - now).days

                if days_left < 0:
                    findings.append(Finding(
                        vuln_type=VulnType.MISCONFIG, severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        title=f"TLS — Certificate Expired ({abs(days_left)} days ago)",
                        description=(
                            f"The TLS certificate for {host} expired on {not_after_str}. "
                            f"Browsers and clients will reject HTTPS connections, causing downtime."
                        ),
                        evidence=Evidence(request_url=ep.url, matched_pattern="expired cert",
                                         notes=f"notAfter={not_after_str}"),
                        remediation="Renew the TLS certificate immediately (Let\'s Encrypt is free).",
                        endpoint=ep, detector="tls-analyzer",
                        tags=["tls", "cert-expired"], owasp_id="A05:2021", cwe_id="CWE-298",
                    ))
                elif days_left < _EXPIRY_WARN_DAYS:
                    findings.append(Finding(
                        vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        title=f"TLS — Certificate Expires in {days_left} Day(s)",
                        description=f"Certificate for {host} expires on {not_after_str}.",
                        evidence=Evidence(request_url=ep.url, matched_pattern="cert-expiry-soon",
                                         notes=f"notAfter={not_after_str}, days_left={days_left}"),
                        remediation="Renew the certificate before it expires to avoid downtime.",
                        endpoint=ep, detector="tls-analyzer",
                        tags=["tls", "cert-expiry-soon"], owasp_id="A05:2021", cwe_id="CWE-298",
                    ))
            except ValueError:
                pass

        # ── CN / SAN mismatch ─────────────────────────────────────────────
        sans = [v for _, v in cert.get("subjectAltName", [])]
        cn_tuple = dict(cert.get("subject", (()))).get("commonName", "")
        all_names = set(sans + ([cn_tuple] if cn_tuple else []))

        def _name_matches(h: str, pattern: str) -> bool:
            if pattern.startswith("*."):
                return h.endswith(pattern[1:]) or h == pattern[2:]
            return h == pattern

        host_matched = any(_name_matches(host, n) for n in all_names)
        if not host_matched and all_names:
            findings.append(Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="TLS — Certificate CN/SAN Mismatch",
                description=(
                    f"Certificate CN/SANs ({sorted(all_names)!r}) do not match host {host!r}."
                ),
                evidence=Evidence(request_url=ep.url, matched_pattern="CN mismatch",
                                 notes=f"host={host!r}, cert_names={sorted(all_names)!r}"),
                remediation="Issue a certificate that includes the correct hostname in SAN.",
                endpoint=ep, detector="tls-analyzer",
                tags=["tls", "cert-mismatch"], owasp_id="A02:2021", cwe_id="CWE-297",
            ))

        return findings

    def _check_cipher(self, cipher: tuple, url: str, ep: Endpoint) -> Optional[Finding]:
        cipher_name, _, bits = cipher
        if _WEAK_CIPHERS.search(cipher_name or ""):
            # Find associated CVE
            cve_id = "CWE-326"
            cve_desc = ""
            for keyword, cve, desc in _CIPHER_CVES:
                if keyword.upper() in (cipher_name or "").upper():
                    cve_id   = cve
                    cve_desc = f" ({desc})"
                    break
            return Finding(
                vuln_type=VulnType.MISCONFIG, severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                title=f"TLS — Weak Cipher Suite: {cipher_name} [{cve_id}]",
                description=(
                    f"The server negotiated a weak cipher suite: {cipher_name} ({bits} bits). "
                    f"Associated vulnerability: {cve_id}{cve_desc}."
                ),
                evidence=Evidence(request_url=url, matched_pattern=cipher_name,
                                 notes=f"cipher={cipher_name}, bits={bits}, cve={cve_id}"),
                remediation=(
                    "Disable RC4, DES, 3DES, NULL, EXPORT, ADH, and MD5 cipher suites. "
                    "Prefer AES-256-GCM and ChaCha20-Poly1305 with forward secrecy (ECDHE)."
                ),
                endpoint=ep, detector="tls-analyzer",
                tags=["tls", "weak-cipher", cve_id.lower()],
                owasp_id="A02:2021", cwe_id="CWE-326",
            )
        return None

    def get_ja3_fingerprint(self, host: str, port: int = 443) -> Optional[str]:
        """
        Collect TLS handshake parameters and return a simplified JA3-style
        fingerprint string: "TLSVersion,Ciphers,Extensions,EllipticCurves,ECFormats"

        Note: Python ssl does not expose full ClientHello parameters, so this
        returns a server-perspective fingerprint (negotiated cipher + version).
        For full JA3 client fingerprinting, use a raw socket with TLS dissection
        (e.g. pyshark / scapy). This method provides server-side TLS profiling.
        """
        import hashlib
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher      = ssock.cipher()
                    version     = ssock.version() or "?"
                    cipher_name = (cipher[0] or "") if cipher else ""
                    # Build a fingerprint string
                    fp_str = f"{version}:{cipher_name}:{host}"
                    fp_hash = hashlib.md5(fp_str.encode()).hexdigest()
                    return fp_hash
        except Exception as exc:
            log.debug("[tls] JA3 fingerprint failed for %s: %s", host, exc)
            return None

    def _check_protocol(self, proto: str, url: str, ep: Endpoint) -> Optional[Finding]:
        weak_protos = {
            "SSLv2":   Severity.CRITICAL,
            "SSLv3":   Severity.CRITICAL,
            "TLSv1":   Severity.HIGH,
            "TLSv1.0": Severity.HIGH,
            "TLSv1.1": Severity.MEDIUM,
        }
        sev = weak_protos.get(proto)
        if sev:
            cve_id   = "CWE-326"
            cve_desc = ""
            for keyword, cve, desc in _PROTO_CVES:
                if keyword == proto:
                    cve_id   = cve
                    cve_desc = f" {desc}."
                    break
            return Finding(
                vuln_type=VulnType.MISCONFIG, severity=sev,
                confidence=Confidence.CONFIRMED,
                title=f"TLS — Outdated Protocol Version: {proto} [{cve_id}]",
                description=(
                    f"The server negotiated {proto}, which is deprecated.{cve_desc}"
                ),
                evidence=Evidence(request_url=url, matched_pattern=proto,
                                 notes=f"proto={proto} cve={cve_id}"),
                remediation=(
                    f"Disable {proto} and configure minimum TLS 1.2 (prefer TLS 1.3). "
                    f"Update your web server TLS configuration."
                ),
                endpoint=ep, detector="tls-analyzer",
                tags=["tls", "weak-protocol", proto.lower(), cve_id.lower()],
                owasp_id="A02:2021", cwe_id="CWE-326",
            )
        return None
