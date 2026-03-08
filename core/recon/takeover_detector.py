"""
core/recon/takeover_detector.py — Plasma v3.3
──────────────────────────────────────────────
Async subdomain takeover detection.

After SubdomainDiscovery runs, this module:
1. Resolves CNAME records for each discovered subdomain
2. Checks whether the CNAME target belongs to a known cloud provider
3. Verifies whether the provider resource is claimed (fingerprint check)
4. Reports unclaimed / dangling CNAMEs as HIGH findings

Supported providers
───────────────────
  GitHub Pages   — io.github.com, .github.io
  AWS S3         — s3.amazonaws.com, s3-website-*.amazonaws.com
  Heroku         — herokuapp.com
  Netlify        — netlify.app, netlify.com
  Vercel         — vercel.app
  Azure          — azurewebsites.net, cloudapp.azure.com
  Fastly         — fastly.net
  Shopify        — myshopify.com
  Zendesk        — zendesk.com
  Surge.sh       — surge.sh
  ReadTheDocs    — readthedocs.io

References
──────────
  https://github.com/EdOverflow/can-i-take-over-xyz
  https://owasp.org/www-project-web-security-testing-guide/ WSTG-CONF-10
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass
from typing import Optional

from core.models import (
    Confidence, Endpoint, Evidence, Finding, ScanContext,
    Severity, VulnType,
)

log = logging.getLogger(__name__)


# ── Provider fingerprint table ────────────────────────────────────────────────
# (cname_pattern, unclaimed_http_fingerprint, provider_name)
@dataclass
class ProviderFP:
    cname_re:     re.Pattern
    unclaimedRe:  re.Pattern
    name:         str
    check_http:   bool = True


_PROVIDERS: list[ProviderFP] = [
    ProviderFP(re.compile(r"\.github\.io$",          re.I),
               re.compile(r"There isn't a GitHub Pages site here", re.I),
               "GitHub Pages"),
    ProviderFP(re.compile(r"s3[-\.].*\.amazonaws\.com$", re.I),
               re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I),
               "AWS S3"),
    ProviderFP(re.compile(r"s3-website.*\.amazonaws\.com$", re.I),
               re.compile(r"NoSuchBucket|404", re.I),
               "AWS S3 Website"),
    ProviderFP(re.compile(r"\.herokuapp\.com$", re.I),
               re.compile(r"no such app|herokucdn\.com/error-pages/no-such-app", re.I),
               "Heroku"),
    ProviderFP(re.compile(r"\.netlify\.app$|\.netlify\.com$", re.I),
               re.compile(r"Not found|netlify\s+404", re.I),
               "Netlify"),
    ProviderFP(re.compile(r"\.vercel\.app$", re.I),
               re.compile(r"The deployment could not be found", re.I),
               "Vercel"),
    ProviderFP(re.compile(r"\.azurewebsites\.net$", re.I),
               re.compile(r"does not exist|Error 404", re.I),
               "Azure Web App"),
    ProviderFP(re.compile(r"\.cloudapp\.azure\.com$", re.I),
               re.compile(r"page not found|404", re.I),
               "Azure Cloud App"),
    ProviderFP(re.compile(r"\.fastly\.net$", re.I),
               re.compile(r"Fastly error: unknown domain", re.I),
               "Fastly CDN"),
    ProviderFP(re.compile(r"\.myshopify\.com$", re.I),
               re.compile(r"Sorry, this shop is currently unavailable", re.I),
               "Shopify"),
    ProviderFP(re.compile(r"\.zendesk\.com$", re.I),
               re.compile(r"Help Center Closed", re.I),
               "Zendesk"),
    ProviderFP(re.compile(r"\.surge\.sh$", re.I),
               re.compile(r"project not found", re.I),
               "Surge.sh"),
    ProviderFP(re.compile(r"\.readthedocs\.io$", re.I),
               re.compile(r"is not a valid RTD domain|project doesn't exist", re.I),
               "ReadTheDocs"),
]


class SubdomainTakeoverDetector:
    """
    Check each discovered subdomain for dangling CNAME → takeover risk.

    Usage (called from ScanManager)::

        detector = SubdomainTakeoverDetector(context)
        findings = await detector.run(subdomains)
        context.findings.extend(findings)
    """

    def __init__(self, context: ScanContext) -> None:
        self.context  = context
        self._timeout = context.settings.timeout
        self._sem     = asyncio.Semaphore(20)

    async def run(self, subdomains: list[str]) -> list[Finding]:
        """Check all subdomains concurrently. Returns findings."""
        if not subdomains:
            return []
        self.context.log(
            f"  [takeover] checking {len(subdomains)} subdomain(s) for dangling CNAMEs…"
        )
        tasks   = [self._check(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = [f for f in results if isinstance(f, Finding)]
        if findings:
            self.context.log(
                f"  [takeover] ⚠ {len(findings)} potential takeover(s) found!"
            )
        else:
            self.context.log("  [takeover] no dangling CNAMEs detected")
        return findings

    async def _check(self, subdomain_url: str) -> Optional[Finding]:
        async with self._sem:
            # Parse hostname from URL
            from urllib.parse import urlparse
            host = urlparse(subdomain_url).hostname or subdomain_url

            cname = await self._get_cname(host)
            if not cname:
                return None

            provider = self._match_provider(cname)
            if not provider:
                return None

            # HTTP fingerprint check
            unclaimed = await self._http_fingerprint(subdomain_url, provider)
            if not unclaimed:
                return None

            log.warning(
                "[takeover] POTENTIAL TAKEOVER: %s → %s (%s)", host, cname, provider.name
            )
            ep = Endpoint(url=subdomain_url, method="GET", tags=["subdomain", "takeover"])
            return Finding(
                vuln_type=VulnType.MISCONFIG,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"Subdomain Takeover — {host} → {provider.name}",
                description=(
                    f"The subdomain {host} has a CNAME pointing to {cname!r} "
                    f"({provider.name}), but the resource appears unclaimed. "
                    f"An attacker can register this resource and serve malicious "
                    f"content under your domain."
                ),
                evidence=Evidence(
                    request_url=subdomain_url,
                    request_method="GET",
                    matched_pattern=f"CNAME → {cname}",
                    notes=f"Provider: {provider.name}  CNAME: {cname}",
                ),
                remediation=(
                    f"Either claim the {provider.name} resource for {cname}, "
                    f"or remove the CNAME DNS record from {host}. "
                    f"Never leave dangling DNS records pointing to third-party services."
                ),
                endpoint=ep,
                detector="takeover-detector",
                tags=["subdomain", "takeover", provider.name.lower().replace(" ", "-")],
                owasp_id="A05:2021",
                cwe_id="CWE-350",
            )

    async def _get_cname(self, host: str) -> Optional[str]:
        """Resolve CNAME record via DNS. Returns canonical name or None."""
        loop = asyncio.get_running_loop()
        try:
            # Use getaddrinfo first to check the host resolves at all
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, host),
                timeout=self._timeout,
            )
        except Exception:
            return None

        # Then try to get CNAME via dnspython if available
        try:
            import dns.resolver  # type: ignore
            try:
                answers = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(host, "CNAME")
                    ),
                    timeout=self._timeout,
                )
                return str(answers[0].target).rstrip(".")
            except Exception:
                pass
        except ImportError:
            pass

        # Fallback: use socket.getfqdn (works for simple CNAME chains)
        try:
            fqdn = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getfqdn, host),
                timeout=self._timeout,
            )
            if fqdn and fqdn != host:
                return fqdn
        except Exception:
            pass
        return None

    @staticmethod
    def _match_provider(cname: str) -> Optional[ProviderFP]:
        """Return the ProviderFP whose cname_re matches, or None."""
        for provider in _PROVIDERS:
            if provider.cname_re.search(cname):
                return provider
        return None

    async def _http_fingerprint(self, url: str, provider: ProviderFP) -> bool:
        """Return True if the HTTP response contains the unclaimed fingerprint."""
        if not provider.check_http:
            return True  # assume unclaimed without HTTP check
        import aiohttp  # type: ignore; optional dep
        try:
            async with asyncio.timeout(self._timeout):
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(url, ssl=False, allow_redirects=True) as resp:
                        text = await resp.text(errors="replace")
                        return bool(provider.unclaimedRe.search(text))
        except ImportError:
            # aiohttp not available — fall back to requests in executor
            return await self._http_fingerprint_sync(url, provider)
        except Exception as exc:
            log.debug("[takeover] HTTP fingerprint failed for %s: %s", url, exc)
            return False

    async def _http_fingerprint_sync(self, url: str, provider: ProviderFP) -> bool:
        """Sync HTTP fallback using requests."""
        import requests  # type: ignore
        loop = asyncio.get_running_loop()
        try:
            def _get():
                r = requests.get(url, timeout=self._timeout, verify=False,
                                  allow_redirects=True)
                return r.text
            text = await asyncio.wait_for(
                loop.run_in_executor(None, _get),
                timeout=self._timeout + 2,
            )
            return bool(provider.unclaimedRe.search(text))
        except Exception:
            return False
