"""
tests/test_detectors.py — Plasma V1
─────────────────────────────────────
Unit tests for all vulnerability detectors and utility modules.
Run: pytest tests/ -v
"""
from __future__ import annotations

import asyncio
import json
import re
import unittest
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch

# ── Minimal stubs so tests run without full install ────────────────────────────

@dataclass
class _FakeSettings:
    profile: str = "default"
    timeout: int = 10
    collaborator_url: Optional[str] = None
    enabled_detectors: set = field(default_factory=set)

@dataclass
class _FakeContext:
    target_url: str = "https://example.com"
    settings: _FakeSettings = field(default_factory=_FakeSettings)
    findings: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    history: list = field(default_factory=list)
    def log(self, msg): self.history.append(msg)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HAR Parser
# ═══════════════════════════════════════════════════════════════════════════════

class TestHARParser(unittest.TestCase):

    def _make_har(self, entries: list) -> dict:
        return {"log": {"version": "1.2", "entries": entries}}

    def _make_entry(self, url: str, method: str = "GET", qs=None, body=None) -> dict:
        entry: dict = {
            "request": {
                "method": method,
                "url": url,
                "queryString": qs or [],
                "headers": [],
                "postData": None,
            }
        }
        if body:
            entry["request"]["postData"] = {
                "mimeType": "application/json",
                "text": json.dumps(body),
            }
        return entry

    def test_basic_get_parse(self):
        from utils.har_parser import HARParser
        har = self._make_har([self._make_entry("https://example.com/api/users?id=1")])
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            name = f.name
        try:
            parser = HARParser(name, target_filter=None)
            endpoints = parser.parse()
            self.assertGreater(len(endpoints), 0)
            self.assertEqual(endpoints[0].url, "https://example.com/api/users")
        finally:
            os.unlink(name)

    def test_post_json_body(self):
        from utils.har_parser import HARParser
        entry = self._make_entry(
            "https://example.com/api/login", method="POST",
            body={"username": "admin", "password": "secret"}
        )
        har = self._make_har([entry])
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            name = f.name
        try:
            parser = HARParser(name, target_filter=None)
            endpoints = parser.parse()
            self.assertEqual(len(endpoints), 1)
            ep = endpoints[0]
            self.assertIn("username", ep.parameters)
        finally:
            os.unlink(name)

    def test_deduplication(self):
        from utils.har_parser import HARParser
        entry = self._make_entry("https://example.com/api/users?id=1")
        har = self._make_har([entry, entry, entry])
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            name = f.name
        try:
            parser = HARParser(name, target_filter=None)
            endpoints = parser.parse()
            self.assertEqual(len(endpoints), 1, "Duplicate entries should be deduplicated")
        finally:
            os.unlink(name)

    def test_target_filter(self):
        from utils.har_parser import HARParser
        entries = [
            self._make_entry("https://example.com/api/users"),
            self._make_entry("https://other.com/evil"),
        ]
        har = self._make_har(entries)
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            name = f.name
        try:
            parser = HARParser(name, target_filter="https://example.com")
            endpoints = parser.parse()
            self.assertEqual(len(endpoints), 1)
            self.assertTrue(endpoints[0].url.startswith("https://example.com"))
        finally:
            os.unlink(name)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Scan Diff Tool
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanDiff(unittest.TestCase):

    def _make_scan_json(self, findings: list) -> str:
        import tempfile, json, os
        data = {"findings": findings, "target": "https://example.com"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            return f.name

    def test_new_finding_detected(self):
        from utils.scan_diff import diff_scans
        before_path = self._make_scan_json([
            {"title": "XSS Found", "severity": "HIGH", "url": "https://example.com/x"}
        ])
        after_path = self._make_scan_json([
            {"title": "XSS Found",   "severity": "HIGH",   "url": "https://example.com/x"},
            {"title": "SQLi Found",  "severity": "CRITICAL","url": "https://example.com/s"},
        ])
        try:
            code = diff_scans(before_path, after_path, jsonl=False)
            self.assertEqual(code, 1, "Exit code 1 expected when regressions exist")
        finally:
            import os
            os.unlink(before_path)
            os.unlink(after_path)

    def test_fixed_finding(self):
        from utils.scan_diff import diff_scans
        before_path = self._make_scan_json([
            {"title": "XSS Found", "severity": "HIGH", "url": "https://example.com/x"}
        ])
        after_path = self._make_scan_json([])
        try:
            code = diff_scans(before_path, after_path, jsonl=False)
            self.assertEqual(code, 0, "Exit 0 expected when no regressions")
        finally:
            import os
            os.unlink(before_path)
            os.unlink(after_path)

    def test_no_change(self):
        from utils.scan_diff import diff_scans
        scan = [{"title": "XSS Found", "severity": "HIGH", "url": "https://example.com/x"}]
        before_path = self._make_scan_json(scan)
        after_path  = self._make_scan_json(scan)
        try:
            code = diff_scans(before_path, after_path, jsonl=False)
            self.assertEqual(code, 0)
        finally:
            import os
            os.unlink(before_path)
            os.unlink(after_path)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CSP Evaluator
# ═══════════════════════════════════════════════════════════════════════════════

class TestCSPEvaluator(unittest.TestCase):

    def _fake_endpoint(self) -> object:
        ep = MagicMock()
        ep.url = "https://example.com/"
        return ep

    def test_missing_csp(self):
        from core.passive.security_hardening import CSPEvaluator
        evaluator = CSPEvaluator()
        findings = evaluator.evaluate("", self._fake_endpoint())
        self.assertGreater(len(findings), 0)
        self.assertIn("Missing", findings[0].title)

    def test_unsafe_inline(self):
        from core.passive.security_hardening import CSPEvaluator
        evaluator = CSPEvaluator()
        csp = "default-src 'self'; script-src 'unsafe-inline'"
        findings = evaluator.evaluate(csp, self._fake_endpoint())
        titles = [f.title for f in findings]
        self.assertTrue(any("unsafe-inline" in t for t in titles))

    def test_wildcard_script_src(self):
        from core.passive.security_hardening import CSPEvaluator
        evaluator = CSPEvaluator()
        csp = "default-src 'self'; script-src *"
        findings = evaluator.evaluate(csp, self._fake_endpoint())
        titles = [f.title for f in findings]
        self.assertTrue(any("Wildcard" in t for t in titles))

    def test_strong_csp_no_findings(self):
        from core.passive.security_hardening import CSPEvaluator
        evaluator = CSPEvaluator()
        csp = "default-src 'none'; script-src 'nonce-abc123'; style-src 'self'"
        findings = evaluator.evaluate(csp, self._fake_endpoint())
        self.assertEqual(len(findings), 0, "Strong CSP should produce no findings")

    def test_unsafe_eval(self):
        from core.passive.security_hardening import CSPEvaluator
        evaluator = CSPEvaluator()
        csp = "default-src 'self'; script-src 'unsafe-eval'"
        findings = evaluator.evaluate(csp, self._fake_endpoint())
        self.assertGreater(len(findings), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Cookie Auditor
# ═══════════════════════════════════════════════════════════════════════════════

class TestCookieAuditor(unittest.TestCase):

    def _fake_endpoint(self, scheme="https") -> object:
        ep = MagicMock()
        ep.url = f"{scheme}://example.com/"
        return ep

    def test_missing_secure_flag(self):
        from core.passive.security_hardening import CookieAuditor
        auditor = CookieAuditor()
        headers = {"set-cookie": "session=abc; HttpOnly; SameSite=Lax"}
        findings = auditor.audit(headers, self._fake_endpoint())
        titles = [f.title for f in findings]
        self.assertTrue(any("Secure" in t for t in titles))

    def test_missing_httponly(self):
        from core.passive.security_hardening import CookieAuditor
        auditor = CookieAuditor()
        headers = {"set-cookie": "session=abc; Secure; SameSite=Lax"}
        findings = auditor.audit(headers, self._fake_endpoint())
        titles = [f.title for f in findings]
        self.assertTrue(any("HttpOnly" in t for t in titles))

    def test_all_flags_present_no_findings(self):
        from core.passive.security_hardening import CookieAuditor
        auditor = CookieAuditor()
        headers = {"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}
        findings = auditor.audit(headers, self._fake_endpoint())
        self.assertEqual(len(findings), 0, "Cookie with all flags should have no findings")

    def test_non_sensitive_cookie_no_httponly_warning(self):
        from core.passive.security_hardening import CookieAuditor
        auditor = CookieAuditor()
        headers = {"set-cookie": "theme=dark; SameSite=Lax"}
        findings = auditor.audit(headers, self._fake_endpoint())
        # Non-sensitive cookies should not trigger HttpOnly findings
        httponly_findings = [f for f in findings if "HttpOnly" in f.title]
        self.assertEqual(len(httponly_findings), 0)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Rate Limiter — WAF Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════

class TestRateLimiter(unittest.TestCase):

    def _fake_response(self, status: int, headers: dict = None, body: str = "") -> MagicMock:
        r = MagicMock()
        r.status_code = status
        r.headers     = headers or {}
        r.text        = body
        return r

    def test_cloudflare_detected(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter()
        r = self._fake_response(403, {"cf-ray": "abc123-AMS", "server": "cloudflare"})
        limiter.observe(r)
        self.assertTrue(limiter.waf_detected)
        self.assertEqual(limiter.waf_provider, "Cloudflare")

    def test_429_exponential_backoff(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter(base_delay=0.1)
        r = self._fake_response(429, {})
        limiter.observe(r)
        self.assertGreater(limiter.current_delay, 0.1)
        self.assertTrue(limiter.is_throttled)

    def test_retry_after_parsed(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter(base_delay=0.1)
        r = self._fake_response(429, {"Retry-After": "30"})
        limiter.observe(r)
        self.assertEqual(limiter._retry_after_s, 30.0)

    def test_calibrate(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter()
        limiter.calibrate(5.0)  # 5 RPS → 0.2s delay
        self.assertAlmostEqual(limiter.current_delay, 0.2, places=3)

    def test_recovery_after_clean_responses(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter(base_delay=0.1)
        # Trigger backoff
        limiter.observe(self._fake_response(429, {}))
        backed_off_delay = limiter.current_delay
        # Simulate clean responses
        clean = self._fake_response(200, {})
        for _ in range(10):
            limiter.observe(clean)
        # Delay should have recovered toward base
        self.assertLessEqual(limiter.current_delay, backed_off_delay)

    def test_fingerprint_report_keys(self):
        from core.evasion.rate_limiter import RateLimiter
        limiter = RateLimiter()
        report = limiter.fingerprint_report()
        required_keys = {"waf_detected", "waf_provider", "rate_limited",
                         "total_429s", "current_delay_s", "estimated_rps"}
        self.assertTrue(required_keys.issubset(set(report.keys())))


# ═══════════════════════════════════════════════════════════════════════════════
# 6. GraphQL Detector — Unit Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGraphQLHelpers(unittest.TestCase):

    def test_unwrap_type_direct(self):
        from core.vulnerability_detectors.graphql_detector import _unwrap_type
        self.assertEqual(_unwrap_type({"kind": "SCALAR", "name": "String"}), "String")

    def test_unwrap_type_non_null(self):
        from core.vulnerability_detectors.graphql_detector import _unwrap_type
        t = {"kind": "NON_NULL", "name": None,
             "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}
        self.assertEqual(_unwrap_type(t), "Int")

    def test_unwrap_type_list(self):
        from core.vulnerability_detectors.graphql_detector import _unwrap_type
        t = {
            "kind": "LIST", "name": None,
            "ofType": {
                "kind": "NON_NULL", "name": None,
                "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}
            }
        }
        self.assertEqual(_unwrap_type(t), "ID")

    def test_sql_error_regex(self):
        from core.vulnerability_detectors.graphql_detector import _SQL_ERROR_RE
        self.assertIsNotNone(_SQL_ERROR_RE.search("You have an error in your sql syntax"))
        self.assertIsNotNone(_SQL_ERROR_RE.search("ORA-00933: SQL command not properly ended"))
        self.assertIsNone(_SQL_ERROR_RE.search("everything is fine"))


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Report Hasher
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportHasher(unittest.TestCase):

    def test_hash_and_verify(self):
        import os, tempfile
        from core.passive.security_hardening import ReportHasher

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"findings": [], "target": "https://example.com"}')
            path = f.name
        try:
            digest = ReportHasher.hash_file(path)
            self.assertEqual(len(digest), 64, "SHA-256 hex digest should be 64 chars")
            ok = ReportHasher.verify_file(path)
            self.assertTrue(ok, "Freshly hashed file should verify")

            # Tamper with the file
            with open(path, "a") as f:
                f.write("\n// tampered")
            ok_after = ReportHasher.verify_file(path)
            self.assertFalse(ok_after, "Tampered file should fail verification")
        finally:
            import glob as _glob
            os.unlink(path)
            for sf in _glob.glob(path + "*.sha256") + _glob.glob(path.replace(".json","") + "*.sha256"):
                try: os.unlink(sf)
                except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Adaptive LRU Cache
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveLRUCache(unittest.TestCase):

    def _make_engine(self):
        """Create AsyncHTTPEngine with a patched semaphore (no running loop needed)."""
        from unittest.mock import patch
        import asyncio
        from core.async_http_engine import AsyncHTTPEngine
        with patch.object(asyncio, "get_event_loop", return_value=asyncio.new_event_loop()):
            e = object.__new__(AsyncHTTPEngine)
            from core.async_http_engine import _LRUCache, EngineStats, _HostThrottler
            from concurrent.futures import ThreadPoolExecutor
            e._cache     = _LRUCache()
            e._stats     = EngineStats()
            e._semaphore = None
            return e

    def test_resize_grows(self):
        engine = self._make_engine()
        engine.resize_cache(5000)  # 5000 * 4 = 20000 → capped at 16384
        self.assertEqual(engine._cache._maxsize, 16384)

    def test_resize_minimum(self):
        engine = self._make_engine()
        engine.resize_cache(1)  # 1 * 4 = 4 → minimum 2048
        self.assertEqual(engine._cache._maxsize, 2048)

    def test_resize_does_not_shrink(self):
        engine = self._make_engine()
        engine._cache._maxsize = 8000
        engine.resize_cache(10)  # would set to 2048, which is less than 8000
        self.assertEqual(engine._cache._maxsize, 8000, "Cache should not shrink")


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Models — ScanSettings V1 Fields
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanSettings(unittest.TestCase):

    def test_all_v1_fields_present(self):
        from core.models import ScanSettings
        s = ScanSettings()
        v1_fields = [
            "fuzz_websocket", "har_file", "http2", "browser_parallel",
            "test_cache_poisoning", "tls_analysis", "subdomain_takeover",
            "jsonl_output",
        ]
        for f in v1_fields:
            self.assertTrue(hasattr(s, f), f"ScanSettings missing field: {f}")

    def test_default_values_are_safe(self):
        from core.models import ScanSettings
        s = ScanSettings()
        self.assertFalse(s.fuzz_websocket)
        self.assertFalse(s.http2)
        self.assertFalse(s.tls_analysis)
        self.assertFalse(s.subdomain_takeover)
        self.assertFalse(s.jsonl_output)
        self.assertFalse(s.test_cache_poisoning)
        self.assertIsNone(s.har_file)
        self.assertEqual(s.browser_parallel, 3)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. CLI Flag Coverage
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLIFlags(unittest.TestCase):
    """Verify all V1 flags are registered and produce no parse errors."""

    def _get_help(self) -> str:
        import subprocess
        r = subprocess.run(
            ["python3", "main.py", "--help"],
            capture_output=True, text=True, cwd="/home/claude/csrfguard"
        )
        return r.stdout + r.stderr

    def test_all_v1_flags_in_help(self):
        help_text = self._get_help()
        required = [
            "--fuzz-websocket", "--har", "--http2", "--browser-parallel",
            "--test-cache-poisoning", "--tls-analysis", "--subdomain-takeover",
            "--jsonl", "--diff-scans", "--test-ssti", "--test-smuggling",
            "--no-verify-ssl", "--collaborator", "--extract-db",
        ]
        missing = [f for f in required if f not in help_text]
        self.assertEqual(missing, [], f"Missing CLI flags: {missing}")

    def test_version_in_help(self):
        help_text = self._get_help()
        self.assertIn("Plasma", help_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
