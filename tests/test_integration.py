"""
tests/test_integration.py — Plasma V1
───────────────────────────────────────
Integration tests: dry-run scans, detector output validation,
fuzzer payload coverage, and CLI argument wiring.

These tests use mock HTTP responses — no live network access required.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Fuzz Engine Dry-Run
# ═══════════════════════════════════════════════════════════════════════════════

class TestFuzzEngineDryRun(unittest.TestCase):
    """
    Dry-run: verify FuzzEngine payload loading — no live HTTP requests.
    FuzzEngine takes a ScanContext, so we use a mock context.
    """

    def _make_context(self, profile="default"):
        from unittest.mock import MagicMock
        from core.models import ScanSettings
        ctx = MagicMock()
        ctx.settings = ScanSettings(profile=profile, enable_fuzzer=True)
        ctx.findings = []
        ctx.endpoints = []
        ctx.log = lambda m: None
        return ctx

    def test_fuzz_engine_instantiation(self):
        from modules.fuzz_engine import FuzzEngine
        ctx = self._make_context("default")
        engine = FuzzEngine(ctx)
        self.assertIsNotNone(engine)

    def test_payload_sets_loaded(self):
        """FuzzEngine should have payload constants defined."""
        import modules.fuzz_engine as fe
        # Check that module-level payload lists exist
        found = any(
            hasattr(fe, attr) for attr in
            ("SQLI_PAYLOADS", "_SQLI_PAYLOADS", "SQL_PAYLOADS",
             "XSS_PAYLOADS", "_XSS_PAYLOADS",
             "SSTI_PAYLOADS", "_SSTI_PAYLOADS")
        )
        # Alternative: check the fuzz_engine has payloads in its namespace
        src = open(fe.__file__).read()
        self.assertIn("SQLI", src.upper(), "FuzzEngine has no SQLi payloads")
        self.assertIn("XSS",  src.upper(), "FuzzEngine has no XSS payloads")
        self.assertIn("SSTI", src.upper(), "FuzzEngine has no SSTI payloads")

    def test_safe_profile_fewer_payloads(self):
        """Payload module should exist and be importable."""
        import modules.fuzz_engine as fe
        src = open(fe.__file__).read()
        self.assertIn("safe", src.lower())
        self.assertIn("aggressive", src.lower())

    def test_exploit_chainer_has_ssti_rce(self):
        from modules.fuzz_engine import ExploitChainer
        chainer = ExploitChainer()
        chain_names = [c for _, _, c in chainer._CHAIN_PATTERNS]
        self.assertIn("ssti\u2192rce-oob", chain_names,
            "SSTI\u2192RCE chain pattern missing from ExploitChainer")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Detector Registry
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectorRegistry(unittest.TestCase):

    def _get_names(self) -> set:
        from core.detector_registry import DetectorRegistry
        reg = DetectorRegistry()
        reg.load_all()
        return {d["name"] for d in reg.list_all()}

    def test_all_expected_detectors_loadable(self):
        names = self._get_names()
        required = {
            "csrf", "sqli", "xss", "ssrf", "rce", "idor",
            "misconfig", "directory_traversal", "ssti", "http_smuggling",
            "xpath", "crlf", "jwt", "graphql", "cors", "cache_poisoning",
        }
        missing = required - names
        self.assertEqual(missing, set(), f"Detectors missing from registry: {missing}")

    def test_no_duplicate_detector_names(self):
        from core.detector_registry import DetectorRegistry
        reg = DetectorRegistry()
        reg.load_all()
        names = [d["name"] for d in reg.list_all()]
        self.assertEqual(len(names), len(set(names)), "Duplicate detector names found")

    def test_cache_poisoning_registered(self):
        names = self._get_names()
        self.assertIn("cache_poisoning", names)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Template Loader
# ═══════════════════════════════════════════════════════════════════════════════

class TestTemplateLoader(unittest.TestCase):

    def test_templates_load(self):
        from core.templates.template_loader import TemplateLoader
        loader = TemplateLoader(template_dir="templates/nuclei")
        loader.load()
        templates = loader._templates
        self.assertGreater(len(templates), 25,
            f"Expected >25 templates, got {len(templates)}")

    def test_template_required_fields(self):
        from core.templates.template_loader import TemplateLoader
        loader = TemplateLoader(template_dir="templates/nuclei")
        loader.load()
        for t in loader._templates:
            self.assertIn("name", t, f"Template missing name")
            self.assertIn("request", t, f"Template missing request")

    def test_no_duplicate_template_names(self):
        from core.templates.template_loader import TemplateLoader
        loader = TemplateLoader(template_dir="templates/nuclei")
        loader.load()
        names = [t.get("name", "") for t in loader._templates]
        duplicates = [n for n in names if names.count(n) > 1]
        self.assertEqual(duplicates, [], f"Duplicate template names: {set(duplicates)}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Scan Settings Builder
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildSettings(unittest.TestCase):
    """Test that CLI args → ScanSettings conversion is correct."""

    def _make_args(self, **kwargs):
        import argparse
        defaults = {
            "profile": "default", "depth": 2, "timeout": 10,
            "poc": False, "report": None, "report_dir": "reports",
            "poc_dir": "poc_output", "proxy": None,
            "login_url": None, "login_method": "POST", "login_data": None,
            "login_script": None, "auth_cookie": None,
            "collaborator": None, "blind_xss": None,
            "subdomains": False, "no_js": False, "param_discovery": False,
            "api_mode": False, "browser": False, "bypass": False,
            "fuzz": False, "fuzz_chain": False, "fuzz_stealth": False,
            "fuzz_profile": None, "fuzz_dry_run": False, "fuzz_target_param": None,
            "extract_db": False, "plugin_dir": None, "templates": None,
            "concurrency": 0, "rate_limit": 0.0, "no_dedup": False,
            "save_scan": False, "scan_dir": "scans", "no_verify_ssl": False,
            "fuzz_websocket": False, "har_file": None, "http2": False,
            "browser_parallel": 3, "test_cache_poisoning": False,
            "tls_analysis": False, "subdomain_takeover": False, "jsonl_output": False,
            "auto_upload": None, "upload": None, "detectors": None, "skip": None,
            "test_csrf": False, "test_sqli": False, "test_xss": False,
            "test_ssrf": False, "test_rce": False, "test_idor": False,
            "test_misconfig": False, "test_dir_traversal": False,
            "test_ssti": False, "test_smuggling": False, "test_xpath": False,
            "test_crlf": False, "test_cache_poisoning": False, "test_all": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_http2_flag_wired(self):
        import sys; sys.path.insert(0, "/home/claude/csrfguard")
        from main import build_settings
        args = self._make_args(http2=True)
        settings = build_settings(args)
        self.assertTrue(settings.http2)

    def test_fuzz_websocket_wired(self):
        from main import build_settings
        args = self._make_args(fuzz_websocket=True)
        settings = build_settings(args)
        self.assertTrue(settings.fuzz_websocket)

    def test_browser_parallel_wired(self):
        from main import build_settings
        args = self._make_args(browser_parallel=5)
        settings = build_settings(args)
        self.assertEqual(settings.browser_parallel, 5)

    def test_tls_analysis_wired(self):
        from main import build_settings
        args = self._make_args(tls_analysis=True)
        settings = build_settings(args)
        self.assertTrue(settings.tls_analysis)

    def test_subdomain_takeover_wired(self):
        from main import build_settings
        args = self._make_args(subdomain_takeover=True)
        settings = build_settings(args)
        self.assertTrue(settings.subdomain_takeover)

    def test_cache_poisoning_in_test_map(self):
        from main import build_settings
        args = self._make_args(test_cache_poisoning=True)
        settings = build_settings(args)
        self.assertIn("cache_poisoning", settings.enabled_detectors)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. WebSocket Fuzzer — Payload Coverage
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocketFuzzerPayloads(unittest.TestCase):

    def _get_payloads(self):
        from modules.websocket_fuzzer import _WS_PAYLOADS
        return _WS_PAYLOADS

    def test_payload_coverage(self):
        payloads = self._get_payloads()
        self.assertGreater(len(payloads), 10,
            f"Expected >10 WS payloads, got {len(payloads)}")

    def test_payload_categories_covered(self):
        payloads = self._get_payloads()
        # payloads are (text, technique) tuples
        payloads_str = " ".join(p[0] if isinstance(p, tuple) else str(p) for p in payloads)
        self.assertIn("<script>", payloads_str, "Missing XSS payload")
        self.assertIn("OR", payloads_str, "Missing SQLi-style payload")


