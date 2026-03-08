"""
core/detector_registry.py — WebGuard v3
─────────────────────────────────────────
Registry that discovers and manages all vulnerability detector classes.
Detectors are loaded from core/vulnerability_detectors/ and plugins/.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import os
from pathlib import Path
from typing import Optional

from core.vulnerability_detectors.base_detector import BaseDetector

log = logging.getLogger(__name__)

# Mapping: module_path → class names to import
_BUILT_IN_DETECTORS = [
    ("core.vulnerability_detectors.csrf_detector",         "CSRFDetector"),
    ("core.vulnerability_detectors.sqli_detector",         "SQLiDetector"),
    ("core.vulnerability_detectors.xss_detector",          "XSSDetector"),
    ("core.vulnerability_detectors.ssrf_detector",         "SSRFDetector"),
    ("core.vulnerability_detectors.rce",                   "RCEDetector"),
    ("core.vulnerability_detectors.idor",                  "IDORDetector"),
    ("core.vulnerability_detectors.misconfig",             "MisconfigDetector"),
    ("core.vulnerability_detectors.directory_traversal",   "DirectoryTraversalDetector"),
    ("modules.file_upload_detector", "FileUploadVulnDetector"),
    ("core.vulnerability_detectors.open_redirect",         "OpenRedirectDetector"),
    ("core.vulnerability_detectors.cors_detector",         "CORSDetector"),
    ("core.vulnerability_detectors.jwt_detector",          "JWTDetector"),
    ("core.vulnerability_detectors.graphql_detector",      "GraphQLDetector"),
    ("core.vulnerability_detectors.sensitive_files",       "SensitiveFilesDetector"),
    ("modules.bypass_engine",                              "BypassEngine"),
    ("core.vulnerability_detectors.ssti_detector",         "SSTIDetector"),
    ("core.vulnerability_detectors.xpath_detector",        "XPathInjectionDetector"),
    ("core.vulnerability_detectors.crlf_detector",         "CRLFInjectionDetector"),
    ("core.vulnerability_detectors.http_smuggling_detector", "HTTPSmugglingDetector"),
    ("core.vulnerability_detectors.cache_poisoning_detector", "CachePoisoningDetector"),
]


class DetectorRegistry:
    """
    Discovers, instantiates, and manages all vulnerability detectors.

    Usage:
        registry = DetectorRegistry()
        registry.load_all()                          # load built-ins
        registry.load_plugins("plugins/")            # optional plugins
        detectors = registry.get_enabled()           # run-ready instances
    """

    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}
        self._loaded = False

    def load_all(self) -> None:
        """Load all built-in detectors from the registry table."""
        if self._loaded:
            return
        for module_path, class_name in _BUILT_IN_DETECTORS:
            try:
                module = importlib.import_module(module_path)
                cls    = getattr(module, class_name)
                instance = cls()
                self._detectors[instance.NAME] = instance
                log.debug("Loaded detector: %s", instance.NAME)
            except Exception as exc:
                log.warning("Failed to load %s.%s: %s", module_path, class_name, exc)
        self._loaded = True
        log.info("DetectorRegistry: %d detector(s) loaded", len(self._detectors))

    def load_plugins(self, plugin_dir: str) -> int:
        """
        Dynamically load detectors from Python files in plugin_dir.
        Returns the number of new detectors loaded.
        """
        count = 0
        plugin_path = Path(plugin_dir)
        if not plugin_path.is_dir():
            log.warning("Plugin dir not found: %s", plugin_dir)
            return 0

        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                import importlib.util
                spec   = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BaseDetector)
                            and obj is not BaseDetector
                            and obj.NAME not in self._detectors):
                        instance = obj()
                        self._detectors[instance.NAME] = instance
                        log.info("Plugin detector loaded: %s from %s", instance.NAME, py_file)
                        count += 1
            except Exception as exc:
                log.warning("Failed to load plugin %s: %s", py_file, exc)
        return count

    def get_enabled(
        self,
        filter_names: Optional[set[str]] = None,
        exclude:      Optional[set[str]] = None,
    ) -> list[BaseDetector]:
        """
        Return all enabled detector instances.

        Args:
            filter_names: if set, only return detectors whose NAME is in this set.
            exclude:      if set, skip detectors whose NAME is in this set.
                          Use this instead of calling disable() so the shared
                          registry state is never mutated (concurrent-scan safe).
        """
        return [
            d for d in self._detectors.values()
            if d.enabled
            and (filter_names is None or d.NAME in filter_names)
            and (exclude      is None or d.NAME not in exclude)
        ]

    def enable(self, name: str) -> bool:
        if d := self._detectors.get(name):
            d.enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        if d := self._detectors.get(name):
            d.enabled = False
            return True
        return False

    def get(self, name: str) -> Optional[BaseDetector]:
        return self._detectors.get(name)

    def list_all(self) -> list[dict]:
        return [d.metadata for d in self._detectors.values()]

    def __len__(self) -> int:
        return len(self._detectors)
