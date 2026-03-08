"""
plugins/fuzz_plugin_api.py — Plasma v3
───────────────────────────────────────
Public API for writing FuzzEngine plugins.

A fuzz plugin is any Python callable that follows the signature:

    def fuzz_plugin(
        endpoint: Endpoint,
        context:  ScanContext | None,
        matrix:   PayloadMatrix,
    ) -> list[tuple[str, str]]:
        ...

It receives the current endpoint, scan context (may be None in standalone
mode), and the PayloadMatrix instance (for generating additional payloads).

It returns a list of (payload_str, technique_label) tuples.

The module also exposes helper functions that make writing plugins easier:

    make_plugin(payloads, label)     — wrap a list into a plugin function
    chain_plugins(*plugins)          — combine multiple plugins into one

Loading plugins
───────────────
Drop any .py file exporting a `fuzz_plugin` callable into the plugins/
directory (or a custom dir passed with --plugin-dir). FuzzEngine will
load them automatically when --fuzz is active.

Example
───────
    from plugins.fuzz_plugin_api import make_plugin
    fuzz_plugin = make_plugin(["'UNION SELECT 1,2,3--", "' OR 1=1#"], "sqli:custom")
"""

from __future__ import annotations

from typing import Any, Callable, Optional


def make_plugin(
    payloads: list[str],
    label:    str = "custom",
) -> Callable:
    """
    Wrap a plain list of payload strings into a valid fuzz plugin.

    Args:
        payloads : list of raw payload strings
        label    : technique label appended to each result

    Returns:
        A callable compatible with FuzzPluginProtocol.

    Example:
        from plugins.fuzz_plugin_api import make_plugin
        fuzz_plugin = make_plugin(["admin'--", "1 OR 1=1"], label="sqli:custom-list")
    """
    def _plugin(endpoint: Any, context: Any, matrix: Any) -> list[tuple[str, str]]:
        return [(p, label) for p in payloads]
    _plugin.__name__ = f"make_plugin:{label}"
    return _plugin


def chain_plugins(*plugins: Callable) -> Callable:
    """
    Combine multiple fuzz plugins into a single plugin that returns the
    union of all their payloads.

    Example:
        from plugins.fuzz_plugin_api import chain_plugins, make_plugin
        fuzz_plugin = chain_plugins(
            make_plugin(["custom1"], "custom:a"),
            make_plugin(["custom2"], "custom:b"),
        )
    """
    def _chained(endpoint: Any, context: Any, matrix: Any) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        for plugin in plugins:
            try:
                results.extend(plugin(endpoint, context, matrix))
            except Exception:
                pass
        return results
    _chained.__name__ = "chain_plugins"
    return _chained


def filter_plugin(
    plugin:    Callable,
    predicate: Callable[[str], bool],
) -> Callable:
    """
    Wrap an existing plugin to only emit payloads that satisfy `predicate`.

    Example:
        from plugins.fuzz_plugin_api import filter_plugin
        # Only emit payloads longer than 10 chars
        fuzz_plugin = filter_plugin(base_plugin, lambda p: len(p) > 10)
    """
    def _filtered(endpoint: Any, context: Any, matrix: Any) -> list[tuple[str, str]]:
        return [(p, t) for p, t in plugin(endpoint, context, matrix) if predicate(p)]
    _filtered.__name__ = "filter_plugin"
    return _filtered


def polymorphic_plugin(
    payloads:  list[str],
    label:     str = "custom:polymorphic",
) -> Callable:
    """
    Like make_plugin, but also emits URL-encoded and base64 variants.

    Example:
        from plugins.fuzz_plugin_api import polymorphic_plugin
        fuzz_plugin = polymorphic_plugin(["<script>alert(1)</script>"], "xss:custom")
    """
    import base64
    import urllib.parse

    def _plugin(endpoint: Any, context: Any, matrix: Any) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        for p in payloads:
            results.append((p, label + ":raw"))
            results.append((urllib.parse.quote(p, safe=""), label + ":url-encoded"))
            results.append((base64.b64encode(p.encode()).decode(), label + ":base64"))
        return results

    _plugin.__name__ = f"polymorphic_plugin:{label}"
    return _plugin
