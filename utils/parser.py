"""
utils/parser.py
----------------
HTML and HTTP header parsing utilities for Plasma.

Centralises all BeautifulSoup and header-parsing logic so the
crawler stays focused on traversal strategy rather than parsing details.

Production optimisations
------------------------
extract_links: replaced O(n^2) list-membership dedup with an O(1) set.
  Before: `if full_url not in links` scans a growing list on every link.
  After:  `if full_url not in seen` — O(1) hash lookup.
  On pages with 100+ links the old code did ~5050 comparisons; the new
  code does ~100.  Savings compound across a 200-page crawl.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag
from requests import Response


# -- Form Extraction ----------------------------------------------------------

def extract_forms(html: str, source_url: str) -> list[dict]:
    """
    Parse all <form> elements from an HTML string.

    Returns a list of raw form dicts, each containing:
        action   -- absolute URL of the form's action attribute
        method   -- HTTP method (uppercased, defaults to GET)
        enctype  -- encoding type (lowercased)
        inputs   -- list of {name, type, value, tag} dicts
        raw_html -- first 500 chars of the serialised form tag

    All relative action URLs are resolved against source_url.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form_tag in soup.find_all("form"):
        action_raw = form_tag.get("action", source_url) or source_url
        forms.append({
            "action":   urljoin(source_url, action_raw),
            "method":   form_tag.get("method", "GET").upper(),
            "enctype":  form_tag.get("enctype", "application/x-www-form-urlencoded").lower(),
            "inputs":   _extract_inputs(form_tag),
            "raw_html": str(form_tag)[:500],
        })

    return forms


def _extract_inputs(form_tag: Tag) -> list[dict]:
    """Extract all input-like elements from a form tag."""
    inputs = []
    for element in form_tag.find_all(["input", "select", "textarea", "button"]):
        inputs.append({
            "name":  element.get("name", ""),
            "type":  element.get("type", "text").lower(),
            "value": element.get("value", ""),
            "tag":   element.name,
        })
    return inputs


# -- Link Extraction ----------------------------------------------------------

def extract_links(html: str, base_url: str, origin: str) -> list[str]:
    """
    Extract all same-origin anchor hrefs from an HTML string.

    Fragment identifiers (#section) are stripped.
    Only URLs starting with `origin` are returned.

    Performance: uses a set for O(1) deduplication instead of
    `if url not in list` which is O(n) per check -> O(n^2) total.
    The final list preserves first-seen insertion ordering.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    seen: set[str] = set()

    for tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, tag["href"]).split("#")[0]
        if full_url.startswith(origin) and full_url not in seen:
            seen.add(full_url)
            links.append(full_url)

    return links


# -- Cookie Parsing -----------------------------------------------------------

def parse_samesite(set_cookie_header: str) -> Optional[str]:
    """
    Extract the SameSite directive from a raw Set-Cookie header string.

    Returns "Strict", "Lax", "None", or None if the attribute is absent.
    """
    lower = set_cookie_header.lower()
    if "samesite=strict" in lower:
        return "Strict"
    if "samesite=lax" in lower:
        return "Lax"
    if "samesite=none" in lower:
        return "None"
    return None


def parse_cookie_flags(response: Response) -> dict[str, bool]:
    """
    Inspect the raw Set-Cookie response header for security flags.

    Returns a dict with:
        secure    -- True if the Secure flag is present
        http_only -- True if the HttpOnly flag is present
    """
    raw = response.headers.get("Set-Cookie", "").lower()
    return {
        "secure":    "secure"   in raw,
        "http_only": "httponly" in raw,
    }
