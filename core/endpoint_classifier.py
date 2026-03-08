"""
core/endpoint_classifier.py
─────────────────────────────
Transforms raw crawled forms into classified Endpoint objects.

Classification decisions:
  - Is the method state-changing? (POST/PUT/PATCH/DELETE)
  - Does the form upload files?   (multipart enctype or file inputs)
  - Is there a CSRF token field?  (name-pattern heuristic)

No network I/O. Pure data transformation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from config import STATE_CHANGING_METHODS, MULTIPART_ENCTYPE, CSRF_TOKEN_PATTERNS
from core.crawler import RawForm

log = logging.getLogger(__name__)


@dataclass
class ClassifiedEndpoint:
    """A classified form endpoint ready for security analysis."""
    url:               str
    source_page:       str
    method:            str
    enctype:           str
    inputs:            list[dict]
    is_state_changing: bool
    has_file_upload:   bool
    csrf_token_field:  Optional[str] = None
    raw_html:          str = ""

    @property
    def input_names(self) -> list[str]:
        return [i["name"] for i in self.inputs if i.get("name")]


class EndpointClassifier:
    """Converts RawForm objects into ClassifiedEndpoint objects (no I/O)."""

    def classify(self, forms: list[RawForm]) -> list[ClassifiedEndpoint]:
        endpoints = []
        for form in forms:
            ep = self._classify(form)
            endpoints.append(ep)
            log.debug("[%s] %s  state=%s  upload=%s",
                      ep.method, ep.url, ep.is_state_changing, ep.has_file_upload)
        return endpoints

    def _classify(self, form: RawForm) -> ClassifiedEndpoint:
        method = form.method.upper()
        return ClassifiedEndpoint(
            url=form.action, source_page=form.source_url,
            method=method, enctype=form.enctype, inputs=form.inputs,
            is_state_changing=method in STATE_CHANGING_METHODS,
            has_file_upload=self._has_file_upload(form),
            csrf_token_field=self._find_csrf_field(form),
            raw_html=form.raw_html,
        )

    @staticmethod
    def _has_file_upload(form: RawForm) -> bool:
        if MULTIPART_ENCTYPE in form.enctype.lower():
            return True
        return any(i.get("type", "").lower() == "file" for i in form.inputs)

    @staticmethod
    def _find_csrf_field(form: RawForm) -> Optional[str]:
        for inp in form.inputs:
            name_lower = inp.get("name", "").lower().strip()
            if any(p in name_lower for p in CSRF_TOKEN_PATTERNS):
                return inp["name"]
        return None
