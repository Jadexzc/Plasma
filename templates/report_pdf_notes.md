# PDF Report Generation

Plasma uses **WeasyPrint** (with **reportlab** as a fallback) to convert the HTML report to PDF.

## Installation

```bash
pip install weasyprint
# or
pip install reportlab
```

System-level dependencies are required for WeasyPrint. See [docs/installation.md](../docs/installation.md) for platform-specific instructions.

## Generation

The `reporting/report_builder.py` module calls `_generate_pdf()`, which:

1. Generates the HTML report
2. Passes the HTML through WeasyPrint to produce a PDF

If WeasyPrint is unavailable, reportlab generates a simplified plain-text PDF.

## Template

PDF output uses `templates/report_template.html` with the same `{{ VARIABLE }}` placeholder substitution system as the HTML report.
