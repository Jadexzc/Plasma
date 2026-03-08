"""
core/auth/auth_manager.py — WebGuard v3
─────────────────────────────────────────
Handles authenticated scanning: performs login, stores session cookies,
and shares the authenticated session with all crawlers and detectors.

Supports:
  - Form-based POST login (login_url + login_data)
  - Cookie injection (auth_cookie string)
  - Custom Python auth scripts (login_script)
  - Session persistence to disk (AUTH_SESSION_FILE)
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, parse_qsl

import requests

from config import AUTH_SESSION_FILE, USER_AGENT, DEFAULT_TIMEOUT
from utils.http_client import set_auth_session

log = logging.getLogger(__name__)


class AuthManager:
    """
    Performs login and establishes an authenticated session.

    Usage:
        am = AuthManager(settings)
        session = await am.authenticate()   # or am.authenticate_sync()
        # session is now shared via http_client.set_auth_session()
    """

    def __init__(self, settings) -> None:
        self._settings = settings
        self._session: Optional[requests.Session] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def authenticate_sync(self) -> Optional[requests.Session]:
        """Perform authentication synchronously. Returns session or None."""
        s = self._settings

        # Priority 1: raw cookie string
        if s.auth_cookie:
            return self._inject_cookie(s.auth_cookie)

        # Priority 2: custom Python auth script
        if s.login_script and os.path.isfile(s.login_script):
            return self._run_script(s.login_script)

        # Priority 3: form-based login
        if s.login_url and s.login_data:
            return self._form_login(s.login_url, s.login_method, s.login_data)

        log.debug("AuthManager: no auth credentials configured — using anonymous session")
        return None

    def is_configured(self) -> bool:
        s = self._settings
        return bool(s.auth_cookie or s.login_url or s.login_script)

    # ── Auth methods ───────────────────────────────────────────────────────────

    def _inject_cookie(self, cookie_str: str) -> requests.Session:
        """Create a session with manually provided cookies."""
        session = self._base_session()
        # Parse "name=value; name2=value2" format
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                session.cookies.set(name.strip(), value.strip())
        log.info("AuthManager: injected %d cookie(s) from --auth-cookie",
                 len(session.cookies))
        set_auth_session(session)
        self._session = session
        return session

    def _form_login(self, login_url: str, method: str, login_data: str) -> Optional[requests.Session]:
        """Perform a form-based login and retain the resulting session."""
        session = self._base_session()
        try:
            # Parse "key=value&key=value" into dict
            data = dict(parse_qsl(login_data, keep_blank_values=True))
            log.info("AuthManager: attempting %s login → %s", method.upper(), login_url)

            # GET login page first (obtain any CSRF tokens)
            pre = session.get(login_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)

            # Extract CSRF token if present in form
            csrf_name, csrf_val = self._extract_csrf(pre.text)
            if csrf_name:
                data[csrf_name] = csrf_val
                log.debug("AuthManager: found CSRF token '%s' on login form", csrf_name)

            resp = session.request(
                method.upper(), login_url,
                data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=True,
            )
            log.info("AuthManager: login response HTTP %d (cookies: %d)",
                     resp.status_code, len(session.cookies))

            if resp.status_code in (200, 302, 303):
                set_auth_session(session)
                self._session = session
                self._save_session(session)
                return session
            else:
                log.warning("AuthManager: login failed — HTTP %d", resp.status_code)
        except Exception as exc:
            log.error("AuthManager: login error: %s", exc)
        return None

    def _run_script(self, script_path: str) -> Optional[requests.Session]:
        """
        Load and execute a custom Python auth script.

        The script must define a function:
            def authenticate(session: requests.Session) -> requests.Session
        """
        try:
            spec   = importlib.util.spec_from_file_location("auth_script", script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            session = self._base_session()
            result  = module.authenticate(session)
            if result:
                set_auth_session(result)
                self._session = result
                return result
        except Exception as exc:
            log.error("AuthManager: script error in %s: %s", script_path, exc)
        return None

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _base_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        return session

    @staticmethod
    def _extract_csrf(html: str):
        """Try to find a CSRF hidden field in a login form."""
        import re
        patterns = [
            r'<input[^>]+name=["\'](_token|csrf|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](_token|csrf|csrfmiddlewaretoken|authenticity_token)["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.I)
            if m:
                groups = m.groups()
                return (groups[0], groups[1]) if len(groups) >= 2 else (None, None)
        return (None, None)

    def _save_session(self, session: requests.Session) -> None:
        """Persist cookies to disk for optional reuse."""
        try:
            data = {c.name: c.value for c in session.cookies}
            Path(AUTH_SESSION_FILE).write_text(json.dumps(data))
            log.debug("AuthManager: session saved to %s", AUTH_SESSION_FILE)
        except OSError:
            pass

    def load_saved_session(self) -> Optional[requests.Session]:
        """Load cookies from a previous session if available."""
        try:
            if not Path(AUTH_SESSION_FILE).exists():
                return None
            data    = json.loads(Path(AUTH_SESSION_FILE).read_text())
            session = self._base_session()
            for name, value in data.items():
                session.cookies.set(name, value)
            set_auth_session(session)
            self._session = session
            log.info("AuthManager: loaded saved session (%d cookies)", len(data))
            return session
        except Exception:
            return None
