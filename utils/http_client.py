"""
utils/http_client.py — Plasma v3
----------------------------------
HTTP session factory with v3 authentication support.
All detectors and the crawler share sessions via make_session().
An authenticated session (set by AuthManager) is injected into
ScanContext and retrieved here via get_session(context).

Production optimisations
------------------------
1. HTTPAdapter with tuned connection pool sizes.
   Default requests.Session uses only 10 connections per host.  For a
   scanner launching hundreds of concurrent requests this creates a queue
   inside urllib3.  We raise pool_connections=20, pool_maxsize=100 and
   enable pool_block=False so workers never block waiting for a slot.

2. Retry adapter with exponential back-off for transient network errors.
   Retries 3 times on connection/read errors with a 0.5s back-off factor,
   covering the most common transient failures (TCP RST, brief overload).
   Status-force-list covers 429 (rate-limited) and 5xx server errors.
   This prevents false-negative findings on flaky targets.

3. Session reuse across make_session() calls.
   When no authenticated session exists, we return a single shared
   anonymous session (_anon_session) rather than creating a new Session
   object on every call.  Session creation allocates ~6 objects + an
   HTTPAdapter; reuse eliminates that overhead completely.
   Thread-safety note: requests.Session is NOT thread-safe for concurrent
   writes; detectors only read (make GET/POST) so sharing is safe here.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import USER_AGENT, DEFAULT_TIMEOUT

log = logging.getLogger(__name__)

# -- Pool / retry configuration -----------------------------------------------

# Raised from default 10 to handle concurrent scanner workloads.
_POOL_CONNECTIONS = 20
_POOL_MAXSIZE     = 100

# Retry on transient network errors; exponential back-off: 0.5, 1, 2 seconds.
_RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist={429, 500, 502, 503, 504},
    allowed_methods={"HEAD", "GET", "OPTIONS"},  # only safe methods
    raise_on_status=False,
)

# -- Module-level state -------------------------------------------------------

# Module-level authenticated session (set by AuthManager after login).
_auth_session: Optional[Session] = None

# Shared anonymous session — reused instead of allocating a new Session per
# make_session() call.  Reset to None when proxy settings change.
_anon_session: Optional[Session] = None

# Module-level proxy (set from ScanSettings.proxy before crawl/detect).
_proxy: Optional[str] = None

# Lock protecting all three globals above.  Concurrent detectors (run via
# asyncio thread-pool executors) can call make_session() simultaneously;
# without a lock, two threads can both see _anon_session is None and each
# build a new Session, leaking one of them.
_session_lock = threading.Lock()


# -- Internal helpers ---------------------------------------------------------

def _build_adapter() -> HTTPAdapter:
    """Return a tuned HTTPAdapter with retry and large connection pool."""
    adapter = HTTPAdapter(
        max_retries=_RETRY_STRATEGY,
        pool_connections=_POOL_CONNECTIONS,
        pool_maxsize=_POOL_MAXSIZE,
        pool_block=False,
    )
    return adapter


def _new_session(user_agent: Optional[str] = None, verify: bool = True) -> Session:
    """Create a fresh Session with tuned adapter and standard headers."""
    session = requests.Session()
    adapter = _build_adapter()
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.headers.update({
        "User-Agent":      user_agent or USER_AGENT,
        "Accept":          "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    })
    session.verify = verify
    if _proxy:
        session.proxies.update({"http": _proxy, "https": _proxy})
    return session


# -- Public configuration API -------------------------------------------------

def set_proxy(proxy_url: Optional[str]) -> None:
    """Configure a proxy for all subsequent sessions."""
    global _proxy, _anon_session
    with _session_lock:
        _proxy = proxy_url
        # Invalidate the cached anonymous session so the next make_session() call
        # creates one with the proxy applied.
        _anon_session = None
    log.debug("http_client: proxy set to %s", proxy_url)


def set_auth_session(session: Session) -> None:
    """Called by AuthManager after successful login to share session."""
    global _auth_session
    with _session_lock:
        _auth_session = session
    log.debug("Authenticated session registered in http_client")


def get_auth_session() -> Optional[Session]:
    """Return the shared authenticated session if one was established."""
    return _auth_session


# -- Session factory ----------------------------------------------------------

def make_session(timeout: Optional[int] = None, verify: bool = True) -> Session:
    """
    Return a pre-configured requests.Session.

    If an authenticated session has been registered, return it (shared).
    Otherwise return the shared anonymous session, creating it on first call.

    Thread-safe: _session_lock guards the _anon_session initialisation so
    concurrent thread-pool workers cannot each allocate a separate Session.

    Args:
        verify: SSL certificate verification (set False for self-signed certs)
    """
    global _anon_session
    if _auth_session is not None:
        _auth_session.verify = verify
        return _auth_session
    if _anon_session is None or _anon_session.verify != verify:
        with _session_lock:
            if _anon_session is None or _anon_session.verify != verify:
                _anon_session = _new_session(verify=verify)
    return _anon_session


def make_anon_session() -> Session:
    """Always return a fresh anonymous session (bypasses cached auth/anon sessions)."""
    return _new_session()


# -- Request helpers ----------------------------------------------------------

def safe_get(
    session: Session,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs,
) -> Optional[Response]:
    """GET with full error handling. Returns None on any network failure."""
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
        log.debug("GET %s -> %d", url, response.status_code)
        return response
    except requests.exceptions.ConnectionError:
        log.warning("Connection refused: %s", url)
    except requests.exceptions.Timeout:
        log.warning("Timeout after %ds: %s", timeout, url)
    except requests.exceptions.RequestException as exc:
        log.warning("Request failed (%s): %s", url, exc)
    return None


def safe_request(
    session: Session,
    method: str,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs,
) -> Optional[Response]:
    """Generic safe request for any HTTP method."""
    try:
        response = session.request(method.upper(), url, timeout=timeout, **kwargs)
        log.debug("%s %s -> %d", method.upper(), url, response.status_code)
        return response
    except requests.exceptions.ConnectionError:
        log.warning("Connection refused: %s %s", method, url)
    except requests.exceptions.Timeout:
        log.warning("Timeout: %s %s", method, url)
    except requests.exceptions.RequestException as exc:
        log.warning("Request error (%s %s): %s", method, url, exc)
    return None


def _apply_proxy(session: Session) -> Session:
    """Apply the module-level proxy to a session if configured. (Backward compat shim.)"""
    if _proxy:
        session.proxies.update({"http": _proxy, "https": _proxy})
    return session
