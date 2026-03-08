"""
config.py
──────────
Central configuration for Plasma V1 security testing framework.

All tunable constants, feature flags, and scan profiles live here.
No module should hardcode values that appear in this file.
"""

# ─── Tool Identity ────────────────────────────────────────────────────────────

TOOL_NAME    = "Plasma"
TOOL_VERSION = "1.0.0"
USER_AGENT   = f"{TOOL_NAME}/{TOOL_VERSION} (Academic Security Testing)"
DISCLAIMER   = "For Authorized Testing Only — Do Not Use Without Permission"

# ─── Crawler ──────────────────────────────────────────────────────────────────

DEFAULT_CRAWL_DEPTH   = 2
DEFAULT_TIMEOUT       = 10        # seconds per request
REQUEST_DELAY         = 0.3       # polite inter-request delay (seconds)
MAX_PAGES_PER_SCAN    = 200       # hard cap on crawled pages

# ─── Endpoint Classification ──────────────────────────────────────────────────

STATE_CHANGING_METHODS  = {"POST", "PUT", "PATCH", "DELETE"}
MULTIPART_ENCTYPE       = "multipart/form-data"
CSRF_TOKEN_PATTERNS = [
    "csrf", "token", "_token", "csrftoken", "csrf_token",
    "authenticity_token", "xsrf", "_csrf", "anti_csrf",
    "__requestverificationtoken",
]

# ─── Token / Entropy Thresholds ───────────────────────────────────────────────

MIN_TOKEN_LENGTH     = 16
MIN_TOKEN_ENTROPY    = 3.5
STRONG_TOKEN_LENGTH  = 32
STRONG_TOKEN_ENTROPY = 4.0

# ─── Cookie Analysis ──────────────────────────────────────────────────────────

SESSION_COOKIE_PATTERNS = [
    "session", "sessionid", "sess", "sid", "auth",
    "jsessionid", "phpsessid", "connect.sid", ".aspxauth",
    "token", "login", "user",
]

# ─── Risk Scoring Weights ─────────────────────────────────────────────────────

WEIGHT_MISSING_TOKEN    = 4
WEIGHT_WEAK_TOKEN       = 3
WEIGHT_TOKEN_REUSE      = 2
WEIGHT_MISSING_SAMESITE = 2
WEIGHT_SAMESITE_NONE    = 3
WEIGHT_MISSING_SECURE   = 1
WEIGHT_MISSING_HTTPONLY = 1
WEIGHT_FILE_UPLOAD      = 4
WEIGHT_SQLI             = 9
WEIGHT_XSS              = 7
WEIGHT_SSRF             = 8
WEIGHT_RCE              = 10
WEIGHT_IDOR             = 7
WEIGHT_MISCONFIG        = 5
WEIGHT_DIR_TRAVERSAL    = 8
WEIGHT_OPEN_REDIRECT    = 5
WEIGHT_CORS             = 6
WEIGHT_JWT              = 6
WEIGHT_SENSITIVE_FILE   = 7

# Severity → numeric for aggregation
SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Info": 0,
}

# ─── Risk Classification Bands ────────────────────────────────────────────────

RISK_BANDS = [
    (3,  "Low"),
    (7,  "Medium"),
    (12, "High"),
]
# Any score > 12 → "Critical"

# ─── Vulnerability Detector Enable Flags ──────────────────────────────────────

ENABLED_DETECTORS = {
    "csrf":               True,
    "sqli":               True,
    "xss":                True,
    "ssrf":               True,
    "rce":                True,
    "idor":               True,
    "misconfig":          True,
    "directory_traversal": True,
    "file-upload":        True,
    "open-redirect":      True,
    "cors":               True,
    "jwt":                True,
    "graphql":            True,
    "sensitive-files":    True,
    "xpath":              True,
    "crlf":               True,
}

# ─── Scan Profiles ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "safe": {
        "description":    "Passive analysis only — no active payloads sent",
        "request_delay":  1.0,
        "max_payloads":   3,
        "evasion":        False,
        "active_probing": False,
    },
    "default": {
        "description":    "Balanced — active probing with polite delays",
        "request_delay":  0.3,
        "max_payloads":   10,
        "evasion":        False,
        "active_probing": True,
    },
    "aggressive": {
        "description":    "Full payload sets, no delays, all evasion techniques",
        "request_delay":  0.0,
        "max_payloads":   50,
        "evasion":        True,
        "active_probing": True,
    },
    "stealth": {
        "description":    "Slow requests, user-agent rotation, randomised delays",
        "request_delay":  3.0,
        "max_payloads":   5,
        "evasion":        True,
        "active_probing": True,
    },
}

DEFAULT_SCAN_PROFILE = "default"

# ─── Evasion / Stealth ────────────────────────────────────────────────────────

ROTATE_USER_AGENTS = False          # Rotate UA strings across requests
PROXY_LIST: list = []               # Optional proxy pool ["http://...", ...]
JITTER_RANGE = (0.1, 0.5)          # Random extra delay (min, max) in seconds
MAX_RETRIES  = 3

USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

# ─── Concurrency ──────────────────────────────────────────────────────────────

MAX_CONCURRENT_SCANS     = 10      # parallel ScanManager workers
MAX_CONCURRENT_DETECTORS = 20      # detectors per scan running concurrently
MAX_CONCURRENT_PARAMS    = 16      # concurrent param probes per detector
PASSIVE_BATCH_SIZE       = 50      # max endpoints analysed in the passive phase
ADAPTIVE_CONCURRENCY     = True    # enable AIMD adaptive concurrency
MAX_SCAN_CONCURRENCY     = 48      # hard ceiling for adaptive semaphore

# ─── Output Directories ───────────────────────────────────────────────────────

DEFAULT_POC_DIR      = "poc_output"
DEFAULT_REPORT_DIR   = "reports"
DEFAULT_LOG_DIR      = "logs"
DEFAULT_SCAN_DIR     = "scans"
DEFAULT_SCREENSHOT_DIR = "screenshots"

# ─── UI / Server ──────────────────────────────────────────────────────────────

UI_HOST    = "127.0.0.1"
UI_PORT    = 5001
UI_DEBUG   = False
UI_SECRET  = "change-me-in-production"     # Flask secret key

# ─── Reporting ────────────────────────────────────────────────────────────────

REPORT_FORMATS = ["markdown", "html", "pdf"]
DEFAULT_REPORT_FORMAT = "markdown"

# ─── Authentication ───────────────────────────────────────────────────────────

AUTH_SESSION_FILE = ".wg_session.json"   # persisted cookie jar

# ─── Reconnaissance ───────────────────────────────────────────────────────────

SUBDOMAIN_WORDLIST     = "wordlists/subdomains-top1million-5000.txt"
PARAMETER_WORDLIST     = "wordlists/parameters.txt"
SUBDOMAIN_CONCURRENCY  = 20
PARAMETER_CONCURRENCY  = 15
SUBDOMAIN_TIMEOUT      = 3         # seconds

# ─── Rate Limiting / WAF Detection ────────────────────────────────────────────

RATE_LIMIT_CODES     = {429, 503}
WAF_BLOCK_CODES      = {403, 406, 419, 999}
WAF_SLOWDOWN_FACTOR  = 3.0         # multiply request_delay when WAF detected
WAF_SIGNATURES = [
    "cloudflare", "akamai", "incapsula", "sucuri", "f5", "barracuda",
    "mod_security", "naxsi", "captcha", "__cf_bm", "x-cache-status",
]

# ─── Technology Detection ─────────────────────────────────────────────────────

TECH_FINGERPRINTS = {
    "nginx":      {"headers": ["server: nginx"]},
    "apache":     {"headers": ["server: apache"]},
    "iis":        {"headers": ["server: microsoft-iis", "x-powered-by: asp.net"]},
    "php":        {"headers": ["x-powered-by: php"]},
    "wordpress":  {"paths": ["/wp-login.php", "/wp-admin/"], "meta": ["WordPress"]},
    "drupal":     {"paths": ["/user/login"], "meta": ["Drupal"]},
    "django":     {"headers": ["x-frame-options: sameorigin"], "cookies": ["csrftoken"]},
    "laravel":    {"cookies": ["laravel_session", "XSRF-TOKEN"]},
    "nodejs":     {"headers": ["x-powered-by: express"]},
    "joomla":     {"paths": ["/administrator/"], "meta": ["Joomla"]},
    "react":      {"meta": ["__reactFiber", "data-reactroot"]},
    "angular":    {"meta": ["ng-version", "_nghost"]},
    "vue":        {"meta": ["__vue__", "data-v-"]},
    "spring":     {"headers": ["x-application-context"]},
    "ruby":       {"headers": ["x-powered-by: phusion passenger", "server: thin"]},
}

# ─── Sensitive File Paths ─────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/phpinfo.php", "/info.php", "/test.php",
    "/config.php", "/config.bak", "/config.old",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/wp-config.php", "/wp-config.php.bak",
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/web.config.bak",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/robots.txt", "/sitemap.xml",
    "/admin/config.php", "/administrator/index.php",
    "/.DS_Store", "/Thumbs.db",
]

SENSITIVE_FILE_SIGNATURES = [
    "DB_PASSWORD", "DB_USER", "APP_SECRET", "SECRET_KEY",
    "mysql_connect", "password =", "passwd =",
    "[database]", "smtp_pass", "api_key",
    "root:x:", "[extensions]", "Index of /",
    "Directory listing", "Parent Directory",
]

# ─── GraphQL ──────────────────────────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/api/v1/graphql", "/query", "/gql",
]

# ─── JWT ──────────────────────────────────────────────────────────────────────

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt", "token",
    "letmein", "changeme", "admin", "test",
]

# ─── CORS ─────────────────────────────────────────────────────────────────────

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]

# ─── Open Redirect ────────────────────────────────────────────────────────────

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirectTo", "redirectUrl",
    "next", "url", "return", "returnTo", "return_url", "returnUrl",
    "goto", "go", "destination", "dest", "continue", "forward",
    "location", "link", "to",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http://evil.com@trusted.com",
    "javascript:alert(1)",
]

# ─── Templates ────────────────────────────────────────────────────────────────

TEMPLATE_DIRS = ["templates/nuclei"]

# ─── Fuzzing Engine ───────────────────────────────────────────────────────────

FUZZ_MAX_MUTATIONS       = 30      # max payload mutations per technique
FUZZ_CONCURRENCY         = 8       # max concurrent fuzz probes per endpoint
FUZZ_CHAIN_DEPTH         = 3       # max exploit chain depth
FUZZ_FEEDBACK_WINDOW     = 50      # sliding window for adaptive feedback loop
FUZZ_WAF_DETECT_THRESH   = 0.6     # WAF detection confidence threshold (0–1)
FUZZ_PLUGIN_DIR          = "plugins"   # default plugin search path
FUZZ_PAYLOAD_UPDATE_URL  = ""      # optional: URL to fetch external payload lists
FUZZ_LOG_EVASION_METRICS = True    # write evasion metrics to scan log
FUZZ_STEALTH_JITTER      = (0.2, 1.5)  # per-probe jitter range in stealth mode

# SSL/TLS verification (disable for self-signed cert test environments)
VERIFY_SSL = True
