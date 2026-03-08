# Pentest Workflows

Typical workflow examples for different engagement types. All examples assume you have written permission to test the target.

---

## 1. Standard Web Application Pentest

**Goal:** Comprehensive vulnerability assessment of a web application.

```bash
# Step 1 — Passive recon (safe to run in production)
plasma --url https://target.com --profile safe --subdomains --param-discovery \
  --report markdown --report-dir ./recon

# Step 2 — Active vulnerability scan
plasma --url https://target.com --profile aggressive \
  --report html,markdown --poc --report-dir ./findings

# Step 3 — Fuzzing focus on high-value endpoints
plasma --url https://target.com --profile aggressive \
  --fuzz --fuzz-chain --extract-db \
  --report html --poc --report-dir ./fuzz-findings

# Step 4 — Replay + manual verification
plasma --replay findings/scan_*.json --verbose
```

---

## 2. Authenticated Application Scan

For applications that require login before exposing most functionality.

**Form-based login:**
```bash
plasma --url https://target.com \
  --login-url https://target.com/login \
  --login-data "username=admin&password=Passw0rd!" \
  --profile aggressive --report html --poc
```

**Cookie / session token injection:**
```bash
plasma --url https://target.com \
  --auth-cookie "session=eyJhbGciOiJ...; csrftoken=abc123" \
  --profile default
```

**Custom multi-step auth (OAuth, MFA, SAML):**

Create a Python script `auth.py`:
```python
def authenticate(session):
    """Plasma calls this before crawling. Return the authenticated session."""
    # Step 1: Get CSRF token
    r = session.get("https://target.com/login")
    csrf = extract_csrf(r.text)  # your extraction logic

    # Step 2: POST credentials
    session.post("https://target.com/login", data={
        "username": "admin",
        "password": "Passw0rd!",
        "_token": csrf,
    })
    return session
```

```bash
plasma --url https://target.com --login-script auth.py --profile aggressive
```

---

## 3. API Security Testing

For REST APIs that return JSON rather than HTML forms.

```bash
# API mode disables form-based crawling; focuses on URL path parameters
plasma --url https://api.target.com --api-mode \
  --test-sqli --test-ssrf --test-idor --test-rce \
  --profile aggressive --report html --poc
```

---

## 4. Bug Bounty Workflow

Optimised for bug bounty programs: safe recon first, focused active testing.

```bash
# 1. Safe recon — no active payloads
plasma --url https://target.com --profile safe --subdomains \
  --output-json recon.json

# 2. Review recon output; pick specific detectors
plasma --url https://target.com \
  --test-sqli --test-xss --test-ssrf \
  --collaborator https://YOUR.oastify.com \
  --blind-xss https://YOUR.xsshunter.com \
  --profile default --report html --poc --report-dir ./bb-findings

# 3. Blind confirmation (OOB callbacks)
#    Check your collaborator/XSS hunter dashboard for callbacks
```

---

## 5. Batch / Multi-Target Scan

```bash
# urls.txt — one URL per line
echo "https://target1.com
https://target2.com
https://target3.com" > urls.txt

plasma --batch urls.txt --profile default \
  --report html --report-dir ./batch-results
```

---

## 6. CI/CD Pipeline Integration

Run Plasma as a gate in your deployment pipeline.

```bash
plasma --url https://staging.internal \
  --profile default \
  --report html \
  --output-json ci-results.json \
  --quiet

# Exit code: 0 = no findings, 1 = findings present
echo "Exit code: $?"
```

Parse `ci-results.json` to enforce severity thresholds in your pipeline logic.

---

## 7. Replay and Verification

Scans saved with `--save-scan` can be replayed to verify fixes or compare scan states.

```bash
# Save a scan
plasma --url https://target.com --profile aggressive --save-scan --scan-dir ./scans

# Replay it later
plasma --replay scans/scan_2024-01-15.json --verbose

# Replay with a different profile or detector focus
plasma --replay scans/scan_2024-01-15.json --test-sqli --profile aggressive
```

---

## 8. Proxy Integration (Burp Suite)

Route all Plasma traffic through Burp Suite for manual review alongside automated testing.

```bash
plasma --url https://target.com \
  --proxy http://127.0.0.1:8080 \
  --profile default
```

All requests appear in Burp's HTTP history. You can intercept, modify, or replay them manually.
