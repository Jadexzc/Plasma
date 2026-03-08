# False Positives — Triage Guide

Automated scanners, including Plasma, can produce false positives — results that appear to indicate a vulnerability but do not represent a real exploitable issue. **All findings must be manually verified before being reported.**

---

## Why False Positives Occur

| Cause | Example |
|---|---|
| Generic error strings | A page that always returns "SQL error" in marketing copy |
| Slow responses | A legitimately slow endpoint triggering time-based detection |
| Reflected input in safe context | User input reflected inside a JavaScript string with proper escaping |
| WAF error pages | A WAF returning 500 with generic text that matches error patterns |
| Application quirks | A redirect that coincidentally mirrors part of the injected payload |

---

## How Plasma Reduces False Positives

Plasma uses several techniques to minimise false positives before reporting a finding:

| Technique | Description |
|---|---|
| **Differential response comparison** | Compares the injected response against a clean baseline. Only flags significant differences. |
| **Multi-payload confirmation** | Requires multiple payload variants to produce consistent results before raising HIGH/CRITICAL. |
| **Timing analysis** | Time-based detections require the injected response to be significantly slower than a measured baseline (≥2.5 seconds delta), not just slow in absolute terms. |
| **Reflection context analysis** | XSS detectors verify the probe is reflected *unescaped* — not just present in the response. |
| **Unique probe markers** | Uses unique, non-guessable probe strings (e.g. `PLXSS42`, `WGRCE42XY`) that are unlikely to appear naturally. |

---

## Manual Verification Checklist

For each finding, verify:

**SQL Injection**
- [ ] Reproduce the exact payload in a browser or with curl
- [ ] Confirm the database error is caused by injection, not a pre-existing broken query
- [ ] For time-based: run the delay payload 2–3 times to confirm timing consistency

**XSS**
- [ ] Load the URL with the payload in a real browser
- [ ] Confirm the script/tag executes (not just appears as text)
- [ ] Check that the reflection is not inside a comment or encoded attribute

**SSRF**
- [ ] Check your collaborator dashboard for DNS/HTTP callbacks
- [ ] Verify the response body contains cloud metadata content, not a cached or mocked response

**RCE**
- [ ] Confirm the echo marker appears in the response and is not a static string
- [ ] For time-based: verify the delay is consistent across multiple requests

**IDOR**
- [ ] Confirm the alternate ID response returns data belonging to a different user/account
- [ ] Verify the data is not publicly intended (e.g. public profile pages)

**Directory Traversal**
- [ ] Confirm the system file content (`root:x:`, `[fonts]`) appears in the response
- [ ] Verify it is not a cached, templated, or example page

---

## Reporting Confidence Levels

Plasma assigns a confidence level to each finding:

| Level | Meaning |
|---|---|
| `CONFIRMED` | Definitive proof (e.g. echo marker in response, DNS callback received) |
| `HIGH` | Strong evidence (e.g. DB error pattern matched, reflection confirmed unescaped) |
| `MEDIUM` | Indirect evidence (e.g. time delay, boolean differential) |
| `LOW` | Weak signal — always verify manually |

Prioritise verification of `MEDIUM` and `LOW` findings before including them in a report.

---

## Suppressing Known False Positives

Use `--skip` to exclude detectors that are generating noise on a specific target:

```bash
# Skip JWT and CORS detectors (e.g. if target uses a third-party auth service)
plasma --url https://target.com --skip jwt,cors --profile aggressive
```

Or use `--detectors` to run only the detectors you care about:

```bash
plasma --url https://target.com --detectors sqli,xss,ssrf
```
