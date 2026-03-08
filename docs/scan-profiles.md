# Scan Profiles

Scan profiles control how aggressively Plasma tests a target — how many payloads it sends, how fast it sends them, and whether evasion techniques are active.

---

## Profile Summary

| Profile | Behavior | Request Volume | Delays | Evasion | Safe for Production |
|---|---|---|---|---|:---:|
| `safe` | Passive checks only | Minimal | 1 second | Off | ✅ Yes |
| `default` | Balanced active testing | Medium | 0.3 seconds | Off | ⚠ Usually |
| `aggressive` | Full payload sets | High | None | On | ❌ No |
| `stealth` | Low-rate, evasive | Low | 3 seconds | On | ⚠ Depends |

---

## Profile Details

### `safe`

- **Payload limit:** 3 per parameter
- **Request delay:** 1.0 second between requests
- **Active probing:** Disabled — no payloads are injected
- **Evasion:** Off
- **Use case:** Initial reconnaissance, verifying the scanner can reach the target, running alongside production traffic without disruption

```bash
plasma --url https://target.com --profile safe
```

Detectors still run, but only perform passive checks (response header analysis, cookie flag inspection, CORS policy review).

---

### `default`

- **Payload limit:** 10 per parameter
- **Request delay:** 0.3 seconds
- **Active probing:** Enabled
- **Evasion:** Off
- **Use case:** Standard penetration test engagement, staged environments, API testing

```bash
plasma --url https://target.com --profile default
```

This is the recommended starting point for most engagements. It catches the majority of common vulnerabilities without flooding the target.

---

### `aggressive`

- **Payload limit:** 50 per parameter
- **Request delay:** 0 (no delay)
- **Active probing:** Enabled
- **Evasion:** On (WAF bypass, encoding variants, header manipulation)
- **Use case:** Dedicated test environments, CTF challenges, maximum coverage

```bash
plasma --url https://target.com --profile aggressive --fuzz
```

⚠ This profile can send thousands of requests per minute. Confirm target capacity and scope before use. Do not run against production systems without explicit approval.

---

### `stealth`

- **Payload limit:** 5 per parameter
- **Request delay:** 3.0 seconds (randomised ±jitter)
- **Active probing:** Enabled
- **Evasion:** On (user-agent rotation, timing jitter)
- **Use case:** Evading WAF rate limits, low-noise recon, targets with aggressive bot detection

```bash
plasma --url https://target.com --profile stealth --rate-limit 1
```

Combine with `--rate-limit` for additional throttling beyond the profile default.

---

## Combining Profiles with Flags

Profiles set defaults. Individual flags override them:

```bash
# Use aggressive profile but cap at 5 requests/second
plasma --url https://target.com --profile aggressive --rate-limit 5

# Use stealth profile but run a specific detector with full payloads
plasma --url https://target.com --profile stealth --test-sqli --detectors sqli

# Override concurrency ceiling
plasma --url https://target.com --profile aggressive --concurrency 16
```

---

## Fuzzer Profile Override

`--fuzz-profile` sets the profile **only for the fuzzer phase**, independent of the main `--profile`:

```bash
# Stealth crawl + recon, but aggressive fuzzing on discovered endpoints
plasma --url https://target.com --profile stealth --fuzz --fuzz-profile aggressive
```

---

## Configuration Reference

Profile settings are defined in `config.py` under `SCAN_PROFILES`. You can extend or modify profiles there for custom engagements.
