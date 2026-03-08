# Plasma Security Analysis Report

> This file is the report template skeleton. The actual report is generated
> programmatically by `reporting/report_builder.py`.
> All section variables below are populated at runtime.

---

## Table of Contents

1. Executive Summary
2. Endpoint Findings
3. Cookie Security Analysis
4. Token Entropy Analysis
5. File Upload Risk Assessment
6. Risk Score Breakdown
7. Remediation Guidance
8. PoC File Inventory

---

## 1. Executive Summary

**Target:** `{{ TARGET_URL }}`
**Overall Risk:** `{{ OVERALL_RISK }}`
**Generated:** `{{ TIMESTAMP }}`

{{ EXECUTIVE_NARRATIVE }}

---

## 2. Endpoint Findings

{{ ENDPOINT_TABLE }}

---

## 3. Cookie Security Analysis

{{ COOKIE_TABLE }}

---

## 4. Token Entropy Analysis

**Formula:** H = − Σ (pᵢ × log₂ pᵢ)

{{ TOKEN_TABLE }}

---

## 5. File Upload Risk Assessment

{{ FILE_UPLOAD_TABLE }}

---

## 6. Risk Score Breakdown

{{ SCORE_BREAKDOWN }}

---

## 7. Remediation Guidance

{{ REMEDIATION_SECTIONS }}

### Priority Matrix

| Priority | Action | Effort | Impact |
|:---:|---|:---:|:---:|
| P1 | Add CSRF tokens to all state-changing forms | Low | Critical |
| P2 | Set `SameSite=Strict` on session cookies | Low | High |
| P3 | Set `HttpOnly` + `Secure` on all cookies | Low | High |
| P4 | Strengthen token length and entropy | Low | High |
| P5 | Protect file upload endpoints | Medium | High |

---

## 8. PoC File Inventory

{{ POC_TABLE }}

---

## References

| Resource | URL |
|----------|-----|
| OWASP CSRF Prevention | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html |
| OWASP Session Management | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |
| OWASP File Upload | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html |
