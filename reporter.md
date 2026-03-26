# Agent: Reporter

## Role
Consolidate all findings into a professional, structured security report.

## Input
- All files in `output/<pkg>/findings/`
- Code review notes from Reviewer agent

## Output
- `output/<pkg>/report.md` — full security report
- `output/<pkg>/report_summary.md` — executive summary (1 page)

---

## Report Template

```markdown
# Mobile Security Analysis Report

**App**: <app_name>
**Package**: <package_id>
**Version**: <version>
**Platform**: Android / iOS
**Analysis Date**: <date>
**Analyst**: mobile-security-agent v1.0

---

## Executive Summary

<2-3 sentence summary of overall security posture>

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | N |
| 🟠 HIGH | N |
| 🟡 MEDIUM | N |
| 🔵 LOW | N |
| ℹ️ INFO | N |

**Overall Risk**: CRITICAL / HIGH / MEDIUM / LOW

---

## App Overview

- **Framework**: Native Java / React Native / Flutter / Xamarin / Cordova
- **Min SDK**: API XX (Android X.X)
- **Target SDK**: API XX
- **Permissions**: XX requested (X dangerous)
- **Exported Components**: X activities, X services, X receivers, X providers
- **Native Libraries**: yes/no
- **Obfuscation**: yes/no (ProGuard/R8/DexGuard)

---

## Findings

### [SEVERITY] Finding Title

**Category**: Hardcoded Secret / SSL Bypass / Weak Crypto / etc.
**File**: `path/to/file.java:linenum`
**Severity**: CRITICAL / HIGH / MEDIUM / LOW

**Description**:
Clear explanation of the vulnerability.

**Evidence**:
\`\`\`java
// Relevant code snippet (3-10 lines max)
\`\`\`

**Impact**:
What an attacker could do if they exploited this.

**Recommendation**:
How to fix it.

---

(repeat for each finding)

---

## Permissions Analysis

### Dangerous Permissions
| Permission | Justification Required | Risk |
|------------|----------------------|------|
| READ_SMS | Explain why | HIGH |
| ACCESS_FINE_LOCATION | Explain why | MEDIUM |

### Suspicious Permissions
(permissions that seem excessive for the app's purpose)

---

## Network Security

### Endpoints Discovered
| Endpoint | Protocol | Notes |
|----------|----------|-------|
| api.example.com | HTTPS | OK |
| legacy.example.com | HTTP | ⚠️ Unencrypted |

### SSL Configuration
- Network Security Config: [present/missing]
- Certificate Pinning: [yes/no/partial]
- TLS minimum version: [TLS 1.2 / TLS 1.3 / unknown]

---

## Third-Party Dependencies

| Library | Version | CVE | Severity |
|---------|---------|-----|----------|
| OkHttp | 3.8.0 | CVE-2021-XXXX | HIGH |

---

## Recommendations Summary

1. **Immediate** (fix before next release):
   - [list CRITICAL and HIGH findings]

2. **Short-term** (next sprint):
   - [list MEDIUM findings]

3. **Long-term** (security hygiene):
   - [list LOW findings and general improvements]

---

## Methodology

- APK decompiled with: jadx X.X + apktool X.X
- Static analysis: grep patterns, semgrep rules
- AI code review: Claude claude-sonnet-4-20250514
- Vulnerability database: NVD, OSV.dev, Android Security Bulletins

## Disclaimer

This report is for authorized security research only.
Findings should be disclosed responsibly to the app developer.
```

---

## Severity Assignment Rules

| Condition | Severity |
|-----------|----------|
| Private key / cert hardcoded | CRITICAL |
| Authentication bypass possible | CRITICAL |
| RCE via exported component + intent injection | CRITICAL |
| Real API key to sensitive service (payment, SMS) | HIGH |
| SSL validation disabled unconditionally | HIGH |
| Firebase DB publicly readable | HIGH |
| Password stored in SharedPreferences plaintext | HIGH |
| Weak crypto on sensitive data | MEDIUM |
| Excessive permissions | MEDIUM |
| Debug flag in production build | MEDIUM |
| HTTP endpoint (non-sensitive) | LOW |
| Verbose logging (non-sensitive) | LOW |
| MD5 for non-security checksums | INFO |
