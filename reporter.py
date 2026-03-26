#!/usr/bin/env python3
"""
Reporter: Generate final markdown security report from all findings.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict


def generate_report(output_dir: str, findings: List[Dict], info: dict) -> str:
    """Generate a full security report. Returns path to report.md."""
    out = Path(output_dir)
    report_path = out / "report.md"

    pkg_id = info.get("identifier", out.name)
    platform = info.get("platform", "android").capitalize()
    framework = (out / "framework.txt").read_text().strip() if (out / "framework.txt").exists() else "Unknown"

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    # Overall risk
    if counts["CRITICAL"] > 0:
        overall = "🔴 CRITICAL"
    elif counts["HIGH"] >= 3:
        overall = "🔴 HIGH"
    elif counts["HIGH"] > 0:
        overall = "🟠 HIGH"
    elif counts["MEDIUM"] > 0:
        overall = "🟡 MEDIUM"
    else:
        overall = "🟢 LOW"

    lines = []

    # Header
    lines += [
        "# 📱 Mobile Security Analysis Report",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **App / Package** | `{pkg_id}` |",
        f"| **Platform** | {platform} |",
        f"| **Framework** | {framework} |",
        f"| **Analysis Date** | {datetime.now().strftime('%Y-%m-%d %H:%M')} |",
        f"| **Tool** | mobile-security-agent v1.0 |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Summary table
    lines += [
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
        f"| 🟠 HIGH | {counts['HIGH']} |",
        f"| 🟡 MEDIUM | {counts['MEDIUM']} |",
        f"| 🔵 LOW | {counts['LOW']} |",
        f"| ℹ️ INFO | {counts['INFO']} |",
        "",
        f"**Overall Risk Level: {overall}**",
        "",
        _executive_summary(findings, counts),
        "",
        "---",
        "",
    ]

    # Findings by severity
    lines += [
        "## Findings",
        "",
    ]

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}

    for sev in sev_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        lines.append(f"### {sev_emoji[sev]} {sev} Severity\n")

        for i, finding in enumerate(sev_findings, 1):
            name = finding.get("name", "Unknown")
            file_path = finding.get("file", "")
            line_num = finding.get("line", "")
            content = finding.get("content", "")
            module = finding.get("module", "")

            lines += [
                f"#### {i}. {name}",
                "",
                f"**Category**: {_module_to_category(module)}  ",
                f"**Severity**: {sev}  ",
            ]
            if file_path:
                display_path = _shorten_path(file_path)
                lines.append(f"**Location**: `{display_path}:{line_num}`  ")
            lines.append("")

            if content:
                lines += [
                    "**Evidence**:",
                    "```",
                    content[:300],
                    "```",
                    "",
                ]

            lines += [
                f"**Recommendation**: {_get_recommendation(name, module)}",
                "",
                "---",
                "",
            ]

    # Recommendations summary
    lines += [
        "## Remediation Priority",
        "",
        "### Immediate (before next release)",
    ]

    immediate = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if immediate:
        for f in immediate[:10]:
            lines.append(f"- [ ] Fix: {f.get('name','?')}")
    else:
        lines.append("- No critical/high findings 🎉")

    lines += [
        "",
        "### Short-term (next sprint)",
    ]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    if medium:
        for f in medium[:8]:
            lines.append(f"- [ ] {f.get('name','?')}")
    else:
        lines.append("- No medium findings")

    lines += [
        "",
        "### Long-term (security hygiene)",
    ]
    low = [f for f in findings if f.get("severity") in ("LOW", "INFO")]
    if low:
        for f in low[:6]:
            lines.append(f"- [ ] {f.get('name','?')}")
    else:
        lines.append("- No low findings")

    lines += [
        "",
        "---",
        "",
        "## Methodology",
        "",
        "- APK decompiled with: jadx + apktool",
        "- Pattern matching: custom grep rules (secrets, SSL, crypto, storage, WebView)",
        "- Permission analysis: AndroidManifest.xml parsing",
        "- Static analysis: semgrep mobile security ruleset (if installed)",
        "- AI code review: Claude claude-sonnet-4-20250514",
        "",
        "## Disclaimer",
        "",
        "> This report is for **authorized security research only**. Findings should be",
        "> responsibly disclosed to the app developer before public release.",
        "> Do not use this tool to attack production systems without authorization.",
    ]

    report_content = "\n".join(lines)
    report_path.write_text(report_content)

    return str(report_path)


def _executive_summary(findings, counts):
    total = sum(counts.values())
    if total == 0:
        return "No security issues were detected during static analysis. Manual review is still recommended."

    top = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    top_names = ", ".join(f.get("name", "?") for f in top)

    return (
        f"Analysis identified **{total} potential security issues** across all scan modules. "
        f"Key findings include: {top_names}. "
        f"Immediate remediation is recommended for all Critical and High severity findings "
        f"before the next public release."
    )


def _module_to_category(module: str) -> str:
    return {
        "secrets": "Hardcoded Secrets / Credential Exposure",
        "ssl": "Network Security / SSL-TLS",
        "crypto": "Cryptography",
        "webview": "WebView Security",
        "storage": "Insecure Data Storage",
        "sqli": "SQL Injection",
        "ipc": "Inter-Process Communication",
        "permissions": "Permissions / Component Exposure",
        "semgrep": "Static Analysis (Semgrep)",
    }.get(module, module.capitalize())


def _get_recommendation(name: str, module: str) -> str:
    recs = {
        "secrets": "Remove hardcoded credentials. Use environment variables, Android Keystore, or a secrets management service.",
        "ssl": "Enforce certificate validation. Use network_security_config.xml with certificate pinning. Never accept all certificates.",
        "crypto": "Use strong, modern algorithms: AES-256-GCM for encryption, SHA-256+ for hashing, SecureRandom for key generation.",
        "webview": "Disable JavaScript unless required. Avoid addJavascriptInterface. Validate all URLs loaded in WebViews.",
        "storage": "Use Android Keystore for sensitive data. Avoid SharedPreferences for secrets. Use EncryptedSharedPreferences.",
        "sqli": "Use parameterized queries (SQLiteDatabase.query() with ? placeholders) instead of string concatenation.",
        "ipc": "Validate all data received via Intents. Add android:permission to exported components.",
        "permissions": "Request only permissions that are strictly necessary for app functionality. Justify each dangerous permission.",
    }
    return recs.get(module, "Review the finding and apply appropriate security controls.")


def _shorten_path(path: str) -> str:
    """Shorten long paths for readability."""
    parts = path.replace("\\", "/").split("/")
    # Find 'decompiled' or 'resources' and show relative path from there
    for anchor in ["decompiled", "resources", "raw"]:
        if anchor in parts:
            idx = parts.index(anchor)
            return "/".join(parts[idx:])
    # Otherwise show last 4 components
    return "/".join(parts[-4:]) if len(parts) > 4 else path


if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) < 2:
        print("Usage: reporter.py <output_dir> [findings.json]")
        sys.exit(1)
    findings = []
    if len(sys.argv) > 2:
        findings = json.loads(Path(sys.argv[2]).read_text())
    report = generate_report(sys.argv[1], findings, {"identifier": "app", "platform": "android"})
    print(f"Report: {report}")
