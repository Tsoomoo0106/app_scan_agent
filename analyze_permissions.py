#!/usr/bin/env python3
import re, sys
from pathlib import Path
from typing import List, Dict
from xml.etree import ElementTree as ET

DANGEROUS = {
    "READ_CONTACTS":              ("HIGH",     "Access contacts"),
    "READ_CALL_LOG":              ("HIGH",     "Access call history"),
    "READ_SMS":                   ("HIGH",     "Read SMS messages"),
    "RECEIVE_SMS":                ("HIGH",     "Receive SMS messages"),
    "SEND_SMS":                   ("HIGH",     "Send SMS messages"),
    "RECORD_AUDIO":               ("HIGH",     "Record microphone"),
    "ACCESS_FINE_LOCATION":       ("HIGH",     "Precise GPS location"),
    "ACCESS_BACKGROUND_LOCATION": ("HIGH",     "Background location tracking"),
    "CAMERA":                     ("MEDIUM",   "Camera access"),
    "READ_EXTERNAL_STORAGE":      ("MEDIUM",   "Read files from storage"),
    "WRITE_EXTERNAL_STORAGE":     ("MEDIUM",   "Write files to storage"),
    "REQUEST_INSTALL_PACKAGES":   ("HIGH",     "Install APKs silently"),
    "SYSTEM_ALERT_WINDOW":        ("HIGH",     "Draw over other apps"),
    "BIND_ACCESSIBILITY_SERVICE": ("CRITICAL", "Screen reader — spyware indicator"),
    "BIND_DEVICE_ADMIN":          ("CRITICAL", "Device administrator"),
    "RECEIVE_BOOT_COMPLETED":     ("MEDIUM",   "Auto-start on device boot"),
    "READ_PHONE_STATE":           ("MEDIUM",   "Device ID / phone number"),
    "PROCESS_OUTGOING_CALLS":     ("HIGH",     "Intercept outgoing calls"),
    "MANAGE_EXTERNAL_STORAGE":    ("HIGH",     "Full storage access"),
    "GET_ACCOUNTS":               ("MEDIUM",   "Access device accounts"),
}

SPYWARE_COMBO = [
    {"READ_SMS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO"},
    {"READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION"},
    {"BIND_ACCESSIBILITY_SERVICE", "READ_SMS"},
]

def analyze(manifest_path: str):
    findings = analyze_to_findings(manifest_path)
    print(f"\n📋 Permissions Analysis: {manifest_path}")
    for f in findings:
        e = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "•")
        print(f"  {e} [{f['severity']}] {f['name']}: {f.get('content', '')}")
    print(f"\n  Total: {len(findings)} findings")

def analyze_to_findings(manifest_path: str) -> List[Dict]:
    findings = []
    path = Path(manifest_path)
    if not path.exists():
        return []

    content = path.read_text(errors="ignore")

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return _regex_analyze(content, manifest_path)

    ns = "http://schemas.android.com/apk/res/android"

    # Collect all permissions
    perms = set()
    for el in root.findall("uses-permission"):
        name = el.get(f"{{{ns}}}name", "")
        short = name.replace("android.permission.", "")
        perms.add(short)
        if short in DANGEROUS:
            risk, desc = DANGEROUS[short]
            findings.append({
                "module": "permissions",
                "name": f"Permission: {short}",
                "severity": risk,
                "file": manifest_path,
                "line": "",
                "content": desc
            })

    # Check spyware combos
    for combo in SPYWARE_COMBO:
        if combo.issubset(perms):
            findings.append({
                "module": "permissions",
                "name": f"Spyware permission combo: {', '.join(sorted(combo))}",
                "severity": "CRITICAL",
                "file": manifest_path,
                "line": "",
                "content": "Combination of permissions commonly used by spyware/stalkerware"
            })

    # Application-level checks
    app = root.find("application")
    if app is not None:
        if app.get(f"{{{ns}}}debuggable", "false").lower() == "true":
            findings.append({
                "module": "permissions",
                "name": "debuggable=true",
                "severity": "HIGH",
                "file": manifest_path,
                "line": "",
                "content": "App is debuggable — allows code injection and memory inspection"
            })

        if app.get(f"{{{ns}}}allowBackup", "true").lower() == "true":
            findings.append({
                "module": "permissions",
                "name": "allowBackup=true",
                "severity": "MEDIUM",
                "file": manifest_path,
                "line": "",
                "content": "App data can be extracted via ADB backup"
            })

        # Exported components
        for tag in ["activity", "service", "receiver", "provider"]:
            for el in app.findall(tag):
                name = el.get(f"{{{ns}}}name", "")
                exported = el.get(f"{{{ns}}}exported", None)
                perm = el.get(f"{{{ns}}}permission", None)
                has_filter = el.find("intent-filter") is not None
                is_exported = (
                    exported == "true" or
                    (has_filter and exported != "false" and not perm)
                )
                if is_exported and "MainActivity" not in name:
                    findings.append({
                        "module": "permissions",
                        "name": f"Exported {tag}: {name.split('.')[-1]}",
                        "severity": "HIGH" if tag in ("service", "provider") else "MEDIUM",
                        "file": manifest_path,
                        "line": "",
                        "content": f"Accessible from external apps without permission"
                    })

    return findings

def _regex_analyze(content, path):
    """Fallback regex-based analysis when XML parsing fails (binary manifest)."""
    findings = []
    for m in re.finditer(r'android\.permission\.(\w+)', content):
        short = m.group(1)
        if short in DANGEROUS:
            risk, desc = DANGEROUS[short]
            findings.append({
                "module": "permissions",
                "name": f"Permission: {short}",
                "severity": risk,
                "file": path,
                "line": "",
                "content": desc
            })
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_permissions.py <AndroidManifest.xml>")
        sys.exit(1)
    analyze(sys.argv[1])
