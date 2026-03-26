#!/usr/bin/env python3
"""
Analyze AndroidManifest.xml permissions and exported components.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict
from xml.etree import ElementTree as ET

# Android dangerous permissions with risk levels
DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS":              ("HIGH",   "Access to all contacts"),
    "WRITE_CONTACTS":             ("MEDIUM", "Modify contacts"),
    "READ_CALL_LOG":              ("HIGH",   "Access to call history"),
    "WRITE_CALL_LOG":             ("HIGH",   "Modify call history"),
    "PROCESS_OUTGOING_CALLS":     ("HIGH",   "Intercept outgoing calls"),
    "READ_SMS":                   ("HIGH",   "Read SMS messages"),
    "RECEIVE_SMS":                ("HIGH",   "Receive SMS messages"),
    "SEND_SMS":                   ("HIGH",   "Send SMS (can incur charges)"),
    "RECEIVE_MMS":                ("MEDIUM", "Receive MMS messages"),
    "RECORD_AUDIO":               ("HIGH",   "Record microphone"),
    "CAMERA":                     ("MEDIUM", "Access camera"),
    "ACCESS_FINE_LOCATION":       ("HIGH",   "Precise GPS location"),
    "ACCESS_COARSE_LOCATION":     ("MEDIUM", "Approximate location"),
    "ACCESS_BACKGROUND_LOCATION": ("HIGH",   "Location access in background"),
    "READ_EXTERNAL_STORAGE":      ("MEDIUM", "Read files from storage"),
    "WRITE_EXTERNAL_STORAGE":     ("MEDIUM", "Write files to storage"),
    "MANAGE_EXTERNAL_STORAGE":    ("HIGH",   "Full storage access (Android 11+)"),
    "READ_PHONE_STATE":           ("MEDIUM", "Device ID, phone number"),
    "READ_PHONE_NUMBERS":         ("HIGH",   "Access phone numbers"),
    "CALL_PHONE":                 ("HIGH",   "Make phone calls"),
    "GET_ACCOUNTS":               ("MEDIUM", "Access Google accounts on device"),
    "USE_BIOMETRIC":              ("MEDIUM", "Use biometric authentication"),
    "USE_FINGERPRINT":            ("MEDIUM", "Use fingerprint authentication"),
    "BODY_SENSORS":               ("HIGH",   "Access health sensors"),
    "ACTIVITY_RECOGNITION":       ("MEDIUM", "Detect physical activity"),
    "REQUEST_INSTALL_PACKAGES":   ("HIGH",   "Can install APKs (dropper risk)"),
    "SYSTEM_ALERT_WINDOW":        ("HIGH",   "Draw over other apps (clickjacking)"),
    "WRITE_SETTINGS":             ("MEDIUM", "Modify system settings"),
    "BIND_ACCESSIBILITY_SERVICE": ("CRITICAL","Can read screen content (spyware indicator)"),
    "BIND_DEVICE_ADMIN":          ("CRITICAL","Device administrator (malware indicator)"),
    "RECEIVE_BOOT_COMPLETED":     ("MEDIUM", "Starts on device boot"),
    "FOREGROUND_SERVICE":         ("LOW",    "Persistent foreground service"),
    "WAKE_LOCK":                  ("LOW",    "Prevent device sleep"),
    "BLUETOOTH_SCAN":             ("MEDIUM", "Scan for Bluetooth devices"),
    "BLUETOOTH_CONNECT":          ("MEDIUM", "Connect to Bluetooth devices"),
    "NFC":                        ("MEDIUM", "Access NFC chip"),
    "CHANGE_NETWORK_STATE":       ("LOW",    "Change network settings"),
    "CHANGE_WIFI_STATE":          ("LOW",    "Change Wi-Fi settings"),
    "BLUETOOTH_ADMIN":            ("MEDIUM", "Manage Bluetooth"),
}

# Permissions that are almost never needed legitimately
SUSPICIOUS_COMBOS = [
    (["READ_SMS", "SEND_SMS", "RECEIVE_SMS"],
     "SMS Trojan pattern: read + send + receive SMS"),
    (["RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS"],
     "Spyware pattern: audio + location + contacts"),
    (["BIND_ACCESSIBILITY_SERVICE", "READ_SMS"],
     "Accessibility + SMS = likely screen reader malware"),
    (["REQUEST_INSTALL_PACKAGES", "RECEIVE_SMS"],
     "SMS-triggered dropper pattern"),
]


def analyze(manifest_path: str):
    """Analyze and print permissions report."""
    findings = analyze_to_findings(manifest_path)

    print(f"\n📋 Permissions Analysis: {manifest_path}")
    print("=" * 60)

    for f in findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}.get(f["severity"], "•")
        print(f"{icon} [{f['severity']:8s}] {f['name']}")
        if f.get("content"):
            print(f"           {f['content']}")
    print()


def analyze_to_findings(manifest_path: str) -> List[Dict]:
    """Parse manifest and return findings list."""
    findings = []
    path = Path(manifest_path)

    if not path.exists():
        return []

    content = path.read_text(errors="ignore")

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        # Fallback to regex
        return _regex_analyze(content)

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    android_ns = "http://schemas.android.com/apk/res/android"

    # --- Permissions ---
    app_permissions = set()
    for perm_el in root.findall("uses-permission"):
        perm_name = perm_el.get(f"{{{android_ns}}}name", "")
        short = perm_name.replace("android.permission.", "")
        app_permissions.add(short)

        if short in DANGEROUS_PERMISSIONS:
            risk, desc = DANGEROUS_PERMISSIONS[short]
            findings.append({
                "module": "permissions",
                "name": f"Permission: {short}",
                "severity": risk,
                "file": manifest_path,
                "line": "",
                "content": desc
            })

    # --- Suspicious combos ---
    for combo, message in SUSPICIOUS_COMBOS:
        if all(p in app_permissions for p in combo):
            findings.append({
                "module": "permissions",
                "name": "Suspicious Permission Combination",
                "severity": "HIGH",
                "file": manifest_path,
                "line": "",
                "content": message
            })

    # --- Exported components ---
    app_el = root.find("application")
    if app_el is not None:
        debuggable = app_el.get(f"{{{android_ns}}}debuggable", "false")
        if debuggable.lower() == "true":
            findings.append({
                "module": "permissions",
                "name": "Debuggable=true in production",
                "severity": "HIGH",
                "file": manifest_path,
                "line": "",
                "content": "android:debuggable=true allows ADB debugging of release app"
            })

        backup = app_el.get(f"{{{android_ns}}}allowBackup", "true")
        if backup.lower() == "true":
            findings.append({
                "module": "permissions",
                "name": "allowBackup=true",
                "severity": "LOW",
                "file": manifest_path,
                "line": "",
                "content": "App data can be backed up via ADB (adb backup)"
            })

        # Exported components
        for tag in ["activity", "service", "receiver", "provider"]:
            for el in app_el.findall(tag):
                name = el.get(f"{{{android_ns}}}name", "")
                exported = el.get(f"{{{android_ns}}}exported", None)
                perm = el.get(f"{{{android_ns}}}permission", None)
                has_intent_filter = el.find("intent-filter") is not None

                # Exported if explicitly true, or has intent-filter without permission
                is_exported = (
                    exported == "true" or
                    (has_intent_filter and exported != "false" and perm is None)
                )

                if is_exported and not name.endswith("MainActivity"):
                    sev = "MEDIUM"
                    if tag in ("service", "provider"):
                        sev = "HIGH"
                    findings.append({
                        "module": "permissions",
                        "name": f"Exported {tag.capitalize()}: {name.split('.')[-1]}",
                        "severity": sev,
                        "file": manifest_path,
                        "line": "",
                        "content": f"accessible from external apps without permission"
                        + (" — has intent-filter" if has_intent_filter else "")
                    })

    return findings


def _regex_analyze(content: str) -> List[Dict]:
    """Fallback regex-based analysis."""
    findings = []
    for perm_match in re.finditer(r'android\.permission\.(\w+)', content):
        short = perm_match.group(1)
        if short in DANGEROUS_PERMISSIONS:
            risk, desc = DANGEROUS_PERMISSIONS[short]
            findings.append({
                "module": "permissions",
                "name": f"Permission: {short}",
                "severity": risk,
                "file": "AndroidManifest.xml",
                "line": "",
                "content": desc
            })
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: analyze_permissions.py <AndroidManifest.xml>")
        sys.exit(1)
    analyze(sys.argv[1])
