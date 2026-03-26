#!/usr/bin/env python3
import re, sys
from pathlib import Path
from typing import List, Dict
from xml.etree import ElementTree as ET

DANGEROUS = {
    "READ_CONTACTS":("HIGH","Access contacts"),
    "READ_CALL_LOG":("HIGH","Access call history"),
    "READ_SMS":("HIGH","Read SMS"),
    "RECEIVE_SMS":("HIGH","Receive SMS"),
    "SEND_SMS":("HIGH","Send SMS"),
    "RECORD_AUDIO":("HIGH","Record microphone"),
    "ACCESS_FINE_LOCATION":("HIGH","Precise GPS"),
    "ACCESS_BACKGROUND_LOCATION":("HIGH","Background location"),
    "CAMERA":("MEDIUM","Camera access"),
    "READ_EXTERNAL_STORAGE":("MEDIUM","Read files"),
    "WRITE_EXTERNAL_STORAGE":("MEDIUM","Write files"),
    "REQUEST_INSTALL_PACKAGES":("HIGH","Install APKs"),
    "SYSTEM_ALERT_WINDOW":("HIGH","Draw over apps"),
    "BIND_ACCESSIBILITY_SERVICE":("CRITICAL","Screen reader (spyware indicator)"),
    "BIND_DEVICE_ADMIN":("CRITICAL","Device administrator"),
    "RECEIVE_BOOT_COMPLETED":("MEDIUM","Auto-start on boot"),
    "READ_PHONE_STATE":("MEDIUM","Device ID/phone number"),
    "PROCESS_OUTGOING_CALLS":("HIGH","Intercept calls"),
    "MANAGE_EXTERNAL_STORAGE":("HIGH","Full storage access"),
    "GET_ACCOUNTS":("MEDIUM","Access accounts"),
}

def analyze(manifest_path: str):
    findings = analyze_to_findings(manifest_path)
    print(f"\n📋 Permissions: {manifest_path}")
    for f in findings:
        e = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(f["severity"],"•")
        print(f"  {e} [{f['severity']}] {f['name']}: {f.get('content','')}")

def analyze_to_findings(manifest_path: str) -> List[Dict]:
    findings = []
    path = Path(manifest_path)
    if not path.exists(): return []
    content = path.read_text(errors="ignore")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return _regex_analyze(content, manifest_path)

    ns = "http://schemas.android.com/apk/res/android"
    perms = set()
    for el in root.findall("uses-permission"):
        name = el.get(f"{{{ns}}}name", "")
        short = name.replace("android.permission.", "")
        perms.add(short)
        if short in DANGEROUS:
            risk, desc = DANGEROUS[short]
            findings.append({"module":"permissions","name":f"Permission: {short}",
                              "severity":risk,"file":manifest_path,"line":"","content":desc})

    app = root.find("application")
    if app is not None:
        if app.get(f"{{{ns}}}debuggable","false").lower() == "true":
            findings.append({"module":"permissions","name":"debuggable=true",
                              "severity":"HIGH","file":manifest_path,"line":"",
                              "content":"App is debuggable in production"})
        for tag in ["activity","service","receiver","provider"]:
            for el in app.findall(tag):
                name = el.get(f"{{{ns}}}name","")
                exported = el.get(f"{{{ns}}}exported", None)
                perm = el.get(f"{{{ns}}}permission", None)
                has_filter = el.find("intent-filter") is not None
                is_exported = exported == "true" or (has_filter and exported != "false" and not perm)
                if is_exported and "MainActivity" not in name:
                    findings.append({"module":"permissions",
                                      "name":f"Exported {tag}: {name.split('.')[-1]}",
                                      "severity":"HIGH" if tag in ("service","provider") else "MEDIUM",
                                      "file":manifest_path,"line":"",
                                      "content":"Accessible from external apps"})
    return findings

def _regex_analyze(content, path):
    findings = []
    for m in re.finditer(r'android\.permission\.(\w+)', content):
        short = m.group(1)
        if short in DANGEROUS:
            risk, desc = DANGEROUS[short]
            findings.append({"module":"permissions","name":f"Permission: {short}",
                              "severity":risk,"file":path,"line":"","content":desc})
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: analyze_permissions.py <AndroidManifest.xml>")
        sys.exit(1)
    analyze(sys.argv[1])
