#!/usr/bin/env python3
import re, subprocess
from pathlib import Path
from typing import List, Dict

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\047]([A-Za-z0-9_\-]{16,})["\047]', "Generic API Key", "HIGH"),
    (r'(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\047]([A-Za-z0-9_\-]{16,})["\047]', "Secret Key", "HIGH"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\047]([^"\047\s]{6,})["\047]', "Hardcoded Password", "HIGH"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "CRITICAL"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "HIGH"),
    (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key", "CRITICAL"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token", "HIGH"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub PAT", "CRITICAL"),
    (r'(?i)firebase[_-]?api[_-]?key\s*[:=]\s*["\047]([^"\047]{16,})["\047]', "Firebase API Key", "HIGH"),
]
SSL_PATTERNS = [
    (r'TrustAllCerts|TRUST_ALL_CERTS', "Trust-all certificates", "HIGH"),
    (r'checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}', "Empty checkServerTrusted", "HIGH"),
    (r'onReceivedSslError[^{]*\{[^}]*handler\.proceed', "WebView SSL error ignored", "HIGH"),
    (r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier', "Allow-all hostname verifier", "HIGH"),
    (r'NSAllowsArbitraryLoads.*true', "ATS disabled", "HIGH"),
]
CRYPTO_PATTERNS = [
    (r'MessageDigest\.getInstance\s*\(\s*["\047]MD5["\047]', "MD5 usage", "MEDIUM"),
    (r'Cipher\.getInstance\s*\(\s*["\047][^"]*ECB["\047]', "AES-ECB mode", "HIGH"),
    (r'new\s+Random\s*\(\s*\)', "Insecure Random", "MEDIUM"),
    (r'SecureRandom.*setSeed|\.setSeed\s*\(\s*\d+', "Fixed SecureRandom seed", "HIGH"),
]
WEBVIEW_PATTERNS = [
    (r'setJavaScriptEnabled\s*\(\s*true\s*\)', "JavaScript enabled in WebView", "MEDIUM"),
    (r'addJavascriptInterface\s*\(', "JavaScript bridge exposed", "HIGH"),
    (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', "Universal file access", "CRITICAL"),
]
STORAGE_PATTERNS = [
    (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', "World-readable storage", "HIGH"),
    (r'getExternalStorageDirectory|getExternalFilesDir', "External storage write", "MEDIUM"),
    (r'Log\.[dviwe]\s*\([^)]*(?:password|token|secret|key)', "Logging sensitive data", "HIGH"),
]
SQLI_PATTERNS = [
    (r'rawQuery\s*\([^,)]*\+', "SQL injection in rawQuery", "HIGH"),
    (r'execSQL\s*\([^,)]*\+', "SQL injection in execSQL", "HIGH"),
]

def hunt_app(output_dir: str, info: dict) -> List[Dict]:
    out = Path(output_dir)
    findings_dir = out / "findings"
    findings_dir.mkdir(exist_ok=True)
    platform = info.get("platform", "android")
    scan_dirs = []
    for d in ["decompiled", "resources"]:
        p = out / d
        if p.exists(): scan_dirs.append(str(p))
    if not scan_dirs:
        print("  ⚠️  No source to scan")
        return []
    print(f"  🔍 Scanning {len(scan_dirs)} directories...")
    all_findings = []
    for name, patterns in [("secrets",SECRET_PATTERNS),("ssl",SSL_PATTERNS),
                            ("crypto",CRYPTO_PATTERNS),("webview",WEBVIEW_PATTERNS),
                            ("storage",STORAGE_PATTERNS),("sqli",SQLI_PATTERNS)]:
        findings = _run_scan(name, patterns, scan_dirs, findings_dir)
        all_findings += findings
    if platform == "android":
        manifest = out / "resources" / "AndroidManifest.xml"
        if manifest.exists():
            from scripts.analyze_permissions import analyze_to_findings
            pf = analyze_to_findings(str(manifest))
            all_findings += pf
            _write(pf, findings_dir / "permissions.txt")
    all_findings = _filter_fp(all_findings)
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity","INFO"),4))
    counts = {}
    for f in all_findings:
        s = f.get("severity","INFO"); counts[s] = counts.get(s,0)+1
    print(f"\n  📊 Results:")
    for s,e in [("CRITICAL","🔴"),("HIGH","🟠"),("MEDIUM","🟡"),("LOW","🔵"),("INFO","ℹ️")]:
        if counts.get(s,0): print(f"     {e} {s}: {counts[s]}")
    return all_findings

def scan_secrets(directory: str) -> List[Dict]:
    findings_dir = Path(directory) / "findings"
    findings_dir.mkdir(exist_ok=True)
    findings = _run_scan("secrets", SECRET_PATTERNS, [directory], findings_dir)
    findings = _filter_fp(findings)
    for f in findings:
        print(f"  [{f['severity']}] {f['name']}: {f['file']}:{f['line']}")
    return findings

def _run_scan(module, patterns, scan_dirs, findings_dir):
    findings = []
    for pattern, name, severity in patterns:
        for d in scan_dirs:
            for fp, ln, content in _grep(pattern, d):
                findings.append({"module":module,"name":name,"severity":severity,
                                  "file":fp,"line":ln,"content":content.strip()[:200]})
    if findings:
        _write(findings, findings_dir / f"{module}.txt")
        print(f"  [{module.upper():10s}] {len(findings)} issues")
    else:
        print(f"  [{module.upper():10s}] clean ✓")
    return findings

def _grep(pattern, directory):
    results = []
    use_rg = subprocess.run(["which","rg"], capture_output=True).returncode == 0
    if use_rg:
        cmd = ["rg","--no-heading","--line-number","-e",pattern,directory]
    else:
        cmd = ["grep","-r","-n","-E","--include=*.java","--include=*.kt",
               "--include=*.xml","--include=*.json","--include=*.js",
               "--include=*.swift","--include=*.properties",pattern,directory]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    for line in r.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) >= 2:
            results.append((parts[0], parts[1] if len(parts)>1 else "", parts[2] if len(parts)>2 else ""))
    return results

def _filter_fp(findings):
    fp_pats = [r'/test/',r'Test\.java',r'BuildConfig\.java',r'/R\.java',
               r'example\.com',r'YOUR_KEY',r'placeholder',r'xxx+']
    result = []
    for f in findings:
        if not any(re.search(p, f.get("file",""), re.I) for p in fp_pats):
            result.append(f)
    return result

def _write(findings, path):
    lines = []
    for f in findings:
        lines.append(f"[{f.get('severity','?')}] {f.get('name','?')}")
        lines.append(f"  File: {f.get('file','')}:{f.get('line','')}")
        lines.append(f"  Code: {f.get('content','')}\n")
    path.write_text("\n".join(lines))
