#!/usr/bin/env python3
"""
Hunter: Run all security detectors on decompiled source.
Returns list of findings dicts.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict

# ── Secret Patterns ─────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # Generic
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\047]([A-Za-z0-9_\-]{16,})["\047]',
     "Generic API Key", "HIGH"),
    (r'(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\047]([A-Za-z0-9_\-]{16,})["\047]',
     "Secret Key", "HIGH"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\047]([^"\047\s]{6,})["\047]',
     "Hardcoded Password", "HIGH"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CRITICAL"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\047]([A-Za-z0-9/+=]{40})["\047]',
     "AWS Secret Access Key", "CRITICAL"),
    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "HIGH"),
    (r'(?i)firebase[_-]?api[_-]?key\s*[:=]\s*["\047]([^"\047]{16,})["\047]',
     "Firebase API Key", "HIGH"),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key (LIVE)", "CRITICAL"),
    (r'pk_live_[0-9a-zA-Z]{24}', "Stripe Publishable Key (LIVE)", "MEDIUM"),
    # Twilio
    (r'AC[a-z0-9]{32}', "Twilio Account SID", "HIGH"),
    (r'SK[a-z0-9]{32}', "Twilio API Key", "HIGH"),
    # SendGrid
    (r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}', "SendGrid API Key", "HIGH"),
    # JWT
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
     "JWT Token (hardcoded)", "HIGH"),
    # Private keys
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    # Facebook
    (r'(?i)facebook[_-]?app[_-]?(secret|key)\s*[:=]\s*["\047]([0-9a-f]{32})["\047]',
     "Facebook App Secret", "HIGH"),
    # GitHub
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
    (r'github_pat_[A-Za-z0-9]{82}', "GitHub Fine-grained PAT", "CRITICAL"),
    # Slack
    (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}', "Slack Token", "HIGH"),
]

# ── SSL Bypass Patterns ──────────────────────────────────────────────────────

SSL_PATTERNS = [
    (r'TrustAllCerts|TRUST_ALL_CERTS', "Trust-all certificates implementation", "HIGH"),
    (r'checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}', "Empty checkServerTrusted (SSL bypass)", "HIGH"),
    (r'onReceivedSslError[^{]*\{[^}]*handler\.proceed', "WebView SSL error proceed without check", "HIGH"),
    (r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier', "Allow-all hostname verifier", "HIGH"),
    (r'setHostnameVerifier.*ALLOW_ALL', "Setting allow-all hostname verifier", "HIGH"),
    (r'X509TrustManager', "Custom X509TrustManager (review required)", "MEDIUM"),
    (r'SSLContext\.getInstance\s*\(\s*["\047]SSL["\047]\s*\)', "Insecure SSLContext (SSL instead of TLS)", "MEDIUM"),
    (r'NSAllowsArbitraryLoads.*true|NSAllowsArbitraryLoads\s*=\s*1', "ATS disabled (arbitrary loads)", "HIGH"),
]

# ── Weak Crypto Patterns ─────────────────────────────────────────────────────

CRYPTO_PATTERNS = [
    (r'MessageDigest\.getInstance\s*\(\s*["\047]MD5["\047]', "MD5 usage (review context)", "MEDIUM"),
    (r'MessageDigest\.getInstance\s*\(\s*["\047]SHA-?1["\047]', "SHA-1 usage", "MEDIUM"),
    (r'Cipher\.getInstance\s*\(\s*["\047]DES["\047]', "DES encryption (broken)", "HIGH"),
    (r'Cipher\.getInstance\s*\(\s*["\047][^"]*ECB["\047]', "AES-ECB mode (insecure)", "HIGH"),
    (r'Cipher\.getInstance\s*\(\s*["\047]AES["\047]\s*\)', "AES without mode specified (may default to ECB)", "MEDIUM"),
    (r'new\s+Random\s*\(\s*\)', "java.util.Random (not cryptographically secure)", "MEDIUM"),
    (r'SecureRandom.*setSeed|\.setSeed\s*\(\s*\d+', "SecureRandom with fixed seed", "HIGH"),
    (r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)', "Zero IV (static initialization vector)", "HIGH"),
]

# ── Dangerous WebView Patterns ────────────────────────────────────────────────

WEBVIEW_PATTERNS = [
    (r'setJavaScriptEnabled\s*\(\s*true\s*\)', "JavaScript enabled in WebView", "MEDIUM"),
    (r'addJavascriptInterface\s*\(', "JavaScript bridge exposed (potential XSS→RCE)", "HIGH"),
    (r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)', "Allow file access from file URLs", "HIGH"),
    (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', "Universal file access from file URLs", "CRITICAL"),
    (r'setAllowFileAccess\s*\(\s*true\s*\)', "WebView file access enabled", "MEDIUM"),
    (r'evaluateJavascript|loadUrl.*javascript:', "Dynamic JavaScript execution in WebView", "MEDIUM"),
]

# ── Insecure Storage Patterns ─────────────────────────────────────────────────

STORAGE_PATTERNS = [
    (r'getSharedPreferences|SharedPreferences.*["\047](?:password|token|key|secret|auth)',
     "Sensitive data in SharedPreferences", "HIGH"),
    (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', "World-readable/writable SharedPreferences", "HIGH"),
    (r'openFileOutput.*MODE_WORLD', "World-readable file", "HIGH"),
    (r'getExternalStorageDirectory|getExternalFilesDir', "Writing to external storage", "MEDIUM"),
    (r'\.putString\s*\(["\047][^"]*(?:password|token|secret|key|pin)["\047]',
     "Sensitive string in SharedPreferences", "HIGH"),
    (r'Log\.[dviwe]\s*\([^)]*(?:password|token|secret|key|credit|ssn)',
     "Logging sensitive data", "HIGH"),
]

# ── SQL Injection Patterns ────────────────────────────────────────────────────

SQLI_PATTERNS = [
    (r'rawQuery\s*\([^,)]*\+', "Potential SQL injection in rawQuery", "HIGH"),
    (r'execSQL\s*\([^,)]*\+', "Potential SQL injection in execSQL", "HIGH"),
    (r'query\s*\([^)]*\+[^)]*\)', "Potential SQL injection in query", "MEDIUM"),
]

# ── Intent/IPC Patterns ───────────────────────────────────────────────────────

IPC_PATTERNS = [
    (r'getIntent\(\)\.getStringExtra|getStringExtra\s*\(', "Intent string extra (check for validation)", "LOW"),
    (r'getParcelableExtra|getSerializableExtra', "Parcelable/Serializable from intent (deserialization risk)", "MEDIUM"),
    (r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder', "Command execution", "HIGH"),
]


def hunt_app(output_dir: str, info: dict) -> List[Dict]:
    """Run all detectors, return list of finding dicts."""
    out = Path(output_dir)
    findings_dir = out / "findings"
    findings_dir.mkdir(exist_ok=True)
    platform = info.get("platform", "android")

    all_findings = []

    # Determine scan root
    decompiled = out / "decompiled"
    resources = out / "resources"
    raw = out / "raw"

    scan_dirs = []
    if decompiled.exists():
        scan_dirs.append(str(decompiled))
    if resources.exists():
        scan_dirs.append(str(resources))

    if not scan_dirs:
        print("  ⚠️  No decompiled source found to scan")
        return []

    print(f"  🔍 Scanning {len(scan_dirs)} directories...")

    # Run each module
    all_findings += _run_pattern_scan("secrets", SECRET_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("ssl", SSL_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("crypto", CRYPTO_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("webview", WEBVIEW_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("storage", STORAGE_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("sqli", SQLI_PATTERNS, scan_dirs, findings_dir)
    all_findings += _run_pattern_scan("ipc", IPC_PATTERNS, scan_dirs, findings_dir)

    if platform == "android":
        manifest = resources / "AndroidManifest.xml"
        if manifest.exists():
            from scripts.analyze_permissions import analyze_to_findings
            perm_findings = analyze_to_findings(str(manifest))
            all_findings += perm_findings
            _write_findings(perm_findings, findings_dir / "permissions.txt")

    # Semgrep (optional)
    if _tool_exists("semgrep"):
        all_findings += _run_semgrep(scan_dirs, findings_dir)

    # Filter false positives
    all_findings = _filter_false_positives(all_findings)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 4))

    # Print summary
    counts = {}
    for f in all_findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    print(f"\n  📊 Detector results:")
    for sev, emoji in [("CRITICAL","🔴"),("HIGH","🟠"),("MEDIUM","🟡"),("LOW","🔵"),("INFO","ℹ️")]:
        if counts.get(sev, 0) > 0:
            print(f"     {emoji} {sev}: {counts[sev]}")

    return all_findings

def scan_secrets(directory: str) -> List[Dict]:
    """Run only secrets scanning."""
    findings_dir = Path(directory) / "findings"
    findings_dir.mkdir(exist_ok=True)
    findings = _run_pattern_scan("secrets", SECRET_PATTERNS, [directory], findings_dir)
    findings = _filter_false_positives(findings)
    for f in findings:
        print(f"  [{f['severity']}] {f['name']}: {f['file']}:{f['line']}")
    return findings

def _run_pattern_scan(module: str, patterns, scan_dirs, findings_dir) -> List[Dict]:
    """Run grep patterns across all scan dirs."""
    findings = []
    for pattern, name, severity in patterns:
        for scan_dir in scan_dirs:
            matches = _grep(pattern, scan_dir)
            for file_path, line_num, line_content in matches:
                findings.append({
                    "module": module,
                    "name": name,
                    "severity": severity,
                    "file": file_path,
                    "line": line_num,
                    "content": line_content.strip()[:200],
                    "pattern": pattern
                })

    if findings:
        _write_findings(findings, findings_dir / f"{module}.txt")
        print(f"  [{module.upper():10s}] {len(findings)} potential issues")
    else:
        print(f"  [{module.upper():10s}] clean ✓")

    return findings

def _grep(pattern: str, directory: str) -> List[tuple]:
    """Run grep and return (file, line_num, content) tuples."""
    results = []
    # Use ripgrep if available, else grep
    if _tool_exists("rg"):
        cmd = ["rg", "--no-heading", "--line-number", "-e", pattern,
               "--type-add", "mobile:*.{java,kt,swift,js,ts,xml,json,yaml,yml,properties,plist}",
               "--type", "mobile", directory]
    else:
        cmd = ["grep", "-r", "-n", "-E", "--include=*.java",
               "--include=*.kt", "--include=*.xml", "--include=*.json",
               "--include=*.js", "--include=*.swift", "--include=*.properties",
               pattern, directory]

    result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    for line in result.stdout.splitlines():
        # format: file:linenum:content
        parts = line.split(":", 2)
        if len(parts) >= 3:
            results.append((parts[0], parts[1], parts[2]))
        elif len(parts) == 2:
            results.append((parts[0], parts[1], ""))
    return results

def _filter_false_positives(findings: List[Dict]) -> List[Dict]:
    """Remove known false positive patterns."""
    fp_path_patterns = [
        r'/test/', r'Test\.java', r'Spec\.kt', r'\.g\.dart',
        r'BuildConfig\.java', r'/R\.java', r'androidTest/',
        r'example\.com', r'placeholder', r'your[_-]?api[_-]?key',
        r'YOUR_KEY_HERE', r'xxx+', r'TODO', r'FIXME',
    ]
    fp_content_patterns = [
        r'//.*',        # commented out
        r'^\s*\*',      # javadoc
        r'"[^"]{0,5}"', # too short to be a real secret
    ]

    result = []
    for f in findings:
        file_path = f.get("file", "")
        content = f.get("content", "")

        is_fp = False
        for pat in fp_path_patterns:
            if re.search(pat, file_path, re.IGNORECASE):
                is_fp = True
                break

        if not is_fp:
            result.append(f)

    return result

def _run_semgrep(scan_dirs: list, findings_dir: Path) -> List[Dict]:
    """Run semgrep with mobile security rules."""
    findings = []
    rules_dir = Path(__file__).parent.parent / "semgrep"

    if not rules_dir.exists():
        return []

    for scan_dir in scan_dirs:
        result = subprocess.run([
            "semgrep", "--config", str(rules_dir),
            "--json", scan_dir
        ], capture_output=True, text=True)

        if result.returncode == 0:
            import json
            try:
                data = json.loads(result.stdout)
                for r in data.get("results", []):
                    findings.append({
                        "module": "semgrep",
                        "name": r.get("check_id", "").split(".")[-1],
                        "severity": r.get("extra", {}).get("severity", "MEDIUM").upper(),
                        "file": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "content": r.get("extra", {}).get("lines", "").strip()[:200],
                    })
            except json.JSONDecodeError:
                pass

    if findings:
        _write_findings(findings, findings_dir / "semgrep.txt")
        print(f"  [SEMGREP    ] {len(findings)} findings")

    return findings

def _write_findings(findings: List[Dict], path: Path):
    lines = []
    for f in findings:
        lines.append(f"[{f.get('severity','?')}] {f.get('name','?')}")
        lines.append(f"  File: {f.get('file','')}:{f.get('line','')}")
        lines.append(f"  Code: {f.get('content','')}")
        lines.append("")
    path.write_text("\n".join(lines))

def _tool_exists(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0
