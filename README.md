# 📱 Mobile Security Agent

**Open-source APK & IPA security analysis tool with AI-powered code review**

Inspired by [find-cve-agent](https://github.com/ByamB4/find-cve-agent) — a 6-agent team that systematically scans mobile apps for security vulnerabilities, from Play Store/App Store URL to detailed report.

---

## What It Does

Given a Play Store URL, App Store URL, or local APK/IPA file, this tool:

1. **Downloads** the app automatically (APK via apkeep/APKPure, IPA via ipatool)
2. **Decompiles** APK with jadx + apktool, or extracts IPA
3. **Scans** with 10 security detector modules
4. **Reviews** suspicious code with AI (Claude)
5. **Reports** findings ranked by severity

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/yourname/mobile-security-agent
cd mobile-security-agent
bash setup.sh

# 2. Scan (Play Store URL)
python3 msa.py scan "https://play.google.com/store/apps/details?id=com.example.app"

# 3. Scan (App Store URL)
python3 msa.py scan "https://apps.apple.com/us/app/example/id123456789"

# 4. Scan (local file)
python3 msa.py scan app.apk
python3 msa.py scan MyApp.ipa
```

---

## Agent Team

| Agent | Role |
|-------|------|
| **Fetcher** | Downloads APK/IPA from store URLs |
| **Unpacker** | Decompiles APK (jadx+apktool) or extracts IPA |
| **Hunter** | Runs 10 security detector modules |
| **Reviewer** | AI code review of suspicious files |
| **Reporter** | Generates severity-ranked markdown report |

---

## What Gets Detected

| Module | What It Finds |
|--------|---------------|
| 🔑 **Secrets** | Hardcoded API keys, AWS keys, JWT tokens, private keys, Stripe/Twilio/SendGrid keys |
| 🔒 **SSL/TLS** | Certificate bypass, trust-all certs, WebView SSL errors ignored |
| 🔐 **Cryptography** | MD5/SHA-1, DES, AES-ECB, hardcoded IV, weak Random |
| 🌐 **WebView** | JS enabled, JS bridges, file access, dynamic JS execution |
| 💾 **Storage** | SharedPreferences secrets, world-readable files, external storage, log leaks |
| 📋 **Permissions** | Dangerous/excessive permissions, spyware permission combos |
| 🔧 **IPC** | Exported components, intent injection, command execution |
| 💉 **SQL Injection** | rawQuery/execSQL with string concatenation |
| 📦 **Dependencies** | Libraries with known CVEs (via OSV.dev) |
| 🔍 **Semgrep** | Custom static analysis rules |

---

## Commands

```bash
python3 msa.py scan <url_or_file>     # Full pipeline
python3 msa.py fetch <store_url>       # Download only
python3 msa.py unpack <file>           # Decompile only
python3 msa.py hunt <directory>        # Scan only
python3 msa.py secrets <directory>     # Secrets scan only
python3 msa.py permissions <manifest>  # Permissions only
```

### Claude Code Commands (after plugin install)
```
/scan <url>          Full pipeline scan
/fetch <url>         Download app
/unpack <file>       Decompile/extract
/hunt <dir>          Run detectors
/review <file>       AI code review
/secrets <dir>       Secrets scan
/permissions <file>  Permissions analysis
/report              Generate report
```

---

## Output

```
output/
└── com.example.app/
    ├── decompiled/          # jadx Java/Kotlin source
    ├── resources/           # apktool manifest + resources
    ├── raw/                 # Raw APK contents
    ├── framework.txt        # Detected framework
    ├── jadx.log
    ├── findings/
    │   ├── secrets.txt
    │   ├── ssl.txt
    │   ├── crypto.txt
    │   ├── webview.txt
    │   ├── storage.txt
    │   ├── permissions.txt
    │   ├── sqli.txt
    │   └── ipc.txt
    └── report.md            ← Final security report
```

---

## Requirements

### Required
- Python 3.8+
- Java 11+ (for jadx)
- `jadx` — APK decompiler
- `apktool` — APK resource extractor
- `curl`, `unzip`

### Auto-installed by `setup.sh`
- jadx, apktool, apkeep, ripgrep, semgrep

### Optional
- `ipatool` — iOS IPA download (macOS)
- `class-dump` — iOS binary header extraction
- `semgrep` — Enhanced static analysis

---

## Claude Code Plugin

After `setup.sh`, the plugin installs into `~/.claude/plugins/`. In Claude Code:

```
/scan https://play.google.com/store/apps/details?id=com.whatsapp
```

Claude will run the full pipeline and show findings interactively.

---

## Responsible Use

This tool is for **authorized security research only**:

- ✅ Apps you own or have explicit permission to test
- ✅ Bug bounty programs that include mobile apps
- ✅ CTF challenges
- ✅ Security research with responsible disclosure

**Do NOT** use to attack apps without authorization. Follow responsible disclosure — contact the developer before publishing findings.

---

## License

Apache-2.0
