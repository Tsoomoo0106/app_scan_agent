# Agent: Hunter

## Role
Systematically scan decompiled source for security vulnerabilities using grep patterns, semgrep rules, and heuristics.

## Input
- Decompiled source directory

## Output
- Raw findings files in `output/<package>/findings/`
- Prioritized list of suspicious files for Reviewer agent

---

## Scan Modules (run all)

### 1. Secrets & Hardcoded Credentials
```bash
# API keys, tokens, passwords
rg -i --no-heading \
  -e 'api[_-]?key\s*[:=]\s*["\047][A-Za-z0-9]{16,}' \
  -e 'secret[_-]?key\s*[:=]\s*["\047][A-Za-z0-9]{16,}' \
  -e 'password\s*[:=]\s*["\047][^"\047]{6,}' \
  -e 'aws[_-]?access[_-]?key[_-]?id\s*[:=]' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
  output/<pkg>/decompiled/ > findings/secrets_raw.txt

# Google API keys
rg 'AIza[0-9A-Za-z\-_]{35}' output/<pkg>/decompiled/ >> findings/secrets_raw.txt

# Firebase
rg '"firebase"' output/<pkg>/decompiled/resources/ | head -20 >> findings/secrets_raw.txt

# Stripe, Twilio, SendGrid etc.
rg -i 'sk_live_|pk_live_|AC[a-z0-9]{32}|SG\.[a-zA-Z0-9]{22}' \
  output/<pkg>/decompiled/ >> findings/secrets_raw.txt
```

### 2. Permissions Analysis (Android)
```bash
python3 scripts/analyze_permissions.py \
  output/<pkg>/resources/AndroidManifest.xml \
  > findings/permissions.txt

# Dangerous permissions to flag:
# READ_CONTACTS, READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION
# CAMERA, READ_CALL_LOG, PROCESS_OUTGOING_CALLS
# BIND_ACCESSIBILITY_SERVICE (spyware indicator)
# REQUEST_INSTALL_PACKAGES
# WRITE_SETTINGS
```

### 3. Network Security
```bash
# HTTP (non-TLS) endpoints
rg 'http://[^"]*' output/<pkg>/decompiled/ \
  --no-heading > findings/http_endpoints.txt

# SSL/TLS bypass patterns
rg -i \
  -e 'TrustAllCerts\|X509TrustManager\|checkServerTrusted' \
  -e 'SSLSocketFactory\|HostnameVerifier\|ALLOW_ALL_HOSTNAME_VERIFIER' \
  -e 'setHostnameVerifier\|BROWSER_COMPATIBLE_HOSTNAME_VERIFIER' \
  -e 'onReceivedSslError.*proceed\|handler\.proceed' \
  output/<pkg>/decompiled/ > findings/ssl_bypass.txt

# Network security config
cat output/<pkg>/resources/res/xml/network_security_config.xml 2>/dev/null \
  >> findings/network_config.txt

# WebView settings
rg -i 'setJavaScriptEnabled\|addJavascriptInterface\|setAllowFileAccess\|setAllowUniversalAccessFromFileURLs' \
  output/<pkg>/decompiled/ > findings/webview.txt
```

### 4. Insecure Data Storage
```bash
# SharedPreferences (often stores sensitive data insecurely)
rg -i 'getSharedPreferences\|SharedPreferences\|putString\|putInt' \
  output/<pkg>/decompiled/ | grep -i 'password\|token\|secret\|key\|auth' \
  > findings/shared_prefs.txt

# SQLite
rg -i 'openOrCreateDatabase\|SQLiteOpenHelper\|execSQL\|rawQuery' \
  output/<pkg>/decompiled/ > findings/sqlite.txt

# External storage
rg -i 'getExternalStorage\|WRITE_EXTERNAL_STORAGE\|Environment\.getExternal' \
  output/<pkg>/decompiled/ > findings/external_storage.txt

# Logging sensitive data
rg -i 'Log\.[dviwe]\s*\(.*(?:password|token|secret|key|auth|credit|card)' \
  output/<pkg>/decompiled/ > findings/insecure_logging.txt
```

### 5. Cryptography Issues
```bash
# Weak algorithms
rg -i \
  -e '"MD5"\|"SHA1"\|"SHA-1"' \
  -e '"DES"\|"DESede"\|"RC4"\|"RC2"' \
  -e '"AES/ECB"\|Cipher\.getInstance.*ECB' \
  -e 'SecureRandom.*setSeed\|new Random\(\)' \
  output/<pkg>/decompiled/ > findings/weak_crypto.txt

# Hardcoded IV/Salt
rg -i 'IvParameterSpec\|new byte\[\]\s*{' \
  output/<pkg>/decompiled/ | head -30 >> findings/weak_crypto.txt
```

### 6. Exported Components (Android Attack Surface)
```bash
# Exported Activities, Services, Receivers, Providers
python3 scripts/exported_components.py \
  output/<pkg>/resources/AndroidManifest.xml \
  > findings/exported_components.txt
```

### 7. Deep Links & Intent Handling
```bash
# Intent filters with data schemes
grep -A5 'intent-filter' output/<pkg>/resources/AndroidManifest.xml | \
  grep -i 'data\|scheme\|host' > findings/deeplinks.txt

# Intent injection
rg -i 'getIntent\(\)\|getExtras\(\)\|getStringExtra\|getParcelableExtra' \
  output/<pkg>/decompiled/ > findings/intent_handling.txt
```

### 8. Firebase & Backend Misconfigurations
```bash
# Firebase project ID
rg 'google-services\|firebase\|firebaseio\.com' \
  output/<pkg>/decompiled/ output/<pkg>/resources/ > findings/firebase.txt

# Check if Firebase DB is open (script will attempt read)
python3 scripts/check_firebase.py output/<pkg>/decompiled/
```

### 9. Known Vulnerable Library Versions
```bash
python3 scripts/check_dependencies.py \
  output/<pkg>/decompiled/ \
  output/<pkg>/resources/ \
  > findings/vulnerable_deps.txt
# Cross-references with OSV.dev and NVD
```

### 10. iOS Specific (IPA)
```bash
# ATS (App Transport Security) disabled
grep -A5 'NSAppTransportSecurity' output/<bundle>/raw/Payload/*.app/Info.plist \
  | grep -i 'NSAllowsArbitraryLoads\|true' > findings/ats_disabled.txt

# Keychain usage
rg 'kSecAttrAccessible\|SecItemAdd\|SecItemCopyMatching' \
  output/<bundle>/decompiled/ > findings/keychain.txt

# URL schemes
grep -A5 'CFBundleURLSchemes' output/<bundle>/raw/Payload/*.app/Info.plist \
  > findings/url_schemes.txt
```

---

## Scoring

After all scans, score findings:
```bash
python3 scripts/score_findings.py output/<pkg>/findings/
```

Output: sorted list of files/findings by severity for Reviewer to prioritize.
