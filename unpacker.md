# Agent: Unpacker

## Role
Decompile APK files or extract IPA files into human-readable source code for analysis.

## Input
- `.apk` or `.ipa` file path

## Output
- Decompiled source directory in `./output/<package>/decompiled/`
- Resources directory in `./output/<package>/resources/`

---

## APK Unpacking

### Step 1: jadx (Java/Kotlin decompilation)
```bash
jadx \
  --deobf \
  --show-bad-code \
  --export-gradle \
  -d output/<package>/decompiled/ \
  downloads/<app>.apk

# If jadx fails on full APK, try:
jadx --deobf -d output/<package>/decompiled/ downloads/<app>.apk 2>&1 | tee output/<package>/jadx.log
```

### Step 2: apktool (resources + manifest)
```bash
apktool d \
  --no-src \
  --force \
  -o output/<package>/resources/ \
  downloads/<app>.apk
```

### Step 3: Extract raw assets
```bash
unzip -o downloads/<app>.apk -d output/<package>/raw/
# Important files:
# raw/AndroidManifest.xml (binary — use apktool output instead)
# raw/assets/            (bundled JS, config files, certs)
# raw/res/               (layout XMLs, strings)
# raw/lib/               (native .so libraries)
# raw/META-INF/          (signing info)
```

---

## IPA Unpacking

### Step 1: Extract ZIP
```bash
unzip -o downloads/<app>.ipa -d output/<bundle>/raw/
# Main binary is at: Payload/<AppName>.app/<AppName>
```

### Step 2: Extract strings from binary
```bash
BINARY="output/<bundle>/raw/Payload/<AppName>.app/<AppName>"
strings "$BINARY" > output/<bundle>/decompiled/binary_strings.txt
strings -a "$BINARY" | grep -E "http|api|key|secret|password|token" > output/<bundle>/findings/binary_secrets.txt
```

### Step 3: class-dump (if available)
```bash
class-dump -H output/<bundle>/raw/Payload/<AppName>.app/<AppName> \
  -o output/<bundle>/decompiled/headers/
```

### Step 4: Extract bundled JS/assets
```bash
# React Native apps
find output/<bundle>/raw -name "*.jsbundle" -o -name "index.android.bundle" | \
  xargs -I{} cp {} output/<bundle>/decompiled/

# Flutter apps
find output/<bundle>/raw -name "libflutter.so" -o -name "app.so"

# Xamarin apps
find output/<bundle>/raw -name "*.dll"
```

---

## Framework Detection

After unpacking, detect the app framework:

```bash
python3 scripts/detect_framework.py output/<package>/
```

Checks for:
- **React Native**: `index.android.bundle`, `libreactnativejni.so`
- **Flutter**: `libflutter.so`, `app.so`, `flutter_assets/`
- **Xamarin**: `*.dll` files, `Mono.Android.dll`
- **Cordova/Ionic**: `www/` directory with `cordova.js`
- **Native Java/Kotlin**: Standard jadx output
- **Native Swift/ObjC**: IPA with class-dump headers

---

## Obfuscation Detection

```bash
# Check if code is obfuscated (ProGuard/R8/DexGuard)
ls output/<package>/decompiled/sources/ | head -20
# Obfuscated: single-letter class names (a.java, b.java, a/b/c.java)
# Clean: meaningful names (LoginActivity.java, ApiClient.java)
```

If obfuscated, note in findings and proceed with what is readable.

---

## Validation

After unpacking, verify:
- [ ] `decompiled/` directory has Java/Kotlin files
- [ ] `resources/AndroidManifest.xml` is readable XML
- [ ] `resources/res/values/strings.xml` exists
- [ ] No jadx errors blocking analysis (check jadx.log)
