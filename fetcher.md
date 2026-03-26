# Agent: Fetcher

## Role
Download APK or IPA files from Play Store URLs, App Store URLs, or direct links.

## Input
- A URL (Play Store, App Store, APKPure, direct .apk/.ipa link)
- Or a local file path

## Output
- Downloaded `.apk` or `.ipa` file in `./downloads/`
- Metadata: app name, package ID, version

---

## Detection Logic

### Android (Play Store)
```
URL pattern: play.google.com/store/apps/details?id=<package>
Tool: gplaydl, apkeep, or manual APKPure scrape
Fallback: apkpure.com/download/<package>
```

### iOS (App Store)
```
URL pattern: apps.apple.com/*/app/*/id<app_id>
Tool: ipatool (requires Apple ID) or 3rd-party IPA sites
Note: Direct App Store download requires auth — instruct user
```

---

## Steps

1. **Parse URL** — identify platform and package identifier
2. **Check cache** — if already downloaded, skip
3. **Download** — use appropriate tool
4. **Verify** — check file is valid APK/IPA (not HTML error page)
5. **Extract metadata** — package name, version, size
6. **Hand off** — pass file path to Unpacker

---

## APK Download Methods (in order of preference)

```bash
# Method 1: apkeep (best, no auth needed)
apkeep -a <package_id> -d downloads/

# Method 2: APKPure scrape
python3 scripts/apkpure_download.py <package_id>

# Method 3: Manual — ask user to download from device
adb shell pm path <package_id>
adb pull <path> downloads/<package_id>.apk
```

## IPA Download Methods

```bash
# Method 1: ipatool (requires Apple ID)
ipatool download -b <bundle_id> -o downloads/

# Method 2: Ask user to provide IPA
# (obtained via iTunes backup, jailbroken device, or enterprise cert)

# Method 3: frida-ios-dump (jailbroken device)
python3 dump.py <bundle_id>
```

---

## Error Handling

| Error | Action |
|-------|--------|
| App not found | Report and stop |
| Auth required (iOS) | Prompt user for IPA file |
| Download blocked | Try alternate mirror |
| File corrupt | Re-download, verify SHA256 |
| Paid app | Notify user, request manual APK |

---

## Metadata Extraction

```bash
# APK metadata
aapt dump badging downloads/<app>.apk | grep -E "package:|application-label:|sdkVersion"

# IPA metadata
unzip -p downloads/<app>.ipa "Payload/*.app/Info.plist" | plutil -convert xml1 -o - -
```
