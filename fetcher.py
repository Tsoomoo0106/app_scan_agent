#!/usr/bin/env python3
import os, sys, subprocess, re
from pathlib import Path

DOWNLOADS_DIR = Path("downloads")

def fetch_app(target: str, info: dict) -> str:
    DOWNLOADS_DIR.mkdir(exist_ok=True)
    if info["type"] == "file":
        path = Path(target)
        if not path.exists():
            print(f"❌ File not found: {target}")
            sys.exit(1)
        print(f"  ✅ Using local file: {target}")
        return str(path)
    platform = info.get("platform")
    identifier = info.get("identifier", "unknown")
    if platform == "android":
        return _fetch_apk(target, identifier)
    elif platform == "ios":
        return _fetch_ipa(target, identifier)
    else:
        print("❌ Could not detect platform")
        sys.exit(1)

def _fetch_apk(url: str, package_id: str) -> str:
    out_path = DOWNLOADS_DIR / f"{package_id}.apk"
    if out_path.exists() and out_path.stat().st_size > 100000:
        print(f"  ✅ Already downloaded: {out_path}")
        return str(out_path)
    print(f"  📦 Package: {package_id}")
    # Method 1: apkeep
    if _tool_exists("apkeep"):
        print("  🔧 Trying apkeep...")
        subprocess.run(["apkeep", "-a", package_id, "-d", str(DOWNLOADS_DIR)],
                       capture_output=True)
        if out_path.exists() and out_path.stat().st_size > 100000:
            print(f"  ✅ Downloaded: {out_path}")
            return str(out_path)
    # Method 2: APKPure
    print("  🔧 Trying APKPure...")
    apk_url = _get_apkpure_url(package_id)
    if apk_url:
        subprocess.run(["curl", "-L", "-o", str(out_path), "--user-agent", "Mozilla/5.0", apk_url])
        if out_path.exists() and out_path.stat().st_size > 100000:
            print(f"  ✅ Downloaded: {out_path}")
            return str(out_path)
    # Fallback
    print(f"\n  ⚠️  Auto-download failed. Manual options:")
    print(f"    1. https://apkpure.com/{package_id}/{package_id}")
    print(f"    2. https://apkcombo.com/apk/{package_id}")
    print(f"    3. adb shell pm path {package_id} && adb pull <path>")
    print(f"\n  After downloading, run:")
    print(f"    python3 msa.py scan downloads/{package_id}.apk")
    sys.exit(1)

def _fetch_ipa(url: str, app_id: str) -> str:
    out_path = DOWNLOADS_DIR / f"{app_id}.ipa"
    if out_path.exists():
        print(f"  ✅ Already downloaded: {out_path}")
        return str(out_path)
    print(f"\n  ⚠️  iOS IPA download requires authentication.")
    print(f"    1. ipatool: brew install majd/repo/ipatool")
    print(f"    2. Or provide IPA file manually")
    sys.exit(1)

def _get_apkpure_url(package_id: str):
    import urllib.request, html
    try:
        req = urllib.request.Request(
            f"https://apkpure.com/{package_id}/{package_id}/download",
            headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            content = r.read().decode("utf-8", errors="ignore")
        m = re.search(r'href="(https://[^"]+\.apk[^"]*)"', content)
        if m:
            return html.unescape(m.group(1))
    except Exception as e:
        print(f"  ⚠️  APKPure: {e}")
    return None

def _tool_exists(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0
