#!/usr/bin/env python3
"""
Fetcher: Download APK/IPA from store URLs or direct links.
"""

import os
import sys
import subprocess
import re
from pathlib import Path

DOWNLOADS_DIR = Path("downloads")

def fetch_app(target: str, info: dict) -> str:
    """
    Download an APK or IPA. Returns local file path.
    """
    DOWNLOADS_DIR.mkdir(exist_ok=True)

    if info["type"] == "file":
        path = Path(target)
        if not path.exists():
            print(f"❌ File not found: {target}")
            sys.exit(1)
        print(f"  ✅ Using local file: {target}")
        return str(path)

    # URL-based download
    platform = info.get("platform")
    identifier = info.get("identifier", "unknown")

    if platform == "android":
        return _fetch_apk(target, identifier)
    elif platform == "ios":
        return _fetch_ipa(target, identifier)
    else:
        print("❌ Could not detect platform from URL")
        sys.exit(1)

def _fetch_apk(url: str, package_id: str) -> str:
    """Download APK for an Android app."""
    out_path = DOWNLOADS_DIR / f"{package_id}.apk"

    if out_path.exists():
        print(f"  ✅ Already downloaded: {out_path}")
        return str(out_path)

    print(f"  📦 Package ID: {package_id}")

    # Method 1: apkeep
    if _tool_exists("apkeep"):
        print("  🔧 Using apkeep...")
        ret = subprocess.run(
            ["apkeep", "-a", package_id, "-d", str(DOWNLOADS_DIR)],
            capture_output=True
        ).returncode
        # apkeep saves as <package_id>.apk
        if out_path.exists():
            print(f"  ✅ Downloaded: {out_path}")
            return str(out_path)

    # Method 2: APKPure scrape
    print("  🔧 Trying APKPure...")
    try:
        apkpure_url = _get_apkpure_download_url(package_id)
        if apkpure_url:
            _wget(apkpure_url, str(out_path))
            if out_path.exists() and out_path.stat().st_size > 10000:
                print(f"  ✅ Downloaded: {out_path}")
                return str(out_path)
    except Exception as e:
        print(f"  ⚠️  APKPure failed: {e}")

    # Method 3: Direct URL if not a store URL
    if url.endswith(".apk"):
        print("  🔧 Downloading direct APK URL...")
        _wget(url, str(out_path))
        if out_path.exists():
            return str(out_path)

    # Fallback: manual instructions
    print("\n  ⚠️  Automatic APK download failed.")
    print("  Manual options:")
    print(f"    1. Install on device and pull: adb shell pm path {package_id}")
    print(f"       then: adb pull <path> {out_path}")
    print(f"    2. Download from APKPure: https://apkpure.com/{package_id}/{package_id}")
    print(f"    3. Download from APKCombo: https://apkcombo.com/apk/{package_id}")
    print(f"\n  After downloading, run: python3 msa.py scan {out_path}")
    sys.exit(1)

def _fetch_ipa(url: str, app_id: str) -> str:
    """Download IPA for an iOS app."""
    out_path = DOWNLOADS_DIR / f"{app_id}.ipa"

    if out_path.exists():
        print(f"  ✅ Already downloaded: {out_path}")
        return str(out_path)

    print(f"  📱 App ID: {app_id}")

    # Method 1: ipatool
    if _tool_exists("ipatool"):
        print("  🔧 Using ipatool (requires Apple ID login)...")
        print("  💡 Run: ipatool auth login -e your@email.com")
        ret = subprocess.run(
            ["ipatool", "download", "--bundle-identifier", f"id{app_id}",
             "--output", str(out_path)],
            capture_output=True
        ).returncode
        if out_path.exists():
            return str(out_path)

    # Fallback: manual
    print("\n  ⚠️  Automatic IPA download requires authentication.")
    print("  Options to obtain IPA:")
    print("    1. ipatool: https://github.com/majd/ipatool")
    print("       brew install majd/repo/ipatool")
    print(f"       ipatool download -b <bundle_id> -o {out_path}")
    print("    2. From jailbroken device: frida-ios-dump")
    print("    3. From iTunes backup (older iTunes versions)")
    print(f"\n  After obtaining IPA, run: python3 msa.py scan {out_path}")
    sys.exit(1)

def _get_apkpure_download_url(package_id: str) -> str | None:
    """Scrape APKPure for a direct download URL."""
    import urllib.request
    import html

    try:
        req = urllib.request.Request(
            f"https://apkpure.com/{package_id}/{package_id}/download",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")

        # Look for direct APK download link
        match = re.search(r'href="(https://[^"]+\.apk[^"]*)"', content)
        if match:
            return html.unescape(match.group(1))
    except Exception:
        pass
    return None

def _wget(url: str, out: str):
    """Download a file via curl."""
    subprocess.run(
        ["curl", "-L", "-o", out, "--user-agent", "Mozilla/5.0", url],
        check=False
    )

def _tool_exists(name: str) -> bool:
    return subprocess.run(
        ["which", name], capture_output=True
    ).returncode == 0
