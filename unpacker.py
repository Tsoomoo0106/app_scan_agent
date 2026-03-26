#!/usr/bin/env python3
"""
Unpacker: Decompile APK (jadx + apktool) or extract IPA.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

OUTPUT_DIR = Path("output")

def unpack_app(file_path: str, info: dict) -> str:
    """
    Decompile/extract the app. Returns output directory path.
    """
    path = Path(file_path)
    platform = info.get("platform", "android")
    pkg_id = info.get("identifier") or path.stem

    out_dir = OUTPUT_DIR / pkg_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  📂 Output dir: {out_dir}")

    if platform == "android":
        return _unpack_apk(path, out_dir, pkg_id)
    else:
        return _unpack_ipa(path, out_dir, pkg_id)

def _unpack_apk(apk_path: Path, out_dir: Path, pkg_id: str) -> str:
    """Decompile APK with jadx + apktool."""

    decompiled = out_dir / "decompiled"
    resources = out_dir / "resources"
    raw = out_dir / "raw"

    # --- jadx decompilation ---
    if not decompiled.exists() or not any(decompiled.rglob("*.java")):
        print("  🔧 Running jadx (Java decompilation)...")
        _check_tool("jadx", "https://github.com/skylot/jadx/releases")

        ret = subprocess.run([
            "jadx",
            "--deobf",
            "--show-bad-code",
            "-d", str(decompiled),
            str(apk_path)
        ], capture_output=True, text=True)

        java_files = list(decompiled.rglob("*.java"))
        if java_files:
            print(f"  ✅ jadx: {len(java_files)} Java files decompiled")
        else:
            print(f"  ⚠️  jadx produced no .java files")
            print(f"     stderr: {ret.stderr[:300]}")

        # Save log
        (out_dir / "jadx.log").write_text(ret.stdout + "\n" + ret.stderr)
    else:
        java_files = list(decompiled.rglob("*.java"))
        print(f"  ✅ jadx: already done ({len(java_files)} files)")

    # --- apktool for resources + manifest ---
    if not resources.exists():
        print("  🔧 Running apktool (resources + manifest)...")
        _check_tool("apktool", "https://apktool.org/docs/install")

        subprocess.run([
            "apktool", "d",
            "--no-src",
            "--force",
            "-o", str(resources),
            str(apk_path)
        ], capture_output=True)

        manifest = resources / "AndroidManifest.xml"
        if manifest.exists():
            print(f"  ✅ apktool: manifest extracted")
        else:
            print(f"  ⚠️  apktool: manifest not found")
    else:
        print(f"  ✅ apktool: already done")

    # --- raw unzip ---
    if not raw.exists():
        print("  🔧 Unzipping raw APK...")
        raw.mkdir(parents=True)
        subprocess.run(["unzip", "-o", "-q", str(apk_path), "-d", str(raw)])
        print(f"  ✅ Raw assets extracted")

    # Detect framework
    framework = _detect_framework_android(decompiled, raw)
    (out_dir / "framework.txt").write_text(framework)
    print(f"  📱 Framework: {framework}")

    return str(out_dir)

def _unpack_ipa(ipa_path: Path, out_dir: Path, pkg_id: str) -> str:
    """Extract IPA (zip) and analyze binary."""

    raw = out_dir / "raw"
    decompiled = out_dir / "decompiled"
    decompiled.mkdir(parents=True, exist_ok=True)

    # Extract IPA
    if not raw.exists():
        print("  🔧 Extracting IPA...")
        raw.mkdir(parents=True)
        subprocess.run(["unzip", "-o", "-q", str(ipa_path), "-d", str(raw)])
        print(f"  ✅ IPA extracted")

    # Find main binary
    payload = raw / "Payload"
    app_bundles = list(payload.glob("*.app")) if payload.exists() else []

    if not app_bundles:
        print("  ❌ No .app bundle found in IPA")
        sys.exit(1)

    app_bundle = app_bundles[0]
    app_name = app_bundle.stem
    binary = app_bundle / app_name

    print(f"  📱 App bundle: {app_bundle.name}")
    print(f"  🔧 Extracting strings from binary...")

    # strings extraction
    if binary.exists():
        strings_file = decompiled / "binary_strings.txt"
        result = subprocess.run(["strings", str(binary)], capture_output=True, text=True)
        strings_file.write_text(result.stdout)
        print(f"  ✅ Extracted {len(result.stdout.splitlines())} strings")

    # class-dump if available
    if _tool_exists("class-dump"):
        print("  🔧 Running class-dump...")
        headers_dir = decompiled / "headers"
        headers_dir.mkdir(exist_ok=True)
        subprocess.run([
            "class-dump", "-H", str(binary), "-o", str(headers_dir)
        ], capture_output=True)
        headers = list(headers_dir.glob("*.h"))
        if headers:
            print(f"  ✅ class-dump: {len(headers)} header files")

    # Extract bundled JS (React Native)
    js_bundles = list(raw.rglob("*.jsbundle")) + list(raw.rglob("index.android.bundle"))
    for jsb in js_bundles:
        dest = decompiled / jsb.name
        shutil.copy(jsb, dest)
        print(f"  📄 JS bundle found: {jsb.name} ({jsb.stat().st_size // 1024}KB)")

    # Extract Info.plist copy for easy access
    info_plist = app_bundle / "Info.plist"
    if info_plist.exists():
        shutil.copy(info_plist, out_dir / "Info.plist")

    framework = _detect_framework_ios(raw)
    (out_dir / "framework.txt").write_text(framework)
    print(f"  📱 Framework: {framework}")

    return str(out_dir)

def _detect_framework_android(decompiled: Path, raw: Path) -> str:
    # React Native
    if any(raw.rglob("libreactnativejni.so")) or any(raw.rglob("index.android.bundle")):
        return "React Native"
    # Flutter
    if any(raw.rglob("libflutter.so")):
        return "Flutter"
    # Xamarin
    if any(raw.rglob("Mono.Android.dll")):
        return "Xamarin"
    # Cordova
    if any(raw.rglob("cordova.js")):
        return "Cordova/Ionic"
    return "Native Java/Kotlin"

def _detect_framework_ios(raw: Path) -> str:
    if any(raw.rglob("*.jsbundle")) or any(raw.rglob("libreact*.dylib")):
        return "React Native"
    if any(raw.rglob("flutter_assets")):
        return "Flutter"
    if any(raw.rglob("*.dll")):
        return "Xamarin"
    if any(raw.rglob("cordova.js")):
        return "Cordova/Ionic"
    return "Native Swift/ObjC"

def _check_tool(name: str, install_url: str):
    if not _tool_exists(name):
        print(f"\n  ❌ '{name}' not found.")
        print(f"     Install: {install_url}")
        print(f"     Or run: bash setup.sh")
        sys.exit(1)

def _tool_exists(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0
