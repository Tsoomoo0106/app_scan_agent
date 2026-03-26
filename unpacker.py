#!/usr/bin/env python3
import os, sys, subprocess, shutil
from pathlib import Path

OUTPUT_DIR = Path("output")

def unpack_app(file_path: str, info: dict) -> str:
    path = Path(file_path)
    platform = info.get("platform", "android")
    pkg_id = info.get("identifier") or path.stem

    out_dir = OUTPUT_DIR / pkg_id
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"  📂 Output: {out_dir}")

    if platform == "android":
        return _unpack_apk(path, out_dir)
    else:
        return _unpack_ipa(path, out_dir)

def _unpack_apk(apk_path, out_dir):
    decompiled = out_dir / "decompiled"
    resources  = out_dir / "resources"
    raw        = out_dir / "raw"

    # jadx decompile
    already_done = decompiled.exists() and any(decompiled.rglob("*.java"))
    if not already_done:
        print("  🔧 Running jadx...")
        if not _tool_exists("jadx"):
            print("  ❌ jadx not found.")
            print("     Install: https://github.com/skylot/jadx/releases")
            print("     Or run setup.sh first: bash setup.sh")
            sys.exit(1)
        ret = subprocess.run(
            ["jadx", "--deobf", "--show-bad-code", "-d", str(decompiled), str(apk_path)],
            capture_output=True, text=True
        )
        (out_dir / "jadx.log").write_text(ret.stdout + ret.stderr)
        java_files = list(decompiled.rglob("*.java"))
        print(f"  ✅ jadx: {len(java_files)} Java files decompiled")
    else:
        print(f"  ✅ jadx: already done (skipping)")

    # apktool for resources + manifest
    if not resources.exists():
        print("  🔧 Running apktool...")
        if not _tool_exists("apktool"):
            print("  ⚠️  apktool not found — skipping resource extraction")
        else:
            subprocess.run(
                ["apktool", "d", "--no-src", "--force", "-o", str(resources), str(apk_path)],
                capture_output=True
            )
            print(f"  ✅ apktool: resources extracted")
    else:
        print(f"  ✅ apktool: already done (skipping)")

    # raw unzip
    if not raw.exists():
        raw.mkdir(parents=True)
        subprocess.run(["unzip", "-o", "-q", str(apk_path), "-d", str(raw)])
        print(f"  ✅ raw unzip: done")

    fw = _detect_framework(decompiled, raw)
    (out_dir / "framework.txt").write_text(fw)
    print(f"  📱 Framework detected: {fw}")
    return str(out_dir)

def _unpack_ipa(ipa_path, out_dir):
    raw        = out_dir / "raw"
    decompiled = out_dir / "decompiled"
    decompiled.mkdir(parents=True, exist_ok=True)

    if not raw.exists():
        raw.mkdir(parents=True)
        subprocess.run(["unzip", "-o", "-q", str(ipa_path), "-d", str(raw)])

    payload = raw / "Payload"
    apps = list(payload.glob("*.app")) if payload.exists() else []
    if not apps:
        print("  ❌ No .app bundle found in IPA")
        sys.exit(1)

    app = apps[0]
    binary = app / app.stem
    if binary.exists():
        result = subprocess.run(["strings", str(binary)], capture_output=True, text=True)
        (decompiled / "binary_strings.txt").write_text(result.stdout)
        print(f"  ✅ Extracted {len(result.stdout.splitlines())} strings from binary")

    fw = "Native Swift/ObjC"
    if any(raw.rglob("*.jsbundle")):
        fw = "React Native"
    elif any(raw.rglob("flutter_assets")):
        fw = "Flutter"
    (out_dir / "framework.txt").write_text(fw)
    print(f"  📱 Framework detected: {fw}")
    return str(out_dir)

def _detect_framework(decompiled, raw):
    if any(raw.rglob("libreactnativejni.so")) or any(raw.rglob("index.android.bundle")):
        return "React Native"
    if any(raw.rglob("libflutter.so")):
        return "Flutter"
    if any(raw.rglob("Mono.Android.dll")):
        return "Xamarin"
    if any(raw.rglob("cordova.js")):
        return "Cordova/Ionic"
    return "Native Java/Kotlin"

def _tool_exists(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0
