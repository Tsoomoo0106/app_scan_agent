#!/usr/bin/env python3
"""
mobile-security-agent — CLI entry point
Usage: python3 msa.py scan <url_or_file>
"""

import sys
import os
import argparse
import subprocess
import shutil
from pathlib import Path

# ── Fix module path so `scripts/` is importable from anywhere ────────────────
TOOL_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(TOOL_DIR))
os.chdir(TOOL_DIR)  # Always run from tool directory

BANNER = """
╔══════════════════════════════════════════════════════╗
║  📱 Mobile Security Agent v1.2                       ║
║  APK & IPA Security Analysis Tool (Gemini CLI)       ║
╚══════════════════════════════════════════════════════╝
"""

# ── AI Backend detection ──────────────────────────────────────────────────────
def detect_ai_backend() -> str:
    """Detect which AI CLI is available for code review."""
    if shutil.which("gemini"):
        return "gemini"
    if shutil.which("claude"):
        return "claude"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini_api"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic_api"
    return "none"

def ai_review(prompt: str, backend: str = None) -> str:
    """Send a code review prompt to the available AI backend."""
    if backend is None:
        backend = detect_ai_backend()

    if backend == "gemini":
        result = subprocess.run(
            ["gemini", "-p", prompt],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip() if result.returncode == 0 else f"[gemini error] {result.stderr[:200]}"

    elif backend == "claude":
        result = subprocess.run(
            ["claude", "-p", prompt],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip() if result.returncode == 0 else f"[claude error] {result.stderr[:200]}"

    elif backend == "gemini_api":
        return _ai_via_gemini_api(prompt)

    elif backend == "anthropic_api":
        return _ai_via_anthropic_api(prompt)

    return "[no AI backend] Install gemini CLI: npm install -g @google/gemini-cli"

def _ai_via_gemini_api(prompt: str) -> str:
    try:
        import urllib.request, json
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"[gemini_api error] {e}"

def _ai_via_anthropic_api(prompt: str) -> str:
    try:
        import urllib.request, json
        api_key = os.environ["ANTHROPIC_API_KEY"]
        body = json.dumps({
            "model": "claude-opus-4-6",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return data["content"][0]["text"]
    except Exception as e:
        return f"[anthropic_api error] {e}"

# ── Input type detection ──────────────────────────────────────────────────────
def detect_input_type(target: str) -> dict:
    info = {"type": None, "platform": None, "identifier": None}

    if target.startswith("http"):
        info["type"] = "url"
        if "play.google.com" in target or "apkpure" in target or "apkcombo" in target:
            info["platform"] = "android"
            if "id=" in target:
                info["identifier"] = target.split("id=")[1].split("&")[0].split("?")[0]
            else:
                info["identifier"] = "unknown_android"
        elif "apps.apple.com" in target:
            info["platform"] = "ios"
            for p in target.rstrip("/").split("/"):
                if p.startswith("id") and p[2:].isdigit():
                    info["identifier"] = p[2:]
                    break
            if not info["identifier"]:
                info["identifier"] = "unknown_ios"
        elif target.endswith(".apk"):
            info["platform"] = "android"
            info["identifier"] = target.split("/")[-1].replace(".apk", "")
        elif target.endswith(".ipa"):
            info["platform"] = "ios"
            info["identifier"] = target.split("/")[-1].replace(".ipa", "")
        else:
            print("❌ Could not detect platform from URL")
            sys.exit(1)
    else:
        info["type"] = "file"
        path = Path(target)
        if not path.exists():
            print(f"❌ File not found: {target}")
            sys.exit(1)
        if path.suffix.lower() == ".apk":
            info["platform"] = "android"
            info["identifier"] = path.stem
        elif path.suffix.lower() == ".ipa":
            info["platform"] = "ios"
            info["identifier"] = path.stem
        else:
            print(f"❌ Unknown file type: {path.suffix}")
            sys.exit(1)

    return info

# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_scan(args):
    from scripts.fetcher import fetch_app
    from scripts.unpacker import unpack_app
    from scripts.hunter import hunt_app
    from scripts.reviewer import review_top_findings
    from scripts.reporter import generate_report

    print(BANNER)
    target = args.target
    backend = detect_ai_backend()
    backend_label = {
        "gemini": "🤖 Gemini CLI",
        "claude": "🤖 Claude CLI",
        "gemini_api": "🤖 Gemini API",
        "anthropic_api": "🤖 Anthropic API",
        "none": "⚠️  No AI backend"
    }.get(backend, backend)

    print(f"  AI backend : {backend_label}")
    print(f"🎯 Target    : {target}\n")

    print("Step 1/6 🔍 Detecting input type...")
    info = detect_input_type(target)
    info["ai_backend"] = backend
    print(f"  Platform   : {info['platform'].upper()}")
    print(f"  Package    : {info['identifier']}")

    print("\nStep 2/6 📥 Fetching app...")
    local_file = fetch_app(target, info)

    print("\nStep 3/6 📦 Unpacking / decompiling...")
    output_dir = unpack_app(local_file, info)

    print("\nStep 4/6 🔎 Running security detectors...")
    findings = hunt_app(output_dir, info)

    if backend != "none" and not getattr(args, 'no_ai', False):
        print(f"\nStep 5/6 🧠 AI code review ({backend_label})...")
        findings = review_top_findings(output_dir, findings, info, ai_review_fn=ai_review)
    else:
        print(f"\nStep 5/6 🧠 AI code review skipped")
        if backend == "none":
            print("  💡 Install Gemini CLI: npm install -g @google/gemini-cli && gemini")

    print("\nStep 6/6 📄 Generating report...")
    report_path = generate_report(output_dir, findings, info)

    counts = {}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    print(f"\n{'='*54}")
    print(f"✅ Scan complete!")
    print(f"📄 Report: {report_path}")
    print(f"📊 Findings: 🔴{counts.get('CRITICAL',0)} critical  🟠{counts.get('HIGH',0)} high  🟡{counts.get('MEDIUM',0)} medium  🔵{counts.get('LOW',0)} low")
    print(f"{'='*54}\n")

def cmd_fetch(args):
    from scripts.fetcher import fetch_app
    info = detect_input_type(args.url)
    fetch_app(args.url, info)

def cmd_unpack(args):
    from scripts.unpacker import unpack_app
    info = detect_input_type(args.file)
    unpack_app(args.file, info)

def cmd_hunt(args):
    from scripts.hunter import hunt_app
    info = {"platform": getattr(args, 'platform', 'android') or "android"}
    findings = hunt_app(args.directory, info)
    print(f"\n✅ Found {len(findings)} potential issues")

def cmd_review(args):
    path = Path(args.file)
    if not path.exists():
        print(f"❌ File not found: {args.file}")
        sys.exit(1)
    backend = detect_ai_backend()
    print(f"🧠 AI backend: {backend}")
    content = path.read_text(errors="ignore")[:8000]
    prompt = f"""You are a mobile app security researcher. Review this decompiled source file for security vulnerabilities.

FILE: {path.name}

{content}

Report each finding with: SEVERITY, description, line reference, and fix recommendation."""
    result = ai_review(prompt, backend)
    print(f"\n{'='*54}\n{result}\n{'='*54}\n")
    out_file = path.parent / f"{path.stem}_ai_review.txt"
    out_file.write_text(result)
    print(f"💾 Saved: {out_file}")

def cmd_secrets(args):
    from scripts.hunter import scan_secrets
    findings = scan_secrets(args.directory)
    print(f"\n✅ Found {len(findings)} potential secrets")

def cmd_permissions(args):
    from scripts.analyze_permissions import analyze
    analyze(args.manifest)

def cmd_ai_info(args):
    backend = detect_ai_backend()
    print(f"\n🤖 AI Backend Detection\n{'='*40}")
    print(f"  Active             : {backend}")
    print(f"  gemini CLI         : {'✅' if shutil.which('gemini') else '❌  npm install -g @google/gemini-cli'}")
    print(f"  claude CLI         : {'✅' if shutil.which('claude') else '❌  https://claude.ai/code'}")
    print(f"  GEMINI_API_KEY     : {'✅ set' if os.environ.get('GEMINI_API_KEY') else '❌ not set'}")
    print(f"  ANTHROPIC_API_KEY  : {'✅ set' if os.environ.get('ANTHROPIC_API_KEY') else '❌ not set'}")
    if backend == "none":
        print(f"\n  💡 Quickest option:")
        print(f"     npm install -g @google/gemini-cli")
        print(f"     gemini   # login once with Google account")
        print(f"     # then re-run: python3 msa.py scan <url>")

def main():
    parser = argparse.ArgumentParser(
        prog="msa",
        description="📱 Mobile Security Agent — APK & IPA security analysis"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Full pipeline (fetch → unpack → hunt → AI review → report)")
    p.add_argument("target", help="Play Store URL, App Store URL, or local APK/IPA")
    p.add_argument("--no-ai", action="store_true", help="Skip AI code review")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("fetch", help="Download APK/IPA from store URL")
    p.add_argument("url")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("unpack", help="Decompile APK or extract IPA")
    p.add_argument("file")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("hunt", help="Run detectors on decompiled source")
    p.add_argument("directory")
    p.add_argument("--platform", choices=["android", "ios"], default="android")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("review", help="AI code review of a specific file")
    p.add_argument("file")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("secrets", help="Scan for hardcoded secrets only")
    p.add_argument("directory")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("permissions", help="Analyze manifest permissions")
    p.add_argument("manifest")
    p.set_defaults(func=cmd_permissions)

    p = sub.add_parser("ai-info", help="Show AI backend detection status")
    p.set_defaults(func=cmd_ai_info)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
