#!/usr/bin/env python3
import os
import re
from pathlib import Path
from typing import List, Dict, Callable

MAX_FILES = 8
MAX_CHARS = 6000

def review_top_findings(output_dir, findings, info, ai_review_fn):
    out = Path(output_dir)
    findings_dir = out / "findings"
    findings_dir.mkdir(exist_ok=True)

    backend = info.get("ai_backend", "none")
    if backend == "none":
        return findings

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 4))

    reviewed = set()
    to_review = []
    for f in sorted_f:
        fp = f.get("file", "")
        if fp and fp not in reviewed and Path(fp).exists():
            reviewed.add(fp)
            to_review.append(fp)
            if len(to_review) >= MAX_FILES:
                break

    if not to_review:
        print("  ⚠️  No files available for AI review")
        return findings

    print(f"  📂 Reviewing {len(to_review)} highest-severity files...")
    ai_notes = []

    for i, file_path in enumerate(to_review, 1):
        path = Path(file_path)
        print(f"  [{i}/{len(to_review)}] {path.name} ...", end="", flush=True)

        try:
            content = path.read_text(errors="ignore")[:MAX_CHARS]
        except Exception as e:
            print(f" ❌ {e}")
            continue

        file_findings = [f for f in findings if f.get("file") == file_path]
        flags = "\n".join(
            f"- [{f['severity']}] {f['name']}: {f.get('content','')[:80]}"
            for f in file_findings[:5]
        )

        prompt = f"""You are a mobile app security researcher analyzing decompiled Android/iOS source.

FILE: {path.name}

SCANNER FLAGS:
{flags}

CODE:
{content}

Find real security vulnerabilities. For each:
SEVERITY: CRITICAL/HIGH/MEDIUM/LOW
TYPE: vulnerability type
EVIDENCE: exact code snippet
IMPACT: what an attacker can do
FIX: how to remediate

Also mark any scanner false positives. Be concise."""

        result = ai_review_fn(prompt, backend)
        print(" ✅")
        ai_notes.append({"file": file_path, "filename": path.name, "review": result})
        _parse_ai(result, file_path, findings)

    if ai_notes:
        text = "\n\n" + "="*60 + "\n\n".join(
            f"FILE: {n['filename']}\n{n['review']}" for n in ai_notes
        )
        (findings_dir / "ai_code_review.txt").write_text(text)
        print(f"  💾 AI review saved → findings/ai_code_review.txt")

    return findings

def _parse_ai(text, file_path, findings):
    for m in re.finditer(r'(?i)\b(CRITICAL|HIGH|MEDIUM|LOW)\b[:\s]+([^\n]{10,80})', text):
        sev = m.group(1).upper()
        desc = m.group(2).strip()
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            findings.append({
                "module": "ai_review",
                "name": f"AI: {desc[:60]}",
                "severity": sev,
                "file": file_path,
                "line": "",
                "content": desc
            })
