#!/usr/bin/env python3
"""
Reviewer: AI-powered code review of top findings from Hunter.
Reads actual source files and asks AI to analyze them deeply.
"""

import os
from pathlib import Path
from typing import List, Dict, Callable

MAX_FILES_TO_REVIEW = 8    # Max files to send to AI
MAX_FILE_CHARS = 6000      # Max chars per file sent to AI


def review_top_findings(
    output_dir: str,
    findings: List[Dict],
    info: dict,
    ai_review_fn: Callable
) -> List[Dict]:
    """
    Take top findings from Hunter, read the actual source files,
    send to AI for deep analysis. Enriches findings with AI notes.
    Returns updated findings list.
    """
    out = Path(output_dir)
    findings_dir = out / "findings"
    findings_dir.mkdir(exist_ok=True)

    backend = info.get("ai_backend", "none")
    if backend == "none":
        return findings

    # Pick top unique files to review (prioritize CRITICAL/HIGH)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity","INFO"), 4))

    reviewed_files = set()
    files_to_review = []
    for f in sorted_findings:
        fp = f.get("file", "")
        if fp and fp not in reviewed_files and Path(fp).exists():
            reviewed_files.add(fp)
            files_to_review.append(fp)
        if len(files_to_review) >= MAX_FILES_TO_REVIEW:
            break

    if not files_to_review:
        print("  ⚠️  No source files found for AI review")
        return findings

    print(f"  📂 Reviewing {len(files_to_review)} files with AI...")

    ai_notes = []
    for i, file_path in enumerate(files_to_review, 1):
        path = Path(file_path)
        print(f"  [{i}/{len(files_to_review)}] {path.name} ...", end="", flush=True)

        try:
            content = path.read_text(errors="ignore")[:MAX_FILE_CHARS]
        except Exception as e:
            print(f" ❌ read error: {e}")
            continue

        # Find what Hunter flagged in this file
        file_findings = [f for f in findings if f.get("file") == file_path]
        flags = "\n".join(f"- [{f['severity']}] {f['name']}: {f.get('content','')[:100]}"
                          for f in file_findings[:5])

        prompt = f"""You are a mobile application security researcher analyzing decompiled Android/iOS source code.

FILE: {path.name}
PATH: {file_path}

AUTOMATED SCANNER FLAGGED:
{flags}

SOURCE CODE:
{content}

Perform a focused security code review. For each real vulnerability found:
1. SEVERITY: CRITICAL/HIGH/MEDIUM/LOW
2. VULNERABILITY TYPE: (e.g. Hardcoded Secret, SSL Bypass, SQL Injection)
3. EVIDENCE: exact line or code snippet
4. IMPACT: what an attacker can do
5. FIX: how to remediate

Also identify any FALSE POSITIVES from the scanner flags above.
Be concise. If no real issues, say "No confirmed vulnerabilities."
"""

        result = ai_review_fn(prompt, backend)
        print(" ✅")

        ai_notes.append({
            "file": file_path,
            "filename": path.name,
            "review": result
        })

        # Add AI-confirmed findings back into findings list
        _parse_ai_findings(result, file_path, findings)

    # Save AI review notes
    if ai_notes:
        review_text = "\n\n" + "="*60 + "\n\n".join(
            f"FILE: {n['filename']}\n{n['review']}" for n in ai_notes
        )
        (findings_dir / "ai_code_review.txt").write_text(review_text)
        print(f"  💾 AI review saved → findings/ai_code_review.txt")

    return findings


def _parse_ai_findings(ai_text: str, file_path: str, findings: List[Dict]):
    """
    Attempt to extract structured findings from AI response
    and add them to the findings list with module='ai_review'.
    """
    import re
    # Look for severity markers in AI output
    sev_pattern = re.compile(
        r'(?i)\b(CRITICAL|HIGH|MEDIUM|LOW)\b[:\s]+([^\n]{10,80})',
        re.MULTILINE
    )
    for match in sev_pattern.finditer(ai_text):
        sev = match.group(1).upper()
        desc = match.group(2).strip()
        # Avoid duplicating existing findings
        already_exists = any(
            f.get("file") == file_path and f.get("content", "")[:50] == desc[:50]
            for f in findings
        )
        if not already_exists and sev in ("CRITICAL", "HIGH", "MEDIUM"):
            findings.append({
                "module": "ai_review",
                "name": f"AI: {desc[:60]}",
                "severity": sev,
                "file": file_path,
                "line": "",
                "content": desc
            })
