"""Optional CTF-only artifact triage.

Disabled by default. It reports candidates with offsets/evidence; it never
changes the artifact and never claims a candidate is a confirmed flag.
"""
import re

PATTERNS = [
    re.compile(rb"\b[A-Za-z0-9_.-]{2,24}\{[^}\r\n]{1,200}\}"),
    re.compile(rb"(?i)\b(?:flag|ctf|answer|secret)\s*[:=]\s*[\"']?[^\s\"']{4,200}"),
]


def triage_file(path, label, storage, logger):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"label": label, "path": path, "error": str(e), "candidates": []}
    candidates, seen = [], set()
    for pattern in PATTERNS:
        for m in pattern.finditer(data):
            key = (m.start(), m.group(0))
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "offset": m.start(),
                "offset_hex": hex(m.start()),
                "candidate": m.group(0).decode("utf-8", "replace")[:240],
                "confidence": 0.85 if b"{" in m.group(0) and b"}" in m.group(0) else 0.55,
            })
            if len(candidates) >= 100:
                break
    result = {"label": label, "path": path, "candidates": candidates, "note": "Candidates only; manually verify against challenge context."}
    storage.save_analysis_result(f"ctf_triage_{label}", result)
    storage.log_event("ctf_triage", "DONE", f"candidates={len(candidates)}", path)
    return result
