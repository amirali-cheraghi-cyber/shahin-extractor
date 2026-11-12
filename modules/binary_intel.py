"""
binary_intel.py

Lightweight binary intelligence for ESP dumps.
Does not fully parse NVS or filesystems (that requires dedicated tools),
but extracts high-signal structural hints that reduce manual work on hard challenges.
"""

import re
import struct
from typing import List, Dict


def find_printable_islands(data: bytes, min_len: int = 12) -> List[Dict]:
    """Locate contiguous printable regions — often configs or logs."""
    islands = []
    start = None
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if start is None:
                start = i
        else:
            if start is not None and (i - start) >= min_len:
                text = data[start:i].decode("ascii", errors="replace")
                islands.append({"offset": start, "length": i - start, "text": text[:200]})
            start = None
    if start is not None and (len(data) - start) >= min_len:
        text = data[start:].decode("ascii", errors="replace")
        islands.append({"offset": start, "length": len(data) - start, "text": text[:200]})
    return islands[:40]


def score_region(data: bytes, offset: int, size: int = 256) -> Dict:
    """Simple score: higher = more likely to contain useful plaintext."""
    chunk = data[offset:offset+size]
    if not chunk:
        return {"offset": offset, "score": 0}
    printable = sum(1 for b in chunk if 32 <= b <= 126)
    ratio = printable / len(chunk)
    # Bonus for credential-like keywords
    low = chunk.lower()
    bonus = 0
    for kw in (b"pass", b"key", b"ssid", b"secret", b"wifi", b"mqtt", b"auth", b"admin"):
        if kw in low:
            bonus += 15
    score = int(ratio * 70 + bonus)
    return {"offset": offset, "score": min(score, 100), "printable_ratio": round(ratio, 2)}


def extract_candidate_configs(data: bytes) -> List[Dict]:
    """Pull likely config fragments."""
    results = []
    # key = value or key: value patterns with reasonable length
    pat = re.compile(rb"([A-Za-z0-9_\-]{3,24})\s*[=:]\s*([^\s\x00]{4,48})")
    for m in pat.finditer(data):
        key = m.group(1).decode("ascii", errors="replace").strip()
        key = re.sub(r"^[^A-Za-z]+", "", key)  # drop leading noise
        val = m.group(2).decode("ascii", errors="replace")
        if any(k in key.lower() for k in ("pass", "pwd", "key", "secret", "ssid", "token", "user")):
            results.append({
                "offset": m.start(),
                "key": key,
                "value": val,
                "context": data[max(0, m.start()-20):m.end()+20].decode("ascii", errors="replace"),
            })
    return results[:30]


class BinaryIntel:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def analyze(self, path: str, label: str) -> dict:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            return {"error": str(e)}

        islands = find_printable_islands(data)
        configs = extract_candidate_configs(data)

        # Score a few windows
        scores = []
        for off in range(0, min(len(data), 65536), 512):
            scores.append(score_region(data, off))
        scores.sort(key=lambda x: -x["score"])

        result = {
            "label": label,
            "path": path,
            "printable_islands": islands,
            "candidate_configs": configs,
            "top_regions": scores[:15],
        }

        if configs:
            self.logger.info(f"[binary] {label}: {len(configs)} candidate config(s)")
            for c in configs[:5]:
                self.logger.info(f"  {c['key']} = {c['value']}")
        if islands:
            self.logger.info(f"[binary] {label}: {len(islands)} printable island(s)")

        self.storage.save_analysis_result(f"binary_{label}", result)
        self.storage.log_event("binary_intel", "DONE", f"{len(configs)} configs, {len(islands)} islands", path)
        return result
