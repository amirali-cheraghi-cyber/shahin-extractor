"""
auto_extractor.py

Higher-level automated extraction layer that runs on every collected text
or binary artifact. Goal: reduce manual work on hard challenges by pulling
out credentials, config fragments, and interesting structures automatically.
"""

import re
import os
import base64
import binascii
from typing import List, Dict


# Additional patterns focused on config-style and weakly-obfuscated data
EXTRA_PATTERNS = {
    "loose_kv": re.compile(rb"(?i)(pass(?:word)?|pwd|secret|token|api[_-]?key|ssid)\s*[=:]\s*[\"']?([^\s\"']{3,48})"),
    "loose_json_pass": re.compile(rb'["\']?(?:pass|password|pwd|secret|token)["\']?\s*[:=]\s*["\']([^"\']{3,48})["\']', re.I),
    "json_like_password": re.compile(rb'["\'](?:password|passwd|pwd|pass|secret|key|token)["\']\s*:\s*["\']([^"\']{4,64})["\']', re.I),
    "env_style": re.compile(rb'(?:WIFI_PASS|WIFI_PASSWORD|MQTT_PASS|API_KEY|SECRET)\s*[=:]\s*([^\s\x00]{4,64})', re.I),
    "base64_blob": re.compile(rb'(?:[A-Za-z0-9+/]{40,}={0,2})'),
    # NVS keys are normally structured names such as wifi_ssid, wifi_pass,
    # mqtt_user, ota_url, etc. Require a separator + meaningful suffix so
    # ordinary prose ("apple", "happy", "mapping") is not treated as a key.
    "possible_nvs_key": re.compile(
        rb'(?<![A-Za-z0-9_-])(?:wifi|sta|ap|mqtt|ota|nvs)[_-][a-z0-9][a-z0-9_-]{1,24}(?=$|[\x00\s:=])',
        re.I,
    ),
}


def decode_base64_candidates(data: bytes, limit: int = 15) -> list:
    out = []
    for m in EXTRA_PATTERNS["base64_blob"].finditer(data):
        if len(out) >= limit:
            break
        try:
            decoded = base64.b64decode(m.group(0), validate=True)
        except (ValueError, binascii.Error):
            continue
        printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in decoded) / max(1, len(decoded))
        if printable >= 0.70:
            out.append({"offset": m.start(), "decoded_length": len(decoded), "preview": decoded[:240].decode("utf-8", "replace")})
    return out


def extract_from_text_blob(data: bytes) -> Dict:
    """Run all extra extractors on a binary/text blob."""
    results = {
        "json_credentials": [],
        "loose_kv": [],
        "env_credentials": [],
        "base64_candidates": [],
        "nvs_like_keys": [],
        "decoded_base64": [],
    }

    for m in EXTRA_PATTERNS.get("loose_kv", re.compile(b"$^")).finditer(data):
        results["loose_kv"].append({
            "key": m.group(1).decode("ascii", errors="replace"),
            "value": m.group(2).decode("ascii", errors="replace"),
            "offset": m.start(),
        })
    for m in EXTRA_PATTERNS["json_like_password"].finditer(data):
        results["json_credentials"].append({
            "match": m.group(0).decode("ascii", errors="replace")[:120],
            "value": m.group(1).decode("ascii", errors="replace"),
            "offset": m.start(),
        })

    for m in EXTRA_PATTERNS["env_style"].finditer(data):
        results["env_credentials"].append({
            "match": m.group(0).decode("ascii", errors="replace")[:120],
            "value": m.group(1).decode("ascii", errors="replace"),
            "offset": m.start(),
        })

    # Limit base64 to avoid noise
    b64_count = 0
    for m in EXTRA_PATTERNS["base64_blob"].finditer(data):
        if b64_count >= 15:
            break
        blob = m.group(0)
        if len(blob) >= 40:
            results["base64_candidates"].append({
                "offset": m.start(),
                "length": len(blob),
                "preview": blob[:60].decode("ascii", errors="replace"),
            })
            b64_count += 1

    results["decoded_base64"] = decode_base64_candidates(data)

    seen = set()
    for m in EXTRA_PATTERNS["possible_nvs_key"].finditer(data):
        key = m.group(0).decode("ascii", errors="replace")
        if key.lower() not in seen and len(key) >= 4:
            seen.add(key.lower())
            results["nvs_like_keys"].append({"key": key, "offset": m.start()})

    return results


class AutoExtractor:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def process_file(self, path: str, label: str) -> dict:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            self.logger.warning(f"[auto] cannot read {path}: {e}")
            return {"error": str(e)}

        extracted = extract_from_text_blob(data)
        total = sum(len(v) for v in extracted.values())
        if total:
            self.logger.info(f"[auto] {label}: {total} automated extraction(s)")
            if extracted["json_credentials"]:
                self.logger.info(f"  json-style creds: {len(extracted['json_credentials'])}")
            if extracted["env_credentials"]:
                self.logger.info(f"  env-style creds: {len(extracted['env_credentials'])}")
            if extracted["base64_candidates"]:
                self.logger.info(f"  base64 candidates: {len(extracted['base64_candidates'])}")
            if extracted["nvs_like_keys"]:
                self.logger.info(f"  nvs-like keys: {len(extracted['nvs_like_keys'])}")

        result = {"label": label, "path": path, "extracted": extracted, "total": total}
        self.storage.save_analysis_result(f"auto_{label}", result)
        self.storage.log_event("auto_extractor", "DONE", f"{total} items", path)
        return result
