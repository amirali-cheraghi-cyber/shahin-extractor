"""Read-only static analysis for ESP flash/partition artifacts."""

import math
import re
import shutil
import subprocess
from collections import Counter


def shannon_entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def extract_high_value_strings(data, min_len=8):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    keys = ("pass", "pwd", "key", "secret", "token", "ssid", "wifi", "mqtt", "auth", "admin", "user", "http")
    return [s for s in out if any(k in s.lower() for k in keys)][:100]


SECRET_PATTERNS = {
    "private_key_header": re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "api_key_assignment": re.compile(rb"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-.]{12,}"),
    "bearer_token": re.compile(rb"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{10,}"),
    # [\"']? right after the keyword covers JSON-style quoted keys too, e.g.
    # "mqtt_pass":"value" (a closing quote sits between the keyword and the
    # colon, which the old pattern -- keyword directly followed by \s*[:=] --
    # did not allow for).
    "password_assignment": re.compile(rb"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?[^\s\"'\x00]{4,64}"),
    "wifi_ssid_assignment": re.compile(rb"(?i)(ssid|wifi_ssid)[\"']?\s*[:=]\s*[\"']?[^\s\"'\x00]{2,32}"),
    "mqtt_credentials": re.compile(rb"(?i)mqtt[_-]?(user|pass|password)[\"']?\s*[:=]\s*[\"']?[^\s\"'\x00]{2,64}"),
    "default_credential": re.compile(rb"(?i)\b(admin[:/]admin|esp32[:/]esp32|root[:/]root|admin[:/]password|password[:/]12345678)\b"),
    "nvs_context": re.compile(rb"(?i)\b(nvs|namespace|nvs_key|nvs_handle)\b"),
    "verbose_debug_log": re.compile(rb"(?m)^[DV] \([0-9]+\) "),
}


def scan_for_secrets(data, logger):
    findings, seen = [], set()
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(data):
            key = (name, m.start(), m.group(0)[:120])
            if key in seen:
                continue
            seen.add(key)
            start, end = m.span()
            findings.append({
                "pattern": name, "offset": start, "offset_hex": hex(start),
                "match_text": m.group(0).decode("utf-8", "replace")[:120],
                "context_preview": data[max(0, start - 80):min(len(data), end + 120)].decode("utf-8", "replace"),
            })
    logger.info(f"[static] {len(findings)} potential secret/config finding(s)")
    return findings


def find_interesting_low_entropy(data, window=128):
    results = []
    step = max(32, window // 2)
    for off in range(0, max(0, len(data) - window + 1), step):
        chunk = data[off:off + window]
        ent = shannon_entropy(chunk)
        printable = sum(32 <= b <= 126 for b in chunk)
        if ent < 6.0 and printable > window * 0.4:
            results.append({"offset": off, "entropy": round(ent, 2), "preview": chunk.decode("ascii", "replace")[:100]})
            if len(results) >= 40:
                break
    return results


def run_binwalk(file_path, logger, timeout=60):
    if not shutil.which("binwalk"):
        return {"available": False, "signatures": []}
    try:
        p = subprocess.run(["binwalk", file_path], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return {"available": True, "signatures": [], "error": str(e)}
    signatures = []
    for line in p.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 3 and parts[0].isdigit():
            signatures.append({"offset_decimal": int(parts[0]), "description": parts[2]})
    return {"available": True, "signatures": signatures, "raw": p.stdout}


class StaticAnalyzer:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def analyze(self, file_path, label):
        result = {"label": label, "path": file_path}
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except OSError as e:
            result["error"] = str(e)
            return result

        result["size_bytes"] = len(data)
        result["secrets"] = scan_for_secrets(data, self.logger)
        result["high_value_strings"] = extract_high_value_strings(data)
        result["entropy_regions"] = []
        window = 256
        for off in range(0, max(0, len(data) - window + 1), window):
            ent = shannon_entropy(data[off:off + window])
            if ent >= 7.2:
                result["entropy_regions"].append({"offset": off, "entropy": round(ent, 2)})
                if len(result["entropy_regions"]) >= 50:
                    break
        result["interesting_low_entropy"] = find_interesting_low_entropy(data)
        result["binwalk"] = run_binwalk(file_path, self.logger)
        self.storage.save_analysis_result(f"static_{label}", result)
        self.storage.log_event("static_analysis", "DONE", f"secrets={len(result['secrets'])}", file_path)
        return result
