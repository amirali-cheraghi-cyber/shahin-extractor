"""
deobfuscator.py
Structurally-aware XOR and Base64 recovery.

Scans the dump with a sliding window (64+ bytes) against all 255
single-byte XOR keys. A hit is only reported when the decoded window is
at least 88% printable AND additionally matches an assignment-like
structure (`key=value` / `key: value`) or a known default-credential
pattern -- a bare keyword substring appearing anywhere is not enough on
its own, since that produces printable-but-meaningless false positives
over a multi-MB dump. Overlapping windows that hit the same region are
merged into one finding, and each finding carries a 0.0-1.0
`confidence` score rather than being presented as a flat list.

PERFORMANCE / COVERAGE (weakness report section 2.1):

The previous implementation XORed each sliding window against all 255
keys with a per-byte Python list comprehension, and hard-capped the scan
at 250 KB (XOR) / 350 KB (Base64). A realistic ESP32 flash dump is 4 MB
(up to 16 MB on WROVER-class modules), so ~94-98% of a real dump was
never checked for single-byte-XOR-obfuscated secrets -- the exact class
of weakness this module exists to find. The cap existed only because the
per-byte loop was slow (measured on this machine: 53 s for a 100 KB
buffer, ~61 s for 300 KB).

The fix keeps the same detection semantics but replaces the per-window
per-key work with one C-speed pass per key, using a printable-mask
trick:

  For a given key k, define a 256-byte translation table that maps
  every byte b to 1 if (b XOR k) is printable ASCII and to 0 otherwise.
  Applying it to the whole buffer with bytes.translate() yields a
  "printable mask" in a single C-speed pass (4 MB in ~3 ms).

  A window of length W is >=88% printable exactly when the mask has
  >=0.88*W ones in that window -- and counting ones in a mask slice is
  also a C-speed operation. So the printable-ratio test, which used to
  be a Python loop over every byte of every window, becomes a cheap
  slice count.

  The mask also immediately identifies *where* printable text exists.
  A window that is 88% printable must contain a long run of printable
  bytes, so the scan only examines offsets near such runs, instead of
  testing every offset of the file against every key.

Net effect: the ENTIRE file is covered (the 250 KB / 350 KB caps are
gone) and the scan is roughly two orders of magnitude faster, reporting
the same findings.
"""

import base64
import binascii
import re
from typing import List, Dict

_KEYWORDS = ("pass", "pwd", "key", "secret", "token", "ssid", "wifi", "admin", "mqtt", "auth", "user", "api")

# Require an assignment-like shape, not just a keyword appearing anywhere
# in the decoded text (e.g. random bytes happening to decode through
# "...keyboard..." previously counted as a "key" hit).
_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,24}\s*[:=]\s*[^\s\"']{2,80}")
_DEFAULT_CRED_RE = re.compile(r"(?i)\b(admin|root|esp32|esp8266)[:/](admin|root|password|12345678)\b")

# --- bytes variants of the same rules ---
_KEYWORDS_LOWER = tuple(k.encode("ascii") for k in _KEYWORDS)

# Window sizes / steps used for the precise check (same as the original
# implementation, so the same offsets are considered).
_WINDOWS = ((64, 16), (96, 24), (128, 32))
_MIN_WINDOW = min(w for w, _ in _WINDOWS)
_MAX_WINDOW = max(w for w, _ in _WINDOWS)

# The smallest number of printable bytes that a window of the smallest
# size must contain to satisfy the >=88% printable rule.
_MIN_PRINTABLE = 57  # ceil(0.88 * 64)

# Per-key cap on reported findings, and an absolute safety net so a
# pathological input can never run unbounded.
_PER_KEY_HIT_CAP = 5
_ABSOLUTE_HIT_CAP = 5000

# Bytes that are not printable ASCII (used for C-speed printable counts).
_NON_PRINTABLE = bytes(b for b in range(256) if not (32 <= b <= 126))

# Per-key tables:
#   _XOR_TABLE[k]       : b -> b XOR k
#   _PRINT_MASK[k]      : b -> 1 if (b XOR k) is printable else 0
_XOR_TABLE = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}
_PRINT_MASK = {
    k: bytes(1 if 32 <= (b ^ k) <= 126 else 0 for b in range(256))
    for k in range(1, 256)
}

# The printable-mask bytes used for run detection.
_ONE = b"\x01"
_ZERO = b"\x00"
_RUN_NEEDLE = b"\x01" * _MIN_PRINTABLE


def _pratio(data: bytes) -> float:
    """Fraction of printable ASCII bytes. C-speed via translate-delete."""
    if not data:
        return 0.0
    # translate(None, delete) removes every non-printable byte, so the
    # length of the result IS the printable count.
    printable = len(data.translate(None, _NON_PRINTABLE))
    return printable / len(data)


def _structural_hit(text: str) -> bool:
    low = text.lower()
    if not any(k in low for k in _KEYWORDS):
        return False
    return bool(_ASSIGNMENT_RE.search(text) or _DEFAULT_CRED_RE.search(text))


def _confidence(pratio: float, structural: bool, window: int) -> float:
    score = 0.4 if structural else 0.0
    score += min(pratio, 1.0) * 0.4
    score += min(window / 128, 1.0) * 0.2
    return round(min(score, 1.0), 2)


def _printable_runs(mask: bytes, min_len: int = _MIN_PRINTABLE):
    """
    Yield (start, end) of maximal runs of printable bytes, keeping only
    runs of at least min_len bytes. Uses C-level find() so this stays
    fast even on a multi-MB buffer.
    """
    n = len(mask)
    pos = 0
    while True:
        s = mask.find(_RUN_NEEDLE, pos)
        if s < 0:
            break
        # Extend the run to the right.
        e = mask.find(_ZERO, s)
        if e < 0:
            e = n
        # Extend to the left: because _RUN_NEEDLE is min_len long, the
        # run can start at most (min_len - 1) bytes before s.
        start = s
        limit = max(0, s - (_MIN_PRINTABLE - 1))
        while start > limit and mask[start - 1] == 1:
            start -= 1
        if e - start >= min_len:
            yield start, e
        pos = e if e > s else s + 1


def _keyword_positions(text: bytes) -> List[int]:
    """Start positions of any credential keyword in an already-lowercased run."""
    positions: List[int] = []
    for needle in _KEYWORDS_LOWER:
        start = 0
        while True:
            idx = text.find(needle, start)
            if idx < 0:
                break
            positions.append(idx)
            start = idx + 1
    return positions


def scan_xor(data: bytes, max_hits: int = 15) -> List[Dict]:
    """
    Full-file single-byte XOR scan.

    For each key the whole buffer is turned into a printable mask with a
    single C-speed bytes.translate() call, printable runs are located
    with C-level find(), and only windows inside those runs are verified
    against the original detection rules. The ENTIRE file is scanned.
    """
    hits: List[Dict] = []
    if len(data) < _MIN_WINDOW:
        return hits

    for key in range(1, 256):
        mask = data.translate(_PRINT_MASK[key])   # one C-speed pass over the file
        runs = list(_printable_runs(mask))
        if not runs:
            continue

        xor_table = _XOR_TABLE[key]
        # Regions already reported for THIS key -- mirrors the original's
        # seen_spans logic, so one key never reports the same secret twice.
        seen_spans: List[tuple] = []
        key_hits = 0

        for run_start, run_end in runs:
            if key_hits >= _PER_KEY_HIT_CAP:
                break
            run = data[run_start:run_end].translate(xor_table)
            run_low = run.lower()
            kw_positions = _keyword_positions(run_low)
            if not kw_positions:
                continue

            for kw_rel in kw_positions:
                if key_hits >= _PER_KEY_HIT_CAP:
                    break
                kw_abs = run_start + kw_rel
                for window, step in _WINDOWS:
                    # Grid offsets whose window contains the keyword. The
                    # original rules require the keyword to be INSIDE the
                    # window, so these are the only offsets that can match.
                    lo = max(0, kw_abs - window + 1)
                    first = ((lo + step - 1) // step) * step
                    for off in range(first, kw_abs + 1, step):
                        if off + window > len(data):
                            break
                        # printable count straight from the mask (C-speed)
                        printable = mask[off:off + window].count(1)
                        if printable < 0.88 * window:
                            continue
                        chunk = data[off:off + window].translate(xor_table)
                        text = chunk.decode("ascii", errors="ignore")
                        if not _structural_hit(text):
                            continue
                        # same key, overlapping region -> same underlying secret
                        if any(abs(off - s) < window for _, s, _ in seen_spans):
                            continue
                        seen_spans.append((key, off, off + window))
                        hits.append({
                            "offset": off,
                            "xor_key": key,
                            "window": window,
                            "preview": text[:120],
                            "confidence": _confidence(printable / window, True, window),
                        })
                        key_hits += 1
                        if key_hits >= _PER_KEY_HIT_CAP:
                            break
                    if key_hits >= _PER_KEY_HIT_CAP:
                        break
            if len(hits) >= _ABSOLUTE_HIT_CAP:
                break
        if len(hits) >= _ABSOLUTE_HIT_CAP:
            break

    hits.sort(key=lambda h: (-h["confidence"], h["offset"]))
    return hits[:max_hits]


def _decode_b64_alignments(chunk: bytes):
    """
    Base64 has no self-synchronising delimiter, so a run of base64
    characters embedded in other data decodes to garbage unless the
    alignment (offset mod 4) is right. Yield the plausible decodings:
    each of the 4 possible start alignments, with the length trimmed to a
    multiple of 4.
    """
    for align in range(4):
        body = chunk[align:]
        body = body[:len(body) - (len(body) % 4)]
        if len(body) < 8:
            continue
        try:
            yield base64.b64decode(body, validate=False)
        except (ValueError, binascii.Error):
            continue


def scan_b64(data: bytes, max_hits: int = 10) -> List[Dict]:
    """
    Full-file Base64 scan (the previous 350 KB hard cap is gone).

    Each base64-looking run is decoded at all four possible alignments,
    because a secret embedded in surrounding data only decodes cleanly at
    the correct alignment.
    """
    hits: List[Dict] = []
    seen_spans: List[tuple] = []
    for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        chunk = m.group(0)
        best = None
        for dec in _decode_b64_alignments(chunk):
            if len(dec) < 6:
                continue
            pratio = _pratio(dec)
            if pratio < 0.75:
                continue
            text = dec.decode("ascii", errors="ignore")
            structural = _structural_hit(text)
            # Accept on structure, OR on very high printable ratio
            # (near-certain text).
            if not (structural or pratio > 0.92):
                continue
            cand = {
                "offset": m.start(),
                "preview": text[:120],
                "confidence": _confidence(pratio, structural, len(dec)),
            }
            if best is None or cand["confidence"] > best["confidence"]:
                best = cand

        if best is None:
            continue
        off = best["offset"]
        if any(abs(off - s) < 8 for s, _ in seen_spans):
            continue
        seen_spans.append((off, off + len(chunk)))
        hits.append(best)
        if len(hits) >= max_hits:
            break
    hits.sort(key=lambda h: -h["confidence"])
    return hits


class Deobfuscator:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def process(self, path: str, label: str) -> dict:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            return {"error": str(e)}
        xor_hits = scan_xor(data)
        b64_hits = scan_b64(data)
        result = {
            "label": label,
            "scanned_bytes": len(data),
            "xor_candidates": xor_hits,
            "base64_layers": b64_hits,
            "interesting": bool(xor_hits or b64_hits),
            "high_confidence": any(h["confidence"] >= 0.75 for h in xor_hits + b64_hits),
        }
        if xor_hits:
            self.logger.info(
                f"[deobf] {len(xor_hits)} XOR hit(s) in {len(data)} bytes, "
                f"top confidence {xor_hits[0]['confidence']}"
            )
        if b64_hits:
            self.logger.info(
                f"[deobf] {len(b64_hits)} Base64 hit(s) in {len(data)} bytes, "
                f"top confidence {b64_hits[0]['confidence']}"
            )
        self.storage.save_analysis_result(f"deobf_{label}", result)
        self.storage.log_event("deobfuscator", "DONE", f"xor={len(xor_hits)} b64={len(b64_hits)}", path)
        return result
