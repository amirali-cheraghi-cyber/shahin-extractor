"""
post_analysis.py

General-purpose, non-judgmental forensic summary of a raw file: printable
strings and filesystem signatures. This module intentionally does NOT
search for or highlight CTF flags -- that decision is deliberate. This
project's job ends at extraction and weakness diagnosis; picking through
the result for the actual flag is a manual step done separately, with more
care than a regex can offer (a flag's exact format varies per competition
and a wrong regex match is worse than no match at all).

Important principle: any error here must be fully isolated and must never
cause the loss of, or loss of access to, an already-saved raw file. That's
why these functions are all read-only and never touch the original file's
location.
"""

import string


PRINTABLE = set(bytes(string.printable, "ascii"))


def extract_strings(data: bytes, min_len: int = 4):
    """Simple equivalent of 'strings'; returns runs of printable bytes."""
    out = []
    current = bytearray()
    for b in data:
        if b in PRINTABLE:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(current.decode("ascii", errors="replace"))
            current = bytearray()
    if len(current) >= min_len:
        out.append(current.decode("ascii", errors="replace"))
    return out


# (description, byte pattern, search-whole-file vs offset-0-only)
MAGIC_SIGNATURES = [
    ("ZIP archive", b"\x50\x4b\x03\x04", False),
    ("gzip-compressed data", b"\x1f\x8b", False),
    ("tar archive (ustar)", b"ustar", False),
    ("ELF binary", b"\x7fELF", False),
    ("LittleFS superblock marker", b"littlefs", False),
    ("JFFS2 filesystem", b"\x85\x19", False),
    ("CPIO archive", b"070701", False),
    ("SQLite database", b"SQLite format 3\x00", False),
    ("PEM certificate/key block", b"-----BEGIN", False),
    ("ESP flash image header (offset 0)", b"\xe9", True),
]


def detect_filesystem_signature(data: bytes) -> list:
    """
    Looks for known signatures of common ESP filesystems and embedded file
    formats. This is just a helper (exact-match scan over a short, curated
    signature list), not a full filesystem parser -- for exhaustive binary
    signature detection, binwalk (run separately in static_analysis.py) is
    the authoritative tool.
    """
    hits = []
    for description, pattern, offset_zero_only in MAGIC_SIGNATURES:
        if offset_zero_only:
            if data[: len(pattern)] == pattern:
                hits.append(f"{description} found at offset 0.")
        elif pattern in data:
            hits.append(f"{description} signature found.")
    return hits


class PostAnalyzer:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def analyze_file(self, path: str, label: str) -> dict:
        """
        Analyzes one raw file. The whole function is wrapped in a broad
        try/except so that no analysis error can stop the program or
        affect the original raw file.
        """
        result = {"label": label, "path": path, "ok": False}
        try:
            with open(path, "rb") as f:
                data = f.read()

            strings_list = extract_strings(data)
            fs_hits = detect_filesystem_signature(data)

            result.update(
                {
                    "ok": True,
                    "size_bytes": len(data),
                    "num_strings": len(strings_list),
                    "filesystem_hints": fs_hits,
                    "sample_strings": strings_list[:200],
                }
            )

            for h in fs_hits:
                self.logger.info(f"[analysis] {label}: {h}")

            self.storage.save_analysis_result(f"analysis_{label}", result)
            self.storage.log_event(
                "post_analysis", "DONE", f"{len(fs_hits)} fs hint(s), {result['size_bytes']} bytes"
            )
        except Exception as e:
            self.logger.warning(f"[analysis failed] {label}: {e} (raw file left untouched)")
            result["error"] = str(e)
            self.storage.log_event("post_analysis", "ANALYSIS_ERROR", str(e))
        return result
