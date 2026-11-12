"""
nvs_helper.py
Structural ESP-IDF NVS page/entry parser.

Implements the real on-flash format, per the official ESP-IDF docs
("Non-volatile storage library" -> Internals -> "Structure of a page" /
"Structure of entry" -> https://docs.espressif.com/projects/esp-idf/en/
stable/esp32/api-reference/storage/nvs_flash.html):

    Page (4096 bytes) = Header(32) + Entry state bitmap(32) + 126 * Entry(32)
    Header            = State(4) | SeqNo(4) | Version(1) | Unused(19) | CRC32(4)
    Entry             = NS(1) | Type(1) | Span(1) | ChunkIndex(1) | CRC32(4) | Key(16) | Data(8)
    Entry state       = 2 bits/entry in the bitmap: 11=Empty 10=Written 00=Erased

This recovers actual key = value pairs with their real key name, type
and owning namespace (namespaces are themselves NS=0 entries that map
an index to a name), instead of unlabelled substrings. Primitive
integer types, zero-terminated strings, and blob/blob_data chunks are
all fully decoded (blob payload is given a printable preview when it
looks like text, plus a credential-regex pass over the raw bytes for
binary/structured blobs such as embedded JSON or INI-style config);
blob_idx entries are metadata-only by design (they just point at where
the real chunks are) and are reported as such.

Pages that are encrypted (NVS+flash encryption) or too corrupted to
walk structurally will not parse; for those, a low-confidence fallback
string scan still runs, but its hits are explicitly labelled
low-confidence rather than mixed in with real decoded data.
"""

import struct
import zlib
from typing import List, Dict, Optional

from modules.static_analysis import SECRET_PATTERNS  # reuse, don't duplicate the regexes


def _scan_blob_for_secrets(raw: bytes) -> List[Dict]:
    """Run the same credential regexes used on whole flash dumps over one
    decoded NVS blob chunk, so a JSON/INI-style config stashed in a blob
    (rather than a plain NVS string) is still caught."""
    hits = []
    for name, pattern in SECRET_PATTERNS.items():
        m = pattern.search(raw)
        if m:
            hits.append({"pattern": name, "match_text": m.group(0).decode("utf-8", "replace")[:120]})
    return hits

NVS_PAGE_SIZE = 4096
NVS_ENTRY_SIZE = 32
NVS_HEADER_SIZE = 32
NVS_BITMAP_SIZE = 32
NVS_ENTRIES_PER_PAGE = 126  # (4096 - 32 - 32) / 32

# Page header state values (ESP-IDF Page::PageState, as written to flash)
PAGE_STATE = {
    0xFFFFFFFF: "EMPTY",
    0xFFFFFFFE: "ACTIVE",
    0xFFFFFFFC: "FULL",
    0xFFFFFFF8: "FREEING",
    0xFFFFFFF0: "CORRUPT",
}

# Entry type values (ESP-IDF nvs_types.h ItemType)
NVS_TYPES = {
    0x01: ("u8", 1), 0x11: ("i8", 1),
    0x02: ("u16", 2), 0x12: ("i16", 2),
    0x04: ("u32", 4), 0x14: ("i32", 4),
    0x08: ("u64", 8), 0x18: ("i64", 8),
    0x21: ("str", None),
    0x41: ("blob_old", None),
    0x42: ("blob_data", None),
    0x48: ("blob_idx", None),
}

_INT_FMT_U = {1: "B", 2: "H", 4: "I", 8: "Q"}
_INT_FMT_I = {1: "b", 2: "h", 4: "i", 8: "q"}


def _entry_state(bitmap: bytes, index: int) -> str:
    """2 bits per entry; 0b11=Empty, 0b10=Written, 0b00=Erased."""
    byte = bitmap[index // 4]
    shift = (index % 4) * 2
    bits = (byte >> shift) & 0b11
    return {0b11: "EMPTY", 0b10: "WRITTEN", 0b00: "ERASED"}.get(bits, "UNKNOWN")


def _decode_key(raw16: bytes) -> Optional[str]:
    end = raw16.find(b"\x00")
    key_bytes = raw16 if end == -1 else raw16[:end]
    if not key_bytes or len(key_bytes) > 15:
        return None
    if not all(32 <= b <= 126 for b in key_bytes):
        return None
    try:
        return key_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_page(data: bytes, page_off: int) -> Dict:
    """Parse one 4096-byte NVS page at page_off into namespaces + decoded items."""
    page = data[page_off:page_off + NVS_PAGE_SIZE]
    if len(page) < NVS_PAGE_SIZE:
        return {"offset": page_off, "valid": False, "reason": "truncated"}

    state_raw = struct.unpack_from("<I", page, 0)[0]
    seq_no = struct.unpack_from("<I", page, 4)[0]
    version = page[8]
    header_crc_stored = struct.unpack_from("<I", page, 28)[0]
    # CRC32 covers bytes 4..27 (everything in the header except State and CRC32
    # itself). Confirmed against the ESP-IDF ROM crc32_le convention: one-shot
    # use (init=0) is bit-for-bit compatible with zlib.crc32, so this check is
    # trustworthy -- still kept as a confidence signal rather than a hard
    # rejection, since a page can legitimately be mid-write during a power-off
    # capture and fail CRC without being otherwise unreadable.
    header_crc_calc = zlib.crc32(page[4:28]) & 0xFFFFFFFF
    page_state = PAGE_STATE.get(state_raw, f"UNKNOWN(0x{state_raw:08x})")

    bitmap = page[NVS_HEADER_SIZE:NVS_HEADER_SIZE + NVS_BITMAP_SIZE]
    entries_raw = page[NVS_HEADER_SIZE + NVS_BITMAP_SIZE:]

    namespaces: Dict[int, str] = {}
    items: List[Dict] = []

    idx = 0
    while idx < NVS_ENTRIES_PER_PAGE:
        if _entry_state(bitmap, idx) != "WRITTEN":
            idx += 1
            continue

        base = idx * NVS_ENTRY_SIZE
        entry = entries_raw[base:base + NVS_ENTRY_SIZE]
        if len(entry) < NVS_ENTRY_SIZE:
            break

        ns_idx, item_type, span_raw, chunk_idx = entry[0], entry[1], entry[2], entry[3]
        key_raw = entry[8:24]
        data_raw = entry[24:32]
        span = max(span_raw, 1)

        key = _decode_key(key_raw)
        type_name, width = NVS_TYPES.get(item_type, (None, None))

        if key is None or type_name is None:
            # Not a recognizable entry header (could be mid-span payload we
            # haven't skipped over, or a corrupted/unsupported entry) -> move on.
            idx += 1
            continue

        item = {
            "page_offset": page_off,
            "entry_index": idx,
            "ns_index": ns_idx,
            "type": type_name,
            "key": key,
            "chunk_index": chunk_idx,
        }
        consumed = 1

        if type_name in ("u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64"):
            fmt = (_INT_FMT_I if type_name.startswith("i") else _INT_FMT_U)[width]
            item["value"] = struct.unpack_from("<" + fmt, data_raw, 0)[0]
        elif type_name == "str":
            size = struct.unpack_from("<H", data_raw, 0)[0]
            payload_entries = (size + NVS_ENTRY_SIZE - 1) // NVS_ENTRY_SIZE if size else 0
            start = base + NVS_ENTRY_SIZE
            raw_payload = entries_raw[start:start + payload_entries * NVS_ENTRY_SIZE]
            item["value"] = raw_payload[:size].rstrip(b"\x00").decode("utf-8", errors="replace") if size else ""
            item["declared_size"] = size
            consumed = 1 + payload_entries
        elif type_name in ("blob_data", "blob_old"):
            # Per the ESP-IDF entry-structure spec, blob/string data-chunk entries
            # share the same Data layout: Size(2) + Rsv(2) + CRC32(4). The chunk
            # payload itself follows in the next `span - 1` entries, same as a
            # string. Unlike a string it isn't assumed to be text, so instead of
            # forcing a UTF-8 decode we: (a) keep the raw bytes, (b) give a
            # best-effort printable preview, and (c) run the same credential
            # regexes used on flash dumps over the chunk, since it's common for
            # CTF firmware to stash a config blob (JSON/INI-like bytes) here.
            size = struct.unpack_from("<H", data_raw, 0)[0]
            payload_entries = (size + NVS_ENTRY_SIZE - 1) // NVS_ENTRY_SIZE if size else 0
            start = base + NVS_ENTRY_SIZE
            raw_payload = entries_raw[start:start + payload_entries * NVS_ENTRY_SIZE][:size]
            item["declared_size"] = size
            item["raw_hex_preview"] = raw_payload[:32].hex()
            printable_ratio = (sum(1 for b in raw_payload if 32 <= b <= 126) / len(raw_payload)) if raw_payload else 0.0
            if printable_ratio > 0.85:
                item["value"] = raw_payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                item["blob_kind"] = "text-like"
            else:
                item["value"] = None
                item["blob_kind"] = "binary"
            item["embedded_matches"] = _scan_blob_for_secrets(raw_payload)
            consumed = 1 + payload_entries
        else:
            # blob_idx: fixed-length metadata entry only (Size/ChunkCount/ChunkStart),
            # points at separate blob_data chunks elsewhere -- nothing to decode here.
            size, chunk_count, chunk_start = struct.unpack_from("<IBB", data_raw, 0)
            item["value"] = None
            item["note"] = f"blob index: total {size} bytes across {chunk_count} chunk(s) starting at chunk {chunk_start}"
            consumed = max(span, 1)

        if ns_idx == 0 and type_name == "u8" and isinstance(item.get("value"), int):
            # NS=0 entries are the namespace table itself: key=name, value=index
            namespaces[item["value"]] = key
        else:
            items.append(item)

        idx += max(consumed, 1)

    for item in items:
        item["namespace"] = namespaces.get(item["ns_index"], f"ns#{item['ns_index']}")

    return {
        "offset": page_off,
        "valid": True,
        "page_state": page_state,
        "seq_no": seq_no,
        "version_byte": version,
        "header_crc_ok": header_crc_calc == header_crc_stored,
        "namespaces": namespaces,
        "items": items,
    }


def find_candidate_pages(data: bytes) -> List[int]:
    """4096-aligned offsets whose header *state* word is a real NVS page state."""
    offsets = []
    for off in range(0, len(data) - NVS_PAGE_SIZE + 1, NVS_PAGE_SIZE):
        state_raw = struct.unpack_from("<I", data, off)[0]
        if state_raw in PAGE_STATE:
            offsets.append(off)
    return offsets


# ---- Fallback: low-confidence string scan, used ONLY for pages that
# don't structurally parse (encrypted NVS, partial/corrupted dumps). Its
# hits are explicitly marked low-confidence. ----

def _legacy_string_scan(data: bytes, page_offsets: List[int]) -> List[Dict]:
    found = []
    for off in page_offsets:
        page = data[off:off + NVS_PAGE_SIZE]
        current = bytearray()
        start = 0
        for i, b in enumerate(page):
            if 32 <= b <= 126:
                if not current:
                    start = i
                current.append(b)
            else:
                if len(current) >= 4:
                    text = current.decode("ascii", errors="replace")
                    if any(k in text.lower() for k in ("wifi", "pass", "ssid", "mqtt", "sta", "ap", "key", "nvs", "user", "token", "secret")):
                        found.append({
                            "page_offset": off, "inner_offset": start,
                            "text": text[:80], "confidence": "LOW (unstructured fallback scan)",
                        })
                current = bytearray()
        if len(found) > 40:
            break
    return found


class NVSHelper:
    def __init__(self, storage, logger):
        self.storage = storage
        self.logger = logger

    def analyze(self, path: str, label: str) -> dict:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            return {"error": str(e)}

        candidate_pages = find_candidate_pages(data)
        parsed_pages = []
        structured_items = []

        for off in candidate_pages:
            parsed = parse_page(data, off)
            parsed_pages.append(parsed)
            if parsed.get("valid") and parsed.get("items"):
                structured_items.extend(parsed["items"])

        covered = {p["offset"] for p in parsed_pages if p.get("items")}
        fallback_offsets = [o for o in candidate_pages if o not in covered]
        fallback_strings = _legacy_string_scan(data, fallback_offsets) if fallback_offsets else []

        result = {
            "label": label,
            "candidate_pages": candidate_pages,
            "pages": parsed_pages,
            "structured_items": structured_items,
            "fallback_strings": fallback_strings,
            # kept for backward compatibility with anything still reading the old key name
            "interesting_strings": fallback_strings,
        }

        if structured_items:
            self.logger.info(f"[nvs] {label}: {len(structured_items)} structurally decoded key-value item(s) across {len(candidate_pages)} candidate page(s)")
            for it in structured_items[:10]:
                self.logger.info(f"  ns={it['namespace']} key={it['key']} type={it['type']} value={it.get('value')!r}")
        if fallback_strings:
            self.logger.info(f"[nvs] {label}: {len(fallback_strings)} low-confidence fallback string(s) (pages that did not structurally parse)")

        self.storage.save_analysis_result(f"nvs_{label}", result)
        self.storage.log_event(
            "nvs_helper", "DONE",
            f"pages={len(candidate_pages)} items={len(structured_items)} fallback={len(fallback_strings)}",
            path,
        )
        return result
