"""
End-to-end smoke test: builds a synthetic 4 MB ESP32 flash dump
(bootloader + partition table + app + an XOR-obfuscated secret +
a Base64 secret + NVS-like page) and runs the real analysis stack
over it, verifying that findings actually surface.
"""
import base64, json, os, random, struct, sys, tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.logger_setup import setup_logger
from modules.storage import SessionStorage
from modules.post_analysis import PostAnalyzer
from modules.static_analysis import StaticAnalyzer
from modules.auto_extractor import AutoExtractor
from modules.binary_intel import BinaryIntel
from modules.deobfuscator import Deobfuscator
from modules.nvs_helper import NVSHelper
from modules.region_extractor import RegionExtractor
from modules.correlation_engine import CorrelationEngine
from modules.diagnosis_report import DiagnosisReport

random.seed(99)
SIZE = 4 * 1024 * 1024
dump = bytearray(random.randrange(256) for _ in range(SIZE))

# --- 1. ESP32 image header at 0x1000 ---
dump[0x1000] = 0xE9

# --- 2. IDF partition table at 0x8000 ---
def p_entry(name, ptype, subtype, off, size):
    return struct.pack("<2sBBII16sI", b"\xaa\x50", ptype, subtype, off, size,
                       name.encode().ljust(16, b"\x00"), 0)

pt = b""
pt += p_entry("nvs",     1, 0x02, 0x9000,  0x6000)
pt += p_entry("spiffs",  1, 0x82, 0xF000,  0x10000)
pt += p_entry("factory", 0, 0x00, 0x10000, 0x180000)
dump[0x8000:0x8000+len(pt)] = pt

# --- 3. XOR-obfuscated secret deep in the app partition (offset 1.5 MB) ---
SECRET = b"wifi_password=XorSecret42;mqtt_pass=hunter2;api_key=AKIA1234567890ABCDEF;"
KEY = 0x5A
obf = bytes(b ^ KEY for b in SECRET)
dump[1_500_000:1_500_000+len(obf)] = obf

# --- 4. Base64 secret near the end ---
b64 = base64.b64encode(b"mqtt_user=admin;mqtt_pass=Base64Secret777;")
dump[3_900_000:3_900_000+len(b64)] = b64

# --- 5. Plaintext secret in the NVS partition (offset 0x9000) ---
nvs_text = b"wifi_ssid=CTF_LAB_NET\x00wifi_password=PlainNvsSecret123\x00"
dump[0x9000:0x9000+len(nvs_text)] = nvs_text

# --- 6. A real NVS page at 0x10000 ---
page = bytearray(b"\xff" * 4096)
struct.pack_into("<I", page, 0, 0xFFFFFFFE)  # ACTIVE
struct.pack_into("<I", page, 4, 1)
page[8] = 0xFE
bitmap = bytearray(b"\xff" * 32)

def mark(idx):
    b, s = idx // 4, (idx % 4) * 2
    bitmap[b] &= (~(0b11 << s)) & 0xFF
    bitmap[b] |= (0b10 << s)

def entry(ns, t, span, chunk, key, data8):
    kf = key.encode().ljust(16, b"\x00")
    return struct.pack("<BBBB", ns, t, span, chunk) + b"\x00"*4 + kf + data8

eo, idx = 64, 0
e = entry(0, 0x01, 1, 0xFF, "wifi", struct.pack("<Q", 1)[:8])
page[eo:eo+32] = e; mark(idx); idx += 1
val = b"NvsPageSecret!\x00"
e = entry(1, 0x21, 2, 0xFF, "password", struct.pack("<H", len(val)) + b"\x00"*6)
page[eo+idx*32:eo+idx*32+32] = e; mark(idx); idx += 1
page[eo+idx*32:eo+idx*32+32] = (val + b"\x00"*(32-len(val)))[:32]; mark(idx); idx += 1
page[32:64] = bitmap
dump[0x10000:0x10000+4096] = page

with tempfile.TemporaryDirectory() as d:
    dump_path = Path(d, "full_flash_dump.bin")
    dump_path.write_bytes(bytes(dump))

    logger = setup_logger(d)
    storage = SessionStorage(d, logger)

    files = [("full_flash_dump", str(dump_path))]

    print("=== post analysis ===")
    PostAnalyzer(storage, logger).analyze_file(str(dump_path), "full_flash_dump")

    print("=== static analysis ===")
    sa = StaticAnalyzer(storage, logger).analyze(str(dump_path), "full_flash_dump")
    print(f"   secrets: {len(sa.get('secrets', []))}")
    for s in sa.get("secrets", [])[:5]:
        print(f"     - {s['pattern']}: {s['match_text'][:60]}")

    print("=== auto extractor ===")
    ae = AutoExtractor(storage, logger).process_file(str(dump_path), "full_flash_dump")
    print(f"   total: {ae.get('total')}")
    print(f"   nvs_like_keys: {[k['key'] for k in ae['extracted']['nvs_like_keys']][:6]}")

    print("=== binary intel ===")
    bi = BinaryIntel(storage, logger).analyze(str(dump_path), "full_flash_dump")
    print(f"   configs: {len(bi.get('candidate_configs', []))}")

    print("=== deobfuscator (the fixed one) ===")
    db = Deobfuscator(storage, logger).process(str(dump_path), "full_flash_dump")
    print(f"   scanned: {db['scanned_bytes']} bytes")
    for h in db["xor_candidates"]:
        print(f"   XOR key=0x{h['xor_key']:02X} off={h['offset']} conf={h['confidence']} :: {h['preview'][:60]}")
    for h in db["base64_layers"]:
        print(f"   B64 off={h['offset']} conf={h['confidence']} :: {h['preview'][:60]}")

    print("=== nvs helper ===")
    nv = NVSHelper(storage, logger).analyze(str(dump_path), "full_flash_dump")
    print(f"   structured items: {len(nv.get('structured_items', []))}")
    for it in nv.get("structured_items", [])[:5]:
        print(f"     ns={it['namespace']} key={it['key']} value={it.get('value')!r}")

    print("=== region extractor ===")
    regions_dir = os.path.join(d, "raw", "regions")
    ex = RegionExtractor(storage, logger)
    parts = ex.extract_partition_table(str(dump_path), regions_dir)
    for p in parts:
        print(f"   {p['name']:<10} {p['subtype']:<8} off=0x{p['offset']:x} size=0x{p['size']:x} -> {bool(p.get('extracted_path'))}")
    fs = ex.extract_filesystem_regions(str(dump_path), regions_dir, partitions=parts)
    for r in fs:
        print(f"   fs region {r['type']} size={r.get('size')}")

    print("=== correlation ===")
    corr = CorrelationEngine(storage, logger).correlate(
        security_report={"weakness_findings": [
            {"severity": "HIGH", "title": "Flash encryption is disabled",
             "detail": "Readable flash dump exposes firmware.", "confidence": 0.98},
        ]},
        dumped_files=files,
        console_result={"responsive_ecosystems": ["esp_idf_console"]},
    )
    print(f"   assessment: {corr['assessment']}")
    for p in corr["ranked_findings"][:8]:
        print(f"     #{p['rank']} [{p['category']}/{p['priority']}] {p['title']}")

    print("=== diagnosis ===")
    rep = DiagnosisReport(storage, logger).build_and_print(
        chip_info={"chip": "ESP32", "chip_id_hex": "0x1234"},
        bootloader_ok=True, used_no_stub=False,
        security_report={"feature_status": {"flash_encryption": "OFF"},
                         "weakness_findings": [
                             {"severity": "HIGH", "title": "Flash encryption is disabled",
                              "detail": "x", "confidence": 0.98}]},
        wiring_result={"pattern_echoed_back": False},
        console_result={"responsive_ecosystems": ["esp_idf_console"]},
        extraction_path=str(dump_path),
        dumped_files=files,
        correlation_report=corr,
    )
    print(f"   verdict: {rep['verdict']}")
    print(f"   summary.txt exists: {os.path.exists(os.path.join(d, 'summary.txt'))}")
    print(f"   history export exists: {os.path.exists(os.path.join(d, 'history_export.json'))}")

    print("\n=== raw files saved (collision check) ===")
    for p in sorted(Path(d, "raw").iterdir()):
        print(f"   {p.name}")
