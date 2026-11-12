"""
Regression tests covering:
  - nvs_helper.py: real page/entry structural parsing (ints, strings, blobs)
  - deobfuscator.py: false-positive bar on XOR recovery, real secrets still caught
  - correlation_engine.py: STRONG requires >=2 independent categories or
    one CRITICAL finding, and nvs_ results feed into ranking
  - static_analysis.py: JSON-quoted key=value credentials are matched
"""

import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

from modules.nvs_helper import parse_page, NVS_PAGE_SIZE
from modules.deobfuscator import scan_xor
from modules.correlation_engine import CorrelationEngine
from modules.static_analysis import scan_for_secrets


class DummyLog:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


class DummyStorage:
    def __init__(self, d):
        self.session_dir = d

    def save_analysis_result(self, label, data):
        Path(self.session_dir, label + ".json").write_text(json.dumps(data), encoding="utf-8")

    def log_event(self, *a, **k):
        pass


def _mark_written(bitmap, idx):
    byte, shift = idx // 4, (idx % 4) * 2
    bitmap[byte] &= ~(0b11 << shift) & 0xFF
    bitmap[byte] |= (0b10 << shift)


def _build_entry(ns, type_byte, span, chunk, key, data8):
    key_field = key.encode("ascii") + b"\x00" * (16 - len(key))
    return struct.pack("<BBBB", ns, type_byte, span, chunk) + b"\x00\x00\x00\x00" + key_field + data8


def _blank_page():
    page = bytearray(b"\xff" * NVS_PAGE_SIZE)
    struct.pack_into("<I", page, 0, 0xFFFFFFFE)  # ACTIVE
    struct.pack_into("<I", page, 4, 1)
    page[8] = 0xFE
    return page, bytearray(b"\xff" * 32)


class NVSStructuralParserTests(unittest.TestCase):
    def test_decodes_string_and_integer_entries_with_namespace(self):
        page, bitmap = _blank_page()
        entries_off, idx = 64, 0

        e = _build_entry(0, 0x01, 1, 0xFF, "wifi", struct.pack("<Q", 1)[:8])
        page[entries_off:entries_off + 32] = e
        _mark_written(bitmap, idx); idx += 1

        val = b"S3cr3tCTF!\x00"
        data8 = struct.pack("<H", len(val)) + b"\x00" * 6
        e = _build_entry(1, 0x21, 2, 0xFF, "password", data8)
        page[entries_off + idx * 32: entries_off + idx * 32 + 32] = e
        _mark_written(bitmap, idx); idx += 1
        payload = val + b"\x00" * (32 - len(val))
        page[entries_off + idx * 32: entries_off + idx * 32 + 32] = payload[:32]
        _mark_written(bitmap, idx); idx += 1

        page[32:64] = bitmap
        result = parse_page(bytes(page), 0)

        self.assertTrue(result["valid"])
        self.assertEqual(result["namespaces"], {1: "wifi"})
        item = next(i for i in result["items"] if i["key"] == "password")
        self.assertEqual(item["namespace"], "wifi")
        self.assertEqual(item["value"], "S3cr3tCTF!")

    def test_blob_data_decoded_with_embedded_secret_scan(self):
        page, bitmap = _blank_page()
        entries_off, idx = 64, 0
        blob = b'{"mqtt_user":"admin","mqtt_pass":"BlobSecret99"}'
        data8 = struct.pack("<H", len(blob)) + b"\x00" * 6
        span = 1 + ((len(blob) + 31) // 32)
        e = _build_entry(1, 0x42, span, 0, "cfg_blob", data8)
        page[entries_off:entries_off + 32] = e
        _mark_written(bitmap, idx); idx += 1
        payload_entries = (len(blob) + 31) // 32
        padded = blob + b"\x00" * (payload_entries * 32 - len(blob))
        for i in range(payload_entries):
            page[entries_off + idx * 32: entries_off + idx * 32 + 32] = padded[i * 32:(i + 1) * 32]
            _mark_written(bitmap, idx); idx += 1
        page[32:64] = bitmap

        result = parse_page(bytes(page), 0)
        item = next(i for i in result["items"] if i["key"] == "cfg_blob")
        self.assertEqual(item["blob_kind"], "text-like")
        self.assertIn("BlobSecret99", item["value"])
        patterns_hit = {m["pattern"] for m in item["embedded_matches"]}
        self.assertIn("mqtt_credentials", patterns_hit)

    def test_truncated_page_reported_invalid_not_crashed(self):
        result = parse_page(b"\xff" * 100, 0)
        self.assertFalse(result["valid"])


class DeobfuscatorThresholdTests(unittest.TestCase):
    def test_real_xor_secret_is_still_found(self):
        random.seed(1)
        secret = b"wifi_password=SuperSecret123;mqtt_user=admin;mqtt_pass=hunter2;"
        key = 0x5A
        obf = bytes(b ^ key for b in secret)
        noise = bytes(random.randrange(256) for _ in range(100_000))
        data = noise[:40000] + obf + noise[40000:]
        hits = scan_xor(data)
        self.assertTrue(any(h["xor_key"] == key for h in hits))

    def test_pure_noise_produces_no_hits(self):
        random.seed(42)
        noise = bytes(random.randrange(256) for _ in range(300_000))
        self.assertEqual(scan_xor(noise), [])


class CorrelationStrongThresholdTests(unittest.TestCase):
    def test_single_medium_finding_is_not_strong(self):
        with tempfile.TemporaryDirectory() as d:
            eng = CorrelationEngine(DummyStorage(d), DummyLog())
            report = {"weakness_findings": [
                {"severity": "MEDIUM", "title": "t", "detail": "d", "confidence": 0.8}
            ]}
            result = eng.correlate(report, [], {})
            self.assertEqual(result["assessment"], "PARTIAL")

    def test_single_critical_finding_is_strong(self):
        with tempfile.TemporaryDirectory() as d:
            eng = CorrelationEngine(DummyStorage(d), DummyLog())
            report = {"weakness_findings": [
                {"severity": "CRITICAL", "title": "t", "detail": "d", "confidence": 0.95}
            ]}
            result = eng.correlate(report, [], {})
            self.assertEqual(result["assessment"], "STRONG")

    def test_two_independent_high_categories_is_strong(self):
        with tempfile.TemporaryDirectory() as d:
            eng = CorrelationEngine(DummyStorage(d), DummyLog())
            report = {"weakness_findings": [
                {"severity": "HIGH", "title": "t", "detail": "d", "confidence": 0.9}
            ]}
            result = eng.correlate(report, [], {"responsive_ecosystems": ["monitor"]})
            self.assertEqual(result["assessment"], "STRONG")

    def test_nvs_structured_credentials_feed_into_ranking(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "nvs_flash.json").write_text(json.dumps({
                "label": "flash",
                "structured_items": [{"namespace": "wifi", "key": "wifi_pass", "value": "hunter2"}],
                "fallback_strings": [],
            }), encoding="utf-8")
            eng = CorrelationEngine(DummyStorage(d), DummyLog())
            result = eng.correlate({}, [], {})
            self.assertTrue(any(p["category"] == "credentials" and "NVS" in p["title"] for p in result["ranked_findings"]))


class StaticAnalysisJSONRegexTests(unittest.TestCase):
    def test_json_quoted_mqtt_credentials_are_matched(self):
        findings = scan_for_secrets(b'{"mqtt_user":"admin","mqtt_pass":"BlobSecret99"}', DummyLog())
        patterns = {f["pattern"] for f in findings}
        self.assertIn("mqtt_credentials", patterns)


if __name__ == "__main__":
    unittest.main()
