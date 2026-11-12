import json
import tempfile
import unittest
from pathlib import Path

from modules.security_audit import parse_efuse_summary, _normalize_chip_family, correlate_known_weaknesses
from modules.region_extractor import RegionExtractor
from modules.ctf_triage import triage_file
from modules.auto_extractor import extract_from_text_blob
from modules.diagnosis_report import DiagnosisReport


class DummyLog:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass

class DummyStorage:
    def __init__(self, d): self.session_dir = d
    def save_analysis_result(self, label, data):
        Path(self.session_dir, label + '.json').write_text(json.dumps(data), encoding='utf-8')
    def log_event(self, *a, **k): pass
    def save_text(self, *a, **k): return ''

class CoreTests(unittest.TestCase):
    def test_efuse_parser_and_protection(self):
        raw = 'BLOCK_KEY0 (BLOCK4)\n= 00 00 00 -/W (0x00)\nSPI_BOOT_CRYPT_CNT (BLOCK0) x = Enable R/W (0b001)'
        fields = parse_efuse_summary(raw)
        self.assertFalse(fields['BLOCK_KEY0']['readable'])
        self.assertTrue(fields['SPI_BOOT_CRYPT_CNT']['value'].lower() == 'enable')

    def test_family_normalization(self):
        self.assertEqual(_normalize_chip_family('ESP32-C3'), 'ESP32-C3')
        self.assertEqual(_normalize_chip_family('ESP32-S3'), 'ESP32-S3')

    def test_partition_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            dump = Path(d, 'flash.bin')
            data = bytearray(0x20000)
            import struct
            entry = struct.pack('<2sBBII16sI', b'\xaa\x50', 1, 2, 0x10000, 0x1000, b'nvs\\0', 0)
            data[0x8000:0x8020] = entry
            dump.write_bytes(data)
            ex = RegionExtractor(DummyStorage(d), DummyLog())
            parts = ex.extract_partition_table(str(dump), d)
            self.assertEqual(parts[0]['subtype'], 'nvs')
            self.assertTrue(Path(parts[0]['extracted_path']).exists())


    def test_structured_findings_do_not_crash_diagnosis(self):
        finding = {
            "severity": "HIGH",
            "title": "Secure Boot is disabled",
            "detail": "Firmware authenticity is not enforced.",
            "evidence": ["SECURE_BOOT_EN = False"],
            "confidence": 0.98,
        }
        verdict, headline = DiagnosisReport._determine_verdict(
            bootloader_ok=True,
            security_report={"weakness_findings": [finding]},
            extraction_path="",
        )
        self.assertEqual(verdict, "BLOCKED_WITH_FINDINGS")
        self.assertIn("1 specific weakness", headline)
        self.assertTrue(DiagnosisReport._is_real_finding(finding))
        self.assertIn("[HIGH] Secure Boot is disabled", DiagnosisReport._finding_text(finding))

    def test_nvs_key_extractor_rejects_plain_prose(self):
        prose = b"apple happy mapping are ordinary words and should not be NVS keys"
        result = extract_from_text_blob(prose)
        self.assertEqual(result["nvs_like_keys"], [])

        structured = b"wifi_ssid\x00wifi_password\x00mqtt_user=admin\x00"
        result = extract_from_text_blob(structured)
        keys = {item["key"].lower() for item in result["nvs_like_keys"]}
        self.assertIn("wifi_ssid", keys)
        self.assertIn("wifi_password", keys)
        self.assertIn("mqtt_user", keys)

if __name__ == '__main__':
    unittest.main()
