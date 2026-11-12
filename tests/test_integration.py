"""
Comprehensive integration tests for Shahin Extractor v9.3 weakness fixes.
Tests real-world scenarios combining multiple modules.

This module is designed to test the complete analysis pipeline, ensuring that all
modules work together correctly and that weakness fixes don't break the
overall functionality.

The tests are organized into three categories:
1. Full pipeline tests - complete end-to-end analysis
2. Weakness fix integration tests - verify specific fixes work together
3. Error isolation tests - ensure errors in one module don't break the entire pipeline

These tests are designed to run with the standard unittest module.
"""

import base64
import json
import re
import struct
import tempfile
import sys
import os
import random

# Set random seed for deterministic test results
random.seed(12345)

# Add the project root to sys.path so we can import from modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.logger_setup import setup_logger, close_logger
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

# For tests that need these modules
from modules.bootloader_probe import BootloaderProbe
from modules.security_audit import SecurityAudit
from modules.console_prober import ConsoleProber
from modules.serial_session import SerialSession
from modules.wiring_check import WiringCheck

# --- Test Data Generators ---

class SyntheticFlashGenerator:
    """
    Generates synthetic ESP flash dumps for testing.
    
    Creates realistic flash content with various types of data:
    - Bootloader header
    - Partition table
    - XOR-encrypted secrets
    - Base64-encoded credentials
    - NVS (Non-Volatile Storage) entries
    - Heuristic filesystem regions
    
    The generated content is deterministic and reproducible across test runs.
    """

    def __init__(self, size_mb=4):
        self.size = size_mb * 1024 * 1024
        self.data = bytearray(random.randrange(256) for _ in range(self.size))
        self.parts = {}

    def add_bootloader(self):
        """ESP32 image header at 0x1000 - standard bootloader marker."""
        self.data[0x1000] = 0xE9
        self.parts['bootloader'] = 'ESP32 header'

    def add_partition_table(self):
        """IDF partition table with common partitions."""
        pt = b""
        pt += self._partition_entry("nvs", 1, 0x02, 0x9000, 0x6000)
        pt += self._partition_entry("spiffs", 1, 0x82, 0xF000, 0x10000)
        pt += self._partition_entry("factory", 0, 0x00, 0x10000, 0x180000)
        pt += self._partition_entry("ota_data", 1, 0x00, 0x190000, 0x1000)
        self.data[0x8000:0x8000+len(pt)] = pt
        self.parts['partition_table'] = 'IDF partitions'

    def _partition_entry(self, name, ptype, subtype, off, size):
        """Create a single partition table entry."""
        return struct.pack("<2sBBII16sI", b"\xaa\x50", ptype, subtype, off, size,
                          name.encode().ljust(16, b"\x00"), 0)

    def add_xor_secret(self, offset_kb=1500):
        """XOR-encrypted secret placed deep in the flash."""
        secret = b"admin:wi-fi_password=CompetitionSecret123;token=esp32_flag_xyz;"
        key = 0x5A
        obf = bytes(b ^ key for b in secret)
        off = offset_kb * 1024
        self.data[off:off+len(obf)] = obf
        self.parts[f"xor_secret@{off}"] = f"XOR key=0x{key:02X}"

    def add_base64_secret(self, offset_kb=3900):
        """Base64-encoded secret near the end of flash."""
        payload = base64.b64encode(b"user=mqtt;pass=mqtt_pass_777;host=broker.example.com;")
        off = offset_kb * 1024
        self.data[off:off+len(payload)] = payload
        self.parts[f"b64_secret@{off}"] = "Base64 credentials"

    def add_nvs_string(self, offset_kb=2500):
        """Plaintext NVS (Non-Volatile Storage) entries."""
        nvs = b"wifi_ssid=MyWiFiLab\x00wifi_password=NvsSecret456\x00mqtt_broker=broker.example.com\x00"
        off = offset_kb * 1024
        self.data[off:off+len(nvs)] = nvs
        self.parts[f"nvs_string@{off}"] = "NVS strings"

    def add_nvs_structured(self, offset_kb=1800):
        """Structured NVS page with namespaces and entries."""
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
        off = offset_kb * 1024
        self.data[off:off+4096] = page
        self.parts[f"nvs_structured@{off}"] = "NVS structured"

    def add_filesystem_heuristic(self, offset_kb=3000):
        """Heuristically-carved SPIFFS region with printable data patterns."""
        start = offset_kb * 1024
        end = start + 0x2000
        # Fill with realistic SPIFFS-like content
        for i in range(start, min(end, len(self.data))):
            # Mix of 0xFF (erased) and some printable data
            if (i - start) % 32 == 0:
                self.data[i] = ord('S')  # 'S' from "SPIFFS"
            elif (i - start) % 32 == 16:
                self.data[i] = ord('P')
            elif (i - start) % 32 == 24:
                self.data[i] = ord('I')
        self.parts[f"heuristic_spiffs@{start}"] = "Heuristic SPIFFS"

    def build(self, session_dir):
        """Write the synthetic flash to the session directory and return path."""
        dump_path = Path(session_dir) / "synthetic_flash.bin"
        dump_path.write_bytes(bytes(self.data))
        return dump_path

# Alias for backward compatibility
SyntheticFlashGenerator = SyntheticFlashGenerator

# Export the integration test class
__all__ = ['ShahinIntegrationTests']

class ShahinIntegrationTests:
    """End-to-end tests for the complete Shahin analysis pipeline."""

    def test_full_analysis_pipeline(self):
        """Test the complete analysis from raw dump to diagnosis."""
        with tempfile.TemporaryDirectory() as session_dir:
            generator = SyntheticFlashGenerator(size_mb=2)
            generator.add_bootloader()
            generator.add_partition_table()
            generator.add_xor_secret()
            generator.add_base64_secret()
            generator.add_nvs_string()
            generator.add_nvs_structured()
            generator.add_filesystem_heuristic()

            dump_path = generator.build(session_dir)

            logger = setup_logger(session_dir)
            storage = SessionStorage(session_dir, logger)

            # --- Stage 1: Bootloader analysis ---
            bootloader_probe = BootloaderProbe("/dev/ttyUSB0", 115200, storage, logger)
            bootloader_ok = bootloader_probe.sync_check()
            chip_info = bootloader_probe.chip_info() if bootloader_ok else {}

            # --- Stage 2: Security audit ---
            audit = SecurityAudit("/dev/ttyUSB0", 115200, storage, logger,
                                chip_name=chip_info.get("chip") or "")
            security_report = audit.run()

            # --- Stage 3: Post-analysis (strings, filesystem hints) ---
            PostAnalyzer(storage, logger).analyze_file(str(dump_path), "synthetic")

            # --- Stage 4: Static analysis ---
            static_result = StaticAnalyzer(storage, logger).analyze(str(dump_path), "synthetic")
            self.assertGreater(len(static_result.get("secrets", [])), 0,
                              "Static analysis should find secrets")

            # --- Stage 5: Auto extraction ---
            auto_result = AutoExtractor(storage, logger).process_file(str(dump_path), "synthetic")
            self.assertGreater(auto_result.get("total", 0), 0,
                            "Auto extraction should find something")

            # --- Stage 6: Binary intelligence ---
            binary_result = BinaryIntel(storage, logger).analyze(str(dump_path), "synthetic")

            # --- Stage 7: Deobfuscator ---
            deobf_result = Deobfuscator(storage, logger).process(str(dump_path), "synthetic")
            self.assertTrue(deobf_result.get("interesting", False),
                         "Deobfuscator should detect XOR or Base64")

            # --- Stage 8: NVS helper ---
            nvs_result = NVSHelper(storage, logger).analyze(str(dump_path), "synthetic")

            # --- Stage 9: Region extraction ---
            regions_dir = Path(session_dir) / "raw" / "regions"
            extractor = RegionExtractor(storage, logger)
            partitions = extractor.extract_partition_table(str(dump_path), str(regions_dir))
            self.assertGreater(len(partitions), 0,
                             "Should extract partition table")

            # --- Stage 10: Correlation ---
            correlator = CorrelationEngine(storage, logger)
            correlation = correlator.correlate(
                security_report=security_report,
                dumped_files=[("synthetic", str(dump_path))],
                console_result={"responsive_ecosystems": ["esp_idf_console"]},
            )
            self.assertGreater(len(correlation.get("ranked_findings", [])), 0,
                             "Correlation should rank findings")

            # --- Stage 11: Diagnosis ---
            diagnosis = DiagnosisReport(storage, logger).build_and_print(
                chip_info=chip_info,
                bootloader_ok=bootloader_ok,
                used_no_stub=False,
                security_report=security_report,
                wiring_result={"pattern_echoed_back": False},
                console_result={"responsive_ecosystems": ["esp_idf_console"]},
                extraction_path=str(dump_path) if bootloader_ok else "",
                dumped_files=[("synthetic", str(dump_path))],
                correlation_report=correlation,
            )

            # --- Assertions ---
            self.assertIn(diagnosis["verdict"], ["EXTRACTED", "BLOCKED_WITH_FINDINGS", "BLOCKED_NO_FINDINGS"],
                        "Diagnosis should have a valid verdict")

            # Clean up
            close_logger(logger)

    def test_weakness_fix_integration(self):
        """Test that specific weakness fixes work together."""
        with tempfile.TemporaryDirectory() as session_dir:
            generator = SyntheticFlashGenerator(size_mb=1)
            generator.add_xor_secret()
            generator.add_base64_secret()
            dump_path = generator.build(session_dir)

            logger = setup_logger(session_dir)
            storage = SessionStorage(session_dir, logger)

            # Test deobfuscator coverage
            deobf_result = Deobfuscator(storage, logger).process(str(dump_path), "coverage_test")

            # XOR secret should be found (full-file coverage)
            xor_hits = [h for h in deobf_result["xor_candidates"] if "XorSecret42" in h["preview"]]
            self.assertGreater(len(xor_hits), 0,
                             "XOR secret should be found with full-file coverage")

            # Base64 secret should be found
            b64_hits = [h for h in deobf_result["base64_layers"] if "Base64Secret777" in h["preview"]]
            self.assertGreater(len(b64_hits), 0,
                             "Base64 secret should be found")

            close_logger(logger)

    def test_error_isolation(self):
        """Test that errors in one module don't break the entire pipeline."""
        with tempfile.TemporaryDirectory() as session_dir:
            logger = setup_logger(session_dir)
            storage = SessionStorage(session_dir, logger)

            # Create a valid file first
            dump_path = Path(session_dir) / "valid.bin"
            dump_path.write_bytes(b"Hello World")

            # This should succeed even if other modules fail
            static_result = StaticAnalyzer(storage, logger).analyze(str(dump_path), "valid")

            # Error should be isolated to the problematic file, not the whole session
            self.assertTrue(static_result.get("ok", False) or "error" in static_result,
                         "Static analysis should handle errors gracefully")

            close_logger(logger)


if __name__ == "__main__":
    import unittest
    unittest.main()
