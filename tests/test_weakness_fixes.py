"""
Regression tests for the four weakness-report fixes (v9.3):

  2.1 [HIGH]  XOR/Base64 deobfuscation only scanned the first 250/350 KB
  2.2 [MEDIUM] Console-probe wait times were not actually respected
  2.3 [MEDIUM] Carved SPIFFS/LittleFS images were unpacked without size
  2.4 [LOW]   Raw-file names could collide and silently overwrite
"""

import os
import random
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from modules.deobfuscator import scan_xor, scan_b64, _pratio
from modules.serial_session import SerialSession
from modules.storage import SessionStorage
from modules.region_extractor import RegionExtractor


class DummyLog:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


class DummyStorage:
    def __init__(self, d):
        self.session_dir = d

    def save_analysis_result(self, label, data):
        Path(self.session_dir, label + ".json").write_text(
            __import__("json").dumps(data), encoding="utf-8"
        )

    def log_event(self, *a, **k):
        pass


# ---------------------------------------------------------------------
# 2.1 -- full-file coverage for XOR / Base64
# ---------------------------------------------------------------------
class DeobfuscatorCoverageTests(unittest.TestCase):
    SECRET = b"wifi_password=SuperSecret123;mqtt_user=admin;mqtt_pass=hunter2;"
    KEY = 0x5A

    def test_pratio_counts_printable_bytes(self):
        """Regression: an inverted printable count silently rejected every hit."""
        self.assertEqual(_pratio(b"abc"), 1.0)
        self.assertEqual(_pratio(b"\x00\x01\x02"), 0.0)
        self.assertAlmostEqual(_pratio(b"ab\x00cd"), 4 / 5)

    def test_xor_secret_beyond_the_old_250kb_cap_is_found(self):
        """The old code capped the XOR scan at 250 KB, so a secret in a
        realistic 4 MB dump was never checked."""
        random.seed(11)
        size = 1_200_000  # well past the old 250 KB cap
        data = bytearray(random.randrange(256) for _ in range(size))
        obf = bytes(b ^ self.KEY for b in self.SECRET)
        data[1_000_000:1_000_000 + len(obf)] = obf

        hits = scan_xor(bytes(data))
        self.assertTrue(
            any(h["xor_key"] == self.KEY for h in hits),
            "XOR secret past the old 250 KB cap was not detected",
        )
        hit = next(h for h in hits if h["xor_key"] == self.KEY)
        self.assertIn("SuperSecret123", hit["preview"])

    def test_base64_secret_beyond_the_old_350kb_cap_is_found(self):
        import base64
        random.seed(12)
        payload = base64.b64encode(b"wifi_password=Base64Secret777;mqtt_user=admin;")
        size = 900_000  # well past the old 350 KB cap
        data = bytearray(random.randrange(256) for _ in range(size))
        data[800_000:800_000 + len(payload)] = payload

        hits = scan_b64(bytes(data))
        self.assertTrue(
            any("Base64Secret777" in h["preview"] for h in hits),
            "Base64 secret past the old 350 KB cap was not detected",
        )

    def test_xor_scan_is_fast_enough_for_a_full_dump(self):
        """A full 4 MB scan must finish in seconds, not minutes."""
        random.seed(13)
        data = bytes(random.randrange(256) for _ in range(4 * 1024 * 1024))
        t0 = time.time()
        scan_xor(data)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 30, f"4 MB XOR scan took {elapsed:.1f}s")


# ---------------------------------------------------------------------
# 2.2 -- console-probe wait times actually respected
# ---------------------------------------------------------------------
class FakeSerial:
    """Minimal pyserial stand-in that never returns data."""

    def __init__(self, timeout=1.0):
        self.timeout = timeout
        self.is_open = True
        self._closed = False

    def read(self, size=1):
        time.sleep(min(self.timeout, 0.05))
        return b""

    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def reset_input_buffer(self):
        pass

    def close(self):
        self._closed = True


class SerialWaitTimeTests(unittest.TestCase):
    def test_read_for_respects_the_callers_wait(self):
        """The port's own 1.0 s timeout used to override the caller's
        shorter wait, so every silent probe took ~1 s instead of ~0.3 s."""
        session = SerialSession("COM1", 115200, DummyLog(), timeout=1.0)
        session.ser = FakeSerial(timeout=1.0)

        t0 = time.time()
        session.read_for(0.3)
        elapsed = time.time() - t0

        self.assertLess(elapsed, 0.75, f"read_for(0.3) took {elapsed:.2f}s")
        self.assertEqual(session.ser.timeout, 1.0, "port timeout was not restored")

    def test_read_for_restores_timeout_even_on_error(self):
        session = SerialSession("COM1", 115200, DummyLog(), timeout=1.0)
        session.ser = FakeSerial(timeout=1.0)

        def boom(*a, **k):
            raise OSError("link lost")

        session.ser.read = boom
        with self.assertRaises(OSError):
            session.read_for(0.2)
        self.assertEqual(session.ser.timeout, 1.0)


# ---------------------------------------------------------------------
# 2.3 -- filesystem unpack receives the real size
# ---------------------------------------------------------------------
class FilesystemUnpackParameterTests(unittest.TestCase):
    def test_partition_size_is_threaded_into_the_unpack_command(self):
        ex = RegionExtractor(DummyStorage(tempfile.gettempdir()), DummyLog())

        with tempfile.TemporaryDirectory() as d:
            image = Path(d, "spiffs.bin")
            image.write_bytes(b"\x00" * 4096)

            with mock.patch("modules.region_extractor.shutil.which", return_value="/usr/bin/mkspiffs"), \
                 mock.patch("modules.region_extractor.subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                ex.unpack_filesystem_image(str(image), "spiffs", d, partition_size=0x10000)

            cmd = run.call_args[0][0]
            self.assertIn("-s", cmd, "mkspiffs was invoked without an explicit size")
            self.assertIn("65536", cmd, "the real partition size was not passed")
            # -u takes two arguments, so it must come last (before the
            # image) or argparse swallows the option.
            self.assertLess(cmd.index("-u"), len(cmd) - 1)

    def test_unpack_falls_back_when_the_sized_attempt_is_rejected(self):
        ex = RegionExtractor(DummyStorage(tempfile.gettempdir()), DummyLog())

        with tempfile.TemporaryDirectory() as d:
            image = Path(d, "spiffs.bin")
            image.write_bytes(b"\x00" * 4096)

            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if "-s" in cmd:
                    return mock.Mock(returncode=1, stdout="", stderr="bad size")
                return mock.Mock(returncode=0, stdout="ok", stderr="")

            with mock.patch("modules.region_extractor.shutil.which", return_value="/usr/bin/mkspiffs"), \
                 mock.patch("modules.region_extractor.subprocess.run", side_effect=fake_run):
                result = ex.unpack_filesystem_image(str(image), "spiffs", d, partition_size=0x10000)

            self.assertEqual(len(calls), 2, "expected a fallback attempt after the sized one failed")
            self.assertNotIn("-s", calls[1])
            self.assertTrue(result["available"])


# ---------------------------------------------------------------------
# 2.4 -- raw filenames never collide
# ---------------------------------------------------------------------
class RawFilenameCollisionTests(unittest.TestCase):
    def test_same_label_twice_in_the_same_second_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            storage = SessionStorage(d, DummyLog())
            p1 = storage.save_raw("bootloader_sync", b"first-attempt")
            p2 = storage.save_raw("bootloader_sync", b"second-attempt")

            self.assertNotEqual(p1, p2, "two saves of the same label collided")
            self.assertEqual(Path(p1).read_bytes(), b"first-attempt")
            self.assertEqual(Path(p2).read_bytes(), b"second-attempt")

    def test_many_saves_in_a_burst_all_survive(self):
        with tempfile.TemporaryDirectory() as d:
            storage = SessionStorage(d, DummyLog())
            paths = [storage.save_raw("console_probe", f"payload-{i}".encode())
                     for i in range(50)]
            self.assertEqual(len(set(paths)), 50, "burst saves collided")
            for i, p in enumerate(paths):
                self.assertEqual(Path(p).read_bytes(), f"payload-{i}".encode())


if __name__ == "__main__":
    unittest.main()
