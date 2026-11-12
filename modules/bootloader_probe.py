"""
bootloader_probe.py

Interaction layer with the ESP chip ROM bootloader. Instead of hand-rolling
the sync protocol (which differs between ESP8266 / ESP32 / ESP32-S/C
generations), we use esptool itself as a compatibility layer, since it's
the official Espressif tool and always has the most up-to-date multi-chip
support.

Every raw esptool output (success, failure, or timeout) is saved before any
interpretation happens.

Important: long-running commands (full flash dump) stream their output to
the console live, line by line, as esptool produces it. Without this, a
multi-minute dump looks "stuck" even when it's working normally -- esptool
prints a running percentage, and the user should see it update in real time
instead of staring at a blank terminal until the process finishes.
"""

import subprocess
import time


# Rough, deliberately pessimistic throughput assumption for computing a safe
# timeout on long transfers (read_flash). Real esptool throughput at 115200
# baud is roughly 10-14 KB/s; we assume less to leave headroom for retries,
# slow USB-TTL adapters, etc.
ASSUMED_MIN_BYTES_PER_SEC = 6000
MIN_TRANSFER_TIMEOUT = 120  # floor, even for small dumps
TRANSFER_TIMEOUT_MARGIN = 60  # extra seconds of slack on top of the estimate

# A sync attempt is retried this many times before being treated as a real
# "no response." A single transient glitch on a freshly-jumpered line
# (a bad moment for a loose jumper, USB-TTL hiccup, etc.) is common and
# otherwise indistinguishable from a genuinely unreachable bootloader --
# on the one board you get in a competition, that false negative is costly.
SYNC_RETRY_ATTEMPTS = 3
SYNC_RETRY_DELAY = 1.5


def estimate_transfer_timeout(num_bytes: int) -> int:
    return max(MIN_TRANSFER_TIMEOUT, int(num_bytes / ASSUMED_MIN_BYTES_PER_SEC) + TRANSFER_TIMEOUT_MARGIN)


class BootloaderProbe:
    def __init__(self, port: str, baud: int, storage, logger):
        self.port = port
        self.baud = baud
        self.storage = storage
        self.logger = logger
        # set True once a --no-stub fallback sync succeeds, so every later
        # call in this session also uses --no-stub (mixing modes mid-session
        # doesn't work: once we know the stub path is blocked, stay in the
        # mode that's actually reachable)
        self.no_stub = False

    def _run_esptool(self, args: list, label: str, timeout: int = 30, stream: bool = False):
        """
        Runs esptool as a subprocess.

        stream=False (default): waits for completion, then saves + returns
        the full output. Fine for short commands (chip_id, flash_id).

        stream=True: prints each line of esptool's output to the console as
        it arrives (so progress percentages show up live), while still
        collecting everything for storage. Use this for anything that can
        take more than a few seconds (read_flash).

        Always saves the raw output (success, timeout, or error) before any
        interpretation happens. Returns (returncode, stdout_text).
        """
        full_args = list(args)
        if self.no_stub and "--no-stub" not in full_args:
            full_args = ["--no-stub"] + full_args
        cmd = ["esptool", "--port", self.port, "--baud", str(self.baud)] + full_args
        self.logger.info(f"[bootloader] running: {' '.join(cmd)}")

        if not stream:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
                combined = (result.stdout or "") + "\n--STDERR--\n" + (result.stderr or "")
                self.storage.save_text(label, combined)
                return result.returncode, result.stdout or ""
            except FileNotFoundError:
                self.logger.error("'esptool' command not found. Install with 'pip install esptool'.")
                return -1, ""
            except subprocess.TimeoutExpired as e:
                partial = (e.stdout or "") if isinstance(e.stdout, str) else ""
                self.storage.save_text(label + "_timeout", partial)
                self.logger.warning(f"[bootloader] {label} timed out (no bootloader response).")
                return -2, partial

        # --- streaming path ---
        lines = []
        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            self.logger.error("'esptool' command not found. Install with 'pip install esptool'.")
            return -1, ""

        try:
            while True:
                if time.time() - start > timeout:
                    proc.kill()
                    self.logger.warning(
                        f"[bootloader] {label} exceeded {timeout}s and was killed."
                    )
                    break
                line = proc.stdout.readline()
                if line:
                    lines.append(line)
                    self.logger.info(f"  [esptool] {line.rstrip()}")
                elif proc.poll() is not None:
                    break
        finally:
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        combined = "".join(lines)
        self.storage.save_text(label, combined)
        rc = proc.returncode if proc.returncode is not None else -2
        return rc, combined

    def _sync_with_retries(self, args: list, label: str) -> tuple:
        """
        Runs one sync attempt up to SYNC_RETRY_ATTEMPTS times, stopping at
        the first success. A short delay separates attempts so a transient
        line glitch has a moment to clear. Every attempt's raw output is
        still saved (via _run_esptool), so a retry sequence is fully
        visible in the session log even when it eventually succeeds.
        """
        rc, out = -2, ""
        for attempt in range(1, SYNC_RETRY_ATTEMPTS + 1):
            rc, out = self._run_esptool(args, label, timeout=15)
            if rc == 0:
                if attempt > 1:
                    self.logger.info(
                        f"[bootloader] {label} succeeded on retry {attempt}/"
                        f"{SYNC_RETRY_ATTEMPTS} (treat earlier failures as line "
                        f"noise, not evidence the bootloader is unreachable)."
                    )
                return rc, out
            if attempt < SYNC_RETRY_ATTEMPTS:
                self.logger.info(
                    f"[bootloader] {label} attempt {attempt}/{SYNC_RETRY_ATTEMPTS} "
                    f"failed; retrying in {SYNC_RETRY_DELAY}s ..."
                )
                time.sleep(SYNC_RETRY_DELAY)
        return rc, out

    def sync_check(self) -> bool:
        """
        Does the ROM bootloader respond at all on this wiring? Tries the
        normal (stub-loader) sync first; if that fails, falls back to a
        --no-stub sync attempt. Each of the two is itself retried a few
        times before being treated as a real "no response" -- see
        _sync_with_retries.

        Why --no-stub matters as an actual weakness test, not just a retry:
        the stub loader is a small program esptool uploads and runs in RAM
        to speed up transfers. Some restricted configurations (e.g. certain
        Secure Download Mode states) are intended to block the full stub
        command set while still leaving the raw ROM bootloader's limited
        command set reachable. If --no-stub succeeds where the normal
        attempt failed, that is itself a finding: restricted-but-not-fully-
        locked-down UART download access.
        """
        rc, out = self._sync_with_retries(["chip_id"], "bootloader_sync")
        ok = rc == 0
        if ok:
            self.storage.log_event("bootloader_sync", "OK", out[:300])
            return True

        self.logger.info(
            "[bootloader] normal sync failed after retries; trying --no-stub "
            "fallback (tests whether the raw ROM loader is reachable even if "
            "the stub upload path is blocked) ..."
        )
        rc2, out2 = self._sync_with_retries(
            ["--no-stub", "chip_id"], "bootloader_sync_nostub"
        )
        ok2 = rc2 == 0
        if ok2:
            self.no_stub = True
            self.logger.warning(
                "[bootloader] FINDING: --no-stub sync succeeded even though the "
                "normal (stub) sync failed. The raw ROM bootloader is reachable; "
                "this may allow restricted read access even under a configuration "
                "meant to block the full command set. Continuing this session in "
                "--no-stub mode."
            )
            self.storage.log_event("bootloader_sync_nostub", "OK", out2[:300])
        else:
            self.storage.log_event("bootloader_sync", "NO_RESPONSE", (out + out2)[:300])
        return ok2

    def chip_info(self) -> dict:
        rc, out = self._run_esptool(["chip_id"], "chip_id")
        info = {
            "raw": out, "chip": None, "chip_id_hex": None, "mac": None,
            "crystal_freq": None, "features": None,
        }
        for line in out.splitlines():
            if "Chip is" in line:
                info["chip"] = line.split("Chip is", 1)[1].strip()
            if "Chip ID:" in line:
                info["chip_id_hex"] = line.split("Chip ID:", 1)[1].strip()
            if line.strip().startswith("MAC:"):
                info["mac"] = line.split("MAC:", 1)[1].strip()
            if "Crystal is" in line:
                info["crystal_freq"] = line.split("Crystal is", 1)[1].strip()
            if line.strip().startswith("Features:"):
                info["features"] = line.split("Features:", 1)[1].strip()
        self.storage.save_analysis_result("chip_info", info)
        self.storage.log_event("chip_info", "OK" if rc == 0 else "FAIL", str(info))
        return info

    def get_security_info(self) -> dict:
        """
        Runs esptool's official `get_security_info` command. Per Espressif's
        own serial protocol documentation, this command is explicitly
        supported while the chip is in Secure Download Mode, unlike most
        other commands (including, often, espefuse summary). That makes it
        the most reliable security-state source precisely in the case we
        care about most: when normal access is restricted.
        """
        rc, out = self._run_esptool(["get_security_info"], "get_security_info", timeout=15)
        ok = rc == 0
        self.storage.save_analysis_result("get_security_info", {"raw": out, "ok": ok})
        self.storage.log_event("get_security_info", "OK" if ok else "FAIL", out[:300])
        return {"raw": out, "ok": ok}

    def flash_id(self) -> dict:
        rc, out = self._run_esptool(["flash_id"], "flash_id")
        detected_size_bytes = self._parse_flash_size(out)
        info = {
            "raw": out, "ok": rc == 0, "detected_size_bytes": detected_size_bytes,
            "manufacturer": None, "device": None,
        }
        for line in out.splitlines():
            if line.strip().startswith("Manufacturer:"):
                info["manufacturer"] = line.split(":", 1)[1].strip()
            if line.strip().startswith("Device:"):
                info["device"] = line.split(":", 1)[1].strip()
        self.storage.save_analysis_result("flash_id", info)
        self.storage.log_event("flash_id", "OK" if rc == 0 else "FAIL", str(info)[:300])
        return info

    @staticmethod
    def _parse_flash_size(flash_id_output: str):
        """
        esptool's flash_id output includes a line like:
        'Detected flash size: 4MB'
        Parses that into bytes, if present.
        """
        for line in flash_id_output.splitlines():
            if "Detected flash size" in line:
                token = line.split(":", 1)[1].strip().upper()
                try:
                    if token.endswith("MB"):
                        return int(float(token[:-2]) * 1024 * 1024)
                    if token.endswith("KB"):
                        return int(float(token[:-2]) * 1024)
                except ValueError:
                    return None
        return None

    def dump_full_flash(self, out_path: str, size: str = "0x400000") -> str:
        """
        Dumps the whole flash, streaming esptool's own progress output live
        so a multi-minute transfer doesn't look stuck. The timeout is
        computed from the requested size instead of a fixed short value, so
        a legitimate large dump isn't killed before it can finish.

        If Flash Encryption is enabled on chips that support it, esptool
        reads back the same raw encrypted bytes (which by itself isn't
        usable without the AES key) -- that's expected hardware behavior,
        not a tool bug.
        """
        try:
            num_bytes = int(size, 0)
        except ValueError:
            num_bytes = 4 * 1024 * 1024  # fallback assumption: 4MB

        timeout = estimate_transfer_timeout(num_bytes)
        self.logger.info(
            f"[bootloader] dumping {size} ({num_bytes} bytes) -- "
            f"this can take several minutes at baud={self.baud}, timeout set to {timeout}s"
        )

        rc, out = self._run_esptool(
            ["read_flash", "0x0", size, out_path], "flash_dump_log",
            timeout=timeout, stream=True,
        )
        ok = rc == 0
        self.storage.log_event(
            "flash_dump", "OK" if ok else "FAIL", out[-300:], file_path=out_path
        )
        if ok:
            self.logger.info(f"[dump complete] flash saved to {out_path}")
        else:
            self.logger.warning("[dump failed or incomplete] see raw log for details.")
        return out_path if ok else ""
