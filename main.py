#!/usr/bin/env python3
"""
Shahin Extractor -- software-weakness discovery and content extraction tool
for ESP-family boards over UART, for Team Shahin (hardware CTF prep).

Competition constraint: only a multimeter + USB-TTL module + jumper wires
are allowed. This tool does not try to break encryption; it looks for
incomplete security configuration, leaked logs, and leftover debug consoles.

Scope, by design: this tool extracts content and diagnoses software
weaknesses. It does NOT search for or highlight CTF flags -- that's a
deliberate decision, done by hand afterwards for accuracy. What it reports
at the end is always one of: content extracted (here's the file), a
specific pinpointed weakness (here's the mechanism), or neither found.

Core design principle: any data pulled from the board must never be lost,
even if the rest of the program crashes.

Usage:
    python3 main.py --port /dev/ttyUSB0 --baud 115200
    python3 main.py --port /dev/ttyUSB0 --skip-bootloader --listen-seconds 10
"""

import argparse
import sys
from pathlib import Path

from modules.logger_setup import setup_logger, new_session_dir, close_logger
from modules.storage import SessionStorage
from modules.serial_session import SerialSession
from modules.bootloader_probe import BootloaderProbe
from modules.security_audit import SecurityAudit
from modules.passive_listener import PassiveListener
from modules.console_prober import ConsoleProber
from modules.post_analysis import PostAnalyzer
from modules.static_analysis import StaticAnalyzer
from modules.auto_extractor import AutoExtractor
from modules.correlation_engine import CorrelationEngine
from modules.binary_intel import BinaryIntel
from modules.deobfuscator import Deobfuscator
from modules.nvs_helper import NVSHelper
from modules.baud_scanner import BaudScanner
from modules.wiring_check import WiringCheck
from modules.region_extractor import RegionExtractor
from modules.diagnosis_report import DiagnosisReport
from modules.ctf_triage import triage_file

VERSION = (Path(__file__).resolve().parent / "VERSION").read_text().strip()


def parse_args():
    p = argparse.ArgumentParser(description="Shahin Extractor")
    p.add_argument("--version", action="version", version=f"Shahin Extractor {VERSION}")
    p.add_argument("--port", required=True, help="e.g. /dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--bootloader-baud", type=int, default=115200)
    p.add_argument(
        "--flash-size", default=None,
        help="flash size for dump, e.g. 0x400000 for 4MB. "
             "If omitted, the size esptool auto-detects from the chip is used.",
    )
    p.add_argument("--listen-seconds", type=float, default=5.0)
    p.add_argument("--skip-bootloader", action="store_true", help="skip bootloader attempt")
    p.add_argument("--skip-console", action="store_true", help="skip console probing")
    p.add_argument("--skip-dump", action="store_true", help="recon only, no full flash dump")
    p.add_argument("--skip-static-analysis", action="store_true", help="skip binwalk/secret scan")
    p.add_argument(
        "--carve-filesystems", action="store_true",
        help="also carve out heuristically-detected SPIFFS/LittleFS regions as "
             "separate files. Off by default: the primary deliverable is one "
             "consolidated dump file unless a REAL partition table proves "
             "there are genuinely separate images.",
    )
    p.add_argument(
        "--aggressive", action="store_true",
        help="also try console commands that could reboot/reset/erase the board "
             "(reboot, reset, erase, format, ...). OFF by default -- only use this "
             "if you can afford the board resetting or losing state.",
    )
    p.add_argument(
        "--no-baud-fallback", action="store_true",
        help="don't auto-run a baud scan as a last resort when bootloader, "
             "passive listen, and console probe all found nothing",
    )
    p.add_argument(
        "--export", choices=["json", "csv"], default="json", help="history export format"
    )
    p.add_argument(
        "--no-prompt", action="store_true",
        help="skip the interactive 'press Enter once board is in bootloader mode' pause",
    )
    p.add_argument(
        "--ctf-mode", action="store_true",
        help="enable optional CTF candidate triage (pattern candidates only; disabled by default)",
    )
    p.add_argument(
        "--scan-baud", action="store_true",
        help="only scan common baud rates for any readable traffic, then exit",
    )
    return p.parse_args()


def main():
    args = parse_args()
    session_dir = new_session_dir()
    logger = setup_logger(session_dir)
    storage = SessionStorage(session_dir, logger)

    logger.info("=" * 60)
    logger.info(f"Shahin Extractor {VERSION} -- starting new session")
    logger.info(f"session folder: {session_dir}")
    logger.info("=" * 60)

    dumped_files = []       # (label, path) -- everything that gets post-analyzed
    chip_info = {}
    security_report = {}
    wiring_result = {}
    console_result = {}
    extraction_path = ""    # the single primary deliverable, if any

    if args.scan_baud:
        scanner = BaudScanner(args.port, storage, logger)
        scanner.scan()
        logger.info("baud scan complete; re-run without --scan-baud, using --baud <value>.")
        close_logger(logger)
        return

    # ----------------------------------------------------------------
    # Stage 1: try the ROM bootloader
    # ----------------------------------------------------------------
    bootloader_ok = False
    probe = None
    if not args.skip_bootloader:
        if not args.no_prompt:
            logger.info(
                "Since only GND/TXD/RXD are wired (no DTR/RTS), esptool cannot "
                "auto-reset the board into bootloader mode."
            )
            logger.info(
                "If this board needs manual entry: hold FLASH/BOOT/GPIO0, tap RESET, "
                "then release FLASH -- do it now."
            )
            input("Press Enter once the board is in bootloader mode (or just Enter to try as-is): ")
        probe = BootloaderProbe(args.port, args.bootloader_baud, storage, logger)
        bootloader_ok = probe.sync_check()

        if bootloader_ok:
            logger.info(
                "[OK] bootloader responded."
                + (" (via --no-stub fallback)" if probe.no_stub else "")
            )
            chip_info = probe.chip_info()
            logger.info(f"chip: {chip_info.get('chip')} | Chip ID: {chip_info.get('chip_id_hex')}")

            sec_info = probe.get_security_info()

            flash_info = probe.flash_id()
            detected_size = flash_info.get("detected_size_bytes")

            flash_size_arg = args.flash_size
            if flash_size_arg is None:
                if detected_size:
                    flash_size_arg = hex(detected_size)
                    logger.info(f"using auto-detected flash size: {flash_size_arg}")
                else:
                    flash_size_arg = "0x400000"
                    logger.info(
                        f"could not auto-detect flash size; falling back to {flash_size_arg}"
                    )

            audit = SecurityAudit(
                args.port, args.bootloader_baud, storage, logger,
                chip_name=chip_info.get("chip") or "",
            )
            extra_sources = [("get_security_info", sec_info["raw"])] if sec_info.get("ok") else []
            security_report = audit.run(extra_raw_sources=extra_sources)

            if not args.skip_dump:
                dump_path = f"{session_dir}/raw/full_flash_dump.bin"
                result_path = probe.dump_full_flash(dump_path, size=flash_size_arg)
                if result_path:
                    extraction_path = result_path
                    dumped_files.append(("full_flash_dump", result_path))

                    # Structured extraction: primary deliverable stays ONE
                    # file. We only split into more files when there's real
                    # evidence of genuinely separate images (a valid IDF
                    # partition table). Heuristic filesystem carving is
                    # opt-in, since it's a guess, not a proof.
                    regions_dir = f"{session_dir}/raw/regions"
                    extractor = RegionExtractor(storage, logger)
                    partitions = extractor.extract_partition_table(result_path, regions_dir)
                    for p in partitions:
                        if p.get("extracted_path"):
                            dumped_files.append((f"partition_{p['name']}", p["extracted_path"]))
                    if args.carve_filesystems:
                        fs_regions = extractor.extract_filesystem_regions(result_path, regions_dir, partitions=partitions)
                        for r in fs_regions:
                            if not r.get("extracted_path"):
                                continue
                            dumped_files.append((r["type"], r["extracted_path"]))
                            # try to turn the raw candidate region into
                            # actual individual files, not just a blob.
                            # The region size is threaded through so the
                            # unpacker gets the real filesystem geometry
                            # instead of guessing (see weakness report 2.3).
                            unpacked = extractor.unpack_filesystem_image(
                                r["extracted_path"], r["type"], regions_dir,
                                partition_size=r.get("size"),
                            )
                            for f in unpacked.get("files", []):
                                dumped_files.append((f"unpacked_{r['type']}", f))
        else:
            logger.info(
                "[NO] bootloader did not respond (either normal firmware is running, "
                "or download mode is locked)."
            )

    # ----------------------------------------------------------------
    # Stage 2: if bootloader didn't respond (or was skipped), listen
    # passively, then probe for a debug console
    # ----------------------------------------------------------------
    boot_log = b""
    with SerialSession(args.port, args.baud, logger) as sess:
        if not sess.ser:
            logger.error("serial connection failed; stopping.")
            close_logger(logger)
            sys.exit(1)

        wiring_result = WiringCheck(sess, storage, logger).run()

        if not bootloader_ok:
            listener = PassiveListener(sess, storage, logger)
            boot_log = listener.try_reset_and_listen(args.listen_seconds)

        if not args.skip_console:
            prober = ConsoleProber(sess, storage, logger)
            console_result = prober.probe(aggressive=args.aggressive)
            if console_result.get("raw_path"):
                dumped_files.append(("console_probe", console_result["raw_path"]))

            if console_result.get("any_response"):
                deep = prober.deep_dive(
                    console_result["responsive_ecosystems"], console_result.get("baseline", b"")
                )
                if deep.get("raw_path"):
                    dumped_files.append(("console_deep_dive", deep["raw_path"]))

                # round 3: if any 'help'-shaped command got a real,
                # non-noise response, parse it for command names and try
                # those directly -- this is the single highest-value thing
                # a human operator would do by hand with a found console
                help_text = ""
                for key, entry in console_result.get("results", {}).items():
                    if key.split(":", 1)[-1].lower() in ("help", "?", "menu") and not entry["looks_like_idle_noise"]:
                        if entry["response_len"] > len(help_text):
                            help_text = entry["response_text"]
                if help_text:
                    dynamic = prober.dynamic_followup(
                        help_text, console_result.get("baseline", b""), aggressive=args.aggressive
                    )
                    if dynamic.get("raw_path"):
                        dumped_files.append(("console_dynamic_followup", dynamic["raw_path"]))

        # --------------------------------------------------------
        # Last resort: if NOTHING worked yet, try a baud scan before
        # giving up. Wrong baud is one of the most common reasons
        # everything looks silent.
        # --------------------------------------------------------
        nothing_found_yet = (
            not bootloader_ok and not boot_log and not console_result.get("any_response")
        )
        if nothing_found_yet and not args.no_baud_fallback:
            logger.info(
                "[fallback] bootloader, passive listen, and console probe all found "
                "nothing at the configured baud -- trying a baud scan before giving up."
            )
            scan = BaudScanner(args.port, storage, logger).scan(
                seconds_per_baud=1.5, prompt_reset=False
            )
            if scan.get("best_baud") and scan["best_baud"] != args.baud:
                logger.info(
                    f"[fallback] found a more promising baud ({scan['best_baud']}); "
                    f"re-run with --baud {scan['best_baud']} --skip-bootloader for a "
                    f"focused retry at that rate."
                )

    if boot_log:
        boot_log_path = storage.save_raw("boot_log_combined", boot_log)
        dumped_files.append(("boot_log", boot_log_path))

    # ----------------------------------------------------------------
    # Stage 3: forensic summary + deeper static analysis on everything
    # collected (strings/signatures always; binwalk + secret scan unless
    # disabled)
    # ----------------------------------------------------------------
    analyzer = PostAnalyzer(storage, logger)
    for label, path in dumped_files:
        analyzer.analyze_file(path, label)

    if not args.skip_static_analysis:
        static_analyzer = StaticAnalyzer(storage, logger)
        auto_extractor = AutoExtractor(storage, logger)
        binary_intel = BinaryIntel(storage, logger)
        for label, path in dumped_files:
            static_analyzer.analyze(path, label)
            auto_extractor.process_file(path, label)
            binary_intel.analyze(path, label)
            Deobfuscator(storage, logger).process(path, label)
            NVSHelper(storage, logger).analyze(path, label)
            if args.ctf_mode:
                triage_file(path, label, storage, logger)

    # ----------------------------------------------------------------
    # Correlation layer: turn raw findings into prioritized attack path
    # ----------------------------------------------------------------
    correlator = CorrelationEngine(storage, logger)
    correlation = correlator.correlate(
        security_report=security_report,
        dumped_files=dumped_files,
        console_result=console_result,
    )

    # ----------------------------------------------------------------
    # Final diagnosis: always exactly one clear verdict
    # ----------------------------------------------------------------
    diagnosis = DiagnosisReport(storage, logger).build_and_print(
        chip_info=chip_info,
        bootloader_ok=bootloader_ok,
        used_no_stub=(probe.no_stub if probe else False),
        security_report=security_report,
        wiring_result=wiring_result,
        console_result=console_result,
        extraction_path=extraction_path,
        dumped_files=dumped_files,
        correlation_report=correlation,
    )

    export_path = storage.export_history(args.export)

    logger.info("session files:")
    for label, path in dumped_files:
        logger.info(f"  - {label}: {path}")
    logger.info(f"history export: {export_path}")
    logger.info(f"everything is in this folder, nothing is deleted: {session_dir}")

    # Release the log file handle. On Windows an open FileHandler locks
    # session.log, which would make the session folder impossible to
    # delete, zip, or hand over while the process is still running.
    close_logger(logger)


if __name__ == "__main__":
    main()
