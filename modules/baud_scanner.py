"""
baud_scanner.py

When the board is custom firmware (not a standard ESP-IDF/Arduino image),
the ROM bootloader is often not even a valid target -- entering it requires
pulling GPIO0 low at reset, which isn't possible with GND/TXD/RXD-only
wiring unless the board exposes its own BOOT button. In that case, the real
blocker is often simply: wrong baud rate.

This module briefly listens on each common baud rate and reports which ones
produced anything beyond silence, so you don't have to guess.
"""

import string

from .serial_session import SerialSession

COMMON_BAUD_RATES = [9600, 19200, 38400, 57600, 74880, 115200, 230400, 460800]

PRINTABLE_RATIO_THRESHOLD = 0.6  # heuristic: "looks like text" vs "looks like noise"


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if chr(b) in string.printable)
    return printable / len(data)


class BaudScanner:
    def __init__(self, port: str, storage, logger):
        self.port = port
        self.storage = storage
        self.logger = logger

    def scan(self, seconds_per_baud: float = 2.0, prompt_reset: bool = True) -> dict:
        self.logger.info(
            f"[baud scan] trying {len(COMMON_BAUD_RATES)} common baud rates, "
            f"{seconds_per_baud}s each ..."
        )
        if prompt_reset:
            self.logger.info(
                "Boot-time data is only emitted for a brief moment right after "
                "RESET, so you'll be asked to press RESET again before EACH "
                "rate below -- a single reset at the start would only give the "
                "first rate tried a real chance to catch it."
            )

        results = {}
        best_baud = None
        best_ratio = 0.0

        for baud in COMMON_BAUD_RATES:
            if prompt_reset:
                input(
                    f"  -> about to try {baud} baud. Press RESET on the board now, "
                    f"then press Enter here: "
                )
            with SerialSession(self.port, baud, self.logger, timeout=0.3) as sess:
                if not sess.ser:
                    results[baud] = {"bytes": 0, "printable_ratio": 0.0, "sample": ""}
                    continue
                data = sess.read_for(seconds_per_baud)

            ratio = _printable_ratio(data)
            results[baud] = {
                "bytes": len(data),
                "printable_ratio": round(ratio, 2),
                "sample": data[:80].decode("ascii", errors="replace"),
            }

            tag = ""
            if len(data) > 0 and ratio >= PRINTABLE_RATIO_THRESHOLD:
                tag = "  <-- looks like readable text!"
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_baud = baud
            elif len(data) > 0:
                tag = "  (got bytes, but looks like noise/garbage -- still worth checking)"

            self.logger.info(
                f"  {baud:>7} baud -> {len(data)} bytes, "
                f"printable={ratio:.0%}{tag}"
            )

        self.storage.save_analysis_result("baud_scan", results)
        if best_baud:
            self.logger.info(
                f"[baud scan] best candidate: {best_baud} baud "
                f"({best_ratio:.0%} printable) -- try that with --baud {best_baud}"
            )
        else:
            self.logger.info(
                "[baud scan] no baud rate produced clearly readable text. "
                "If any rate showed nonzero bytes with garbage, the real baud might be close "
                "to it (try nearby nonstandard rates), or the board truly emits nothing "
                "without manual interaction (try pressing buttons/RESET on the board during "
                "a longer passive listen)."
            )
        return {"results": results, "best_baud": best_baud}
