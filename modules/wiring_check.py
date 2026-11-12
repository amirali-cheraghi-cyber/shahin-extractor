"""
wiring_check.py

A large fraction of "no response from the board" results are not a software
weakness (or lack of one) at all -- they're a wiring problem: TXD/RXD
swapped, a bad jumper, or a converter set to the wrong logic level. Before
reporting "no weakness found," it's worth ruling that out, because a false
negative here wastes the rest of the session.

This performs a simple, safe diagnostic: it sends a distinctive byte pattern
and checks what comes back on the same line. It cannot fully prove wiring is
correct (that depends on the target firmware actually echoing/reacting), but
it can catch the single most common mistake: a receive-only line, or a
converter whose TX is internally looped to its own RX (which would make
every probe falsely look like "the board responded" with our own bytes).
"""


PROBE_PATTERN = b"\x55\xaa\x55\xaa"  # distinctive, unlikely to appear by chance


class WiringCheck:
    def __init__(self, session, storage, logger):
        self.session = session
        self.storage = storage
        self.logger = logger

    def run(self) -> dict:
        self.logger.info("[wiring] sanity-checking the serial link ...")
        echoed = self.session.send_and_read(PROBE_PATTERN, wait=0.3)

        result = {"pattern_sent": PROBE_PATTERN.hex(), "pattern_echoed_back": False}

        if echoed == PROBE_PATTERN:
            result["pattern_echoed_back"] = True
            self.logger.warning(
                "[wiring] WARNING: the exact bytes we sent were echoed back "
                "immediately. This usually means TX is looped back to RX "
                "(converter self-loopback, or TXD/RXD miswired to each other) "
                "rather than reaching the board at all. Any 'response' seen "
                "elsewhere in this session may actually just be our own echo -- "
                "double check wiring with the multimeter (continuity test) "
                "before trusting console probe results."
            )
        else:
            self.logger.info(
                "[wiring] no exact self-echo detected -- the link is not simply "
                "looped back on itself. (This does not by itself prove the "
                "board side is wired correctly; it only rules out the most "
                "common false-positive source.)"
            )

        self.storage.save_analysis_result("wiring_check", result)
        self.storage.log_event(
            "wiring_check",
            "SELF_LOOPBACK_DETECTED" if result["pattern_echoed_back"] else "OK",
        )
        return result
