"""
passive_listener.py

When the bootloader doesn't respond (meaning the board is probably running
normal firmware), this module just listens on TXD. Many dev boards print
something on boot or while idle: firmware version, debug log, or even a
console prompt. This itself carries zero risk since we only listen, we
send nothing.
"""


class PassiveListener:
    def __init__(self, session, storage, logger):
        self.session = session
        self.storage = storage
        self.logger = logger

    def listen(self, seconds: float = 5.0) -> bytes:
        self.logger.info(f"[passive listen] listening on TXD for {seconds}s ...")
        data = self.session.read_for(seconds)
        if data:
            path = self.storage.save_raw("boot_log", data)
            self.storage.log_event("passive_listen", "GOT_DATA", f"{len(data)} bytes", path)
            self.logger.info(f"[passive listen] received {len(data)} bytes.")
        else:
            self.storage.log_event("passive_listen", "SILENT", "0 bytes")
            self.logger.info("[passive listen] no data received in this window (silence).")
        return data

    def try_reset_and_listen(self, seconds: float = 5.0) -> bytes:
        """
        Important reminder: per competition rules only a multimeter and
        USB-TTL converter are allowed, so we never toggle a physical RESET
        pin here. This is only for when the user manually presses the
        board's reset button while this function starts listening.
        """
        self.logger.info("If the board has a RESET button, press it now ...")
        return self.listen(seconds)
