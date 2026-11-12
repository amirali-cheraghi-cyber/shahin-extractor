"""
serial_session.py
A thin, safe wrapper around pySerial. No analysis logic lives here -- just
safe port open/close and read/write with a defined timeout, so other
modules don't have to repeat these details.
"""

import time

try:
    import serial
except ImportError:
    serial = None


class SerialSession:
    def __init__(self, port: str, baud: int, logger, timeout: float = 1.0):
        self.port = port
        self.baud = baud
        self.logger = logger
        self.timeout = timeout
        self.ser = None

    def open(self) -> bool:
        if serial is None:
            self.logger.error(
                "pyserial is not installed. Install it with 'pip install pyserial'."
            )
            return False
        try:
            self.ser = serial.Serial(
                port=self.port, baudrate=self.baud, timeout=self.timeout
            )
            self.logger.info(f"opened {self.port} at baud={self.baud}")
            return True
        except serial.SerialException as e:
            self.logger.error(f"failed to open {self.port}: {e}")
            return False

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def read_for(self, seconds: float) -> bytes:
        """Collects whatever arrives on TXD for the given duration (passive listen)."""
        if not self.ser:
            return b""
        buf = bytearray()
        end = time.time() + seconds
        # Temporarily adjust serial timeout to respect the caller's deadline.
        # Use short per-read timeouts so the loop's own deadline actually governs total wait.
        original_timeout = self.ser.timeout
        try:
            while time.time() < end:
                remaining = end - time.time()
                if remaining <= 0:
                    break
                # Use a short per-read timeout so we check the deadline frequently
                self.ser.timeout = min(remaining, 0.2)
                chunk = self.ser.read(256)
                if chunk:
                    buf.extend(chunk)
        finally:
            # Restore original timeout
            self.ser.timeout = original_timeout
        return bytes(buf)

    def send_and_read(self, data: bytes, wait: float = 0.6) -> bytes:
        """Sends one command and waits up to `wait` seconds for a reply."""
        if not self.ser:
            return b""
        try:
            self.ser.reset_input_buffer()
            self.ser.write(data)
            self.ser.flush()
        except Exception as e:
            self.logger.warning(f"sending data over serial failed: {e}")
            return b""
        return self.read_for(wait)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        # don't swallow an exception from inside the `with` block;
        # just make sure the port gets closed either way
        return False
