"""
storage.py

Core design principle: "Any byte we get from the board is saved to disk
immediately, before any analysis, and completely independent of it."

save_raw() has zero dependency on the analysis modules and never raises
for any reason other than a real disk error (disk full, permission denied).
If the analysis layer crashes later, the raw file already saved here stays
intact and untouched.
"""

import csv
import json
import os
import sqlite3
import threading
import time


class SessionStorage:
    def __init__(self, session_dir: str, logger):
        self.session_dir = session_dir
        self.raw_dir = os.path.join(session_dir, "raw")
        self.analysis_dir = os.path.join(session_dir, "analysis")
        self.logger = logger
        self.db_path = os.path.join(session_dir, "history.sqlite3")
        # Guards the raw-filename counter so two threads saving at the same
        # microsecond still get distinct filenames.
        self._name_lock = threading.Lock()
        self._name_counter = 0
        self._init_db()

    # ---------------------------------------------------------------
    # Critical layer: raw save, must either succeed or fail loudly
    # ---------------------------------------------------------------
    def save_raw(self, label: str, data: bytes) -> str:
        """
        Writes raw data to disk immediately.
        label e.g.: 'flash_dump', 'boot_log', 'console_probe'
        Returns: path of the saved file (so the user always knows where it is)
        """
        os.makedirs(self.raw_dir, exist_ok=True)
        # Filename must be unique even for two saves of the same label inside
        # the same second (a fast bootloader-sync retry sequence does exactly
        # that). Second-granularity timestamps alone silently truncated the
        # earlier file, which contradicted this module's core promise that
        # every captured byte is preserved. Microseconds + a monotonic
        # counter make the name collision-proof without changing the label.
        stamp = time.strftime("%H%M%S")
        usec = f"{time.time() % 1:.6f}".replace(".", "")
        with self._name_lock:
            self._name_counter += 1
            counter = self._name_counter
        path = os.path.join(self.raw_dir, f"{stamp}_{usec}_{counter:04d}_{label}.bin")
        try:
            with open(path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.logger.info(f"[saved] {label} -> {path} ({len(data)} bytes)")
            return path
        except OSError as e:
            # The only place we should really raise: it means data was lost
            self.logger.error(f"[CRITICAL] could not save {label}: {e}")
            raise

    def save_text(self, label: str, text: str) -> str:
        return self.save_raw(label, text.encode("utf-8", errors="replace"))

    # ---------------------------------------------------------------
    # Analysis layer: errors here must never affect the raw file
    # ---------------------------------------------------------------
    def save_analysis_result(self, label: str, data: dict) -> str:
        os.makedirs(self.analysis_dir, exist_ok=True)
        path = os.path.join(self.analysis_dir, f"{label}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return path
        except OSError as e:
            self.logger.warning(f"saving analysis result '{label}' failed: {e}")
            return ""

    # ---------------------------------------------------------------
    # History (SQLite)
    # ---------------------------------------------------------------
    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    stage TEXT,
                    status TEXT,
                    detail TEXT,
                    file_path TEXT
                )
                """
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            self.logger.warning(f"creating history DB failed: {e}")

    def log_event(self, stage: str, status: str, detail: str = "", file_path: str = ""):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO events (ts, stage, status, detail, file_path) VALUES (?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), stage, status, detail, file_path),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            self.logger.warning(f"logging event '{stage}' to history failed: {e}")

    def export_history(self, fmt: str = "json") -> str:
        """Exports the full history to JSON or CSV, for attaching to a writeup."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id")]
            conn.close()
        except sqlite3.Error as e:
            self.logger.warning(f"reading history for export failed: {e}")
            return ""

        if fmt == "csv":
            path = os.path.join(self.session_dir, "history_export.csv")
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    if rows:
                        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                        writer.writeheader()
                        writer.writerows(rows)
                return path
            except OSError as e:
                self.logger.warning(f"writing CSV failed: {e}")
                return ""
        else:
            path = os.path.join(self.session_dir, "history_export.json")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=2)
                return path
            except OSError as e:
                self.logger.warning(f"writing JSON failed: {e}")
                return ""
