"""
logger_setup.py
Sets up logging for the whole project: console (concise) + file (full detail).
This module must never crash the program; if the log path isn't writable,
it just continues on console-only.
"""

import logging
import os
from datetime import datetime


def setup_logger(session_dir: str, name: str = "shahin") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Console: important, readable messages only
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    # File: everything, for later review
    try:
        os.makedirs(session_dir, exist_ok=True)
        log_path = os.path.join(session_dir, "session.log")
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Could not create log file; continuing on console only.")

    return logger


def close_logger(logger: logging.Logger) -> None:
    """
    Closes and detaches the logger's handlers.

    On Windows an open FileHandler keeps an exclusive lock on session.log,
    which makes the whole session folder impossible to delete, zip, or
    hand to the team while the process is still alive. Closing it
    explicitly keeps the session folder usable.
    """
    for handler in list(logger.handlers):
        try:
            handler.close()
        except Exception:
            pass
        logger.removeHandler(handler)
    logger.handlers.clear()


def new_session_dir(base: str = "shahin_sessions") -> str:
    """Creates a new, unique folder for each run, based on timestamp."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"session_{stamp}")
    os.makedirs(path, exist_ok=True)
    os.makedirs(os.path.join(path, "raw"), exist_ok=True)
    os.makedirs(os.path.join(path, "analysis"), exist_ok=True)
    return path
