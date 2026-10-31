"""
Local-only logging + uncaught-exception capture.

A non-technical user has no terminal and no console window (the shipped app runs
under pythonw with no stdout). When something goes wrong the only durable record
is a log file they can find and send for support. This module:

  * writes a size-rotated log to ``%APPDATA%\\DataRoomReview\\logs`` (the same
    app-data tree as the matter DBs — see ``app/paths.py``), and
  * installs ``sys.excepthook`` and ``threading.excepthook`` so an uncaught
    exception on *any* thread (the indexer runs on a worker thread) lands in that
    file instead of vanishing.

No network, no telemetry — the log never leaves the machine. Setup is idempotent
so the dev CLI, the desktop entry point, and tests can all call it safely.
"""

import logging
import sys
import threading
from logging.handlers import RotatingFileHandler

from . import __version__
from .paths import logs_dir

LOG_NAME = "dataroomreview"
_configured = False
_log_path = None

log = logging.getLogger(LOG_NAME)


def log_file() -> str:
    """Absolute path of the log file. Pure getter — does not configure logging
    (so a read-only call like /api/about has no global side effects)."""
    if _log_path is not None:
        return str(_log_path)
    return str(logs_dir() / "dataroomreview.log")


def _excepthook(exc_type, exc, tb):
    # KeyboardInterrupt should still reach the default handler (clean Ctrl-C).
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    log.critical("Uncaught exception", exc_info=(exc_type, exc, tb))


def _thread_excepthook(args):
    if issubclass(args.exc_type, KeyboardInterrupt):
        return
    log.critical(
        "Uncaught exception in thread %s",
        getattr(args.thread, "name", "?"),
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def setup_logging(context: str = "app", level: int = logging.INFO) -> str:
    """Configure file logging + crash capture once. Returns the log file path.

    ``context`` is a short tag (``desktop`` / ``dev`` / ``test``) recorded in the
    start-of-session banner so a log can be traced to how the app was launched.
    """
    global _configured, _log_path
    if _configured:
        return str(_log_path)

    _log_path = logs_dir() / "dataroomreview.log"
    handler = RotatingFileHandler(
        _log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )

    # Attach to OUR package logger, not the root logger, and stop propagation:
    # this keeps the file handler + level off the root logger so we don't pollute
    # or duplicate pytest / uvicorn logging. Child loggers ("dataroomreview.web",
    # ".desktop") propagate up to here, so they are still captured.
    log.setLevel(level)
    log.propagate = False
    log.addHandler(handler)
    # In dev (a real console) also echo to stderr; the shipped app has none.
    if sys.stderr is not None and sys.stderr.isatty():
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        log.addHandler(console)

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook

    _configured = True
    log.info("=== session start: v%s (%s), log=%s ===",
             __version__, context, _log_path)
    return str(_log_path)
