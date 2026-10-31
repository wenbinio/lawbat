"""
Desktop entry point — the thing the installed Windows app actually runs.

Flow:
  1. start the FastAPI app under uvicorn, bound to 127.0.0.1 on a RANDOM free
     port, in a background daemon thread;
  2. wait until it answers;
  3. open a native pywebview window pointing at it — no URL bar, no terminal.

No console window appears (build with pythonw / --noconsole). No network egress:
the server is localhost-only on an ephemeral port, the page is self-contained.

Crash diagnostics (OPERATIONAL, not the core audit chain): the shipped app runs
under ``pythonw.exe`` with NO console, so a bare traceback — from a heavy import,
a native-library crash (PyMuPDF / pythonnet), or a daemon-thread exception —
would vanish and leave the user with nothing to send for support. The first
thing this module does (BEFORE any heavy import, using only the stdlib so it
works even if our own packages fail to import) is open a durable ``startup.log``,
wire up ``faulthandler`` + ``sys.excepthook`` + ``threading.excepthook``, and
redirect stdout/stderr into it. Any later failure is logged there and surfaced
to the user with the exact log path via a native message box on Windows.
"""

import datetime
import faulthandler
import io
import os
import sys
import time
import traceback
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # type-hint only; uvicorn is imported lazily at runtime (see below)
    import uvicorn

# --- Stage 1: earliest crash capture (stdlib ONLY) ---------------------------
# This runs at import time, before the heavy third-party imports below, so that a
# failure in *those* imports (or anything after) is still recorded. It must never
# raise: a diagnostics layer that crashes is worse than none. Everything here is
# stdlib so it works even when our own packages can't be imported.

# Cold-start clock — captured BEFORE the heavy imports below so the launch log can
# show how long importing the app stack (uvicorn + app.web -> extractors, ...)
# actually costs. The imports after this point are deliberately not at the very top
# (hence the E402 suppressions).
_T0 = time.perf_counter()

# Set by _bootstrap_diagnostics(); the one path the user is told to send.
_STARTUP_LOG_PATH = None
# Open file handle for faulthandler / stdout-stderr redirection (kept alive).
_STARTUP_LOG_FH = None
# If the heavy imports below fail, the error is captured here (instead of being
# allowed to propagate out of module import) so main() can still run and show a
# friendly dialog pointing at the log.
_IMPORT_ERROR = None


def _startup_logs_dir():
    """A stable, writable dir for the early startup log — stdlib only.

    Mirrors app/paths.py's layout (``%APPDATA%\\DataRoomReview\\logs`` on Windows)
    WITHOUT importing it, because the whole point of stage 1 is to work even if our
    own packages fail to import. Falls back to a home-dir / temp location off
    Windows so a headless Linux import (tests) never breaks. Honours
    ``LAWDATAMAN_DATA_DIR`` so tests stay isolated.
    """
    from pathlib import Path

    override = os.environ.get("LAWDATAMAN_DATA_DIR")
    try:
        if override:
            base = Path(override)
        elif sys.platform == "win32":
            appdata = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
            base = Path(appdata) / "DataRoomReview"
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support" / "DataRoomReview"
        else:
            xdg = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
            base = Path(xdg) / "DataRoomReview"
        d = base / "logs"
        d.mkdir(parents=True, exist_ok=True)
        return d
    except Exception:
        # Last resort: the OS temp dir. Never let log-dir resolution abort startup.
        import tempfile

        d = Path(tempfile.gettempdir()) / "DataRoomReview" / "logs"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            d = Path(tempfile.gettempdir())
        return d


def _has_console():
    """True if there's a usable console attached (dev / a real terminal).

    Under pythonw there is no console and stdout/stderr are typically None (or a
    discarded handle). We only redirect / suppress when there is no real console,
    so dev runs and the test suite keep their normal stdout/stderr.
    """
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except Exception:
        return False


def _safe_app_version():
    """Read app.__version__ defensively — must not fail the banner if app is broken."""
    try:
        from app import __version__

        return __version__
    except Exception as exc:  # noqa: BLE001 - diagnostics must never raise
        return f"unknown ({exc.__class__.__name__})"


def _write_startup_header(fh):
    """Diagnostics banner — useful for both crashes AND slowness reports."""
    try:
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        lines = [
            "",
            "=" * 72,
            f"=== Lawbat startup: {stamp} ===",
            f"app version : {_safe_app_version()}",
            f"executable  : {sys.executable}",
            f"python      : {sys.version.splitlines()[0] if sys.version else '?'}",
        ]
        try:
            import platform

            lines.append(f"platform    : {platform.platform()}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"platform    : unknown ({exc.__class__.__name__})")
        lines.append(f"argv        : {sys.argv!r}")
        lines.append(f"sys.path    : {len(sys.path)} entries")
        lines.append(f"cwd         : {os.getcwd()}")
        lines.append("-" * 72)
        fh.write("\n".join(lines) + "\n")
        fh.flush()
    except Exception:
        # A failed banner must not abort startup.
        pass


def _startup_excepthook(exc_type, exc, tb):
    # KeyboardInterrupt should still reach the default handler (clean Ctrl-C).
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    _log_startup("Uncaught exception (main thread):")
    _log_startup("".join(traceback.format_exception(exc_type, exc, tb)))


def _startup_thread_excepthook(args):
    # The uvicorn server runs in a DAEMON thread; without this its exceptions are
    # invisible (no console, default threading hook just prints to a dead stderr).
    if issubclass(args.exc_type, KeyboardInterrupt):
        return
    name = getattr(args.thread, "name", "?")
    _log_startup(f"Uncaught exception in thread {name}:")
    _log_startup(
        "".join(
            traceback.format_exception(
                args.exc_type, args.exc_value, args.exc_traceback
            )
        )
    )


def _log_startup(msg):
    """Append a line to the startup log. Never raises."""
    try:
        if _STARTUP_LOG_FH is not None and not _STARTUP_LOG_FH.closed:
            _STARTUP_LOG_FH.write(msg.rstrip("\n") + "\n")
            _STARTUP_LOG_FH.flush()
    except Exception:
        pass


def _bootstrap_diagnostics():
    """Open the startup log + install crash hooks. Stdlib only; never raises."""
    global _STARTUP_LOG_PATH, _STARTUP_LOG_FH
    try:
        log_dir = _startup_logs_dir()
        _STARTUP_LOG_PATH = str(log_dir / "startup.log")
        # Line-buffered append; a crash an instant later still leaves the banner.
        _STARTUP_LOG_FH = open(
            _STARTUP_LOG_PATH, "a", encoding="utf-8", buffering=1
        )
    except Exception:
        # If we cannot even open the log file, fall back to a no-op handle so the
        # rest of startup proceeds (better a silent log than a refusing-to-launch
        # app). _STARTUP_LOG_PATH may be set but unwritable; that's acceptable.
        _STARTUP_LOG_FH = None
        return

    _write_startup_header(_STARTUP_LOG_FH)

    # Native/C-extension crashes (segfault in PyMuPDF, pythonnet/CLR, etc.) bypass
    # Python's exception machinery; faulthandler dumps the C stack to our file.
    try:
        faulthandler.enable(file=_STARTUP_LOG_FH)
    except Exception:
        pass

    # Capture uncaught exceptions on the main thread AND on worker/daemon threads.
    try:
        sys.excepthook = _startup_excepthook
    except Exception:
        pass
    try:
        import threading

        threading.excepthook = _startup_thread_excepthook
    except Exception:
        pass


def _redirect_streams_if_needed():
    """Tee stdout/stderr into the startup log when running with NO console.

    pythonw discards stdout/stderr, so any stray print() or low-level traceback
    (e.g. from a C library) would vanish. Redirecting them captures that. Called
    only from main() — NOT at import time — so the test suite (which imports the
    server helpers but never runs main) keeps its normal streams and its OK/FAIL
    output. No-op when a real console exists (dev) or when already redirected.
    """
    if _STARTUP_LOG_FH is None or _has_console():
        return
    try:
        if not isinstance(sys.stdout, _LogStream):
            sys.stdout = _LogStream(_STARTUP_LOG_FH)
        if not isinstance(sys.stderr, _LogStream):
            sys.stderr = _LogStream(_STARTUP_LOG_FH)
    except Exception:
        pass


class _LogStream(io.TextIOBase):
    """Minimal text stream that tees writes into the startup log file.

    Used to capture stdout/stderr under pythonw (where the real streams are
    discarded). Deliberately tiny + defensive — it must never raise, since it
    replaces the interpreter's own error output channel.
    """

    def __init__(self, fh):
        self._fh = fh

    def write(self, s):
        try:
            if self._fh is not None and not self._fh.closed:
                self._fh.write(s)
                self._fh.flush()
        except Exception:
            pass
        return len(s) if isinstance(s, str) else 0

    def flush(self):
        try:
            if self._fh is not None and not self._fh.closed:
                self._fh.flush()
        except Exception:
            pass

    def writable(self):
        return True


# Run stage 1 immediately, at import time, before the heavy imports below.
_bootstrap_diagnostics()


# --- Stage 2: imports (now covered by the diagnostics above) -----------------
# Only the LIGHT, always-needed imports live at module scope: the stdlib helpers,
# the logging setup, and DesktopApi. They are wrapped so a failure here is LOGGED
# (naming the failing dependency) and stashed in _IMPORT_ERROR rather than
# propagating out of module import — that lets main() still run and show the user a
# friendly dialog pointing at the log. On a healthy box (incl. Linux/CI) the
# imports succeed and nothing changes.
#
# The HEAVY server imports — `uvicorn` and `app.web` (which pulls in fastapi, the
# single biggest cold-start cost at ~270ms) — are DELIBERATELY NOT here. They are
# imported on a background thread during _run() (see _ServerBringUp), so that heavy
# import + the uvicorn boot overlap the main thread's expensive `import webview`
# (CLR/pythonnet init). Importing them at module scope would force the two costs to
# run sequentially and lengthen cold start. `_start_server` does a local
# `import uvicorn` so tests that call it directly still work headless.
try:
    import logging  # noqa: E402
    import socket  # noqa: E402
    import threading  # noqa: E402
    import urllib.request  # noqa: E402

    from app.logsetup import setup_logging  # noqa: E402
    from desktop.api import DesktopApi  # noqa: E402
except Exception as _exc:  # noqa: BLE001 - record then defer to main()'s dialog
    _IMPORT_ERROR = _exc
    _log_startup("Import failed during startup:")
    _log_startup("".join(traceback.format_exc()))
    # Keep names that main() / module consumers may touch defined, so the module
    # still imports headless and main() can reach its error path. The real failure
    # has been recorded above and is reported via _IMPORT_ERROR.
    logging = None  # type: ignore[assignment]

_T_IMPORTS = time.perf_counter()

# Package logger (only meaningful once the heavy imports succeeded; guarded use).
log = logging.getLogger("dataroomreview.desktop") if logging is not None else None


def _bind_localhost_socket() -> "socket.socket":
    """Bind a localhost socket on a random free port and return it (still open).

    Handing this exact socket to uvicorn avoids the get-port-then-reopen race
    where another process could grab the port in between.

    Address-reuse semantics differ by platform and MATTER for security here — this
    loopback socket carries file paths and document snippets, so no OTHER local
    process may be allowed to steal the port:

    * POSIX (Linux/macOS): ``SO_REUSEADDR`` only relaxes the TIME_WAIT restriction
      so we can rebind a recently-closed port; it does NOT let a second process bind
      a port we are actively bound to. It is the correct, safe choice there.

    * Windows: ``SO_REUSEADDR`` is DANGEROUS — it lets ANY other local process bind
      the same address/port and hijack the socket, intercepting our loopback HTTP
      traffic (file paths + document snippets). The Windows-only
      ``SO_EXCLUSIVEADDRUSE`` is the right primitive: it claims the address
      exclusively so nothing else can bind it. We bind a FRESH socket to an ephemeral
      port, so there is no TIME_WAIT rebind we need ``SO_REUSEADDR`` to relax.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        # Exclusive bind: deny any other process the same address/port. Guard with
        # getattr — SO_EXCLUSIVEADDRUSE is Windows-only and may be absent on some
        # Python builds; if it's missing we set NOTHING. The Windows default is
        # already non-reusable (the safe behaviour we want); we deliberately do NOT
        # fall back to the hijackable SO_REUSEADDR on Windows.
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            s.setsockopt(socket.SOL_SOCKET, exclusive, 1)
    else:
        # POSIX: SO_REUSEADDR is safe here and lets us rebind promptly across
        # restarts without a stale TIME_WAIT blocking the port.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    return s


def _wait_until_up(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/api/state"
    # Poll briskly at first (the server is usually ready in tens of ms) and back off
    # to a cheap 100ms cadence if it is slow — a fixed 100ms sleep would otherwise add
    # up to ~100ms of dead cold-start wait after the server is already answering.
    delay = 0.005
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(delay)
            delay = min(delay * 1.5, 0.1)
    return False


def _start_server(app, sock: "socket.socket") -> "uvicorn.Server":
    # Imported here, not at module scope, so this heavy import (uvicorn + its
    # protocol stack) runs on the background bring-up thread and overlaps the main
    # thread's `import webview`. Python caches it in sys.modules; a test that calls
    # _start_server directly triggers the import on first use.
    import uvicorn

    # ws="none": the app is HTTP+JSON only (no websocket routes), so skip uvicorn's
    # websockets protocol stack — it otherwise imports ~30 websockets/wsproto modules
    # at server start, pure cold-start cost we never use. access_log=False: a
    # single-user loopback server under pythonw has nowhere useful to send per-request
    # access lines (they would just tee into startup.log as noise).
    config = uvicorn.Config(app, log_level="warning", ws="none", access_log=False)
    server = uvicorn.Server(config)
    # uvicorn installs SIGINT/SIGTERM handlers, which only work on the main
    # thread; disable them since we run in a daemon thread.
    server.install_signal_handlers = lambda: None
    threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
    return server


class _ServerBringUp:
    """Build the app and boot uvicorn on a BACKGROUND thread, off the critical path.

    The heavy server import (``app.web`` -> fastapi, ~270ms) + ``create_app`` +
    uvicorn boot are independent of pywebview, but pywebview/pythonnet must init on
    the MAIN thread (STA on Windows). Running the server work here lets it overlap
    the main thread's ``import webview`` (CLR init), so cold start becomes the slower
    of the two costs instead of their sum.

    All failure modes are captured (never raised out of the thread) and surfaced on
    the main thread by ``_run`` with the SAME user-facing messages as before:
      * ``import``  — the heavy server import failed (-> "required component" dialog,
        carrying the missing module name when available);
      * ``startup`` — app construction / socket bind / server spawn raised;
      * ``not_up``  — the server never answered ``/api/state`` in time.
    On success ``port`` + ``server`` are set and ``error_kind`` is None.
    """

    def __init__(self):
        self.done = threading.Event()
        self.port = None
        self.server = None
        self.error_kind = None  # "import" | "startup" | "not_up" | None
        self.error_exc = None
        self.error_detail = ""

    def _work(self):
        # Heavy import isolated first so its failure maps to the "missing component"
        # message (matching the old stage-2 _IMPORT_ERROR behaviour for app.web).
        try:
            from app.web import AppState, create_app
        except Exception as exc:  # noqa: BLE001 - surfaced on the main thread
            self.error_kind, self.error_exc = "import", exc
            _log_startup("Server import failed during bring-up:")
            _log_startup("".join(traceback.format_exc()))
            self.done.set()
            return
        try:
            state = AppState()
            app = create_app(state)
            sock = _bind_localhost_socket()
            self.port = sock.getsockname()[1]
            self.server = _start_server(app, sock)
        except Exception as exc:  # noqa: BLE001 - surfaced on the main thread
            self.error_kind, self.error_exc = "startup", exc
            _log_startup("App/server construction failed during bring-up:")
            _log_startup("".join(traceback.format_exc()))
            self.done.set()
            return
        if not _wait_until_up(self.port):
            started = getattr(self.server, "started", None)
            self.error_kind = "not_up"
            self.error_detail = f" (server.started={started}; port={self.port})"
            _log_startup("Local server failed to start." + self.error_detail)
        self.done.set()

    def start(self) -> "_ServerBringUp":
        threading.Thread(
            target=self._work, name="server-bringup", daemon=True
        ).start()
        return self


def _show_error_dialog(message: str) -> None:
    """Native, console-free error box on Windows; elsewhere just log.

    The shipped app has no console, so a traceback is invisible. A MessageBox is
    the one way to tell a non-technical user it failed AND where the log is. Guard
    everything: a failing dialog must not mask the original error.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        MB_OK = 0x0
        MB_ICONERROR = 0x10
        ctypes.windll.user32.MessageBoxW(
            None, message, "Lawbat", MB_OK | MB_ICONERROR
        )
    except Exception:
        _log_startup("(could not show native error dialog)")
        _log_startup("".join(traceback.format_exc()))


def _report_fatal(summary: str, detail_exc: BaseException | None = None) -> None:
    """Log full detail, tell the user (dialog + stderr), pointing at the log."""
    log_path = _STARTUP_LOG_PATH or "the application log"
    if log is not None:
        try:
            log.exception("fatal: %s", summary)
        except Exception:
            pass
    _log_startup(f"FATAL: {summary}")
    if detail_exc is not None:
        _log_startup("".join(traceback.format_exception(detail_exc)))
    user_msg = (
        f"Lawbat could not start.\n\n"
        f"{summary}\n\n"
        f"A diagnostic log was written to:\n{log_path}\n\n"
        f"Please send that file to support."
    )
    # If a console exists (dev), make the path obvious there too.
    if _has_console():
        try:
            print(user_msg, file=sys.__stderr__ or sys.stderr)
        except Exception:
            pass
    _show_error_dialog(user_msg)


def main():
    # Under pythonw there is no console; tee stdout/stderr into the startup log so
    # nothing is lost. Done here (not at import) so the test suite keeps its
    # streams. Stage-1 diagnostics (log file + faulthandler + excepthooks) are
    # already live from import time.
    _redirect_streams_if_needed()

    # If the heavy imports failed, we never got a working app/logsetup logger; the
    # failure is already in startup.log. Tell the user and exit non-zero.
    if _IMPORT_ERROR is not None:
        dep = getattr(_IMPORT_ERROR, "name", None)
        which = f" (missing component: {dep})" if dep else ""
        _report_fatal(
            "A required program component failed to load" + which + ".",
            _IMPORT_ERROR,
        )
        raise SystemExit(1)

    # Integrate the rich rotating app log (app/logsetup.py) with the early startup
    # log: setup_logging records its rotating-log path, and we note it in the
    # startup log so support has BOTH files cross-referenced from one place.
    try:
        logfile = setup_logging("desktop")
        _log_startup(f"app log (rotating): {logfile}")
    except Exception as exc:  # noqa: BLE001 - keep going on the startup log alone
        logfile = _STARTUP_LOG_PATH
        _log_startup("setup_logging() failed; continuing on startup.log only:")
        _log_startup("".join(traceback.format_exc()))
        _ = exc

    try:
        _run()
    except SystemExit:
        # A controlled abort (e.g. "Local server failed to start.") already logged
        # below in _run; re-raise so the process exits non-zero without a dialog
        # duplicating a message _run already surfaced.
        raise
    except Exception as exc:  # noqa: BLE001 - top-level catch-all for the GUI app
        _report_fatal("An unexpected error occurred during startup.", exc)
        raise SystemExit(1)


def _run():
    t_run = time.perf_counter()

    # Boot the server (heavy app.web/fastapi + uvicorn import, create_app, uvicorn
    # start) on a BACKGROUND thread FIRST, so it overlaps the main thread's expensive
    # `import webview` (CLR/pythonnet) below. The two are independent; cold start
    # becomes the slower of them, not their sum. webview MUST stay on the main thread
    # (STA on Windows), so only the server work is moved off it.
    bringup = _ServerBringUp().start()

    # Imported late so the module is importable headless (tests) and so a missing
    # WebView2 runtime / pywebview surfaces as a clear message, not a silent death.
    try:
        import webview
    except Exception as exc:  # noqa: BLE001
        _report_fatal(
            "The application window component (pywebview) failed to load. "
            "Microsoft Edge WebView2 Runtime is required — install it and retry.",
            exc,
        )
        raise SystemExit(1)
    t_webview = time.perf_counter()

    # The server has been booting in parallel; collect the result now. A daemon-thread
    # crash (e.g. a port/bind error) was also logged by threading.excepthook above —
    # all of these point support at the same log.
    if not bringup.done.wait(timeout=20.0):
        _log_startup("Server bring-up timed out (thread did not finish).")
        _report_fatal("The local server did not start in time (bring-up timed out).")
        raise SystemExit("Local server failed to start.")
    if bringup.error_kind == "import":
        dep = getattr(bringup.error_exc, "name", None)
        which = f" (missing component: {dep})" if dep else ""
        _report_fatal(
            "A required program component failed to load" + which + ".",
            bringup.error_exc,
        )
        raise SystemExit(1)
    if bringup.error_kind == "startup":
        _report_fatal(
            "An unexpected error occurred while starting the local server.",
            bringup.error_exc,
        )
        raise SystemExit(1)
    if bringup.error_kind == "not_up" or bringup.port is None:
        _report_fatal(
            "The local server did not start in time." + bringup.error_detail
            + " See the log for any server-thread error.",
        )
        raise SystemExit("Local server failed to start.")
    port = bringup.port
    t_server = time.perf_counter()

    api = DesktopApi()
    window = webview.create_window(
        "Lawbat",
        f"http://127.0.0.1:{port}/",
        js_api=api,
        width=1100,
        height=820,
        min_size=(820, 600),
    )
    api.set_window(window)
    # Cold-start breakdown (seconds) up to the point the window starts rendering. The
    # server bring-up runs in PARALLEL with the webview import, so total-pre-window
    # ~= max(webview-import, server-bringup), not their sum. The time the user still
    # waits after this is WebView2/CLR init inside start().
    if log is not None:
        log.info(
            "cold-start s: light-imports=%.2f webview-import=%.2f "
            "server-bringup(overlapped)=%.2f total-pre-window=%.2f",
            _T_IMPORTS - _T0,
            t_webview - t_run,
            t_server - t_run,
            t_server - _T0,
        )
    try:
        webview.start()  # blocks until the window closes; daemon server dies with it
    except Exception as exc:  # noqa: BLE001
        _report_fatal(
            "The application window failed to open. Microsoft Edge WebView2 "
            "Runtime is required — install it and retry.",
            exc,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
