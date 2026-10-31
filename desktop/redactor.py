"""
Desktop entry point for the standalone **Redactor** product variant.

Mirrors ``desktop/main.py`` (bind a localhost socket on a random free port -> run
uvicorn in a background daemon thread -> open a native pywebview window with no URL
bar and no console) but drives the REDACTION-ONLY app factory
(``app.web.create_redactor_app``) and titles the window "Redactor". It REUSES
``desktop/main.py``'s security-critical + diagnostics helpers (the ``SO_EXCLUSIVEADDRUSE``
socket bind, the uvicorn spawn, the startup-log crash capture, the fatal-error dialog)
rather than copying them, so the two entry points can't drift on the parts that matter.

Data isolation: the Redactor defaults its app-data dir to ``%APPDATA%\\Redactor`` (only
when ``LAWDATAMAN_DATA_DIR`` is unset), so a Redactor install's exports / undo / logs /
matter store never mix with a Lawbat install on the same machine. ``app/paths.py`` already
honours ``LAWDATAMAN_DATA_DIR``; this module just sets the default, and does so BEFORE any
import that resolves it (``app.paths`` and ``desktop.main``'s diagnostics bootstrap both
read the env var at import time).
"""

import os
import sys
import time
from pathlib import Path

# --- Data-dir default (MUST run before importing desktop.main / app.*) -------
# Only set it when unset, so an explicit override (tests via LAWDATAMAN_DATA_DIR, or a
# custom deployment) still wins. Off Windows we still pick a "Redactor"-named dir so a dev
# run stays isolated from a Lawbat dev store too.
if not os.environ.get("LAWDATAMAN_DATA_DIR"):
    if sys.platform == "win32":
        _base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        os.environ["LAWDATAMAN_DATA_DIR"] = str(Path(_base) / "Redactor")
    elif sys.platform == "darwin":
        os.environ["LAWDATAMAN_DATA_DIR"] = str(
            Path.home() / "Library" / "Application Support" / "Redactor")
    else:
        _xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        os.environ["LAWDATAMAN_DATA_DIR"] = str(Path(_xdg) / "Redactor")

# Imported AFTER the data-dir default is set (E402): desktop.main bootstraps its startup
# log at import time and must land it in the Redactor data dir, not a Lawbat one.
from desktop import main as dmain  # noqa: E402


def _wait_until_up(port: int, timeout: float = 15.0) -> bool:
    """Poll the served page until it answers. Unlike Lawbat, the Redactor exposes no
    /api/state, so readiness is probed against GET / (the redaction reviewer page)."""
    import urllib.request

    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/"
    delay = 0.005
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(delay)
            delay = min(delay * 1.5, 0.1)
    return False


def _run() -> None:
    """Boot the redaction-only server on a background thread (overlapping the main
    thread's pywebview import) and open the window. Adapted from desktop.main._run —
    same shape, but create_redactor_app + the GET / readiness poll + "Redactor" title."""
    import threading
    import traceback

    result: dict = {"port": None, "server": None, "err": None}
    done = threading.Event()

    def _work():
        try:
            # Imported here (not at module scope) so the heavy app.web import overlaps the
            # main thread's `import webview`, exactly as desktop.main does.
            from app.web import AppState, create_redactor_app

            state = AppState()
            app = create_redactor_app(state)
            sock = dmain._bind_localhost_socket()
            result["port"] = sock.getsockname()[1]
            result["server"] = dmain._start_server(app, sock)
        except Exception as exc:  # noqa: BLE001 - surfaced on the main thread below
            result["err"] = exc
            dmain._log_startup("Redactor bring-up failed:")
            dmain._log_startup("".join(traceback.format_exc()))
        done.set()

    threading.Thread(target=_work, name="redactor-bringup", daemon=True).start()

    # pywebview must init on the MAIN thread (STA on Windows); import it here so the
    # server bring-up above runs in parallel.
    try:
        import webview
    except Exception as exc:  # noqa: BLE001
        dmain._report_fatal(
            "The application window component (pywebview) failed to load. "
            "Microsoft Edge WebView2 Runtime is required — install it and retry.",
            exc,
        )
        raise SystemExit(1)

    if not done.wait(timeout=20.0):
        dmain._report_fatal("The local server did not start in time (bring-up timed out).")
        raise SystemExit("Local server failed to start.")
    if result["err"] is not None:
        dmain._report_fatal(
            "An unexpected error occurred while starting the local server.", result["err"])
        raise SystemExit(1)
    port = result["port"]
    if port is None or not _wait_until_up(port):
        dmain._report_fatal("The local server did not start in time.")
        raise SystemExit("Local server failed to start.")

    from desktop.api import DesktopApi

    api = DesktopApi()
    window = webview.create_window(
        "Redactor",
        f"http://127.0.0.1:{port}/",
        js_api=api,
        width=1100,
        height=820,
        min_size=(820, 600),
    )
    api.set_window(window)
    try:
        webview.start()  # blocks until the window closes; the daemon server dies with it
    except Exception as exc:  # noqa: BLE001
        dmain._report_fatal(
            "The application window failed to open. Microsoft Edge WebView2 "
            "Runtime is required — install it and retry.",
            exc,
        )
        raise SystemExit(1)


def main() -> None:
    # Tee stdout/stderr into the startup log under pythonw (reuses desktop.main's setup).
    dmain._redirect_streams_if_needed()

    # If desktop.main's light imports failed, the failure is already in startup.log.
    if dmain._IMPORT_ERROR is not None:
        dep = getattr(dmain._IMPORT_ERROR, "name", None)
        which = f" (missing component: {dep})" if dep else ""
        dmain._report_fatal(
            "A required program component failed to load" + which + ".",
            dmain._IMPORT_ERROR,
        )
        raise SystemExit(1)

    try:
        from app.logsetup import setup_logging

        setup_logging("redactor")
    except Exception:  # noqa: BLE001 - keep going on the startup log alone
        pass

    try:
        _run()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level catch-all for the GUI app
        dmain._report_fatal("An unexpected error occurred during startup.", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
