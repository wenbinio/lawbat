"""
Guard tests for the desktop shell's two platform-sensitive seams.

These cover behaviours that can only be FULLY exercised on Windows (the COM-STA
folder dialog; the exclusive socket bind), so here we assert the parts that ARE
checkable cross-platform:

  * C6 — the localhost socket selects SO_EXCLUSIVEADDRUSE on Windows and
    SO_REUSEADDR on POSIX, and still binds a usable ephemeral loopback port.
  * C5 — the folder-dialog dispatch helpers are importable, and the bridge
    method degrades to None (never raises) when there is no native window.

The actual Windows STA dialog open and the exclusive-bind hijack-rejection need a
Windows VM (see the module under test for the verification gap).

Run:  PYTHONPATH=. python3 tests/test_desktop.py
"""

import os
import socket
import sys
import tempfile

# Keep app-data isolated, matching the other suites (importing desktop.main pulls
# in app.* which resolves a data dir at import time on some paths).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-desk-"))

from desktop.api import (  # noqa: E402
    DesktopApi,
    _pick_folder_win32_sta,
    _shell_browse_for_folder,
)
from desktop.main import _bind_localhost_socket  # noqa: E402


def test_bind_localhost_socket_platform_options():
    """C6: correct address-reuse sockopt per platform + a real ephemeral bind."""
    sock = _bind_localhost_socket()
    try:
        host, port = sock.getsockname()
        assert host == "127.0.0.1", host
        assert port != 0, "should be bound to a concrete ephemeral port"

        if sys.platform == "win32":
            # On Windows we must NOT have set the hijackable SO_REUSEADDR; instead
            # SO_EXCLUSIVEADDRUSE should be on (when the build defines it).
            reuse = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
            assert reuse == 0, "SO_REUSEADDR must be OFF on Windows (hijack risk)"
            exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if exclusive is not None:
                val = sock.getsockopt(socket.SOL_SOCKET, exclusive)
                assert val != 0, "SO_EXCLUSIVEADDRUSE should be set on Windows"
        else:
            # POSIX: SO_REUSEADDR is the correct, safe choice here.
            reuse = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
            assert reuse != 0, "SO_REUSEADDR should be set on POSIX"
    finally:
        sock.close()


def test_pick_folder_helpers_importable_and_safe():
    """C5: dispatch helpers exist; the bridge method never raises sans window."""
    # Importable on every platform (the Win32-only ctypes work is inside the
    # functions, lazily, so import never touches windll on POSIX).
    assert callable(_pick_folder_win32_sta)
    assert callable(_shell_browse_for_folder)

    api = DesktopApi()
    api.set_window(None)  # dev-browser case: no native window
    if sys.platform != "win32":
        # Non-Windows path returns None when there is no window (falls back to the
        # in-page prompt) and must not raise. Skip if pywebview isn't installed in
        # this env (it's a Windows-runtime dep, excluded from the CI subset) — the
        # branch is the same; we just can't exercise it without the import.
        try:
            import webview  # noqa: F401
        except Exception:
            return
        assert api.pick_folder() is None


def _run():
    test_bind_localhost_socket_platform_options()
    test_pick_folder_helpers_importable_and_safe()
    print(
        "desktop OK — socket sockopt per-platform ("
        + ("win32/exclusive" if sys.platform == "win32" else "posix/reuseaddr")
        + ") + folder-dialog dispatch helpers importable/safe"
    )


if __name__ == "__main__":
    _run()
