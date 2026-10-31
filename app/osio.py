"""
Open a file in its default app, or reveal it in the OS file manager.

Used by the search-hit "Open / Reveal" actions. Confinement (the path must be
inside the open matter's indexed source tree) is enforced by the caller in
web.py before we ever get here.

LAWDATAMAN_DISABLE_OS_OPEN=1 makes these no-ops — set in tests/CI/headless so we
never spawn a viewer.
"""

import os
import subprocess
import sys
from pathlib import Path


def _disabled() -> bool:
    from .releaseflow import STAGE_DIRECTORY
    if STAGE_DIRECTORY.get() is not None:
        return True
    return os.environ.get("LAWDATAMAN_DISABLE_OS_OPEN") == "1"


def open_path(path) -> None:
    if _disabled():
        return
    p = os.path.normpath(str(path))  # native separators (matters on Windows)
    if sys.platform == "win32":
        os.startfile(p)  # type: ignore[attr-defined]  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.Popen(["open", p])
    else:
        subprocess.Popen(["xdg-open", p])


def reveal_in_folder(path) -> None:
    if _disabled():
        return
    p = os.path.normpath(str(path))
    if sys.platform == "win32":
        # /select, highlights the file in Explorer (needs native separators)
        subprocess.Popen(["explorer", "/select,", p])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", p])
    else:
        subprocess.Popen(["xdg-open", str(Path(p).parent)])
