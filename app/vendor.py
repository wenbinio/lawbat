"""
Locate optional bundled command-line tools (Tesseract, qpdf, ...).

The app MUST run with none of these present — they unlock features (OCR, PDF
repair) but are never required. Resolution order, so dev, the installed app, and
CI all work the same way:

  1. explicit env override   LAWDATAMAN_<TOOL>     (absolute path to the binary)
  2. a bundled copy          <vendor>/<tool>/<exe> or <vendor>/<exe>
  3. the system PATH         (shutil.which)

`<vendor>` defaults to a `vendor/` dir next to the app (the MSI lays the binaries
there); override with LAWDATAMAN_VENDOR_DIR. Returns None when not found.
"""

import os
import shutil
from pathlib import Path


def _app_root() -> Path:
    # repo root in dev; the install directory when packaged.
    return Path(__file__).resolve().parent.parent


def vendor_dir() -> Path:
    return Path(os.environ.get("LAWDATAMAN_VENDOR_DIR", _app_root() / "vendor"))


def bundled_tool(name: str) -> str | None:
    """Absolute path to a bundled/installed CLI tool, or None if unavailable."""
    env = os.environ.get("LAWDATAMAN_" + name.upper().replace("-", "_"))
    if env and Path(env).exists():
        return env
    exe = name + (".exe" if os.name == "nt" else "")
    for cand in (vendor_dir() / name / exe, vendor_dir() / exe):
        if cand.exists():
            return str(cand)
    return shutil.which(name) or shutil.which(exe)
