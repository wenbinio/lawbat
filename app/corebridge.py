"""
Shared subprocess-bridge primitives for the Rust core bins (viewgen, redact-cli).

The host shell (this Python pilot) talks to the trusted Rust core through thin
JSON-over-subprocess bins staged under vendor/core/. Both app/viewmodel.py (viewgen)
and app/redactionmodel.py (redact-cli) need the SAME two primitives:
  * LOCATE the bin — env override -> bundled vendor/core/ -> system PATH, and
  * RUN it safely — no shell, args as a list, cleartext on STDIN (never argv),
    UTF-8 both ways, a bounded timeout, and NEVER raising.
That duplicated logic lives here once. The two bridges differ ONLY in what they do
with the outcome (viewgen falls back to a bundled sample; redact-cli surfaces a
structured error the UI shows), so this module returns a NEUTRAL result and lets each
bridge map it to its own shape + log line.

LOCAL-ONLY: this only ever runs a LOCAL executable and exchanges LOCAL JSON/text. No
network, no model — the same air-gap guarantee as the rest of the app.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .vendor import vendor_dir


def locate(env_var: str, stem: str) -> str | None:
    """Absolute path to a core bin, or None if unavailable.

    Mirrors app/vendor.py's resolution order (env -> vendor/ -> PATH) but with the
    bundled copy under `vendor/core/` (the platform data-plane bins), since these are
    CORE binaries, not optional third-party tools like Tesseract:
      1. explicit env override   `env_var`   (absolute path to the binary)
      2. a bundled copy          <vendor>/core/<stem>[.exe]
      3. the system PATH         (shutil.which(stem))
    """
    env = os.environ.get(env_var)
    if env and Path(env).exists():
        return env
    exe = stem + (".exe" if os.name == "nt" else "")
    cand = vendor_dir() / "core" / exe
    if cand.exists():
        return str(cand)
    return shutil.which(stem) or shutil.which(exe)


@dataclass
class RunResult:
    """The neutral outcome of one bin run (never carries matter text).

    `started` is False when the process could not be spawned/run at all (OSError /
    subprocess.SubprocessError, which includes a timeout) — the caller maps that to its
    own fallback/error and logs `exc_name` (the exception CLASS name only, never any
    matter content). On a successful spawn, `returncode` + `stdout` are the process
    outcome; the caller decides whether to parse `stdout` regardless of the code (the
    core bins print their contract envelope on stdout even on a non-zero exit)."""
    started: bool
    stdout: str = ""
    returncode: int = 0
    exc_name: str | None = None


def run(bin_path: str, *, input: str | None = None, timeout: float) -> RunResult:
    """Run `bin_path` once and return a RunResult. NEVER raises.

    No shell=True; args as a list; the optional `input` goes on STDIN (never argv —
    process arguments are visible via ps/Task Manager, so cleartext must not go there);
    a bounded timeout; stdout captured as text.

    FORCE UTF-8 both ways. The core bins emit UTF-8 JSON, but Python's text mode defaults
    to the LOCALE codec — cp1252 on Windows — which raises UnicodeDecodeError on any
    non-ASCII byte in the bin's output inside subprocess's reader thread, wedging the call
    so the response reads back as "not JSON". errors="replace" guarantees a stray byte can
    never crash a request; a replacement char only affects DISPLAY (redaction targets byte
    spans, not the shown value), so it cannot change what is removed."""
    try:
        proc = subprocess.run(
            [bin_path],
            input=input,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return RunResult(started=False, exc_name=type(e).__name__)
    return RunResult(started=True, stdout=proc.stdout, returncode=proc.returncode)
