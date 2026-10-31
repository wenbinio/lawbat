"""
Setup doctor — `python -m app.doctor`.

A one-shot, deterministic, OFFLINE self-check that diagnoses the exact setup friction a
first-time tester hits: a wrong working directory / missing `PYTHONPATH` ("No module
named app"), a missing Python dependency, an absent redaction engine ("Tool offline"),
a SQLite build without FTS5, or an unwritable data dir. It prints a green/red table with
the precise fix per row and exits 0 iff every CRITICAL check passes (non-zero otherwise),
so `run.bat` (and a human) can gate on it.

DESIGN RULES (load-bearing — do not "simplify"):
  * EVERY import a check needs is guarded INSIDE the check (this tool exists to diagnose
    MISSING deps, so importing one at module top would crash the very tool meant to report
    it). The only hard imports here are the stdlib + first-party app modules that have no
    third-party deps of their own (paths/vendor/redactionmodel locators).
  * No network, no model, no cleartext. The engine probe sends an EMPTY-text scan to the
    deterministic local bin and only inspects the response SHAPE — it never handles a real
    document and logs nothing.
  * Reuse the existing locators (redactionmodel.redact_cli_path / vendor.bundled_tool /
    paths.data_dir) rather than re-deriving paths — one source of truth.
"""

import os
import sys
from pathlib import Path

# Min/max Python the pilot targets (CI runs 3.11/3.12; the embedded CPython in the MSI
# matches). Older than 3.11 misses syntax/stdlib the app uses; we only WARN past 3.12.
_MIN_PY = (3, 11)
_OK_PY = {(3, 11), (3, 12)}

# ANSI colours, auto-disabled when stdout isn't a TTY (a redirected/`run.bat`-captured
# log stays clean) or when NO_COLOR is set (https://no-color.org). Windows 10+ terminals
# understand ANSI; we degrade to plain marks if not.
def _use_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001 - a weird stdout must never crash the doctor
        return False


_COLOUR = _use_colour()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOUR else s


# A single check's result. `critical` gates the exit code; a non-critical FAIL is a
# WARNING (printed amber, never flips the exit code) — e.g. OCR / WebView2 / pywebview.
class Result:
    __slots__ = ("name", "ok", "critical", "detail", "fix")

    def __init__(self, name, ok, critical, detail="", fix=""):
        self.name = name
        self.ok = bool(ok)
        self.critical = bool(critical)
        self.detail = detail
        self.fix = fix


def _try_import(modname: str):
    """Import `modname`, returning (module_or_None, error_str_or_None). NEVER raises —
    the whole point of the doctor is to survive a missing/broken dependency."""
    try:
        mod = __import__(modname)
        return mod, None
    except Exception as e:  # noqa: BLE001 - report ANY import failure, never crash
        return None, f"{type(e).__name__}: {e}"


# ----------------------------------------------------------------- checks ----
def check_python() -> Result:
    v = sys.version_info
    cur = (v.major, v.minor)
    if cur in _OK_PY:
        return Result("Python version", True, True, detail=f"Python {v.major}.{v.minor}.{v.micro}")
    if cur >= _MIN_PY:
        # Newer than tested — likely fine, but flag it as a non-blocking note.
        return Result(
            "Python version", True, False,
            detail=f"Python {v.major}.{v.minor}.{v.micro} (tested on 3.11 / 3.12)",
            fix="The app targets Python 3.11 or 3.12. Newer usually works; if you hit an "
                "odd error, install 3.12.",
        )
    return Result(
        "Python version", False, True,
        detail=f"Python {v.major}.{v.minor}.{v.micro} is too old",
        fix="Install Python 3.11 or 3.12 from python.org and run the app with it.",
    )


def check_app_importable() -> Result:
    """The "No module named app" preempt: can `import app` resolve from here?"""
    mod, err = _try_import("app")
    if mod is not None:
        return Result("Can import 'app'", True, True, detail="the app package resolves")
    return Result(
        "Can import 'app'", False, True,
        detail=err or "import failed",
        fix="Run from the repo root with PYTHONPATH set, e.g. `set PYTHONPATH=.` then "
            "`python -m app.serve` — or just use run.bat, which does this for you.",
    )


# (module-name, import-name, critical?, human-fix-hint). The import-name differs from the
# pip name for a couple (pymupdf -> fitz, python-docx -> docx).
_REQUIRED_DEPS = (
    ("fastapi", "fastapi", True, "the web server"),
    ("uvicorn", "uvicorn", True, "the web server"),
    ("pymupdf", "fitz", True, "PDF reading + the in-app sample document"),
    ("python-docx", "docx", True, "Word (.docx) extraction"),
    ("openpyxl", "openpyxl", True, "spreadsheet extraction"),
    ("httpx", "httpx", True, "the in-process web client"),
    ("pillow", "PIL", True, "image handling (OCR / preview)"),
)

# Optional deps: a FAIL here is a WARNING only (never gates the exit code).
_OPTIONAL_DEPS = (
    ("pywebview", "webview", "the native desktop window (dev can use the browser instead)"),
)


def check_deps() -> list:
    out = []
    for pip_name, import_name, critical, why in _REQUIRED_DEPS:
        mod, err = _try_import(import_name)
        if mod is not None:
            out.append(Result(f"Dependency: {pip_name}", True, critical, detail="installed"))
        else:
            out.append(Result(
                f"Dependency: {pip_name}", False, critical,
                detail=f"missing — needed for {why}",
                fix=f"Install it: `pip install -r requirements.txt` (or `pip install {pip_name}`).",
            ))
    for pip_name, import_name, why in _OPTIONAL_DEPS:
        mod, _err = _try_import(import_name)
        if mod is not None:
            out.append(Result(f"Optional: {pip_name}", True, False, detail="installed"))
        else:
            out.append(Result(
                f"Optional: {pip_name}", False, False,
                detail=f"not installed — {why}",
                fix=f"Optional. Install it only if you want {why}: `pip install {pip_name}`.",
            ))
    return out


def check_engine() -> Result:
    """The "Tool offline" preempt: locate the redact-cli bin via the SAME locator the app
    uses, then actually INVOKE it (an empty-text scan) and confirm it answers with the
    expected contract. Reusing redactionmodel keeps the resolution order identical to the
    running app, so a green doctor means a green redaction page."""
    try:
        from . import redactionmodel
    except Exception as e:  # noqa: BLE001 - even importing the bridge must not crash us
        return Result(
            "Redaction engine", False, True,
            detail=f"could not load the engine bridge ({type(e).__name__})",
            fix="This is unusual — make sure the app files are intact and try again.",
        )
    path = None
    try:
        path = redactionmodel.redact_cli_path()
    except Exception:  # noqa: BLE001 - a locator failure is just "not found"
        path = None
    if not path:
        return Result(
            "Redaction engine", False, True,
            detail="redact-cli not found (env / vendor\\core\\ / PATH)",
            fix="Build it: `cargo build -p redact-cli --release` (then it's at "
                "core\\target\\release\\redact-cli.exe), or drop redact-cli.exe into "
                "vendor\\core\\. The app still runs without it — only redaction is paused.",
        )
    # Found the bin — now PROVE it actually responds. scan("") drives the real bin with an
    # empty document: deterministic, touches no matter data, returns the contract envelope
    # (or a structured {"error":...} the bridge maps from a broken bin). NEVER raises.
    try:
        resp = redactionmodel.scan("")
    except Exception as e:  # noqa: BLE001 - the bridge shouldn't raise, but be safe
        resp = {"error": f"{type(e).__name__}"}
    if isinstance(resp, dict) and "error" in resp:
        return Result(
            "Redaction engine", False, True,
            detail=f"found at {path} but it did not respond correctly",
            fix="The engine binary is present but couldn't run a test scan. Rebuild it "
                "(`cargo build -p redact-cli --release`) or replace redact-cli.exe in "
                "vendor\\core\\.",
        )
    return Result("Redaction engine", True, True, detail=f"ready ({path})")


def check_fts5() -> Result:
    """FTS5 is what powers the data-room full-text search (the `chunks MATCH ?` path).
    app.db falls back to pysqlite3 when the stock build lacks it."""
    mod, err = _try_import("app.db")
    if mod is None:
        return Result(
            "Full-text search (FTS5)", False, True,
            detail=f"could not load app.db ({err})",
            fix="Fix the 'Can import app' / dependency rows above first.",
        )
    try:
        from .db import fts5_available
        ok = bool(fts5_available())
    except Exception as e:  # noqa: BLE001 - never crash on a probe
        return Result(
            "Full-text search (FTS5)", False, True,
            detail=f"probe failed ({type(e).__name__})",
            fix="Your SQLite build may lack FTS5. Install pysqlite3-binary: "
                "`pip install pysqlite3-binary`.",
        )
    if ok:
        return Result("Full-text search (FTS5)", True, True, detail="available")
    return Result(
        "Full-text search (FTS5)", False, True,
        detail="this SQLite build has no FTS5",
        fix="Install the bundled SQLite with FTS5: `pip install pysqlite3-binary` "
            "(app/db.py uses it automatically).",
    )


def check_data_dir() -> Result:
    """The per-matter store + exports live here; if it isn't writable, indexing and saving
    a redacted copy both fail. Reuse paths.data_dir() (honours LAWDATAMAN_DATA_DIR)."""
    try:
        from .paths import data_dir
    except Exception as e:  # noqa: BLE001
        return Result(
            "Data folder writable", False, True,
            detail=f"could not resolve the data folder ({type(e).__name__})",
            fix="Fix the 'Can import app' row above first.",
        )
    try:
        d = data_dir()
    except Exception as e:  # noqa: BLE001 - a mkdir failure surfaces here
        return Result(
            "Data folder writable", False, True,
            detail=f"could not create the data folder ({type(e).__name__})",
            fix="Set LAWDATAMAN_DATA_DIR to a folder you can write to.",
        )
    probe = Path(d) / ".doctor-write-probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except Exception as e:  # noqa: BLE001 - permission / disk error
        return Result(
            "Data folder writable", False, True,
            detail=f"{d} is not writable ({type(e).__name__})",
            fix="Pick a writable location with LAWDATAMAN_DATA_DIR, or fix the folder's "
                "permissions.",
        )
    return Result("Data folder writable", True, True, detail=str(d))


def check_optional_tools() -> list:
    """Tesseract (OCR of scanned PDFs) + WebView2 (the native window on Windows). Both are
    OPTIONAL — absent = a WARNING, never a failure."""
    out = []
    # Tesseract via the shared bundled-tool locator (env / vendor / PATH).
    tess = None
    try:
        from .vendor import bundled_tool
        tess = bundled_tool("tesseract")
    except Exception:  # noqa: BLE001
        tess = None
    if tess:
        out.append(Result("Optional: Tesseract (OCR)", True, False, detail=str(tess)))
    else:
        out.append(Result(
            "Optional: Tesseract (OCR)", False, False,
            detail="not found — scanned-PDF OCR redaction is unavailable",
            fix="Optional. Install Tesseract and put it on PATH (or in vendor\\tesseract\\) "
                "only if you need to redact scanned/image PDFs.",
        ))
    # WebView2 is a Windows-only concern (the native window's renderer). On non-Windows we
    # skip it entirely rather than report a misleading miss.
    if os.name == "nt":
        wv2 = _webview2_present()
        if wv2:
            out.append(Result("Optional: WebView2 (Windows)", True, False, detail="present"))
        else:
            out.append(Result(
                "Optional: WebView2 (Windows)", False, False,
                detail="the Edge WebView2 runtime was not detected",
                fix="The native window needs the Evergreen WebView2 runtime (preinstalled on "
                    "Windows 11; a free Microsoft download otherwise). The browser still works.",
            ))
    return out


def _webview2_present() -> bool:
    """Best-effort detection of the Edge WebView2 runtime on Windows — read-only, never
    raises. Checks the Evergreen registry keys (per-machine + per-user). A miss is only a
    WARNING, so a false negative is harmless."""
    if os.name != "nt":
        return False
    try:
        import winreg  # type: ignore  # Windows-only stdlib
    except Exception:  # noqa: BLE001
        return False
    keys = (
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
    )
    for hive, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as k:
                val, _ = winreg.QueryValueEx(k, "pv")
                if val and str(val) not in ("", "0.0.0.0"):
                    return True
        except OSError:
            continue
        except Exception:  # noqa: BLE001 - any registry oddity == "not detected"
            continue
    return False


def run_checks() -> list:
    """Run every check in order and return the flat list of Results. Order = the
    dependency order a tester resolves them: Python -> import app -> deps -> engine ->
    FTS5 -> data dir -> optional tools."""
    results = [check_python(), check_app_importable()]
    results.extend(check_deps())
    results.append(check_engine())
    results.append(check_fts5())
    results.append(check_data_dir())
    results.extend(check_optional_tools())
    return results


def format_report(results: list) -> str:
    """Render the green/red table + the per-row fixes for any failing row. Pure (returns a
    string) so a test can assert on it without capturing stdout."""
    lines = []
    lines.append("")
    lines.append(_c("1", "Lawbat setup doctor"))
    lines.append("=" * 60)
    name_w = max((len(r.name) for r in results), default=10)
    for r in results:
        if r.ok:
            mark = _c("32", "PASS")
        elif r.critical:
            mark = _c("31", "FAIL")
        else:
            mark = _c("33", "WARN")
        detail = f"  {r.detail}" if r.detail else ""
        lines.append(f"  [{mark}] {r.name.ljust(name_w)}{detail}")
    # Per-row fixes for everything that isn't a clean PASS.
    problems = [r for r in results if not r.ok]
    if problems:
        lines.append("")
        lines.append(_c("1", "How to fix:"))
        for r in problems:
            tag = "FIX " if r.critical else "NOTE"
            lines.append(f"  {_c('33', tag)} {r.name}: {r.fix or 'see above'}")
    lines.append("=" * 60)
    crit_fail = [r for r in results if (not r.ok and r.critical)]
    warn = [r for r in results if (not r.ok and not r.critical)]
    if crit_fail:
        lines.append(_c("31",
            f"NOT READY — {len(crit_fail)} critical check(s) failed. Fix the items above, "
            "then run the doctor again."))
    elif warn:
        lines.append(_c("33",
            f"READY (with {len(warn)} optional item(s) not installed). Core features work."))
    else:
        lines.append(_c("32", "READY — all checks passed."))
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    results = run_checks()
    print(format_report(results))
    # Exit 0 iff every CRITICAL check passed (optional WARNs never gate).
    crit_fail = any((not r.ok and r.critical) for r in results)
    return 1 if crit_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
