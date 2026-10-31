"""
Smoke-check the ASSEMBLED Windows bundle BEFORE the MSI is built.

This is the de-risking centrepiece: it runs under the *embedded* interpreter from
the staged payload (NOT the dev/CI Python) so it proves the thing we actually ship
works. It asserts three things that have historically broken a frozen/embedded
build:

  1. Every third-party import the app needs loads (fastapi, uvicorn, fitz/PyMuPDF,
     openpyxl, docx, pptx, extract_msg, and pywebview import-only — no GUI).
  2. SQLite FTS5 actually works (CREATE VIRTUAL TABLE ... USING fts5 + a MATCH
     query). This is the single most common embedded-Python failure (app/db.py
     has a pysqlite3 fallback; this check confirms whichever driver is present
     really does FTS5).
  3. The app server boots on a localhost socket and GET /api/state returns 200,
     headless — no pywebview window required.

Exit non-zero on ANY failure so the CI job (and a human on a Windows box) fails
loud instead of shipping a broken MSI.

HOW IT RUNS
-----------
Invoke with the EMBEDDED interpreter and the staged install dir on sys.path, e.g.

    build\\stage\\DataRoomReview\\python\\python.exe build\\smoke_check.py ^
        --install-dir build\\stage\\DataRoomReview

The embedded ._pth already adds the install dir + site-packages, so imports
resolve from the bundle. --install-dir is belt-and-braces (lets you run the check
standalone) and is also used to point at the staged app/desktop source.

Local-only: binds 127.0.0.1 on an ephemeral port, makes ONE request to itself,
and shuts down. No network egress, no display.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

FAILURES: list[str] = []


def check(name: str, fn) -> None:
    """Run one check; record (don't raise) so we report every failure at once."""
    try:
        fn()
        print(f"  [ OK ] {name}")
    except Exception as exc:  # noqa: BLE001 - report-all, fail at the end
        FAILURES.append(f"{name}: {exc!r}")
        print(f"  [FAIL] {name}: {exc!r}")


# --- 1. imports -------------------------------------------------------------
# (module, attribute-to-touch-or-None). Touching an attribute forces the native
# extension to actually initialise, not just resolve the name.
_IMPORTS = [
    ("fastapi", "FastAPI"),
    ("uvicorn", "Config"),
    ("fitz", "open"),            # PyMuPDF — the native extension that most often
    ("openpyxl", "load_workbook"),
    ("docx", "Document"),        # python-docx
    ("pptx", "Presentation"),    # python-pptx
    ("extract_msg", None),       # GPL .msg parser (C-build dep on some platforms)
    ("pydantic", "BaseModel"),
    ("starlette", None),
]


def _check_imports() -> None:
    for mod, attr in _IMPORTS:
        m = __import__(mod, fromlist=["_"] if attr else [])
        if attr and not hasattr(m, attr):
            raise AssertionError(f"{mod} imported but missing attr {attr!r}")


def _check_pywebview_import_only() -> None:
    # Import only — never start the GUI in a headless check. On a CI runner with
    # no display, `import webview` must still succeed (the window comes later).
    import webview  # noqa: F401


# --- 2. FTS5 really works ---------------------------------------------------
def _check_fts5() -> None:
    # Use the app's own driver selection so we test exactly what ships.
    from app.db import FTS5_DRIVER, fts5_available, sqlite3

    if not fts5_available():
        raise AssertionError(f"FTS5 unavailable; driver={FTS5_DRIVER!r}")
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE VIRTUAL TABLE docs USING fts5(body)")
        con.executemany(
            "INSERT INTO docs(body) VALUES (?)",
            [("the quick brown fox",), ("lorem ipsum dolor",)],
        )
        rows = con.execute(
            "SELECT body FROM docs WHERE docs MATCH ?", ("quick",)
        ).fetchall()
        if len(rows) != 1 or "quick" not in rows[0][0]:
            raise AssertionError(f"FTS5 MATCH returned unexpected rows: {rows!r}")
    finally:
        con.close()
    print(f"         (FTS5 driver: {FTS5_DRIVER})")


# --- 3. server boots + /api/state == 200 ------------------------------------
def _check_server_boots() -> None:
    import socket

    import uvicorn

    from app.web import AppState, create_app

    app = create_app(AppState())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    config = uvicorn.Config(app, log_level="warning")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()

    try:
        url = f"http://127.0.0.1:{port}/api/state"
        deadline = time.time() + 20
        last = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    if resp.status != 200:
                        raise AssertionError(f"/api/state -> HTTP {resp.status}")
                    body = json.loads(resp.read())
                    if "fts5" not in body or "version" not in body:
                        raise AssertionError(f"/api/state body unexpected: {body!r}")
                    print(f"         (/api/state ok; version={body.get('version')}, fts5={body.get('fts5')})")
                    return
            except (urllib.error.URLError, ConnectionError) as exc:
                last = exc
                time.sleep(0.2)
        raise AssertionError(f"server did not answer in time: {last!r}")
    finally:
        server.should_exit = True


# --- 4. OCR bundle (optional feature) ---------------------------------------
def _check_ocr_bundle() -> None:
    """If the OCR feature is staged, prove it works END-TO-END from the bundle: the
    tesseract binary loads (its DLLs resolve), and the bundled tessdata is locatable.
    Both are FATAL (they catch a broken bundle — e.g. the wrong tessdata path or missing
    DLLs). A real OCR round-trip is attempted but only WARNS (font/accuracy can vary).
    If OCR isn't staged (a base-only build), this is a clean skip."""
    from app import ocr

    exe = ocr.tesseract_path()
    if not exe:
        print("         (OCR feature not staged — skipped)")
        return
    r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise AssertionError(f"tesseract --version failed ({r.returncode}); DLLs missing? {r.stderr[:160]!r}")
    td = ocr.tessdata_dir()
    if td is None:
        raise AssertionError(
            "tesseract is staged but no bundled tessdata was found "
            "(expected vendor/tesseract/tessdata/*.traineddata)"
        )
    ver = (r.stdout or r.stderr or "").splitlines()[:1]
    print(f"         (tesseract OK: {ver[0] if ver else '?'}; tessdata: {td})")
    # Best-effort end-to-end OCR — WARN only (rendering/accuracy is not a bundle defect).
    try:
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (680, 160), "white")
        draw = ImageDraw.Draw(img)
        font = None
        try:
            from PIL import ImageFont

            for cand in ("arial.ttf", "DejaVuSans.ttf"):
                try:
                    font = ImageFont.truetype(cand, 64)
                    break
                except OSError:
                    continue
        except Exception:  # noqa: BLE001
            font = None
        draw.text((20, 45), "HELLO 12345", fill="black", font=font)
        p = Path(tempfile.mkdtemp(prefix="ldm-ocrsmoke-")) / "t.png"
        img.save(p)
        text = " ".join(t for _, t in ocr.ocr_image(str(p))).strip()
        if text:
            print(f"         (OCR round-trip read: {text[:32]!r})")
        else:
            print("         [warn] OCR round-trip produced no text (font/accuracy?) — binary+tessdata still OK")
    except Exception as exc:  # noqa: BLE001 - the fatal checks already passed
        print(f"         [warn] OCR round-trip skipped: {exc!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--install-dir",
        default=None,
        help="Staged install root (the dir containing app\\ and desktop\\). "
        "Prepended to sys.path so imports resolve from the bundle.",
    )
    args = ap.parse_args()

    if args.install_dir:
        root = str(Path(args.install_dir).resolve())
        if root not in sys.path:
            sys.path.insert(0, root)

    # Isolate any app-data the server touches into a throwaway dir (never write
    # into a real install or a developer's %APPDATA%).
    import os

    os.environ.setdefault(
        "LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-bundle-smoke-")
    )
    os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

    print(f"Bundle smoke-check under: {sys.executable}")
    print(f"Python: {sys.version}")
    print("--- 1. imports ---")
    check("third-party imports", _check_imports)
    check("pywebview import-only", _check_pywebview_import_only)
    print("--- 2. sqlite fts5 ---")
    check("FTS5 create+match", _check_fts5)
    print("--- 3. server boot ---")
    check("server boots; GET /api/state == 200", _check_server_boots)
    print("--- 4. OCR bundle (optional) ---")
    check("OCR bundle (tesseract binary + tessdata)", _check_ocr_bundle)

    print()
    if FAILURES:
        print(f"SMOKE CHECK FAILED ({len(FAILURES)} failure(s)):")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("SMOKE CHECK OK — bundle is launchable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
