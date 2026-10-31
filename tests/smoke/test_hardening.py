"""
Hardening smoke tests: pre-auth body-size ceiling, UI JS parse gate, setup
doctor (split from tests/test_smoke.py).
"""

import os
import tempfile
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, AppState  # noqa: E402
from tests.smoke._helpers import (  # noqa: E402
    _client,
)


def test_doctor_runs_and_reports_without_crashing():
    """The setup doctor (app/doctor.py) runs end-to-end, returns a Result per check, and
    renders a report WITHOUT crashing — including when a required dependency is missing
    (its whole job is to diagnose that, so it must guard every import). We monkeypatch the
    doctor's own _try_import to simulate a missing 'fitz' and confirm:
      * run_checks() never raises and returns a list of Results,
      * the missing dep is reported as a critical FAIL (so main() would exit non-zero),
      * format_report() renders a string with the FAIL + a fix line,
      * main() returns 1 (non-zero) when a critical check fails.
    Deterministic + offline (the engine probe is a no-op empty scan; no network)."""
    from app import doctor

    # 1. The doctor runs cleanly in this (well-formed) environment.
    results = doctor.run_checks()
    assert isinstance(results, list) and results, "run_checks returned no results"
    names = [r.name for r in results]
    # The load-bearing checks are all present (the "No module named app" + "Tool offline" +
    # FTS5 + data-dir preempts).
    assert "Can import 'app'" in names
    assert "Redaction engine" in names
    assert "Full-text search (FTS5)" in names
    assert "Data folder writable" in names
    # format_report never raises and produces a non-empty report.
    report = doctor.format_report(results)
    assert isinstance(report, str) and "Lawbat setup doctor" in report

    # 2. Simulate a MISSING required dependency by monkeypatching _try_import so 'fitz'
    # (pymupdf) "fails to import". The doctor must report it as a critical FAIL and NOT
    # crash — proving it survives the very condition it exists to diagnose.
    real_try = doctor._try_import

    def fake_try(modname):
        if modname == "fitz":
            return None, "ModuleNotFoundError: No module named 'fitz'"
        return real_try(modname)

    doctor._try_import = fake_try
    try:
        results2 = doctor.run_checks()          # must not raise
        report2 = doctor.format_report(results2)  # must not raise
    finally:
        doctor._try_import = real_try

    pymupdf = [r for r in results2 if r.name == "Dependency: pymupdf"]
    assert pymupdf, "pymupdf check row missing"
    assert pymupdf[0].ok is False and pymupdf[0].critical is True, \
        "a missing required dep must be a critical FAIL"
    assert "FAIL" in report2 and "pip install" in report2, \
        "the report must show the FAIL and the exact fix"

    # 3. main() returns non-zero when a critical check fails, 0 when none do. Drive main()
    # under the monkeypatch and confirm the exit gate.
    import io
    import contextlib

    doctor._try_import = fake_try
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = doctor.main()
    finally:
        doctor._try_import = real_try
    assert rc == 1, "main() must exit non-zero when a critical check fails"


def test_pre_auth_body_size_ceiling_rejects_before_processing():
    """#20: an over-ceiling DECLARED Content-Length is 413'd BEFORE the body is read/parsed
    and BEFORE _require_token — a pre-auth memory-exhaustion pre-filter. A tiny body with a
    spoofed large Content-Length header exercises the declared-size check without sending GB.
    A request WITHOUT the token still gets 413 first (the filter precedes auth) — proving it
    short-circuits before the handler buffers the body."""
    from app import web

    over = web._MAX_REQUEST_BODY_BYTES + 1
    # Tokened client: an over-ceiling declared length is rejected with 413.
    state = AppState()
    c = TestClient(create_app(state))
    c.headers.update({"X-DRR-Token": state.token})
    r = c.post("/api/redaction/scan", json={"text": "x"},
               headers={"Content-Length": str(over)})
    assert r.status_code == 413, ("over-ceiling Content-Length must be 413'd", r.status_code)
    assert "too large" in r.json().get("error", ""), r.text

    # UN-tokened client: the body-size filter runs BEFORE _require_token, so an over-ceiling
    # request is 413'd (not 403) — it never reaches auth, never buffers the body.
    untokened = TestClient(create_app(AppState()))
    r2 = untokened.post("/api/redaction/scan", json={"text": "x"},
                        headers={"Content-Length": str(over)})
    assert r2.status_code == 413, ("the size filter must precede auth", r2.status_code)

    # A request AT the ceiling (declared == ceiling, not over) is NOT rejected by the filter
    # (it falls through to the normal handler / per-field caps).
    r3 = c.post("/api/redaction/scan", json={"text": "x"},
                headers={"Content-Length": str(web._MAX_REQUEST_BODY_BYTES)})
    assert r3.status_code != 413, ("at-ceiling must not be rejected by the size filter",
                                   r3.status_code)


def test_normal_requests_unaffected_by_body_guard():
    """#20: the additive memory guard must NOT regress any NORMAL request. A normal scan,
    scan-file, pdf-scan, and batch all pass the body-size filter (their real bodies are far
    under the ceiling) — they return their usual status (200, or a graceful 4xx/503 when the
    redaction bin is absent), NEVER a 413 from the filter. A request with NO body / no
    Content-Length (a GET) also works — the filter only rejects a PRESENT, over-ceiling
    header, never a missing one."""
    import base64 as _b64
    c = _client()

    # GET with no body / no Content-Length -> works (the filter never rejects a missing header).
    assert c.get("/api/state").status_code == 200

    # A small upload-style base64 (a few bytes) for scan-file / pdf-scan: real, well under cap.
    tiny_b64 = _b64.b64encode(b"hello world").decode("ascii")

    # None of these should be a 413 (the filter must not touch a normal-sized body); the exact
    # 2xx/4xx/503 depends on whether the redaction bin is present, which is fine.
    for path, body in (
        ("/api/redaction/scan", {"text": "Mr Smith called."}),
        ("/api/redaction/scan-file", {"filename": "a.txt", "data_b64": tiny_b64}),
        ("/api/redaction/pdf-scan", {"filename": "a.pdf", "data_b64": tiny_b64}),
        ("/api/reidrisk/batch", {"docs": [{"name": "A", "text": "Mr Smith in California."}]}),
    ):
        r = c.post(path, json=body)
        assert r.status_code != 413, (f"{path} normal request must not be 413'd by the "
                                      f"body-size guard", r.status_code, r.text[:100])


def test_ui_js_parse_gate_node_check():
    """TODO §8 JS parse gate: every served UI JS file must PARSE under `node --check` — the
    local twin of the CI step in .github/workflows/ci.yml. The page tests are
    substring-only, the exact class of gap that once let a stray byte into redaction.js.
    NOTE: redaction.state.js DELIBERATELY carries one raw NUL byte INSIDE a string literal
    (a collision-proof grouping-key separator, formerly in redaction.js before the split);
    that is valid JavaScript and `node --check` accepts it, so the file is checked AS-IS
    (never modified).

    redaction.js was split into ordered fragments (app.ui_manifest.REDACTION_JS_PARTS) at
    its own section-comment boundaries — together they form ONE outer IIFE, so most are NOT
    independently valid JavaScript (only the ASSEMBLED concatenation is). This checks EVERY
    standalone app/ui/*.js file individually (base.js/home.js/dataroom.js/reidrisk.js — the
    files node --check over app/ui/*.js used to cover one-for-one) AND separately node
    --checks the ASSEMBLED script for every page (base.js + that page's JS, in the exact
    order app.web._build_*_page() concatenates them) — the redaction page's assembled
    script is base.js + all 11 fragments. SKIPS (does not fail) if `node` is unavailable on
    the runner — the CI gate covers it wherever node exists. Deterministic + air-gapped (no
    network)."""
    import shutil
    import subprocess

    from app.ui_manifest import BASE_JS, REDACTION_JS_PARTS

    node = shutil.which("node")
    ui_dir = Path(__file__).resolve().parent.parent.parent / "app" / "ui"
    all_files = sorted(ui_dir.glob("*.js"))
    # The gate must never silently pass on an empty set (a moved dir would blind it).
    assert all_files, f"no app/ui/*.js files found under {ui_dir} — the parse gate has nothing to check"

    frag_names = set(REDACTION_JS_PARTS)
    standalone = [f for f in all_files if f.name not in frag_names]
    assert BASE_JS in [f.name for f in standalone], "base.js must exist and be standalone"
    # every fragment named in the manifest must actually be on disk (else the gate below
    # would silently check fewer fragments than the page assembles).
    for frag in REDACTION_JS_PARTS:
        assert (ui_dir / frag).exists(), f"missing redaction fragment: {frag}"

    if not node:
        print("  (skip) node not available — the CI parse gate covers this where node exists")
        return

    def _check(path_str, label):
        proc = subprocess.run(
            [node, "--check", path_str],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, (
            f"UI JS parse gate: {label} failed node --check — a served page script does "
            "not parse:\n" + proc.stdout + "\n" + proc.stderr
        )

    # 1) every standalone file, individually — exactly the pre-split gate's shape.
    for f in standalone:
        _check(str(f), f.name)

    # 2) the assembled script per page — base.js + that page's JS, in shipped order.
    for label, filenames in (
        ("redaction (base.js + 11 fragments)", [BASE_JS, *REDACTION_JS_PARTS]),
        ("home (base.js + home.js)", [BASE_JS, "home.js"]),
        ("dataroom (base.js + dataroom.js)", [BASE_JS, "dataroom.js"]),
        ("reidrisk (base.js + reidrisk.js)", [BASE_JS, "reidrisk.js"]),
    ):
        text = "\n".join((ui_dir / fn).read_text(encoding="utf-8") for fn in filenames)
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8")
        tf.write(text)
        tf.close()
        try:
            _check(tf.name, f"assembled: {label}")
        finally:
            Path(tf.name).unlink(missing_ok=True)
