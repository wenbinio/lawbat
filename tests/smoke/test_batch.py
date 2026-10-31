"""
Smoke tests for BATCH (folder) redaction + the TERMS import feature (increment 1).

TERMS import: the pure parser (redactionmodel.parse_imported_terms) + the /import-terms route.
Batch mode: the enumeration + confinement policy (app/batchredact.py) and the batch routes
(scan-file / read-file / export) exercised with a STUBBED engine so the surface is covered
even when the real redact-cli bin isn't present. The per-file review-STATE ISOLATION invariant
(one file's decisions never leak into another) is proven by the committed node harness
tests/redaction_batch.test.js. All deterministic + air-gapped; no cleartext is logged.
"""

import base64
import json
import logging
import tempfile
from pathlib import Path

from ._helpers import _client, _assembled_redaction_js_path


# ============================================================== TERMS import (pure) ====
from ._helpers import _prepared_result, _prepared_root

def test_parse_imported_terms_csv_cells_and_dedupe():
    from app import redactionmodel as rm
    # Every non-empty CELL is a term; case-insensitive dedupe keeps first casing; 1-char dropped.
    data = b'Alice Tan,Bob Lee\n"Chan, Wei",alice tan\nx\n,\n'
    r = rm.parse_imported_terms("names.csv", data)
    assert r["terms"] == ["Alice Tan", "Bob Lee", "Chan, Wei"]
    assert r["imported"] == 3
    assert r["duplicates"] == 1      # "alice tan" dup of "Alice Tan"
    assert r["dropped"] == 1         # "x" is below MIN_TERM_CHARS


def test_parse_imported_terms_txt_lines_and_caps():
    from app import redactionmodel as rm
    over = "Z" * (rm.MAX_TERM_BYTES + 1)   # exceeds the byte cap -> dropped, never truncated
    data = ("Peter Schwicht\n" + over + "\n\n  Olivia  \n").encode("utf-8")
    r = rm.parse_imported_terms("list.txt", data)
    assert r["terms"] == ["Peter Schwicht", "Olivia"]   # blank line ignored; over-long dropped
    assert r["dropped"] == 1
    # Count cap: excess past MAX_TERMS is counted as dropped, not silently swallowed.
    many = "\n".join(f"name{i}" for i in range(rm.MAX_TERMS + 5)).encode()
    r2 = rm.parse_imported_terms("big.txt", many)
    assert r2["imported"] == rm.MAX_TERMS and r2["dropped"] == 5


def test_parse_imported_terms_no_cleartext_logged():
    from app import redactionmodel as rm
    # A term is a party NAME — the parser must never log it. Capture the module logger.
    records = []

    class _Grab(logging.Handler):
        def emit(self, rec):
            records.append(self.format(rec))
    h = _Grab()
    rm.log.addHandler(h)
    try:
        secret = "Massimo Confidential Greco"
        r = rm.parse_imported_terms("n.txt", (secret + "\n").encode())
        assert r["terms"] == [secret]
    finally:
        rm.log.removeHandler(h)
    assert not any(secret in line for line in records), "a term must never be logged"


def test_parse_imported_terms_never_raises_on_garbage():
    from app import redactionmodel as rm
    for bad in (None, 123, b"\xff\xfe\x00bad bytes"):
        r = rm.parse_imported_terms("x.csv", bad if isinstance(bad, (bytes, bytearray)) else b"")
        assert isinstance(r, dict) and "terms" in r


def test_import_terms_route_parses_and_reports():
    c = _client()
    data = b"Alice Tan\nBob Lee\nalice tan\n"
    b64 = base64.b64encode(data).decode()
    r = c.post("/api/redaction/import-terms", json={"filename": "list.csv", "data_b64": b64})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] is True
    assert d["terms"] == ["Alice Tan", "Bob Lee"] and d["duplicates"] == 1
    # A missing body is a clean 400, not a 500.
    assert c.post("/api/redaction/import-terms", json={}).status_code == 400


# ================================================================ enumeration / caps ====
def _mkfolder():
    d = tempfile.mkdtemp(prefix="ldm-batch-")
    (Path(d) / "memo.txt").write_text("Contact jane@acme.example about it.")
    (Path(d) / "deed.pdf").write_bytes(b"%PDF-1.4 test")
    (Path(d) / "ignore.png").write_bytes(b"\x89PNG")          # unsupported ext
    (Path(d) / "sub").mkdir()
    (Path(d) / "sub" / "brief.docx").write_bytes(b"PK\x03\x04")   # nested, supported
    return d


def test_batch_enumerate_refuses_drive_root():
    from app import batchredact
    r = batchredact.enumerate_folder("/")
    assert r["ok"] is False and r["level"] == "refuse"
    assert batchredact.enumerate_folder("/does/not/exist")["ok"] is False


def test_batch_enumerate_ext_filter_and_recursion():
    from app import batchredact
    d = _mkfolder()
    r = batchredact.enumerate_folder(d)
    assert r["ok"] is True
    rels = sorted(f["rel"] for f in r["files"])
    assert rels == ["deed.pdf", "memo.txt", "sub/brief.docx"]   # .png excluded
    assert r["skipped"]["unsupported"] == 1
    assert r["count"] == 3


def test_batch_enumerate_excludes_symlink_escaping_the_folder():
    # A symlink INSIDE the folder pointing OUTSIDE must not be listed or size-counted —
    # reading it is refused anyway, but enumerating it would leak an out-of-folder file's
    # existence + size (review finding #3). Confinement is enforced at enumerate, not only read.
    import os
    from app import batchredact
    outside = tempfile.mkdtemp(prefix="ldm-outside-")
    secret = Path(outside) / "secret.pdf"
    secret.write_bytes(b"%PDF-1.4 " + b"x" * 5000)   # a distinctive size
    d = _mkfolder()
    link = Path(d) / "leak.pdf"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        return  # platform without symlink support (skip, don't fail)
    r = batchredact.enumerate_folder(d)
    assert r["ok"] is True
    rels = {f["rel"] for f in r["files"]}
    assert "leak.pdf" not in rels                      # not listed
    assert all(f.get("size", 0) != 5009 for f in r["files"])    # target size not counted
    assert r["total_bytes"] < 5009                     # out-of-folder bytes never aggregated


def test_parse_imported_terms_rejects_interior_control_chars():
    # A NUL / C0 control INSIDE a term is corrupt import data (finding #4): dropped, not
    # carried into the textarea. Consistent with the confinement rel control-char refusal.
    from app import redactionmodel as rm
    out = rm.parse_imported_terms("x.txt", b"Acme Corp\nBad\x00Term\nGood Name\nCtrl\x07Here")
    assert "Acme Corp" in out["terms"] and "Good Name" in out["terms"]
    assert not any("\x00" in t or "\x07" in t for t in out["terms"])
    assert out["dropped"] >= 2


def test_batch_enumerate_size_and_count_caps():
    from app import batchredact
    d = tempfile.mkdtemp(prefix="ldm-batch-cap-")
    (Path(d) / "big.txt").write_bytes(b"x" * 100)
    (Path(d) / "small.txt").write_bytes(b"ok")
    # Per-file size cap: shrink it so big.txt is skipped as oversize.
    orig = batchredact.MAX_FILE_BYTES
    try:
        batchredact.MAX_FILE_BYTES = 10
        r = batchredact.enumerate_folder(d)
        assert [f["name"] for f in r["files"]] == ["small.txt"]
        assert r["skipped"]["oversize"] == 1
    finally:
        batchredact.MAX_FILE_BYTES = orig
    # Count cap: truncated=True and the list is bounded.
    d2 = tempfile.mkdtemp(prefix="ldm-batch-count-")
    for i in range(5):
        (Path(d2) / f"f{i}.txt").write_text("x")
    orig_n = batchredact.MAX_FILES
    try:
        batchredact.MAX_FILES = 2
        r2 = batchredact.enumerate_folder(d2)
        assert r2["count"] == 2 and r2["truncated"] is True
    finally:
        batchredact.MAX_FILES = orig_n


def test_batch_resolve_confined_refuses_traversal():
    from app import batchredact
    d = _mkfolder()
    # A legitimate in-folder file resolves; a `..` escape / absolute path / bad ext does NOT.
    assert batchredact.resolve_confined(d, "memo.txt") is not None
    assert batchredact.resolve_confined(d, "sub/brief.docx") is not None
    assert batchredact.resolve_confined(d, "../etc/passwd") is None
    assert batchredact.resolve_confined(d, "/etc/passwd") is None
    assert batchredact.resolve_confined(d, "ignore.png") is None      # unsupported ext
    assert batchredact.resolve_confined(d, "nope.txt") is None        # not a file
    # An embedded NUL is refused before any resolve() (never a 500-class crash).
    assert batchredact.resolve_confined(d, "memo\x00.txt") is None


def test_batch_enumerate_route_and_confinement():
    c = _client()
    d = _mkfolder()
    r = c.post("/api/redaction/batch/enumerate", json={"folder": d})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 3
    # A refused root is a clean 400 with the honest reason.
    r2 = c.post("/api/redaction/batch/enumerate", json={"folder": "/"})
    assert r2.status_code == 400 and "error" in r2.json()


# ============================================================= scan-file / read-file ====
def _stub_engine(rm):
    """Install deterministic scan/apply stubs on app.redactionmodel; return restore()."""
    keys = ("extract_scan", "pdf_scan", "apply", "scan", "pdf_apply")
    saved = {k: getattr(rm, k) for k in keys}
    rm.extract_scan = lambda name, b64, opts=None: {
        "op": "extract_scan", "format": "txt", "text": "Contact [MASK] about it.",
        "warnings": [], "candidates": [{"value": "jane@acme.example", "recognizer": "email",
                                        "start": 8, "end": 25}], "summary": {}}
    rm.pdf_scan = lambda b64, opts=None: {
        "op": "pdf_scan", "candidates": [{"id": 0, "page": 1, "value": "x", "recognizer": "email"}],
        "summary": {}, "low_text": False, "unmapped_fonts": False}
    rm.apply = lambda text, accept, opts=None, replacement_style="redacted": {
        "op": "apply", "redacted": "Contact [REDACTED] about it.", "applied": 1, "stale": 0}
    rm.scan = lambda text, opts=None: {"op": "scan", "candidates": [], "summary": {}}
    rm.pdf_apply = lambda b64, ids=None, opts=None: {
        "op": "pdf_apply", "pdf_b64": base64.b64encode(b"%PDF-1.4 red").decode(),
        "redactions": 1, "could_not_remove": 0, "low_text": False, "unmapped_fonts": False,
        "cleaned": ["body"], "not_removed": ["attachments"]}

    def restore():
        for k, v in saved.items():
            setattr(rm, k, v)
    return restore


def test_batch_scan_file_route_happy_and_error():
    from app import redactionmodel as rm
    c = _client()
    d = _mkfolder()
    restore = _stub_engine(rm)
    try:
        # A supported text file scans -> findings count + kind.
        r = c.post("/api/redaction/batch/scan-file", json={"folder": d, "rel": "memo.txt"})
        assert r.status_code == 200, r.text
        d1 = r.json()
        assert d1["ok"] is True and d1["kind"] == "text" and d1["findings"] == 1
        # A confinement violation is a scan_failed error (not a crash), excluded from export.
        r2 = c.post("/api/redaction/batch/scan-file", json={"folder": d, "rel": "../secret.txt"})
        assert r2.status_code == 400 and r2.json().get("scan_failed") is True
    finally:
        restore()


def test_batch_read_file_route_confined():
    c = _client()
    d = _mkfolder()
    r = c.post("/api/redaction/batch/read-file", json={"folder": d, "rel": "deed.pdf"})
    assert r.status_code == 200, r.text
    dd = r.json()
    assert dd["ok"] is True and dd["kind"] == "pdf"
    assert base64.b64decode(dd["data_b64"]).startswith(b"%PDF")
    # traversal refused
    assert c.post("/api/redaction/batch/read-file",
                  json={"folder": d, "rel": "../x"}).status_code == 400


# ==================================================================== batch export ====
def test_batch_export_writes_outputs_and_summary_excludes_failures():
    from app import redactionroutes as routes, redactionmodel as rm
    from app.paths import exports_dir
    d = _mkfolder()
    restore = _stub_engine(rm)
    try:
        specs = [
            {"rel": "memo.txt", "kind": "text", "accept": [[8, 25]], "options": {}, "format": "txt"},
            {"rel": "deed.pdf", "kind": "pdf", "accept_ids": [0], "options": {}},
            {"rel": "gone.txt", "kind": "text", "accept": []},   # missing -> excluded + listed
        ]
        res = routes._run_batch_export(d, "MyMatter", specs, "R. Eviewer")
        assert res["ok"] is True and res["exported"] == 2
        assert [f["filename"] for f in res["failed"]] == ["gone.txt"]
        bd = exports_dir() / res["batch_dir"]
        names = sorted(p.name for p in bd.iterdir())
        # two redacted outputs + their per-file reports + the batch summary (json + txt)
        assert "memo.redacted.txt" in names and "deed.redacted.pdf" in names
        assert "batch-summary.report.json" in names and "batch-summary.report.txt" in names
        summ = json.loads((bd / res["summary_filename"]).read_text(encoding="utf-8"))
        assert summ["totals"]["files_exported"] == 2 and summ["totals"]["files_failed"] == 1
        assert summ["note"].startswith("workflow record")   # honest not-an-audit header
        # NO cleartext value leaks into the summary.
        assert "jane@acme.example" not in json.dumps(summ)
    finally:
        restore()


def test_batch_export_malformed_span_fails_that_file_only():
    from app import redactionroutes as routes, redactionmodel as rm
    d = _mkfolder()
    restore = _stub_engine(rm)
    try:
        specs = [
            # A MALFORMED accept span (a one-element pair) must fail THIS file with an honest
            # reason — never silently drop the span (which would under-redact the copy) and
            # never sink the rest of the batch.
            {"rel": "memo.txt", "kind": "text", "accept": [[8]], "options": {}, "format": "txt"},
            {"rel": "deed.pdf", "kind": "pdf", "accept_ids": [0], "options": {}},
        ]
        res = routes._run_batch_export(d, "MyMatter", specs, "R. Eviewer")
        # The PDF still exports; the text file is enumerated as failed with a span reason.
        assert res["exported"] == 1, res
        failed = {f["filename"]: f["error"] for f in res["failed"]}
        assert "memo.txt" in failed and "span" in failed["memo.txt"], failed
    finally:
        restore()


def test_batch_export_non_dict_spec_is_failed_not_skipped():
    from app import redactionroutes as routes, redactionmodel as rm
    d = _mkfolder()
    restore = _stub_engine(rm)
    try:
        # A non-dict entry must be ENUMERATED as failed (the docstring's "never silently
        # skipped" contract), not `continue`-dropped; the real file beside it still exports.
        specs = [
            "not-a-dict",
            {"rel": "memo.txt", "kind": "text", "accept": [[8, 25]], "options": {}, "format": "txt"},
        ]
        res = routes._run_batch_export(d, "MyMatter", specs, "R. Eviewer")
        assert res["exported"] == 1, res
        assert any(f["error"] == "malformed entry" for f in res["failed"]), res["failed"]
    finally:
        restore()


def test_batch_export_route_requires_reviewed_files():
    c = _client()
    d = _mkfolder()
    # An empty files list is a clean 400 (never force-exports / never writes an empty batch dir).
    r = c.post("/api/redaction/batch/export", json={"folder": d, "files": []})
    assert r.status_code == 400 and "error" in _prepared_result(r.json())
    r2 = c.post("/api/redaction/batch/export", json={"files": [{"rel": "x", "kind": "text"}]})
    assert r2.status_code == 400   # no folder



def test_build_batch_summary_aggregates_and_no_cleartext():
    from app import redactionreport as rr
    reps = [
        rr.build_report(
            original_filename="a.txt", original_sha256="aa", output_filename="a.redacted.txt",
            output_sha256="bb", engine_path=None, engine_sha256=None, options={"terms": ["x"]},
            findings=3, accepted=2, rejected=1, per_recognizer={"email": 2}, ocr_used=False,
            low_text=False, unmapped_fonts=False, could_not_remove=0, cleaned=[], not_removed=[],
            verification={"state": "no_residuals_detected", "classes": {}}, export_kind="text"),
        rr.build_report(
            original_filename="b.pdf", original_sha256="cc", output_filename="b.redacted.pdf",
            output_sha256="dd", engine_path=None, engine_sha256=None, options={}, findings=1,
            accepted=1, rejected=0, per_recognizer={}, ocr_used=False, low_text=False,
            unmapped_fonts=False, could_not_remove=1, cleaned=[], not_removed=[],
            verification={"state": "residuals_possible", "classes": {"email": 1}},
            export_kind="pdf"),
    ]
    s = rr.build_batch_summary(batch_name="M", reports=reps,
                               failed=[{"filename": "c.txt", "error": "could not read"}],
                               reviewer="Rev")
    assert s["schema"] == rr.BATCH_SCHEMA
    assert s["totals"] == {"files_exported": 2, "files_failed": 1, "findings": 4,
                           "accepted": 3, "rejected": 1, "could_not_remove": 1}
    assert s["verification"]["no_residuals_detected"] == 1
    assert s["verification"]["residuals_possible"] == 1
    # the term cleartext ("x") is reduced to a count in each per-file report, never carried here
    assert "\"x\"" not in json.dumps(s["files"])
    txt = rr.batch_summary_to_text(s)
    assert "batch summary" in txt.lower() and "could not read" in txt


# =================================================================== JS + page wiring ====
def test_batch_and_terms_import_wired_in_page():
    c = _client()
    page = c.get("/redaction").text
    # TERMS import affordance + BATCH panel controls ship in the page.
    assert 'id="termsImport"' in page
    assert 'id="chooseFolderBtn"' in page and 'id="batchPanel"' in page
    assert 'id="batchExportBtn"' in page and 'id="batchList"' in page
    assert 'id="batchBarWrap"' in page and 'id="batchMarkBtn"' in page
    # the wiring + core functions are present in the assembled script.
    assert "function importTermsFromFile(" in page
    assert "function batchPrepareSwitch(" in page
    assert "function doBatchExport(" in page
    assert "/api/redaction/batch/enumerate" in page
    # stays air-gapped after inlining.
    assert "http://" not in page and "https://" not in page


def test_batch_routes_are_token_guarded():
    from fastapi.routing import APIRoute
    from app.web import create_app, AppState
    app = create_app(AppState())
    paths = {"/api/redaction/import-terms", "/api/redaction/batch/enumerate",
             "/api/redaction/batch/scan-file", "/api/redaction/batch/read-file",
             "/api/redaction/batch/export"}

    def has_guard(route):
        return any(getattr(dep.call, "__name__", "") == "require_token"
                   for dep in route.dependant.dependencies)
    routes = {r.path: r for r in app.routes if isinstance(r, APIRoute)}
    for p in paths:
        assert p in routes, f"missing batch route: {p}"
        assert has_guard(routes[p]), f"batch route not token-guarded: {p}"



def test_batch_isolation_node_harness():
    """Behavioral proof of the per-file review-STATE ISOLATION invariant: switching batch
    files WIPES all live scan state so one file's decisions/acks never leak into another.
    Runs the committed node harness; SKIPS if node is unavailable (the wiring test above +
    the CI parse gate cover it elsewhere)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_batch.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run([node, str(harness), str(target)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        "batch isolation harness failed — a file's review state leaked across a switch:\n"
        + proc.stdout + "\n" + proc.stderr)
    assert "ALL PASS" in proc.stdout, proc.stdout
