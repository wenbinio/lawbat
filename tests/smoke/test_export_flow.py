"""
Smoke tests for the redaction EXPORT-flow features:
  A. post-export verification  (app/exportverify.py)
  B. the workflow report        (app/redactionreport.py)
  C. metadata-cleaning visibility (the `cleaned` / `not_removed` surfacing)

The pure classifier + report builder are exercised directly (deterministic, no engine); the
route wiring is exercised with a STUBBED engine (monkeypatching app.redactionmodel) so the
surface is covered even when the real `redact-cli` bin isn't present. A structural JS test
pins the export result strip + the honesty-spine wording invariant (no "safe"/"verified").
"""

import base64
import json
import re
from pathlib import Path

from ._helpers import _client, _assembled_redaction_js_path
from ._helpers import _prepared_result, _prepared_root


# ------------------------------------------------------------------ A: verify ----
def test_exportverify_no_residuals():
    from app import exportverify as ev
    r = ev.classify(
        accepted_values=[{"value": "jane@acme.example", "class": "email"}],
        reextracted_text="Contact [REDACTED] about the matter.",
        residual_candidates=[],
    )
    assert r["state"] == ev.VERDICT_NONE
    assert r["classes"] == {}
    assert r["checks"]["values_checked"] == 1


def test_exportverify_residuals_possible_whitespace_insensitive():
    from app import exportverify as ev
    # The value re-appears SPLIT across whitespace + re-cased — the naive scan would miss it,
    # the whitespace/case-insensitive value search (check 2) catches it.
    r = ev.classify(
        accepted_values=[{"value": "Jane Attorney", "class": "name"}],
        reextracted_text="signed by  JANE\nATTORNEY on the date",
        residual_candidates=[],
    )
    assert r["state"] == ev.VERDICT_POSSIBLE
    assert r["classes"] == {"name": 1}
    # And a fresh-scan candidate that matches an accepted value also flags (check 1).
    r2 = ev.classify(
        accepted_values=[{"value": "jane@acme.example", "class": "email"}],
        reextracted_text="",  # no text, but the scan still surfaced it
        residual_candidates=[{"value": "jane@acme.example", "recognizer": "email"}],
    )
    assert r2["state"] == ev.VERDICT_POSSIBLE and r2["classes"] == {"email": 1}


def test_exportverify_could_not_fully_verify():
    from app import exportverify as ev
    # Image-only / low-text signal -> could_not_fully_verify with the reasons enumerated.
    r = ev.classify(
        accepted_values=[{"value": "jane@acme.example", "class": "email"}],
        reextracted_text="",
        residual_candidates=[],
        low_text_signals=["the exported PDF looks image-only/scanned"],
    )
    assert r["state"] == ev.VERDICT_UNVERIFIED
    assert r["reasons"] == ["the exported PDF looks image-only/scanned"]
    # Extraction failure is also could_not_fully_verify.
    r2 = ev.classify(accepted_values=[], extract_failed=True)
    assert r2["state"] == ev.VERDICT_UNVERIFIED and r2["reasons"]


def test_exportverify_result_carries_no_cleartext():
    from app import exportverify as ev
    secret = "jane@acme.example"
    r = ev.classify(
        accepted_values=[{"value": secret, "class": "email"}],
        reextracted_text="still " + secret + " here",
        residual_candidates=[{"value": secret, "recognizer": "email"}],
    )
    # A residual WAS found, but the verdict must never echo the cleartext value — only counts
    # + the class label.
    assert r["state"] == ev.VERDICT_POSSIBLE
    assert secret not in json.dumps(r)


# ------------------------------------------------------------------ B: report ----
def test_export_report_content_and_hashes():
    from app import redactionreport as rr
    orig = b"original bytes"
    out = b"redacted bytes"
    rep = rr.build_report(
        original_filename="deal.pdf",
        original_sha256=rr.sha256_hex(orig),
        output_filename="deal.redacted.pdf",
        output_sha256=rr.sha256_hex(out),
        engine_path="/x/redact-cli", engine_sha256="deadbeef",
        options={"locales": ["sg"], "context": True},
        findings=5, accepted=4, rejected=1,
        per_recognizer={"email": 2, "sg:nric": 2},
        ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
        cleaned=["document body and annotation text"],
        not_removed=["embedded file attachments"],
        verification={"state": "no_residuals_detected", "classes": {}, "reasons": []},
        reviewer="A. Lawyer",
    )
    # The header states plainly this is NOT a tamper-evident audit log.
    assert rep["note"] == rr.REPORT_NOTE
    assert "not a tamper-evident audit log" in rep["note"]
    # Hash correctness (recomputed independently).
    import hashlib
    assert rep["original"]["sha256"] == hashlib.sha256(orig).hexdigest()
    assert rep["output"]["sha256"] == hashlib.sha256(out).hexdigest()
    assert rep["cleaned"] == ["document body and annotation text"]
    assert rep["not_removed"] == ["embedded file attachments"]
    assert rep["reviewer"] == "A. Lawyer"
    # JSON round-trips + is stable-key ordered.
    parsed = json.loads(rr.to_json(rep))
    assert parsed["schema"] == rr.REPORT_SCHEMA


def test_export_report_omits_term_cleartext():
    from app import redactionreport as rr
    rep = rr.build_report(
        original_filename="m.pdf", original_sha256="a", output_filename="m.redacted.pdf",
        output_sha256="b", engine_path=None, engine_sha256=None,
        options={"terms": ["Massimo Greco", "Project Falcon"], "locales": ["sg"]},
        findings=0, accepted=0, rejected=0, per_recognizer={},
        ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
        cleaned=[], not_removed=[], verification={},
    )
    blob = rr.to_json(rep) + rr.to_text(rep)
    # The term CLEARTEXT never appears — only the COUNT.
    assert "Massimo Greco" not in blob and "Project Falcon" not in blob
    assert rep["options"]["term_count"] == 2
    assert "term_count" in rr.to_json(rep)


def test_export_report_text_has_note_and_reads_cleanly():
    from app import redactionreport as rr
    rep = rr.build_report(
        original_filename="m.pdf", original_sha256="a", output_filename="m.redacted.pdf",
        output_sha256="b", engine_path=None, engine_sha256=None, options={},
        findings=1, accepted=1, rejected=0, per_recognizer={"email": 1},
        ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
        cleaned=["document body and annotation text"], not_removed=["embedded file attachments"],
        verification={"state": "no_residuals_detected", "classes": {}, "reasons": []},
    )
    txt = rr.to_text(rep)
    assert "not a tamper-evident audit log" in txt
    assert "Cleaned:" in txt and "NOT removed:" in txt
    assert "Post-export check: no_residuals_detected" in txt


def test_emit_report_never_overwrites():
    # Two exports that would produce the SAME report name must NOT clobber — the second gets
    # a ` (1)` suffix (the never-overwrite invariant, shared with the redacted file).
    from app import redactionroutes as routes
    from app.redactionreport import build_report
    from app.paths import exports_dir
    out_path = Path(exports_dir()) / "clash.redacted.pdf"
    rep = build_report(
        original_filename="c.pdf", original_sha256="a", output_filename="clash.redacted.pdf",
        output_sha256="b", engine_path=None, engine_sha256=None, options={},
        findings=0, accepted=0, rejected=0, per_recognizer={}, ocr_used=False,
        low_text=False, unmapped_fonts=False, could_not_remove=0, cleaned=[], not_removed=[],
        verification={},
    )
    # _emit_report now returns (json_name, txt_name); the JSON name is the never-overwrite
    # subject (the .txt readable copy rides the same _unique_export mechanics).
    j1, t1 = routes._emit_report(out_path, rep)
    j2, t2 = routes._emit_report(out_path, rep)
    assert j1 and j2 and j1 != j2, (j1, j2)
    assert (exports_dir() / j1).is_file() and (exports_dir() / j2).is_file()
    # The readable .report.txt is written too, and also never clobbers.
    assert t1 and t2 and t1 != t2, (t1, t2)
    assert (exports_dir() / t1).is_file() and (exports_dir() / t2).is_file()


# ------------------------------------------------------------- route wiring (stub) ----
def _stub_pdf_engine(monkey_targets):
    """Install engine stubs on app.redactionmodel; return a restore() callable."""
    from app import redactionmodel as rm
    saved = {k: getattr(rm, k) for k in monkey_targets}

    def restore():
        for k, v in saved.items():
            setattr(rm, k, v)
    return rm, restore


def test_pdf_apply_route_surfaces_cleaned_verification_report():
    from app import redactionmodel as rm
    from app.paths import exports_dir
    c = _client()
    fake_out = base64.b64encode(b"%PDF-1.4 redacted").decode()
    saved = {k: getattr(rm, k) for k in ("pdf_apply", "pdf_scan", "extract_scan")}
    try:
        rm.pdf_apply = lambda *a, **k: {
            "op": "pdf_apply", "pdf_b64": fake_out, "redactions": 2, "could_not_remove": 0,
            "low_text": False, "unmapped_fonts": False, "diagnostics": [],
            "cleaned": ["document body and annotation text",
                        "document information fields (e.g. Author, Title)"],
            "not_removed": ["embedded file attachments"],
        }
        rm.pdf_scan = lambda *a, **k: {
            "op": "pdf_scan",
            "candidates": [{"id": 0, "page": 1, "value": "jane@acme.example",
                            "recognizer": "email"}],
            "summary": {}, "low_text": False, "unmapped_fonts": False, "diagnostics": [],
        }
        rm.extract_scan = lambda *a, **k: {
            "op": "extract_scan", "format": "pdf", "text": "[REDACTED] clean",
            "warnings": [], "candidates": [], "summary": {},
        }
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "memo.pdf", "data_b64": "eA==", "accept_ids": [0],
                         "reviewer": "R Eviewer"})
        assert r.status_code == 200, r.text
        d = _prepared_result(r.json())
        # C — the cleaned + not_removed surfacing.
        assert "document information fields (e.g. Author, Title)" in d["cleaned"]
        assert "embedded file attachments" in d["not_removed"]
        # A — an extraction test double over malformed PDF bytes is not complete
        # multi-vector verification, whether or not a real binary is installed.
        assert d["verification"]["state"] == "could_not_fully_verify"
        assert d["verification"]["rust"]["status"] == "unavailable"
        # B — a report file was written and is well-formed + carries the honesty note.
        assert d["report_filename"]
        rep = json.loads((_prepared_root(d) / d["report_filename"]).read_text(encoding="utf-8"))
        assert "not a tamper-evident audit log" in rep["note"]
        assert rep["per_recognizer"] == {"email": 1}
        assert rep["reviewer"] == "R Eviewer"
    finally:
        for k, v in saved.items():
            setattr(rm, k, v)



def test_pdf_apply_route_flags_residuals_possible():
    from app import redactionmodel as rm
    c = _client()
    fake_out = base64.b64encode(b"%PDF-1.4 leak jane@acme.example").decode()
    saved = {k: getattr(rm, k) for k in ("pdf_apply", "pdf_scan", "extract_scan")}
    try:
        rm.pdf_apply = lambda *a, **k: {
            "op": "pdf_apply", "pdf_b64": fake_out, "redactions": 0, "could_not_remove": 0,
            "low_text": False, "unmapped_fonts": False, "diagnostics": [],
            "cleaned": [], "not_removed": ["embedded file attachments"],
        }
        rm.pdf_scan = lambda *a, **k: {
            "op": "pdf_scan",
            "candidates": [{"id": 0, "page": 1, "value": "jane@acme.example",
                            "recognizer": "email"}],
            "summary": {}, "low_text": False, "unmapped_fonts": False, "diagnostics": [],
        }
        # The re-extraction STILL contains the accepted value -> a residual is possible.
        rm.extract_scan = lambda *a, **k: {
            "op": "extract_scan", "format": "pdf", "text": "still jane@acme.example here",
            "warnings": [], "candidates": [{"value": "jane@acme.example", "recognizer": "email"}],
            "summary": {},
        }
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "memo.pdf", "data_b64": "eA==", "accept_ids": [0]})
        d = _prepared_result(r.json())
        assert d["verification"]["state"] == "residuals_possible"
        assert d["verification"]["classes"] == {"email": 1}
        # The verdict body never leaks the cleartext value.
        assert "jane@acme.example" not in json.dumps(d["verification"])
    finally:
        for k, v in saved.items():
            setattr(rm, k, v)



def test_text_export_route_verification_and_metadata_na():
    # The text-export route runs WITHOUT the bin: verification degrades honestly to
    # could_not_fully_verify (the re-scan needs the engine), metadata cleaning is flagged N/A,
    # and a report is still written beside the copy.
    from app.paths import exports_dir
    c = _client()
    r = c.post("/api/redaction/text-export",
               json={"redacted_text": "Contact [REDACTED] about the matter.",
                     "format": "txt", "applied": 1, "stale": 0, "filename": "note.txt",
                     "reviewer": "T. Ester"})
    assert r.status_code == 200, r.text
    d = _prepared_result(r.json())
    assert d["metadata_na"] is True
    assert "verification" in d and d["verification"]["state"] in (
        "no_residuals_detected", "could_not_fully_verify")
    assert d["report_filename"]
    rep = json.loads((_prepared_root(d) / d["report_filename"]).read_text(encoding="utf-8"))
    assert rep["export_kind"] == "text" and rep["reviewer"] == "T. Ester"



def test_text_export_post_check_real_verdict_with_wired_values():
    """2026-07-17 audit item (b): the flat [REDACTED] text export used to run its post-check
    with NO accepted values (they reached it only via the labeled legend), so a CLEAN
    paste→scan→accept→apply→save run read "Post-check: incomplete". The UI now sends the
    ORIGINAL text + the accept spans that produced the redacted text; the server re-derives
    the values (tamper-safe, like Feature 1) and the check returns a REAL verdict."""
    from .test_review_consistency import _fake_engine
    c = _client()
    text = "Acme and Acme"          # 'Acme' at bytes 0-4 and 9-13
    accept = [[0, 4], [9, 13]]
    with _fake_engine():
        # Both decisions resolve, but the fake engine has no Rust probe support.
        r = c.post("/api/redaction/text-export",
                   json={"redacted_text": "[REDACTED] and [REDACTED]", "format": "txt",
                         "applied": 2, "stale": 0, "filename": "postcheck.txt",
                         "text": text, "accept": accept})
        assert r.status_code == 200, r.text
        v = _prepared_result(r.json())["verification"]
        assert v["state"] == "could_not_fully_verify", v
        assert v["coverage"]["complete"] is True
        assert v["rust"]["status"] == "unavailable"
        assert v["checks"]["values_checked"] == 1, v   # 'Acme' deduped by norm
        # Residual run: an accepted value still present in the written copy -> flagged.
        r2 = c.post("/api/redaction/text-export",
                    json={"redacted_text": "Acme and [REDACTED]", "format": "txt",
                          "applied": 1, "stale": 0, "filename": "postcheck.txt",
                          "text": text, "accept": accept})
        assert r2.status_code == 200, r2.text
        assert _prepared_result(r2.json())["verification"]["state"] == "residuals_possible", _prepared_result(r2.json())
    # A malformed accept-set fails LOUD (400) BEFORE anything is written — same rule as /apply.
    r3 = c.post("/api/redaction/text-export",
                json={"redacted_text": "x", "format": "txt", "filename": "postcheck.txt",
                      "text": text, "accept": [["a", 4]]})
    assert r3.status_code == 400, r3.text



def test_text_export_post_check_legacy_no_values_keeps_honest_copy():
    """A caller that does NOT send text+accept (legacy shape) keeps the honest
    could-not-verify wording when identifier-shaped content remains — never a fabricated
    pass and never a crash."""
    from .test_review_consistency import _fake_engine
    c = _client()
    with _fake_engine():
        # The fake engine's TERM recall makes 'and' a residual candidate in the written copy.
        r = c.post("/api/redaction/text-export",
                   json={"redacted_text": "[REDACTED] and [REDACTED]", "format": "txt",
                         "filename": "legacyshape.txt", "options": {"terms": ["and"]}})
    assert r.status_code == 200, r.text
    v = _prepared_result(r.json())["verification"]
    assert v["state"] == "could_not_fully_verify", v
    assert any("not available" in reason for reason in v["reasons"]), v



def test_text_export_default_name_single_redacted_marker():
    """2026-07-17 audit cosmetic: a pasted-text export (no filename hint) used to save as
    'redacted.redacted.txt', then 'redacted.redacted (1).txt', … — the default stem doubled
    the marker. Now: 'redacted.txt', collision-append PRESERVED (never overwrite), and a
    real filename hint still gets '<name>.redacted.<ext>'."""
    import re as _re
    c = _client()
    first = _prepared_result(c.post("/api/redaction/text-export",
                   json={"redacted_text": "[REDACTED]", "format": "txt"}).json())["filename"]
    second = _prepared_result(c.post("/api/redaction/text-export",
                    json={"redacted_text": "[REDACTED]", "format": "txt"}).json())["filename"]
    assert _re.fullmatch(r"redacted( \(\d+\))?\.txt", first), first
    assert _re.fullmatch(r"redacted( \(\d+\))?\.txt", second), second
    # Distinct private stage directories, verified by the preparation tests, prevent overwrites.
    assert "redacted.redacted" not in first + second
    named = _prepared_result(c.post("/api/redaction/text-export",
                   json={"redacted_text": "[REDACTED]", "format": "txt",
                         "filename": "memo.docx"}).json())["filename"]
    assert named.startswith("memo.redacted") and named.endswith(".txt"), named



def test_ocr_finalize_export_verification_and_report():
    # The OCR (image-burn) finalize helper: verification of a raster output + a report with the
    # OCR-specific cleaned/not-removed disclosure. Runs without the bin (verification degrades).
    from app import redactionroutes as routes
    from app.paths import exports_dir
    out_path = Path(exports_dir()) / "scanned.redacted.pdf"
    out_path.write_bytes(b"%PDF-1.4 raster")
    extras = routes._finalize_ocr_export(
        out_path, b"%PDF-1.4 raster", b"original", {"boxes": 3}, {}, "O. Cr")
    assert extras["cleaned"] == routes._OCR_CLEANED
    assert "document metadata (Info / XMP) — the image path does not scrub it" in extras["not_removed"]
    assert extras["verification"]["state"] in ("could_not_fully_verify", "no_residuals_detected")
    assert extras["report_filename"]
    rep = json.loads((exports_dir() / extras["report_filename"]).read_text(encoding="utf-8"))
    assert rep["ocr_used"] is True and rep["export_kind"] == "ocr"


# ------------------------------------------------------------------- JS structural ----
def test_export_strip_and_no_safe_wording_js():
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    # The strip renderer + the reviewer persistence are wired.
    assert "function renderExportStrip(" in js
    # 2026-07-17 audit item (b): the text SAVE posts the original text + the accept spans
    # captured AT APPLY TIME, so the server-side post-check verifies the real values.
    assert "text: lastTextApply.text" in js
    assert "accept: lastTextApply.accept" in js
    assert "text: scannedText" in js
    assert "exportResultStrip" in js
    assert "function loadReviewerName(" in js and "function reviewerName(" in js
    # The three honest verdict copies are present verbatim.
    assert "No residual text detected" in js
    assert "This is a check, not a guarantee" in js
    assert "Possible residual text — do NOT rely on this copy" in js
    assert "Could not fully verify this copy" in js
    # HONESTY-SPINE INVARIANT: the verdict copy block never uses "safe" or "verified".
    m = re.search(r"var VERDICT_COPY = \{.*?\n  \};", js, re.DOTALL)
    assert m, "VERDICT_COPY block not found"
    block = m.group(0).lower()
    assert "safe" not in block, "verdict copy must never say 'safe'"
    assert "verified" not in block, "verdict copy must never say 'verified'"


def test_export_caveat_gate_covers_both_non_clean_verdict_states_js():
    """FIX (independent review of the compression pass): the text-export path already gated
    auto-advance on `residuals_possible`, but ignored `could_not_fully_verify`; the PDF-export
    path ignored `verification.state` ENTIRELY (only could_not_remove/low_text/unmapped-font
    drove its caveat gate). A shared `verdictIsCaveat()` now folds BOTH non-clean states into
    both paths' caveat conditions, so any non-clean post-export verdict keeps the user on
    Export with the loud strip rather than silently auto-advancing to Report. Structural only
    — no DOM/auto-advance seam assert (this file has no JS test harness)."""
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    assert "function verdictIsCaveat(" in js
    # The helper checks BOTH non-clean states, not just residuals_possible.
    m = re.search(r"function verdictIsCaveat\(v\)\{(.*?)\}", js, re.DOTALL)
    assert m, "verdictIsCaveat body not found"
    body = m.group(1)
    assert "residuals_possible" in body and "could_not_fully_verify" in body
    # TEXT path: textCaveat folds the shared helper in (not a bare residuals_possible check).
    assert "var textCaveat = verdictIsCaveat(r.data.verification) || !!r.data.key_failed;" in js
    # PDF path: hasCaveat now includes the verification verdict alongside the byte-level
    # could_not_remove/low_text/unmapped-font signals — previously it ignored the verdict.
    assert "var verdictCaveat = verdictIsCaveat(r.data.verification);" in js
    assert "var hasCaveat = couldNot > 0 || lowText || unmapped || verdictCaveat;" in js
    # The PDF applySummary headline must not read as a clean checkmark when the ONLY caveat
    # is the verdict — it names the verdict explicitly rather than a bare "0 caveats".
    assert "verdictNote" in js and "VERDICT_COPY[r.data.verification.state]" in js


def test_export_reviewer_input_and_strip_in_page():
    # The redaction PAGE ships the reviewer input + the result-strip container in the export
    # stage, and stays air-gapped after inlining.
    c = _client()
    page = c.get("/redaction").text
    assert 'id="reviewerName"' in page
    assert 'id="exportResultStrip"' in page
    assert "http://" not in page and "https://" not in page


# ------------------------------------------- Labeled Markdown (AI working copy) export ----
# A SECOND, clearly-separate export from the production redacted PDF/copy: rebuild the reviewed
# document as a .md with identifiers replaced by LABELS, for AI-assisted drafting. The AI-prep
# vs production-privilege boundary is stated in the .md header + on the UI card, never blurred.
def test_labeled_markdown_assembly_header_and_no_original_value():
    from app import textexport as te
    md = te.build_labeled_markdown(
        "Contact [A] about [email 1].\n\nRegards, [B]",
        source_filename="deal.docx", source_sha256="abc123",
        generated_utc="2026-07-03T00:00:00Z", app_version="0.1.1")
    # The exact boundary statement is present VERBATIM (the AI-prep vs production line).
    assert te.LABELED_MD_STATEMENT in md
    assert "Rebuilt from text extraction —" in md
    assert "NOT the production redacted document." in md
    # Header provenance: source filename + sha256, generated-by + version, date.
    assert "deal.docx" in md and "abc123" in md and "Lawbat 0.1.1" in md
    assert "2026-07-03T00:00:00Z" in md
    # Labels survive into the body; the header has a thematic-break rule before the body.
    assert "[A]" in md and "[email 1]" in md and "[B]" in md
    assert "\n---\n" in md
    # Single honest flow — NO fake page markers when the extractor gave no page boundaries.
    assert "*Page" not in md


def test_labeled_markdown_page_markers_only_when_real():
    from app import textexport as te
    # REAL page boundaries provided -> a rule + `*Page N*` marker for pages 2..N.
    md = te.build_labeled_markdown(
        "", source_filename="f.pdf", source_sha256="s",
        generated_utc="t", app_version="v", pages=["Page one [A]", "Page two [B]"])
    assert "*Page 2*" in md and "[A]" in md and "[B]" in md
    # No page info -> NO invented page markers (honest single flow).
    md2 = te.build_labeled_markdown(
        "Just one flow [A]", source_filename="f", source_sha256="s",
        generated_utc="t", app_version="v")
    assert "*Page" not in md2


# The engine's labels-style apply output the route stubs consume — labeled text + the
# label->value legend (cleartext, which must land ONLY in the separate key file).
_LABELED_APPLY = {
    "op": "apply", "redacted": "Contact [A] about [email 1].", "applied": 2, "stale": 0,
    "legend": [{"label": "[A]", "value": "Jane Attorney", "count": 1},
               {"label": "[email 1]", "value": "jane@acme.example", "count": 1}],
}


def test_labeled_markdown_route_text_path():
    from app import redactionmodel as rm
    from app import textexport as te
    from app.paths import exports_dir
    c = _client()
    captured = {}
    saved = {k: getattr(rm, k) for k in ("apply", "scan", "redact_cli_path")}
    try:
        rm.redact_cli_path = lambda: None  # test double has no Rust verifier
        def fake_apply(text, accept, options=None, replacement_style="redacted"):
            captured["accept"] = accept
            captured["style"] = replacement_style
            return dict(_LABELED_APPLY)
        rm.apply = fake_apply
        # A clean re-scan (no candidates) so verification runs the value-search over the .md.
        rm.scan = lambda *a, **k: {"op": "scan", "candidates": [], "summary": {}}
        r = c.post("/api/redaction/labeled-markdown",
                   json={"text": "Contact Jane Attorney about jane@acme.example.",
                         "accept": [[8, 21], [28, 45]], "filename": "note.txt",
                         "reviewer": "T. Ester"})
        assert r.status_code == 200, r.text
        d = _prepared_result(r.json())
        # The reviewed accept-set is honored EXACTLY, applied with the labels style (parity).
        assert captured["style"] == "labels"
        assert captured["accept"] == [[8, 21], [28, 45]]
        assert d["kind"] == "labeled-markdown"
        assert d["filename"].endswith(".labeled.md")
        assert d["key_filename"] and d["key_filename"].endswith(".labelkey.txt")
        assert d["key_failed"] is False
        # The .md carries labels + the boundary statement, and NO original value.
        md = (_prepared_root(d) / d["filename"]).read_text(encoding="utf-8")
        assert te.LABELED_MD_STATEMENT in md
        assert "[A]" in md and "[email 1]" in md
        assert "Jane Attorney" not in md and "jane@acme.example" not in md
        # The SEPARATE key file maps labels -> originals + carries the keep-local banner.
        key = (_prepared_root(d) / d["key_filename"]).read_text(encoding="utf-8")
        assert "Jane Attorney" in key and "[A]" in key
        assert "RE-IDENTIFICATION KEY" in key
        # The source decisions (not the legend) account for both targets; the
        # unavailable Rust verifier still prevents a complete negative verdict.
        assert d["verification"]["coverage"]["resolved"] == 2
        assert d["verification"]["state"] == "could_not_fully_verify"
        assert d["verification"]["rust"]["status"] == "unavailable"
        # The workflow report records this export TYPE + the reviewer.
        rep = json.loads((_prepared_root(d) / d["report_filename"]).read_text(encoding="utf-8"))
        assert rep["export_kind"] == "labeled-markdown" and rep["reviewer"] == "T. Ester"
    finally:
        for k, v in saved.items():
            setattr(rm, k, v)



def test_labeled_markdown_route_pdf_accept_all():
    from app import redactionmodel as rm
    from app.paths import exports_dir
    c = _client()
    captured = {}
    saved = {k: getattr(rm, k) for k in ("apply", "scan", "extract_scan")}
    try:
        # A PDF has no text-path reviewed span set, so the route extracts HERE and accepts ALL
        # detected identifiers (recall-first over-labeling is the safe side for a working copy).
        rm.extract_scan = lambda *a, **k: {
            "op": "extract_scan", "format": "pdf",
            "text": "Contact Jane Attorney about jane@acme.example.", "warnings": [],
            "candidates": [
                {"start": 8, "end": 21, "value": "Jane Attorney", "recognizer": "name"},
                {"start": 28, "end": 45, "value": "jane@acme.example", "recognizer": "email"}],
            "summary": {},
        }

        def fake_apply(text, accept, options=None, replacement_style="redacted"):
            captured["accept"] = accept
            captured["style"] = replacement_style
            return dict(_LABELED_APPLY)
        rm.apply = fake_apply
        rm.scan = lambda *a, **k: {"op": "scan", "candidates": [], "summary": {}}
        r = c.post("/api/redaction/labeled-markdown",
                   json={"data_b64": base64.b64encode(b"%PDF-1.4").decode(),
                         "filename": "memo.pdf"})
        assert r.status_code == 200, r.text
        d = _prepared_result(r.json())
        # Accept-ALL: every detected candidate span, applied with the labels style.
        assert captured["style"] == "labels"
        assert captured["accept"] == [[8, 21], [28, 45]]
        assert d["filename"].endswith(".labeled.md")
        md = (_prepared_root(d) / d["filename"]).read_text(encoding="utf-8")
        assert "Jane Attorney" not in md and "jane@acme.example" not in md
        rep = json.loads((_prepared_root(d) / d["report_filename"]).read_text(encoding="utf-8"))
        assert rep["export_kind"] == "labeled-markdown"
    finally:
        for k, v in saved.items():
            setattr(rm, k, v)



def test_labeled_markdown_route_guard_and_caps():
    from app.web import create_app, AppState
    from fastapi.testclient import TestClient
    # TOKEN GUARD: a request WITHOUT the per-session token is rejected (403), like every other
    # state-changing redaction route.
    state = AppState()
    noauth = TestClient(create_app(state))
    r = noauth.post("/api/redaction/labeled-markdown", json={"text": "x", "accept": []})
    assert r.status_code == 403
    # CAPS (authorized): oversize text, too many spans, and an oversize file all 400 BEFORE
    # any engine call.
    c = _client()
    assert c.post("/api/redaction/labeled-markdown",
                  json={"text": "a" * 2_000_001, "accept": []}).status_code == 400
    assert c.post("/api/redaction/labeled-markdown",
                  json={"text": "hi", "accept": [[0, 1]] * 100_001}).status_code == 400
    assert c.post("/api/redaction/labeled-markdown",
                  json={"data_b64": "A" * 14_000_001, "filename": "x.pdf"}).status_code == 400



def test_labeled_markdown_rejects_malformed_span():
    """A MALFORMED accept span on the labeled-markdown text path is REJECTED with a 400 — it is
    NOT silently dropped. Dropping it would leave that identifier as CLEARTEXT in the AI working
    copy (a leak-class miss). Unified with /apply's long-standing 400 (no bin needed: the
    validation fires before any engine call)."""
    c = _client()
    # A one-element span (not a [start, end] pair) is malformed.
    r = c.post("/api/redaction/labeled-markdown",
               json={"text": "Contact Jane Attorney.", "accept": [[8, 21], [0]]})
    assert r.status_code == 400, r.text
    assert "span" in _prepared_result(r.json()).get("error", "")
    # A non-int span member is malformed too.
    r2 = c.post("/api/redaction/labeled-markdown",
                json={"text": "hi", "accept": [["a", "b"]]})
    assert r2.status_code == 400, r2.text



def test_labeled_markdown_ui_structural_separation():
    c = _client()
    page = c.get("/redaction").text
    # TWO distinct export affordances (never one button with a toggle).
    assert 'id="exportBtn"' in page and 'id="labeledMdBtn"' in page
    assert "Export labeled Markdown (AI working copy)" in page
    assert "Save the redacted copy (production)" in page
    # The AI-prep vs production boundary copy + a Details disclosure are on the MD card.
    assert "NOT the production redacted document" in page
    assert 'id="labeledMdDetails"' in page
    # air-gapped after inlining.
    assert "http://" not in page and "https://" not in page
    # The assembled script wires the export button + posts the new route.
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    assert "function doLabeledMarkdownExport(" in js
    assert "/api/redaction/labeled-markdown" in js
    assert "labeledMdBtn" in js
