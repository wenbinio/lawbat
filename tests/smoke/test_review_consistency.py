"""
Review-CONSISTENCY batch — driven by real pilot feedback ("censors erratically";
"whitelist the client's IC and redact everything else"):

  * FEATURE 1 "Redact accepted values everywhere" (default-ON per-export toggle) — the
    two-pass expansion that removes EVERY ws-elastic occurrence of an accepted value, not the
    scattered subset the reviewer happened to click. Wired at the ROUTE layer (one honest
    place) so the scan/apply id-parity contract is never violated (pass-2 scan + apply share
    ONE augmented option set — the accepted values folded in as user TERMS).
  * FEATURE 2 "Keep (never redact)" — a review-layer list that AUTO-DISMISSES matching
    candidates (still SHOWN) and EXCLUDES them from Feature 1's expansion; it NEVER reaches
    the engine.
  * FEATURE 3 — the scanned-PDF (OCR) adapters now match the born-digital defaults: the
    one-shot BURN path EXCLUDES advisory / aggressive recognizers (they were burned by
    default before), and the per-span REVIEW path SURFACES them default-off (shown, marked,
    opt-in) — same treatment AND same opt-in availability, so one document treated two ways
    no longer diverges.

Post-review consolidated FIX batch (see the FIX BATCH section): the PDF union floor (an
explicit accept always redacts; keep limits only the expansion delta; pass-2 under-recovery
fails LOUD), 'targeted' report honesty reconciled with could_not_remove, the short-value
expansion floor, and the scanned-review advisory surfacing.

The redaction engine (redact-cli) is NOT on the dev/CI-python runner, so these tests drive a
tiny deterministic FAKE engine (monkeypatched onto app.redactionmodel) that models the ONE
behavior under test: a user TERM's recall is ws-elastic (every occurrence becomes a
candidate). No cleartext is logged (same contract as the real bridge).
"""

import base64
import json
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from ._helpers import _client, _assembled_redaction_js_path


# --------------------------------------------------------------- fake engine ----
def _txt_cands(text, terms):
    """Every ws-elastic (here: case-insensitive literal) occurrence of each term as a text
    candidate — models the engine's ws-elastic TERM recall. ASCII test text => byte offset ==
    char offset, so start/end are valid byte coordinates."""
    out = []
    low = text.lower()
    for t in terms or []:
        tl = str(t).lower()
        if not tl:
            continue
        i = low.find(tl)
        while i >= 0:
            out.append({"start": i, "end": i + len(t), "value": text[i:i + len(t)],
                        "recognizer": "term", "confidence": "high",
                        "tier": "quick-confirm", "advisory": False})
            i = low.find(tl, i + 1)
    return out


@contextmanager
def _fake_engine(pdf_by_terms=None, extract_echo=False):
    """Patch app.redactionmodel's scan/apply/pdf_scan/pdf_apply/extract_scan with a
    deterministic model of ws-elastic TERM recall. `pdf_by_terms(terms)->candidates` lets a
    PDF test decide the id/value set for pass-1 (no terms) vs pass-2 (with terms)."""
    from app import redactionmodel as rm
    saved = {k: getattr(rm, k) for k in ("scan", "apply", "pdf_scan", "pdf_apply", "extract_scan", "redact_cli_path")}

    def fake_scan(text, options=None):
        options = options or {}
        return {"schema": "firmos.redaction/0", "op": "scan",
                "candidates": _txt_cands(text, options.get("terms")), "summary": {}}

    def fake_apply(text, accept, options=None, replacement_style="redacted"):
        tb = text.encode("utf-8")
        spans = sorted([(s, e) for s, e in accept if 0 <= s < e <= len(tb)], reverse=True)
        out, applied = tb, 0
        for s, e in spans:
            out = out[:s] + b"[REDACTED]" + out[e:]
            applied += 1
        return {"schema": "firmos.redaction/0", "op": "apply",
                "redacted": out.decode("utf-8"), "applied": applied, "stale": 0}

    def fake_pdf_scan(data_b64, options=None):
        options = options or {}
        cands = (pdf_by_terms or (lambda _t: []))(options.get("terms") or [])
        return {"schema": "firmos.redaction/0", "op": "pdf_scan", "candidates": cands,
                "summary": {}, "low_text": False, "unmapped_fonts": False, "diagnostics": []}

    def fake_pdf_apply(data_b64, accept_ids=None, options=None):
        n = len(accept_ids or [])
        return {"schema": "firmos.redaction/0", "op": "pdf_apply",
                "pdf_b64": base64.b64encode(b"%PDF-1.4 redacted").decode(),
                "redactions": n, "could_not_remove": 0, "low_text": False,
                "unmapped_fonts": False, "diagnostics": [], "cleaned": [], "not_removed": []}

    def fake_extract_scan(filename, data_b64, options=None):
        text = "" if not extract_echo else base64.b64decode(data_b64).decode("utf-8", "replace")
        return {"schema": "firmos.redaction/0", "op": "extract_scan", "format": "text",
                "text": text, "warnings": [], "candidates": _txt_cands(text, (options or {}).get("terms")),
                "summary": {}}

    # This test double does not implement Rust recovery probes. It must not
    # accidentally borrow a real binary or manufacture a completed verification.
    rm.redact_cli_path = lambda: None
    rm.scan, rm.apply = fake_scan, fake_apply
    rm.pdf_scan, rm.pdf_apply, rm.extract_scan = fake_pdf_scan, fake_pdf_apply, fake_extract_scan
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(rm, k, v)


# ============================================================ FEATURE 1 (text) ====
from ._helpers import _prepared_result, _prepared_root

def test_f1_text_everywhere_on_removes_all_occurrences():
    """ON: accepting ONE of three occurrences of a value removes ALL three, and the response
    reports `+2` additional occurrences TARGETED (honest, from the pass-2 selection —
    'targeted', not blindly 'removed': see the FIX-2 wording test below)."""
    c = _client()
    text = "Acme and Acme and Acme"   # 'Acme' at bytes 0,9,18
    with _fake_engine():
        r = c.post("/api/redaction/apply",
                   json={"text": text, "accept": [[0, 4]], "redact_everywhere": True})
    assert r.status_code == 200, r.text
    d = r.json()
    assert "Acme" not in d["redacted"], d["redacted"]
    assert d["redacted"].count("[REDACTED]") == 3
    assert d["expansion"]["on"] is True
    assert d["expansion"]["additional_targeted"] == 2, d["expansion"]


def test_f1_text_off_removes_only_reviewed():
    """OFF: only the one reviewed occurrence is removed; the other two survive."""
    c = _client()
    text = "Acme and Acme and Acme"
    with _fake_engine():
        r = c.post("/api/redaction/apply",
                   json={"text": text, "accept": [[0, 4]], "redact_everywhere": False})
    d = r.json()
    assert d["redacted"].count("[REDACTED]") == 1
    assert d["redacted"].count("Acme") == 2
    assert d["expansion"]["on"] is False and d["expansion"]["additional_targeted"] == 0


def test_f1_text_values_rederived_serverside_client_tamper_has_no_effect():
    """The expansion VALUES are re-derived from the authoritative text + accepted spans, NEVER
    a client-sent value list — so a bogus `values` field in the request changes nothing."""
    c = _client()
    text = "Acme and Acme and Acme"
    with _fake_engine():
        clean = c.post("/api/redaction/apply",
                       json={"text": text, "accept": [[0, 4]], "redact_everywhere": True}).json()
        tampered = c.post("/api/redaction/apply",
                          json={"text": text, "accept": [[0, 4]], "redact_everywhere": True,
                                "values": ["and"], "accepted_values": ["and"]}).json()
    # A client trying to inject "and" as the value to expand has NO effect: the word "and"
    # is NOT redacted, and the result is identical to the untampered call.
    assert "and" in tampered["redacted"]
    assert tampered["redacted"] == clean["redacted"]
    assert tampered["expansion"] == clean["expansion"]


def test_f1_terms_cap_overflow_fails_loud_not_silent_subset():
    """If the accepted values would push the TERM set past MAX_TERMS, the export FAILS LOUD
    (400) rather than silently redacting a subset — the under-redaction hazard."""
    from app import redactionmodel as rm
    from app import redactionroutes as routes
    # Unit: the augmenter raises rather than truncates.
    full = [f"t{i:04d}" for i in range(rm.MAX_TERMS)]
    try:
        routes._augmented_options({"terms": full}, ["one-more-value"])
        raised = False
    except routes._TermCapExceeded:
        raised = True
    assert raised, "augmenting past MAX_TERMS must raise, never silently drop"
    # Route: the same overflow surfaces as an honest 400 BEFORE anything is written. (The
    # accepted value must be >= 4 chars — a shorter one now takes the FIX-3 short-value fast
    # path and never reaches the term merge.)
    c = _client()
    with _fake_engine():
        r = c.post("/api/redaction/apply",
                   json={"text": "zzzz", "accept": [[0, 4]], "redact_everywhere": True,
                         "options": {"terms": full}})
    assert r.status_code == 400, r.text
    assert "everywhere" in r.json()["error"].lower()
    # The class marker the UI keys its APPLY-specific copy on (2026-07-17 audit item).
    assert r.json().get("error_kind") == "terms_cap", r.json()


def test_f1_report_expansion_rendering_pure():
    """The workflow record STATES which mode ran + how many extra occurrences fell to it."""
    from app import redactionreport as rr
    base = dict(original_filename="a", original_sha256="", output_filename="b",
                output_sha256="", engine_path=None, engine_sha256=None, options={},
                findings=3, accepted=3, rejected=0, per_recognizer={}, ocr_used=False,
                low_text=False, unmapped_fonts=False, could_not_remove=0)
    on = rr.build_report(**base, expansion={"on": True, "additional_targeted": 2,
                                            "not_expanded": 0, "not_expanded_reasons": []})
    assert on["expansion"] == {"on": True, "additional_targeted": 2, "not_expanded": 0,
                               "not_expanded_reasons": []}
    assert "2 additional occurrence(s) of accepted values were targeted" in rr.to_text(on)
    off = rr.build_report(**base, expansion={"on": False, "additional_targeted": 0,
                                             "not_expanded": 0, "not_expanded_reasons": []})
    assert "OFF" in rr.to_text(off)
    # Absent expansion -> omitted (byte-identical to legacy callers).
    assert "expansion" not in rr.build_report(**base)


def test_f1_text_export_report_carries_expansion():
    """The text export echoes the /apply mode into the written workflow record."""
    from app.paths import exports_dir
    c = _client()
    r = c.post("/api/redaction/text-export",
               json={"redacted_text": "[REDACTED] and [REDACTED]", "format": "txt",
                     "applied": 3, "stale": 0, "filename": "n.txt",
                     "expansion": {"on": True, "additional_targeted": 2, "not_expanded": 0,
                                   "not_expanded_reasons": []}})
    assert r.status_code == 200, r.text
    rep = json.loads((_prepared_root(_prepared_result(r.json())) / _prepared_result(r.json())["report_filename"]).read_text(encoding="utf-8"))
    assert rep["expansion"] == {"on": True, "additional_targeted": 2, "not_expanded": 0,
                                "not_expanded_reasons": []}



def test_f1_labeled_markdown_respects_toggle():
    """The labeled-Markdown (AI working copy) export honors the everywhere toggle too."""
    c = _client()
    text = "Acme and Acme and Acme"
    with _fake_engine():
        r = c.post("/api/redaction/labeled-markdown",
                   json={"text": text, "accept": [[0, 4]], "redact_everywhere": True,
                         "filename": "memo.txt"})
    assert r.status_code == 200, r.text
    assert _prepared_result(r.json())["expansion"] == {"on": True, "additional_targeted": 2, "not_expanded": 0,
                                     "not_expanded_reasons": []}



# ============================================================= FEATURE 1 (PDF) ====
def _pdf_terms_model(terms):
    """Pass-1 (no terms) sees ONE occurrence of 'Acme' (id 0); pass-2 (term 'Acme' folded in)
    sees all THREE (ids 10/11/12) — models the ws-elastic TERM recall on the PDF path."""
    if "Acme" in (terms or []):
        return [{"id": i, "page": 1 if i < 12 else 2, "value": "Acme", "recognizer": "term",
                 "confidence": "high", "tier": "quick-confirm", "advisory": False}
                for i in (10, 11, 12)]
    return [{"id": 0, "page": 1, "value": "Acme", "recognizer": "name",
             "confidence": "high", "tier": "quick-confirm", "advisory": False}]


def test_f1_pdf_everywhere_on_expands_by_value():
    """PDF ON: accepting id 0 (value 'Acme') expands to every candidate whose value matches —
    3 removed, +2 additional — with the pass-2 scan+apply sharing the augmented options."""
    c = _client()
    with _fake_engine(pdf_by_terms=_pdf_terms_model):
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0],
                         "redact_everywhere": True})
    assert r.status_code == 200, r.text
    d = _prepared_result(r.json())
    assert d["redactions"] == 3
    assert d["expansion"]["on"] is True and d["expansion"]["additional_targeted"] == 2
    from app.paths import exports_dir
    rep = json.loads((_prepared_root(d) / d["report_filename"]).read_text(encoding="utf-8"))
    assert rep["expansion"]["on"] is True and rep["expansion"]["additional_targeted"] == 2



def test_f1_pdf_off_is_reviewed_only():
    """PDF OFF (absent flag) is byte-identical to the legacy reviewed-only apply."""
    c = _client()
    with _fake_engine(pdf_by_terms=_pdf_terms_model):
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0]})
    d = _prepared_result(r.json())
    assert d["redactions"] == 1 and d["expansion"]["on"] is False



# ============================================================= FEATURE 1 (batch) ==
def test_f1_batch_text_respects_toggle(tmp_path_factory=None):
    """A per-batch everywhere toggle expands each reviewed file; the per-file report states it."""
    import tempfile
    from app.paths import exports_dir
    folder = Path(tempfile.mkdtemp(prefix="ldm-batch-"))
    (folder / "memo.txt").write_text("Acme and Acme and Acme", encoding="utf-8")
    c = _client()
    with _fake_engine(extract_echo=True):
        r = c.post("/api/redaction/batch/export",
                   json={"folder": str(folder), "batch_name": "b1", "redact_everywhere": True,
                         "files": [{"kind": "text", "rel": "memo.txt", "format": "txt",
                                    "accept": [[0, 4]]}]})
    assert r.status_code == 200, r.text
    d = _prepared_result(r.json())
    assert d["exported"] == 1, d
    bdir = _prepared_root(d) / d["batch_dir"]
    reports = [p for p in bdir.iterdir() if p.name.endswith(".report.json") and "batch-summary" not in p.name]
    assert reports, "a per-file report must be written"
    rep = json.loads(reports[0].read_text(encoding="utf-8"))
    assert rep["expansion"]["on"] is True and rep["expansion"]["additional_targeted"] == 2
    # Every effective decision resolves, but this test double has no Rust probe
    # implementation: a negative re-scan alone is not a complete check.
    assert rep["verification"]["coverage"] == {
        "requested": 3, "resolved": 3, "unresolved": 0, "complete": True}
    assert rep["verification"]["state"] == "could_not_fully_verify", rep["verification"]
    assert rep["verification"]["rust"]["status"] == "unavailable"
    shutil.rmtree(folder, ignore_errors=True)



# ================================================================= FEATURE 2 ======
def test_f2_keep_value_excluded_from_expansion():
    """A value on the KEEP list is NOT expanded by Feature 1 (never redacted-everywhere), even
    when a stray accepted span carries it — the keep list wins, server-side (defense in depth
    over the review-layer auto-dismiss)."""
    c = _client()
    text = "Acme and Acme and Acme"
    with _fake_engine():
        r = c.post("/api/redaction/apply",
                   json={"text": text, "accept": [[0, 4]], "redact_everywhere": True,
                         "keep": ["acme"]})   # keep matches ws/case-insensitively
    d = r.json()
    # Kept -> no everywhere-expansion: the other two occurrences remain.
    assert d["expansion"]["additional_targeted"] == 0, d["expansion"]
    assert d["redacted"].count("Acme") >= 2


# ================================================================= FEATURE 3 ======
def test_f3_ocr_adapter_advisory_parity():
    """The scanned-PDF (OCR) adapter's DEFAULT span set now EXCLUDES advisory candidates,
    matching the born-digital text path's default (advisory surfaced-but-off) — so the SAME
    synthetic content yields the SAME default candidate VALUE set through both adapters."""
    from app import redactionroutes as routes
    scan = {"candidates": [
        {"start": 0, "end": 4, "value": "MINE", "recognizer": "email", "advisory": False},
        {"start": 5, "end": 9, "value": "ADVS", "recognizer": "us:dl", "advisory": True},
    ]}
    # Text-path DEFAULT set (what the born-digital path would redact by default): non-advisory.
    text_default = {c["value"] for c in scan["candidates"] if not c.get("advisory")}
    # OCR adapter DEFAULT set (spans -> values), via the shared route-level filter. The advisory
    # candidate's span must be absent, so the two default VALUE sets agree.
    ocr_pairs = routes._default_spans_from_scan(scan)
    assert ocr_pairs == [(0, 4)], ocr_pairs
    by_span = {(c["start"], c["end"]): c["value"] for c in scan["candidates"]}
    ocr_default = {by_span[(s, e)] for (s, e) in ocr_pairs}
    assert ocr_default == text_default
    # FIX 4 (behavior change from the first cut, deliberate): the REVIEW variant now
    # SURFACES advisory candidates with their flag (shown, marked, default-off in the UI)
    # instead of dropping them — default TREATMENT still matches the text path; opt-in
    # AVAILABILITY now does too.
    review = routes._review_spans_from_scan(scan)
    assert review == [(0, 4, "email", False), (5, 9, "us:dl", True)], review


# ==================================== FIX BATCH (post-review consolidated) ========
def test_f1_pdf_keep_overturned_accept_union_floor():
    """UNION FLOOR (the leak-direction fix): a reviewer's EXPLICIT accept is ALWAYS redacted —
    the keep list limits only the everywhere-EXPANSION delta. The UI-advertised trigger: a kept
    candidate's chip says "Tick to redact it anyway"; the overturned tick reaches the server
    with `keep` still listing the value. ON mode must redact it (>= OFF mode), never zero."""
    c = _client()
    with _fake_engine(pdf_by_terms=_pdf_terms_model):
        off = _prepared_result(c.post("/api/redaction/pdf-apply",
                     json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0],
                           "keep": ["Acme"]}).json())
        on = _prepared_result(c.post("/api/redaction/pdf-apply",
                    json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0],
                          "keep": ["Acme"], "redact_everywhere": True}).json())
    assert off["redactions"] == 1, off
    # The exact prior repro: ON used to yield redactions:0 here. The floor: ON >= OFF.
    assert on["redactions"] >= off["redactions"], (on, off)
    assert on["redactions"] == 1
    # Kept -> nothing expanded, and the accepted occurrence still went (fast path: original
    # ids under original options — reviewed positions exact).
    assert on["expansion"]["on"] is True
    assert on["expansion"]["additional_targeted"] == 0, on["expansion"]



def test_f1_pdf_under_recovery_fails_loud():
    """If pass-2 value-matching recovers FEWER candidates of an accepted value than pass 1 had
    accepted, the export FAILS LOUD (400 + honest message) — never a silent under-redaction."""
    def under_recovery_model(terms):
        if "Acme" in (terms or []):
            # Pass 2 finds only ONE 'Acme' — fewer than the TWO the reviewer accepted.
            return [{"id": 10, "page": 1, "value": "Acme", "recognizer": "term",
                     "confidence": "high", "tier": "quick-confirm", "advisory": False}]
        return [{"id": i, "page": 1, "value": "Acme", "recognizer": "name",
                 "confidence": "high", "tier": "quick-confirm", "advisory": False}
                for i in (0, 1)]
    c = _client()
    with _fake_engine(pdf_by_terms=under_recovery_model):
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0, 1],
                         "redact_everywhere": True})
    assert r.status_code == 400, r.text
    body = _prepared_result(r.json())
    err = body["error"]
    assert "Could not safely expand" in err, err
    assert "Nothing was saved" in err, err
    # The class marker the UI keys its APPLY-specific copy on (2026-07-17 audit item).
    assert body.get("error_kind") == "expand_failed", body



# ---------------- MERGED-SPAN RECOVERY (the 2026-07-17 pdf-apply 400 root cause) ----------
def _merged_superset_model(terms):
    """Pass-1 (no terms): the reviewer accepts an address-recognizer hit. Pass-2 (that value
    folded in as a TERM): the engine's overlap merge EXTENDS the matched span, so the ONLY
    covering candidate's value is a strict SUPERSET string of the accepted value — the exact
    loan-facility class behind the audit's pdf-apply 400 (an FP address hit whose folded-in
    term merged with adjacent amount text into '312.40.\\n\\n3.2 All amounts …')."""
    if terms:
        return [{"id": 10, "page": 1, "value": "312.40. 3.2 All amounts due to the Lender",
                 "recognizer": "term", "confidence": "high", "tier": "quick-confirm",
                 "advisory": False}]
    return [{"id": 0, "page": 1, "value": "2 All amounts due to the Lender",
             "recognizer": "address", "confidence": "medium", "tier": "careful-review",
             "advisory": False}]


def test_f1_pdf_merged_superset_span_recovers_not_400():
    """A pass-2 candidate whose value CONTAINS an expanded accepted value satisfies the union
    floor (term recall flags every occurrence; the merge only EXTENDS spans — over-removal is
    the safe side), so the export SAVES instead of 400ing. Pins the superset property: every
    accepted value is covered by a SELECTED candidate's value, and the selected set applies."""
    from app import redactionroutes as routes
    # Unit: the expansion helper selects the merged candidate; the accept-set covers the
    # reviewed value (containment in the pass-2 id space — the ON ⊇ OFF union floor).
    with _fake_engine(pdf_by_terms=_merged_superset_model):
        new_ids, aug, meta = routes._expand_pdf_accept("eA==", [0], {}, set())
        assert new_ids == [10], new_ids
        assert "2 All amounts due to the Lender" in (aug.get("terms") or []), aug
        accepted_norm = routes._norm_value("2 All amounts due to the Lender")
        selected = {c["id"]: c for c in _merged_superset_model(aug.get("terms"))}
        assert all(i in selected for i in new_ids)
        assert any(accepted_norm in routes._norm_value(selected[i]["value"]) for i in new_ids), \
            "every reviewed value must be contained in a selected pass-2 candidate's value"
        assert meta["additional_targeted"] == 0, meta
    # Route: the same shape end-to-end — 200, saved, honest expansion record (parity: the
    # pass-2 apply shares the augmented options with the pass-2 scan, unchanged mechanics).
    c = _client()
    with _fake_engine(pdf_by_terms=_merged_superset_model):
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0],
                         "redact_everywhere": True})
    assert r.status_code == 200, r.text
    d = _prepared_result(r.json())
    assert d["redactions"] == 1, d
    assert d["expansion"]["on"] is True and d["expansion"]["additional_targeted"] == 0, d



def test_f1_pdf_containment_never_relaxes_nonexpanded_floor():
    """CONTAINMENT recovery applies ONLY to values folded in as TERMS (whose every-occurrence
    recall the engine guarantees). A KEPT accepted value is NOT expanded, so it has no such
    guarantee: if pass 2 offers it only merged inside a different value, the export still
    FAILS LOUD (strict equality floor) — never a positional guess."""
    def model(terms):
        base = {"confidence": "high", "tier": "quick-confirm", "advisory": False}
        if terms:  # pass 2: 'Bravo' folded in; the kept 'Acme' exists only merged-away
            return [{"id": 10, "page": 1, "value": "Bravo", "recognizer": "term", **base},
                    {"id": 11, "page": 1, "value": "X Acme Y", "recognizer": "name", **base}]
        return [{"id": 0, "page": 1, "value": "Acme", "recognizer": "name", **base},
                {"id": 1, "page": 1, "value": "Bravo", "recognizer": "name", **base}]
    c = _client()
    with _fake_engine(pdf_by_terms=model):
        r = c.post("/api/redaction/pdf-apply",
                   json={"filename": "d.pdf", "data_b64": "eA==", "accept_ids": [0, 1],
                         "keep": ["Acme"], "redact_everywhere": True})
    assert r.status_code == 400, r.text
    assert _prepared_result(r.json()).get("error_kind") == "expand_failed", _prepared_result(r.json())



def test_f2_report_never_claims_removed_when_could_not_remove():
    """FIX 2 (honesty): the expansion line says TARGETED, never "removed", and when
    `could_not_remove` > 0 it references that caveat — the report can never claim N
    additional occurrences "were removed" while also saying some could not be."""
    from app import redactionreport as rr
    base = dict(original_filename="a", original_sha256="", output_filename="b",
                output_sha256="", engine_path=None, engine_sha256=None, options={},
                findings=5, accepted=5, rejected=0, per_recognizer={}, ocr_used=False,
                low_text=False, unmapped_fonts=True)
    rep = rr.build_report(**base, could_not_remove=2,
                          expansion={"on": True, "additional_targeted": 3,
                                     "not_expanded": 0, "not_expanded_reasons": []})
    txt = rr.to_text(rep)
    assert "occurrence(s) of accepted values were targeted for removal" in txt
    # The self-contradiction the review reproduced: never "were removed" for the expansion.
    assert "occurrence(s) of accepted values were removed" not in txt
    # The expansion block references the could-not-remove caveat explicitly.
    assert "See 'Could not remove' above" in txt, txt


def test_f3_short_value_not_expanded():
    """FIX 3 (over-reach floor): an accepted value under 4 chars is NOT auto-expanded (terms
    are ws-elastic SUBSTRING matchers — expanding 'Tan' would hit inside 'important'). The
    reviewed span still redacts (union floor); the skip is surfaced with an honest reason."""
    c = _client()
    text = "Tan met Tan"   # 'Tan' at bytes 0 and 8
    with _fake_engine():
        r = c.post("/api/redaction/apply",
                   json={"text": text, "accept": [[0, 3]], "redact_everywhere": True})
    assert r.status_code == 200, r.text
    d = r.json()
    # Only the REVIEWED occurrence went; the second survives (no substring expansion).
    assert d["redacted"].count("[REDACTED]") == 1, d["redacted"]
    assert d["redacted"].count("Tan") == 1
    exp = d["expansion"]
    assert exp["on"] is True and exp["additional_targeted"] == 0
    assert exp["not_expanded"] == 1, exp
    assert any("too short" in reason for reason in exp["not_expanded_reasons"]), exp


def test_f4_scanned_review_surfaces_advisory_default_off():
    """FIX 4 (parity completion): the scanned-PDF REVIEW path SURFACES advisory candidates
    default-off like the born-digital review — threaded adapter -> imageredact -> page JS."""
    from app import imageredact
    from app.ocr import OcrWord
    # (a) imageredact threads the advisory flag from a 4-tuple span into the candidate dict
    #     (3-tuples stay backward-compatible: advisory defaults False).
    words = [OcrWord("SECRET", 10, 10, 40, 12), OcrWord("MAYBE", 10, 40, 40, 12)]
    text, offsets = imageredact._assemble(words)
    spans = [(offsets[0][0], offsets[0][1], "email", False),
             (offsets[1][0], offsets[1][1], "us:dl", True)]
    cands = imageredact._candidates_for_spans(words, offsets, spans, (200, 200))
    assert [c["advisory"] for c in cands] == [False, True], cands
    tri = imageredact._candidates_for_spans(
        words, offsets, [(offsets[0][0], offsets[0][1], "email")], (200, 200))
    assert tri and tri[0]["advisory"] is False
    # (b) the scanned review UI renders an advisory box DEFAULT-OFF ('skip'), visibly marked,
    #     still clickable to opt in — structural pins on the assembled page JS.
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    assert "'img-box ' + (advisory ? 'skip advisory' : 'keep')" in js
    assert "(advisory ? ' — possible' : '')" in js


# ------------------------------------------------------------------ JS structural ----
def test_review_consistency_controls_js():
    """The new UI controls + their wiring ship in the assembled page JS."""
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    # FEATURE 1 toggle read + payload wiring on every export path.
    assert "function redactEverywhere(" in js
    assert "redact_everywhere:redactEverywhere()" in js.replace(" ", "")
    assert "function expansionNote(" in js
    # 2026-07-17 audit: expansion refusals render APPLY-specific copy (nothing saved + the
    # untick remedy) keyed on the server's error_kind — never the generic scan banner.
    assert "function isExpansionBlocked(" in js
    assert "function showExpansionBlocked(" in js
    assert js.count("isExpansionBlocked(r.data)") >= 3, "all three expansion-capable export paths must key on it"
    assert "Nothing was saved" in js
    # FEATURE 2 keep helpers + the review-layer auto-dismiss + accept-all exclusion.
    assert "function parseKeep(" in js and "function candIsKept(" in js
    assert "function normValue(" in js
    # candRow leaves a kept box UNCHECKED regardless of the tier default, and marks it "kept".
    assert "checked && !advisory && !kept" in js
    assert "kept — not redacted" in js
    # renderReview pre-marks kept candidates decided (auto-dismiss, does not block the gate).
    assert "if (candIsKept(c)) decided[i] = true;" in js
    # setTier ("Select all"/"Keep all") skips kept candidates.
    assert "if (c && candIsKept(c)) return;" in js


def test_review_consistency_keep_node_harness():
    """Behavioral proof (where node exists) of the keep predicate + toggle via the seam."""
    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_keep.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run([node, str(harness), str(target)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert re.search(r"redaction keep harness: all \d+ checks passed", proc.stdout), proc.stdout
