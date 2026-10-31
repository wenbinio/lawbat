"""
Headless smoke test of the core + web layers (no pywebview / no display).

Covers the pipeline the desktop shell drives:
  index a folder -> matter becomes active -> search returns hits across formats,
plus redaction / reid-risk / tools / hardening surfaces.

This file used to be one ~5.5k-line module with a hand-maintained __main__ list — a
footgun: a test defined but never added to that list ran in NO suite (9 had silently
drifted off it). It is now a thin RUNNER that DISCOVERS every `test_*` callable across
the tests/smoke/ package by introspection and runs them all, and asserts a hard FLOOR on
the discovered count so a bad split (a dropped test / a module that fails to import) fails
loudly instead of silently shrinking coverage.

The CI entrypoint is unchanged:  PYTHONPATH=. python3 tests/test_smoke.py   runs EVERYTHING
and prints the same final "smoke OK — …" line. (test_e2e.py is a separate real-server run.)
"""

import os
import tempfile

# App-data isolation BEFORE any app import (mirrors tests/smoke/__init__.py; setdefault so
# the whole suite shares ONE throwaway data dir and never touches a real install). Kept
# here too so the entrypoint self-isolates regardless of import path.
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

import importlib  # noqa: E402
import inspect    # noqa: E402
import pkgutil    # noqa: E402

import tests.smoke as smoke_pkg  # noqa: E402

# FLOOR — the number of test_* functions discovery MUST find. Hard-coded so a bad split (a
# dropped test, or a module that fails to import) can't silently shrink the suite: discovery
# must turn up AT LEAST this many or the run aborts. 191 = every test_* defined across
# tests/smoke/. (The old __main__ hand-list only invoked 169 of them — 9 were silently
# unregistered; discovery now runs all of them, which is the whole point of the change.)
# 2026-07-02: +6 for the redaction health-probe (real round-trip) + scan-error honesty tests.
# 2026-07-02 (fix-on-top of e3d42f9): +2 for the /api/redaction/health token-guard test and
# the scan-rejection (unguarded fetch) structural test.
# 2026-07-02: +5 for the standalone Redactor variant (tests/smoke/test_redactor.py).
# 2026-07-02: +2 for the redaction detection-options quick group selectors ("All"/"Default"):
# the structural wiring test + its node harness.
# 2026-07-02: +14 for the export-flow features (tests/smoke/test_export_flow.py): post-export
# verification (A) 4, workflow report (B) 4, route wiring + OCR finalize + cleaned surfacing
# (A/B/C) 4, and the JS/page structural strips + no-"safe"-wording invariant 2.
# 2026-07-02: +1 banner inline-emphasis structural test (CSS child-combinator fix).
# 2026-07-03: +5 for the redaction UI compression pass (tests/smoke/test_redaction.py):
# status chips wired to state, disclosures relocate caveats verbatim, one-primary-action-per-
# stage, empty-states verbatim, and the Report stage + confined open-export route.
# 2026-07-03: +3 fix-on-top from an independent review of that pass: the shared
# verdictIsCaveat() caveat-gate fix (text + PDF export paths), the open-export embedded-NUL
# 400 (was an uncaught ValueError->500), and the humanReviewSummaryChip real-state wiring.
# 2026-07-03: +18 for BATCH mode + TERMS import increment 1 (tests/smoke/test_batch.py):
# terms-import parser (csv/txt/dedupe/caps/no-cleartext/garbage) 4 + import route 1; folder
# enumeration + confinement (drive-root refuse, ext filter/recursion, size+count caps,
# traversal shapes, enumerate route) 5; scan-file/read-file routes 2; batch export (writes
# outputs + summary, excludes failures, empty->400) 2 + summary aggregator 1; JS/page wiring +
# token-guard structural 2 + the per-file review-isolation node harness 1.
# 2026-07-03: +6 for the Labeled Markdown (AI working copy) export (tests/smoke/test_export_flow.py):
# md assembly (header honesty verbatim + no-original-value + rule) 1 + page-markers-only-when-real
# 1; route text-path (reviewed accept-set parity + separate key + verify-on-md + report type) 1 +
# PDF accept-all 1 + route guard/caps 1 + UI structural separation (two affordances + boundary) 1.
# 2026-07-03: +2 batch-review fix-on-top smoke fns (symlink-escape #3, control-char #4).
# 2026-07-03: +6 labeled-Markdown export (test_export_flow.py).
# 2026-07-04: +4 for scanned-PDF line-aware OCR + compressed rebuild (test_redaction.py):
# TSV line-identity parse 1 + line-aware _assemble newline/byte-offset 1 + scan_scanned_pdf
# multiline-to-engine structural 1 + JPEG/DCTDecode compressed burn output 1.
# 2026-07-04: +4 for WHOLE-DOCUMENT scanned-PDF scan (per-page -> one joined scan;
# test_redaction.py): single-call join + cross-page burn 1, page-boundary-straddling span
# burns both fragments 1, empty-OCR page keeps join alignment 1, scan_scanned_pdf single-call
# join + page mapping 1.
# 2026-07-04: +1 multibyte-across-pages byte-offset pin (whole-doc review nit: the ASCII-only
# whole-doc tests would keep passing under a char-arithmetic regression; this one would not).
# 2026-07-04: +1 for the fresh-corpus generalization-harness GENERATOR sanity check
# (tests/smoke/test_genharness.py): deterministic generate_one + planted values present in the
# born-digital PDF text layer (NOT the full harness run — redact-cli+OCR is too slow for smoke).
# 2026-07-05: +4 for the two-review consolidated fix batch: flat-form sg_nric_loose parity 1
# (test_redaction.py); labeled-markdown rejects malformed span 1 (test_export_flow.py); batch
# malformed-span-fails-that-file-only 1 + non-dict-spec-is-failed-not-skipped 1 (test_batch.py).
# (Text-export engine-provenance honesty was folded into the EXISTING provenance test.)
# 2026-07-06: +14 for the review-CONSISTENCY batch (tests/smoke/test_review_consistency.py):
# FEATURE 1 "redact accepted values everywhere" two-pass — text ON/OFF 2, values re-derived
# server-side (client tamper no-op) 1, terms-cap overflow fails loud 1, report rendering 1 +
# text-export report carries it 1, labeled-markdown toggle 1, PDF ON/OFF 2, batch toggle 1;
# FEATURE 2 keep excluded from expansion 1; FEATURE 3 OCR adapter advisory-parity 1; JS
# structural for the new controls 1 + the keep node harness 1.
# 2026-07-06 (fix-on-top, two-review consolidated batch on 1ae32ed): +5 — PDF union floor
# (keep + overturned accept: ON >= OFF, the exact repro shape) 1; pass-2 under-recovery fails
# LOUD 1; report expansion wording never claims "removed" when could_not_remove > 0 1;
# short-value expansion floor (reviewed span redacts, honest not-expanded reason) 1; scanned
# review surfaces advisory default-off (imageredact threading + page JS) 1.
# 2026-07-16 (OCR-quality round): +7 — conf parse/pick-better/words_to_text 1; ocr_langs
# env validation 1; rotated-page corrected-space burn (injected prep_fn) 1; apply-selection
# geo replay parity 1; low-conf flag threading (never filtering) 1; route geo/low-conf
# sanitizers 1; rotated-NRIC real-OCR end-to-end proof (skips without tesseract) 1.
# 2026-07-17 (demo-readiness audit fixes): +2 — PDF merged-superset-span expansion recovery
# (the pdf-apply 400 root cause: engine overlap-merge extends a folded-in term's span, so the
# pass-2 value no longer norm-EQUALS the accepted value; containment now satisfies the union
# floor for EXPANDED values only) 1; the strict-equality floor retained for non-expanded
# (kept/short) accepted values 1.
# 2026-07-17 (demo-readiness audit fixes, item b): +2 — text-export post-check verifies the
# REAL accepted values wired from the UI (text + accept spans re-derived server-side; clean
# run -> real verdict, residual -> flagged, malformed spans -> 400 pre-write) 1; the legacy
# no-values shape keeps the honest could-not-verify wording 1.
# 2026-07-17 (demo-readiness audit cosmetics): +1 — pasted-text export default name keeps a
# SINGLE .redacted marker ("redacted.txt", collision-append preserved; a filename hint still
# yields "<name>.redacted.<ext>").
# 2026-10-31: +5 for the redaction attestation (tests/smoke/test_attestation.py).
_MIN_TESTS = 293


def discover():
    """Yield (module_name, test_name, fn) for every `test_*` callable defined in a
    tests/smoke/test_*.py module, in a STABLE order: module name, then source-line
    definition order within the module. The `__module__` check keeps each test counted in
    exactly the module that DEFINES it (an imported helper is never miscounted)."""
    found = []
    for modinfo in sorted(pkgutil.iter_modules(smoke_pkg.__path__), key=lambda m: m.name):
        if not modinfo.name.startswith("test_"):
            continue
        mod = importlib.import_module(f"tests.smoke.{modinfo.name}")
        tests = [(n, f) for n, f in vars(mod).items()
                 if n.startswith("test_") and callable(f)
                 and getattr(f, "__module__", None) == mod.__name__]
        tests.sort(key=lambda nf: inspect.getsourcelines(nf[1])[1])
        for n, f in tests:
            found.append((modinfo.name, n, f))
    return found


def main():
    discovered = discover()
    assert len(discovered) >= _MIN_TESTS, (
        f"discovered {len(discovered)} smoke tests but expected at least {_MIN_TESTS} — "
        "a smoke module failed to import or tests were dropped in the split "
        "(bump _MIN_TESTS only when you have DELIBERATELY added tests)")
    from tests.smoke._helpers import _clear_prepared_test_jobs
    for _module, _name, fn in discovered:
        try:
            fn()
        finally:
            _clear_prepared_test_jobs()
    print("smoke OK — home/view-model + index/search + rename + manifest + hardening + licensing + review-loop + tool seams + redaction + reid-risk + about/logging + ingestion-safety + multi-source + round2-fixes")


if __name__ == "__main__":
    main()
