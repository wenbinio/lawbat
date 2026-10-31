"""Single source of truth for the ORDER the shared/split UI JS files concatenate in.

Two consumers read this list, and must never drift apart:
  1. app/web.py's `_build_redaction_page()` — inlines these files (in THIS order) into the
     served page via `_build_page()`'s marker-substitution.
  2. The "assembled page JS" node --check gates — tests/test_smoke.py's
     `test_ui_js_parse_gate_node_check()` (+ the four redaction/reidrisk node-harness tests)
     and the CI mirror in .github/workflows/ci.yml.

redaction.js was split at its own pre-existing `---- section ----` comment boundaries into
these ordered fragments so no single file group grows unreviewably large. They are NOT each
independently valid JavaScript — together they form ONE outer IIFE (the first fragment opens
it, `redaction.stepper.js` closes it), so `node --check` can only meaningfully run over the
ASSEMBLED concatenation (base.js + every fragment, in this order), never over a lone
fragment. Each fragment's own header comment says so loudly. Re-ordering this list changes
program semantics — don't, without re-verifying the concatenation is what shipped before.

Deliberately dependency-free (no fastapi/pydantic import): the CI JS-parse-gate step reads
this list via a bare `python3 -c "import app.ui_manifest"` BEFORE the Python test stack
(fastapi etc.) is installed.
"""

# Inlined FIRST on every page (via each page's dedicated __BASE_JS__ marker), before that
# page's own script — defines window.LB (esc/$/get/post/announce) that every page consumes.
BASE_JS = "base.js"

REDACTION_JS_PARTS = [
    "redaction.core.js",         # IIFE-open, LB aliases (esc/$/post/get/announce), DOM refs,
                                  # friendly-error copy, detection-options (opt-in packs)
    "redaction.release.js",      # private preview, explicit exception and release dialog
    "redaction.state.js",        # state vars, engine-error/health banners, scanning-progress
                                  # + stage-button state, review-layer grouping (pure)
    "redaction.review.js",       # candidate row/group rendering, review rendering (text+pdf)
    "redaction.pdf.js",          # on-page VISUAL PDF preview (Phase 2, display-only)
    "redaction.textpreview.js",  # TEXT document preview, byte<->string (UTF-8) helpers,
                                  # confidentiality/privilege passages (surface-only)
    "redaction.gates.js",        # re-identification EXPOSURE meter, the sensitive-passages
                                  # acknowledge gate, the careful-review gate
    "redaction.provenance.js",   # accepted-span/id gathering (apply source of truth),
                                  # the provenance fail-safe (defense in depth)
    "redaction.scan.js",         # scan actions, new-document RESET (leak-direction
                                  # fail-safe), "try a sample document", add-a-redaction
    "redaction.export.js",       # EXPORT (apply only accepted, real endpoints), SAVE the
                                  # redacted text to a file
    "redaction.ocr.js",          # OCR scanned-PDF flow (per-span image review), group
                                  # resync, the flagged-passage popover
    "redaction.batch.js",        # TERMS import (.csv/.txt merge) + BATCH folder mode
                                  # (enumerate / scan-queue / per-file review isolation / export)
    "redaction.stepper.js",      # stage router + stepper, engine health on load, wiring,
                                  # IIFE-close + the __redactionInternals test seam
]
