/* ==== CONCATENATION FRAGMENT 7 of 11 — app/ui/redaction.provenance.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- accepted-span / id gathering (apply source of truth) ----------------------
  function acceptedSpans(){
    var out = [];
    document.querySelectorAll('#review input.memberbox:checked').forEach(function(box){
      var c = cands[+box.getAttribute('data-idx')];
      if (c) out.push([c.start, c.end]);
    });
    return out;
  }
  // The SINGLE classifier the PDF apply path + the live count both derive from, so the
  // "N will be redacted" figure can NEVER drift from the actual accept_ids payload (#7).
  // Walks the checked memberboxes ONCE and partitions the SELECTED candidates into those
  // with a usable engine id (`ids`, the exact apply payload) and those WITHOUT one
  // (`missingId`). A no-id candidate is the carrier hazard: the engine's PdfSelection
  // accepts ONLY by id membership (pure id set — there is NO ordinal/positional fallback),
  // so a :checked no-id candidate would be COUNTED as "will be redacted" yet OMITTED from
  // accept_ids = silent UNDER-removal (fail-OPEN). We surface it via `missingId` so the
  // apply can FAIL CLOSED rather than quietly drop it. (In practice pdf_scan assigns every
  // candidate a stable id, so missingId stays 0 — this is the belt-and-braces invariant.)
  function selectedPdfCandidates(){
    var ids = [], selected = 0, missingId = 0;
    document.querySelectorAll('#review input.memberbox:checked').forEach(function(box){
      var c = (cands || [])[+box.getAttribute('data-idx')];
      if (!c) return;                       // a box with no backing candidate is not selected
      selected++;
      if (c.id != null) ids.push(c.id); else missingId++;
    });
    return {ids: ids, selected: selected, missingId: missingId};
  }
  function acceptedPdfIds(){
    return selectedPdfCandidates().ids;
  }

  // Live "N of M detections will be redacted" — the SELECTED universe is EVERY scan
  // candidate (default all-selected, deselecting one excludes its id from the apply set).
  // N = the currently-SELECTED count; M = the total detected. Refreshed on every toggle so
  // the figure is always the real apply set. PDF mode only (the text path has its own
  // preview semantics).
  function updatePdfRedactCount(){
    if (mode !== 'pdf') return;
    var el = $('pdfRedactCount');
    if (!el) return;
    var total = (cands || []).length;
    // #7: count from the SAME classifier the payload uses (selectedPdfCandidates), so N can
    // never disagree with the accept_ids that will be sent. N counts SELECTION; a no-id
    // candidate (missingId) is still SELECTED + counted (the non-located-still-removed
    // invariant), but it CANNOT be silently dropped from the apply — doPdfExport refuses
    // the whole apply when missingId > 0 (fail-closed), so the count never over-promises.
    var sel = selectedPdfCandidates();
    var selected = sel.selected;
    // Count ADVISORY (aggressive-recognizer) detections that are present but DEFAULT-OFF, so
    // the note can honestly say they are not in the apply set unless the user opts them in.
    var advisoryTotal = 0;
    (cands || []).forEach(function(c){ if (c && c.advisory) advisoryTotal++; });
    var advisorySelected = 0;
    document.querySelectorAll('#review input.memberbox:checked').forEach(function(box){
      var c = (cands || [])[+box.getAttribute('data-idx')];
      if (c && c.advisory) advisorySelected++;
    });
    var warn = selected === 0;
    el.className = 'pdf-redact-count' + (warn ? ' warn' : '');
    var advisoryNote = advisoryTotal
      ? ' <span class="hint">' + advisoryTotal + ' possible (aggressive) detection' +
        (advisoryTotal === 1 ? ' is' : 's are') + ' NOT selected by default' +
        (advisorySelected ? ' (' + advisorySelected + ' opted in)' : '') +
        ' — tick any to include it.</span>'
      : '';
    el.innerHTML = '<b>' + selected + '</b> of <b>' + total + '</b> detection' +
      (total === 1 ? '' : 's') + ' will be redacted.' + advisoryNote +
      (warn ? ' <span class="hint">Nothing is selected — re-select at least one to save a redacted copy.</span>' : '');
  }

  // ---- provenance fail-safe (defense in depth) -----------------------------------
  // Before ANY apply, the document now loaded must be the SAME one the current candidates
  // + scan flags came from. If they don't match (or provenance is unknown), refuse — never
  // apply A's candidates/flags against B's bytes, and never inherit A's "clean" flags. This
  // is belt-and-braces over resetScanState(): even if a future code path forgets to reset,
  // the apply still fails safe.
  function scanProvenanceMatches(){
    if (cands === undefined) return false;   // nothing scanned -> no provenance
    if (mode === 'pdf'){
      return !!(pdfFile && scanProvenanceFile && pdfFile === scanProvenanceFile);
    }
    // text/file mode: the exact text scanned must still be the text we're about to apply to.
    return scanProvenanceText != null && scanProvenanceText === scannedText;
  }

