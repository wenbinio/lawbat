/* ==== CONCATENATION FRAGMENT 2 of 11 — app/ui/redaction.state.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- state ----
  // Promoted from window.__cands / window.__passages / window.__passText /
  // window.__reidBefore / window.__reidAfter (history: these were window-scoped globals
  // for no live reason — every reader/writer lives in this one IIFE). Kept as closure-local
  // state alongside the vars below; nothing outside this file reads them directly anymore
  // (the window.__redactionInternals test seam's setScanState/getScanState is the
  // supported external accessor — see the wiring section at the end of this file).
  var cands;        // scan candidates (was window.__cands) — undefined until a scan runs
  // NOTE: named passageList, NOT passages — app/ui/redaction.core.js's DOM refs
  // section already declares `var passages = $('passages');` (the passages CONTAINER
  // element); reusing that name here would silently clobber the DOM reference the
  // moment a scan/apply set this array.
  var passageList;  // privilege/confidentiality passages (was window.__passages)
  var passText;      // the text passages were computed over (was window.__passText)
  var reidBefore;    // re-identification EXPOSURE meter "before" score (was window.__reidBefore)
  var reidAfter;      // re-identification EXPOSURE meter "after" score (was window.__reidAfter)
  var scannedText = null;       // the exact text the scan coordinates index into (text mode)
  var mode = 'text';            // 'text' | 'pdf'
  var pdfFile = null;
  // A NON-PDF upload (.docx/.eml/.msg/.csv/.txt) held until the Scan step, when it is
  // extracted to text server-side (doTextUpload). Distinct from pasted text (no file):
  // pasted text is scanned in place, an uploaded file is extracted first. Cleared on reset
  // and once extracted, so a re-scan of the now-in-box text goes through the text path.
  var pendingTextFile = null;
  var scanOptions = {};         // the options used for the CURRENT scan — apply must reuse them
  // DECIDED set for the careful-review tier: a candidate is "addressed" once the reviewer
  // explicitly keeps OR dismisses it. The Export gate is cleared only when every Tier-2
  // candidate is decided. Keyed by the cands index (the apply source of truth).
  var decided = {};
  var lastReport = null;        // the last pdf/text apply report (for the export report)
  // The last TEXT apply result, captured so "Save to a file" can format + write it WITHOUT
  // re-redacting. Holds the ALREADY-REDACTED text (no original values) + the labels legend
  // (cleartext, kept LOCAL — only ever posted to the local export route to write the key
  // file, never elsewhere) + the counts + whether labels were used. Cleared on any reset.
  var lastTextApply = null;
  var lastLowText = false, lastUnmappedFonts = false;   // last scan diagnostics
  // PROVENANCE: the document the CURRENT candidates + scan flags belong to. Captured at
  // scan time (the File ref for a PDF/file, or the exact scanned text for paste/text). An
  // apply path checks the now-loaded document still matches this before writing — so a
  // "scan A clean -> load B (unmapped) -> export" sequence can NEVER inherit A's "clean"
  // flags against B's bytes. Provenance unknown => refuse, never inherit (honest default).
  var scanProvenanceFile = null;   // the File the candidates/flags came from (pdf/file mode)
  var scanProvenanceText = null;   // the text the candidates came from (text mode)
  var pdfPreviewReady = false;  // true once the on-page PDF visual preview has rendered
  // Monotonic scan token: bumped at the START of every scan (text OR pdf). loadPdfPreview
  // captures it and refuses to render a preview whose token is no longer current — so a
  // SAME-File re-scan (e.g. changed recognizer settings) can't draw boxes whose value_ref
  // indices are misaligned vs the new candidate list. (File-identity alone misses this.)
  var scanToken = 0;
  // LOAD-BEARING HONESTY FLAG: true when the LAST scan/extract attempt ERRORED (engine
  // unavailable, a transport failure, or a structured {"error":...}). It exists to enforce
  // ONE invariant (do not weaken): an errored scan must NEVER be visually indistinguishable
  // from a clean, EMPTY scan — a red error banner sitting over green "Done / 0 findings /
  // None flagged" steps tells the lawyer the document was scanned-and-clean when it was never
  // scanned at all. So while scanFailed is set, canEnter refuses Review/Sensitive/Export and
  // the stepper paints an explicit error/blocked mark (never Done). Cleared on a successful
  // scan and on resetScanState. Over-blocking is the safe side.
  var scanFailed = false;
  // POST-EXPORT state: `exported` gates the new Report stage (canEnter('report')) and marks
  // Export 'done' in the stepper; it flips true ONLY when a redacted copy has actually been
  // WRITTEN to disk (a text file-save, a PDF apply, or an OCR apply). `lastExport` holds the
  // matter-free descriptor the Report stage renders + the Open-folder / View-report buttons
  // act on (the saved filename + the local report filename, both confined to the exports
  // dir server-side). Both cleared on resetScanState so a new document never inherits them.
  var exported = false;
  var lastExport = null;

  // ---- engine-error / health banners ---------------------------------------------
  function showEngineError(raw){
    var f = friendlyError(raw);
    engineNote.innerHTML =
      '<div class="banner error engine-err">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>' + esc(f.title) + '</b><p>' + esc(f.body) + '</p></div>' +
      '</div>';
  }
  function clearEngineError(){ engineNote.innerHTML = ''; }

  function showEngineOffline(){
    engineNote.innerHTML =
      '<div class="banner error engine-err">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body">' +
          '<b>' + esc('The redaction tool isn’t available right now.') + '</b>' +
          '<p>' + esc('Lawbat couldn’t find the part that searches for identifiers, so scanning is paused. ' +
            'Your files are untouched and nothing has left this computer. You can still read and prepare your ' +
            'document. Try restarting Lawbat — if it keeps happening, your IT contact may need to reinstall it.') +
          '</p>' +
        '</div>' +
      '</div>';
  }

  // Flip the "Tool ready" CHIP (+ footer dot + engineDown) WITHOUT touching the banner area.
  // Split out of setEngineHealth so a failed scan can flip the chip to offline while KEEPING
  // the specific friendlyError banner showEngineError already rendered (setEngineHealth's
  // else-branch would clobber it with the generic offline banner).
  function setEngineChip(ok){
    engineDown = !ok;
    if (engineChip){
      engineChip.className = 'chip ' + (ok ? 'ok' : 'high');
      engineChip.textContent = ok ? '✓ Tool ready' : 'Tool offline';
      engineChip.title = ok ? 'The redaction tool is ready' : 'The redaction tool is not available';
    }
    if (footDot) footDot.className = 'dotmark' + (ok ? '' : ' off');
    if (footState) footState.textContent = ok ? 'Tool ready' : 'Tool offline';
    refreshScanEnabled();
  }

  function setEngineHealth(ok){
    setEngineChip(ok);
    if (ok){ if (engineNote.querySelector('.engine-err')) clearEngineError(); }
    else { showEngineOffline(); }
  }

  // Reflect the REAL OCR-engine (Tesseract) availability into the `OCR unavailable` status
  // chip. Honest: the chip shows ONLY when OCR is unavailable (scanned/photo PDFs can't be
  // image-read on this machine) — an available OCR engine is the silent default. `null`/
  // undefined (the probe didn't report) leaves the chip hidden rather than claiming either way.
  function setOcrAvailable(ok){
    var chip = $('ocrChip');
    if (!chip) return;
    var demo = document.body && document.body.getAttribute('data-demo') === '1';
    if (ok === false && demo) {
      chip.className = 'chip neutral';
      chip.textContent = 'OCR not installed';
      chip.title = 'Scanned pages stay labelled as needing OCR. Born-digital text still redacts.';
      return;
    }
    chip.classList.toggle('hidden', ok !== false);
  }

  // A scan/extract attempt ERRORED. Enforce the honesty invariant (see the scanFailed var):
  // drop candidate state (cands=undefined re-locks Review/Sensitive/Export via canEnter),
  // raise the explicit error flag (the stepper paints an error mark, not Done/0/None), and —
  // when the engine itself is/appears unavailable — flip the "Tool ready" chip to offline
  // (via setEngineChip, which does NOT overwrite the friendly red error banner the caller
  // already showed). `engineOffline` is passed by the caller: true for an engine-unavailable
  // error or a transport failure we couldn't even parse; false for a per-file input error
  // (the engine ran fine, so the chip stays honest-green and the user can retry a fix).
  function markScanFailed(engineOffline){
    cands = undefined;   // no successful scan -> downstream gates re-lock (canEnter)
    decided = {};        // any prior decisions belonged to a document that is no longer scanned
    scanFailed = true;
    if (engineOffline) setEngineChip(false);
    refreshScanEnabled();
    refreshStepper();
  }

  // ---- scanning-in-progress + document-stage button state ------------------------
  function showScanning(title){
    if (scanningTitle) scanningTitle.textContent = title || 'Scanning…';
    if (scanning) scanning.classList.remove('hidden');
    if (scanBtn) scanBtn.disabled = true;
    if (scanHint) scanHint.textContent = '';
  }
  function hideScanning(){
    if (scanning) scanning.classList.add('hidden');
    refreshScanEnabled();
  }

  // Document-stage "Continue" + Detection-stage "Scan" enablement + the persistent hint.
  function refreshScanEnabled(){
    var hasText = !!(input.value && input.value.trim());
    // A held non-PDF upload (pendingTextFile) IS a loaded document even though its text box is
    // still empty — it is extracted at Scan time. Without this the Continue/Scan gates stayed
    // disabled and the non-PDF upload->extract->scan path was unreachable.
    var hasDoc = hasText || (mode === 'pdf' && pdfFile) || !!pendingTextFile;
    var scanningNow = scanning && !scanning.classList.contains('hidden');
    if (scanBtn) scanBtn.disabled = scanningNow || engineDown || !hasDoc;
    var cont = $('toDetectionBtn');
    if (cont){
      cont.disabled = !hasDoc;
      cont.setAttribute('aria-disabled', hasDoc ? 'false' : 'true');
    }
    var ch = $('docContinueHint');
    if (ch) ch.textContent = hasDoc ? 'Next you’ll choose what to look for.' : 'Add a document to continue.';
    if (!pasteHint) return;
    if (engineDown){
      pasteHint.textContent = 'Scanning is paused while the tool is unavailable. You can still paste or upload to prepare.';
      pasteHint.className = 'help warn';
    } else if (!hasDoc){
      pasteHint.textContent = 'Paste some text above, or upload a file, then continue.';
      pasteHint.className = 'help';
    } else {
      pasteHint.textContent = 'Ready — continue to detection settings. Nothing leaves this machine.';
      pasteHint.className = 'help ok';
    }
  }

  function toggleTierActions(show){
    var els = document.querySelectorAll('.tier-actions');
    for (var i = 0; i < els.length; i++) els[i].style.display = show ? '' : 'none';
  }

  // ---- review-layer grouping (PURE; presentation only) ---------------------------
  function digitTemplate(value){
    return String(value == null ? '' : value).replace(/[0-9]+/g, '#');
  }
  function groupCandidates(cands){
    var groups = [];
    var byKey = {};
    (cands || []).forEach(function(c, idx){
      var rec = String(c.recognizer == null ? '' : c.recognizer);
      var tmpl = digitTemplate(c.value);
      var key = rec + ' ' + tmpl;
      var g = byKey[key];
      if (!g){
        g = {recognizer: rec, template: tmpl, members: [], count: 0};
        byKey[key] = g;
        groups.push(g);
      }
      g.members.push({c: c, idx: idx});
      g.count++;
    });
    return groups;
  }

