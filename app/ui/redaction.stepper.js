/* ==== CONCATENATION FRAGMENT 11 of 11 — app/ui/redaction.stepper.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- STAGE ROUTER + STEPPER ----------------------------------------------------
  // Document -> Detect -> Review -> Export -> Report. The former 'sensitive' stage FOLDED
  // INTO review (its passages + acknowledge gate live in the Review section now), so it is
  // no longer a routable stage; 'report' is the new post-export stage. The Export hard-lock
  // is UNCHANGED: canEnter('export') still requires a fresh scan + reviewComplete() +
  // passagesAllAcked() — the same two gates as before, now both enforced within Review.
  var STAGES = ['document', 'detection', 'review', 'export', 'report'];
  var STEP_META = {
    document:{n:1, t:'Document'}, detection:{n:2, t:'Detect'},
    review:{n:3, t:'Review'}, export:{n:4, t:'Export'}, report:{n:5, t:'Report'},
    image:{side:true, t:'Scanned-document (image) redaction'}
  };
  var currentStage = 'document';

  // Can the user enter `name`? document/detection always; review needs a scan; export needs
  // BOTH gates (careful-review complete AND passages acknowledged); report needs a completed
  // export. Stepper clicks + buttons honor this.
  function canEnter(name){
    if (name === 'document' || name === 'detection') return true;
    // 'image' is exempt from the scanFailed guard below ON PURPOSE: it is the scanned-PDF
    // OCR side-path (doPdfOcrScan/doPdfOcrApplySelection), which re-runs the engine itself
    // with its own error handling, and is reachable only once a PDF is loaded (mode==='pdf'
    // && pdfFile) — never as a consequence of a failed ordinary scan. Export still requires
    // the normal review/passages gates, so a stale scanFailed can't smuggle a document
    // through to export via this side path.
    if (name === 'image') return mode === 'pdf' && pdfFile;
    // 'report' is reachable ONLY after a redacted copy has actually been written to disk
    // (exported === true). It carries no matter data of its own — it renders the saved
    // filenames + the post-export check. resetScanState clears `exported`, so a new document
    // re-locks it. (No scanFailed dependency: an export can only have happened on a real scan.)
    if (name === 'report') return exported;
    // HONESTY INVARIANT: a scan that ERRORED must never unlock the downstream stages — an
    // errored scan may not be treated as a clean, empty result (over-blocking is the safe
    // side). markScanFailed also clears cands, so `scanned` is already false; this explicit
    // guard is belt-and-suspenders so a future edit can't accidentally re-open the gates.
    if (scanFailed) return false;
    var scanned = (cands !== undefined);
    // Review requires a FRESH scan (cands set) — NOT merely mode==='pdf'. A PDF
    // registered but not yet scanned (e.g. after resetScanState on a new upload) must keep
    // Review locked so the new file can't ride the prior file's open gates. doPdfScan sets
    // cands BEFORE goStage('review'), so the legitimate PDF flow still passes.
    if (name === 'review') return scanned;
    if (name === 'export') return scanned && reviewComplete() && passagesAllAcked();
    return false;
  }

  function goStage(name){
    if (!STEP_META[name]) return;
    if (!canEnter(name)){
      // Explain the gate rather than silently failing.
      if (name === 'export'){
        announce('That stage is locked. Finish Review and acknowledge the sensitive passages first.');
      } else if (name === 'report'){
        announce('The report opens once you save a redacted copy.');
      }
      return;
    }
    currentStage = name;
    document.querySelectorAll('.stage').forEach(function(s){
      s.classList.toggle('show', s.id === 'stage-' + name);
    });
    if (name === 'export'){ updateExportGate(); }
    // Review now carries the folded-in sensitive-passages acknowledge gate — refresh it (and
    // the single combined Continue button) whenever Review is entered.
    if (name === 'review'){ updateAckGate(); }
    refreshStepper();
    var m = STEP_META[name];
    announce(m.side ? (m.t + ' (a side path).') : ('Stage ' + m.n + ' of 5, ' + m.t + '.'));
    window.scrollTo(0, 0);
  }

  // Repaint the stepper: states (done/current/locked/gate) + the per-step status mark.
  function refreshStepper(){
    // scanFailed forces `scanned` false (markScanFailed clears cands), so no step can read
    // as 'done' / show "0 findings" / "None flagged" on an errored scan — the error path is
    // painted with an explicit 'error' mark instead (see the status map below).
    var scanned = (cands !== undefined) && !scanFailed;
    var reviewOk = reviewComplete();
    var passOk = passagesAllAcked();
    var passTotal = (passageList || []).length;
    var curIdx = STAGES.indexOf(currentStage);
    // 'image' is a side-path: keep the stepper on 'review' visually.
    if (curIdx === -1) curIdx = STAGES.indexOf('review');

    var status = {
      document: scanned ? 'done' : (currentStage === 'document' ? 'current' : 'todo'),
      // On a scan error the Detection step (where the scan is triggered) shows an explicit
      // 'error' mark; the downstream stages stay 'locked' (canEnter refuses while scanFailed).
      detection: scanFailed ? 'error'
              : (scanned ? 'done' : (currentStage === 'detection' ? 'current' : (canEnter('detection') ? 'todo' : 'locked'))),
      // Review now folds in the sensitive-passages acknowledge gate — it is 'done' only when
      // BOTH gates pass (careful-review complete AND all passages acknowledged), else 'gate'.
      review: scanFailed ? 'locked'
              : (!scanned ? (canEnter('review') ? 'todo' : 'locked')
              : (currentStage === 'review' ? 'current' : ((reviewOk && passOk) ? 'done' : 'gate'))),
      export: !canEnter('export') ? 'locked'
              : (currentStage === 'export' ? 'current' : (exported ? 'done' : 'todo')),
      // Report is locked until a redacted copy has actually been written (exported).
      report: !exported ? 'locked' : (currentStage === 'report' ? 'current' : 'done')
    };

    document.querySelectorAll('.stepper .step').forEach(function(li){
      var step = li.getAttribute('data-step');
      var st = status[step] || 'todo';
      li.className = 'step ' + st;
      var btn = li.querySelector('.btn-step');
      if (btn){
        btn.setAttribute('aria-current', st === 'current' ? 'step' : 'false');
        btn.setAttribute('aria-disabled', (st === 'locked') ? 'true' : 'false');
      }
      var num = li.querySelector('.num');
      var mark = li.querySelector('.gatemark, .lockmark, .donemark, .errmark');
      var meta = STEP_META[step] || {};
      // number / check / lock glyph
      if (num){
        if (st === 'done') num.innerHTML = '&#10003;';
        else if (st === 'locked' && (step === 'export' || step === 'report')) num.innerHTML = '&#128274;';
        else num.textContent = String(meta.n || '');
      }
      // status mark text + class
      if (mark){
        var cls = 'gatemark', txt = '';
        if (st === 'done'){ cls = 'donemark'; txt = 'Done'; }
        // 'error' is the errored-scan state — a LOUD, distinct mark so it can never be
        // mistaken for a clean/empty "Done" (see the scanFailed honesty invariant).
        else if (st === 'error'){ cls = 'errmark'; txt = 'Scan failed'; }
        else if (st === 'locked'){ cls = 'lockmark'; txt = 'Locked'; }
        else if (st === 'gate'){
          cls = 'gatemark';
          // Review's gate mark now combines BOTH folded-in gates: careful-review items still
          // to decide PLUS sensitive passages still to acknowledge.
          if (step === 'review') txt = (carefulUnresolved() + (passTotal - ackedCount())) + ' to do';
          else txt = 'Must review';
        }
        mark.className = cls;
        mark.textContent = txt;
      }
      // per-step sub-line
      var subEl = li.querySelector('[data-sub]');
      if (subEl){
        // On an errored scan, OVERWRITE any stale "N findings" sub-line so a prior
        // (successful, empty) scan's reassuring text can't linger under the error mark.
        if (scanFailed && step === 'review'){
          subEl.textContent = 'Not scanned';
        }
        // Review's sub-line now carries BOTH the findings count and the acknowledgement
        // progress (the sensitive passages folded in): "N findings · M of K acknowledged".
        if (step === 'review' && scanned){
          var fnote = (cands.length) + ' finding' + (cands.length === 1 ? '' : 's');
          var anote = passTotal === 0 ? 'none flagged'
            : (ackedCount() + ' of ' + passTotal + ' acknowledged');
          subEl.textContent = fnote + ' · ' + anote;
        }
      }
    });
    updateStatusChips();
    // BATCH: keep the batch context bar (file-of-N + the "mark reviewed" enable) in sync with
    // the gate state on every repaint. No-op in the single-file flow (batchActiveRel null).
    if (typeof updateBatchBar === 'function') updateBatchBar();
  }

  // ---- engine health on load -----------------------------------------------------
  async function checkEngineHealth(){
    try {
      var r = await get('/api/redaction/health');
      setEngineHealth(!!(r.ok && r.data && r.data.ok));
      // Drive the `OCR unavailable` status chip from the REAL OCR probe carried on the
      // health response (ocr:true/false). Absent => leave the chip hidden (don't guess).
      if (r.ok && r.data && typeof r.data.ocr === 'boolean') setOcrAvailable(r.data.ocr);
    } catch(e){
      // FE H-2: a network / fetch error means we COULDN'T reach the redaction tool — we
      // do NOT know it is ready. Showing "✓ Tool ready" here would be a dishonest-ready
      // (violates honest-framing). Fail to the OFFLINE state so the user sees an honest
      // "couldn't reach the tool" banner + scanning is paused, never a false green chip.
      setEngineHealth(false);
    }
  }

  // ---- wiring --------------------------------------------------------------------
  document.querySelectorAll('input.loc, input.prof, input.bi, #ctxToggle, #leiToggle, #sgNricLooseToggle, #orgToggle, #addrFullToggle').forEach(function(b){
    b.addEventListener('change', saveOptions);
  });
  if ($('termsBox')){
    $('termsBox').addEventListener('input', saveOptions);
    $('termsBox').addEventListener('change', saveOptions);
  }
  // FEATURE 2 keep list: invalidate the keepNorms cache + refresh the summary on every edit, so
  // a value typed into Keep marks matching candidates "kept" on the next render. (Never sent to
  // the engine; only drives the review-layer auto-dismiss + Feature 1 exclusion.)
  if ($('keepBox')){
    $('keepBox').addEventListener('input', refreshKeepNorms);
    $('keepBox').addEventListener('change', refreshKeepNorms);
  }
  restoreOptions();
  refreshKeepNorms();
  loadReviewerName();

  // Quick group selectors: capture each group's AS-LOADED state (post-restoreOptions, so a
  // returning user's own saved settings are the "Default" to come back to) before wiring the
  // buttons that read it.
  captureGroupDefault('loc');
  captureGroupDefault('bi');
  if ($('locAllBtn')) $('locAllBtn').addEventListener('click', function(){ selectAllGroup('loc'); });
  if ($('locDefaultBtn')) $('locDefaultBtn').addEventListener('click', function(){ restoreGroupDefault('loc'); });
  if ($('recAllBtn')) $('recAllBtn').addEventListener('click', function(){ selectAllGroup('bi'); });
  if ($('recDefaultBtn')) $('recDefaultBtn').addEventListener('click', function(){ restoreGroupDefault('bi'); });

  restorePassToggle();
  if (passToggle) passToggle.addEventListener('change', onPassToggle);

  // stage navigation: any [data-go] button. A locked target announces the gate.
  document.addEventListener('click', function(e){
    var g = e.target.closest && e.target.closest('[data-go]');
    if (!g) return;
    if (g.getAttribute('aria-disabled') === 'true'){
      e.preventDefault();
      announce('That stage is locked. Finish the earlier stages first.');
      return;
    }
    e.preventDefault();
    var to = g.getAttribute('data-go');
    if (to === 'review') closeFlagModal();   // the popover's "see all" navigates to Review + closes
    // "Redact another document" (data-go="document" from the output card OR the Report stage)
    // starts a NEW document: drop ALL scan-derived state + re-lock the gates so the next file
    // can't inherit this one's findings/flags. (Only this end-of-flow restart resets; the
    // in-flow back-navigation to Document keeps the current upload so a stray Back doesn't wipe it.)
    if (to === 'document' && (g.id === 'redactAnotherBtn' || g.id === 'reportRedactAnotherBtn')){
      resetScanState();
      mode = 'text'; pdfFile = null; scannedText = null;
      input.value = '';
      fileNote.innerHTML = '';
      var sub = $('docSub'); if (sub) sub.textContent = 'Lawbat';
      refreshScanEnabled();
    }
    goStage(to);
  });

  if ($('toDetectionBtn')) $('toDetectionBtn').addEventListener('click', function(){ goStage('detection'); });
  if (scanBtn) scanBtn.addEventListener('click', scanUpload);
  ocrBtn.addEventListener('click', doPdfOcrScan);
  imgApplyBtn.addEventListener('click', doPdfOcrApplySelection);
  $('imgAllBtn').addEventListener('click', function(){ setAllBoxes(true); });
  $('imgNoneBtn').addEventListener('click', function(){ setAllBoxes(false); });

  fileInput.addEventListener('change', function(){
    var f = fileInput.files && fileInput.files[0];
    if (f){ if (typeof batchDetach === 'function') batchDetach(); registerUpload(f); }
    fileInput.value = '';
  });
  if ($('sampleBtn')) $('sampleBtn').addEventListener('click', loadSample);
  copyBtn.addEventListener('click', copyOut);

  $('t1all').addEventListener('click', function(){ setTier('#tier1', true); });
  $('t1none').addEventListener('click', function(){ setTier('#tier1', false); });
  $('t2all').addEventListener('click', function(){ setTier('#tier2', true); });
  $('t2none').addEventListener('click', function(){ setTier('#tier2', false); });

  // Delegated change handler for STANDALONE (non-grouped) candidate rows. A grouped member
  // bubbles its change to the group's own `body` listener (which resyncs the group control +
  // calls onSelectionChanged); a SINGLE top-level candRow appended straight into tier1/tier2
  // has NO such listener, so without this a singleton toggle would not update the live count /
  // preview boxes / gate. We skip any event originating inside a `.candgroup` (already handled
  // there) so a grouped member is never double-processed.
  function onTierMemberChange(e){
    var t = e.target;
    if (!t || !t.classList || !t.classList.contains('memberbox')) return;
    if (t.closest && t.closest('.candgroup')) return;   // grouped: the body listener owns it
    markDecidedFromBox(t);
    onSelectionChanged();
  }
  if (tier1) tier1.addEventListener('change', onTierMemberChange);
  if (tier2) tier2.addEventListener('change', onTierMemberChange);

  if ($('hideEverywhereBtn')) $('hideEverywhereBtn').addEventListener('click', hideEverywhere);
  if ($('hideEverywhere')) $('hideEverywhere').addEventListener('keydown', function(ev){
    if (ev.key === 'Enter'){ ev.preventDefault(); hideEverywhere(); }
  });

  if ($('exportBtn')) $('exportBtn').addEventListener('click', doExport);
  if ($('textSaveBtn')) $('textSaveBtn').addEventListener('click', doTextSave);
  if ($('labeledMdBtn')) $('labeledMdBtn').addEventListener('click', doLabeledMarkdownExport);
  // Report-stage actions — wired to REAL, confined server routes (the file the export wrote,
  // and its local .report.txt). Both post the exact saved filename; the server rejects any
  // path outside the exports dir (app/redactionroutes.py open-export route).
  if ($('openFolderBtn')) $('openFolderBtn').addEventListener('click', openExportFolder);
  if ($('viewReportBtn')) $('viewReportBtn').addEventListener('click', openExportReport);

  // ---- BATCH (folder) + TERMS import wiring --------------------------------------
  // TERMS import: an uploaded .csv/.txt names list is parsed server-side + merged into the
  // terms textarea (which stays the source of truth). Reset the input so the same file can be
  // re-imported if needed.
  if ($('termsImport')) $('termsImport').addEventListener('change', function(){
    var f = this.files && this.files[0];
    if (f) importTermsFromFile(f);
    this.value = '';
  });
  if ($('chooseFolderBtn')) $('chooseFolderBtn').addEventListener('click', chooseBatchFolder);
  if ($('batchExportBtn')) $('batchExportBtn').addEventListener('click', doBatchExport);
  if ($('batchCancelBtn')) $('batchCancelBtn').addEventListener('click', closeBatch);
  if ($('batchBackBtn')) $('batchBackBtn').addEventListener('click', backToBatchList);
  if ($('batchMarkBtn')) $('batchMarkBtn').addEventListener('click', markBatchReviewed);
  // Delegated "Review" click on a batch file row -> load it into the per-file review flow.
  if ($('batchList')) $('batchList').addEventListener('click', function(e){
    var b = e.target.closest && e.target.closest('[data-batch-review]');
    if (!b) return;
    var idx = parseInt(b.getAttribute('data-batch-review'), 10);
    if (isNaN(idx) || !batchFiles[idx]) return;
    openBatchFile(batchFiles[idx].rel);
  });
  document.querySelectorAll('input[name="replstyle"]').forEach(function(r){
    r.addEventListener('change', function(){
      // PDF apply has only the [REDACTED] style (variable-length labels break the byte
      // splice). Disable labels for a PDF document.
      updateExportGate();
    });
  });

  // re-scan-on-edit: if the text changes after a scan, the coordinates no longer match.
  // Typing on the box also SUPERSEDES a prior scan whose document is now orphaned — either
  // a PDF was scanned then the user navigated Back and typed (wasPdf), or the scanned text
  // itself was edited. Route those through resetScanState() so ALL scan-derived state drops
  // (cands, honest-status flags, decided, scanProvenance*, the #review rows, the
  // #summary banner) and the gates re-lock — otherwise a re-entered Review/Export would show
  // the WRONG document's findings + caveats. resetScanState does NOT touch the typed `input`
  // value, so the box keeps the user's text and scanning stays available.
  input.addEventListener('input', function(){
    // A genuine user edit/paste in the box is a single-file takeover — detach from any batch
    // file so a later export can't mutate a batch entry. (Programmatic input.value assignment
    // in doTextUpload does NOT fire this event, so a batch text-file load is unaffected.)
    if (typeof batchDetach === 'function') batchDetach();
    var wasPdf = (mode === 'pdf');
    mode = 'text'; pdfFile = null;
    // The user is typing/pasting their OWN text — a held, not-yet-extracted upload no longer
    // represents the document, so drop it (otherwise Scan would extract the file and silently
    // discard the typed text). Programmatic input.value assignment (doTextUpload) does NOT fire
    // this event, so populating the box after extraction won't wrongly clear anything.
    pendingTextFile = null;
    refreshScanEnabled();
    if (cands !== undefined && (wasPdf || (scannedText != null && input.value !== scannedText))){
      resetScanState();
      applyHint.textContent = 'Scan this text before applying.';
      applyHint.className = 'hint';
    }
  });

  // drag-and-drop: register the file on the Document stage (no auto-scan).
  if (dropzone){
    var dzEnter = function(e){ e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragover'); };
    var dzLeave = function(e){ e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragover'); };
    dropzone.addEventListener('dragenter', dzEnter);
    dropzone.addEventListener('dragover', dzEnter);
    dropzone.addEventListener('dragleave', dzLeave);
    dropzone.addEventListener('drop', function(e){
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.remove('dragover');
      var dt = e.dataTransfer;
      var f = dt && dt.files && dt.files[0];
      if (f){ if (typeof batchDetach === 'function') batchDetach(); registerUpload(f); }
    });
    dropzone.addEventListener('click', function(e){
      if (e.target.closest('.filebtn')) return;   // the label opens the picker itself
      fileInput.click();
    });
    dropzone.addEventListener('keydown', function(ev){
      if (ev.key === 'Enter' || ev.key === ' '){ ev.preventDefault(); fileInput.click(); }
    });
  }
  window.addEventListener('dragover', function(e){ e.preventDefault(); });
  window.addEventListener('drop', function(e){ e.preventDefault(); });

  // flagged-passage popover controls
  if ($('flagModalClose')) $('flagModalClose').addEventListener('click', closeFlagModal);
  if ($('flagModalDismiss')) $('flagModalDismiss').addEventListener('click', closeFlagModal);
  if ($('flagModal')) $('flagModal').addEventListener('click', function(ev){
    if (ev.target === $('flagModal')) closeFlagModal();
  });
  document.addEventListener('keydown', function(ev){
    if (ev.key === 'Escape' && $('flagModal') && !$('flagModal').classList.contains('hidden')) closeFlagModal();
  });

  // seed initial state + health
  refreshScanEnabled();
  refreshStepper();
  checkEngineHealth();

  // Expose the PURE grouping helpers + the leak-direction reset/provenance seam for
  // testability (no behavior change — only read accessors + the real functions are exposed).
  if (typeof window !== 'undefined'){
    window.__redactionInternals = {
      groupCandidates: groupCandidates,
      digitTemplate: digitTemplate,
      // re-identification EXPOSURE meter (before -> after tracker): the renderer + the band
      // class allowlister, so a harness can prove the meter renders deterministically,
      // escapes cleartext, shows before->after + the surviving-category breakdown, and
      // never injects an unknown band into a class.
      renderReidMeter: renderReidMeter,
      reidBandClass: reidBandClass,
      // WARN-ON-DROP seam (TERM byte-cap): the byte-length pre-check, the textarea parser
      // (which drops over-byte terms), the CLIENT-side drop report (the textarea is the source
      // of truth since the browser pre-filters before sending), and the banner renderer — so a
      // harness can prove the browser caps in BYTES (matching the bin) and that an over-byte
      // term is SURFACED + esc()'d rather than silently un-redacted.
      byteLen: byteLen,
      parseTerms: parseTerms,
      clientTermDropReport: clientTermDropReport,
      renderTermDrops: renderTermDrops,
      // FEATURE 2 keep-list seam: the parser + the ws-insensitive normal form + the "is this
      // candidate kept?" predicate + the cache refresh, so a harness can prove a kept value is
      // auto-dismissed (unchecked + not in the accept set), still SHOWN, excluded from
      // accept-all, and overturnable by ticking its box. FEATURE 1 toggle read is exposed too.
      parseKeep: parseKeep,
      normValue: normValue,
      candIsKept: candIsKept,
      refreshKeepNorms: refreshKeepNorms,
      redactEverywhere: redactEverywhere,
      renderReview: renderReview,
      acceptedSpans: acceptedSpans,
      setTier: setTier,
      // leak-direction fail-safe seam (Finding #1/#2):
      resetScanState: resetScanState,
      registerUpload: registerUpload,
      // scan-error honesty seam: prove an errored scan re-locks the downstream gates
      // (canEnter false) and never reads as a clean empty result.
      markScanFailed: markScanFailed,
      refreshStepper: refreshStepper,
      // "Try a sample document" seam (feeds the SAME upload->scan path as a user file):
      loadSample: loadSample,
      scanProvenanceMatches: scanProvenanceMatches,
      canEnter: canEnter,
      // interactive per-span PDF selection seam: the apply-set gatherer + the live count
      // updater, so a harness can prove default=all (apply-all equivalence), subset->only
      // those ids, a toggle changes the payload, and the "N of M" figure tracks selection.
      acceptedPdfIds: acceptedPdfIds,
      // #7: the shared classifier (ids + selected + missingId) the apply + the count both
      // derive from, so a harness can prove the fail-CLOSED no-id behavior (a :checked no-id
      // candidate is counted as selected AND reported via missingId — never silently dropped).
      selectedPdfCandidates: selectedPdfCandidates,
      updatePdfRedactCount: updatePdfRedactCount,
      // quick group selectors ("All" / "Default" on the jurisdiction + recognizer-and-opt-in
      // groups): so a harness can prove "All" checks every box in the group, "Default"
      // restores the AS-LOADED (post-restoreOptions) state rather than a hardcoded guess,
      // and both route through the SAME shared saveOptions() handler a manual click uses.
      selectAllGroup: selectAllGroup,
      restoreGroupDefault: restoreGroupDefault,
      captureGroupDefault: captureGroupDefault,
      // state accessors so a harness can drive the scan A -> load B -> export sequence:
      setScanState: function(s){
        if (s.mode !== undefined) mode = s.mode;
        if (s.pdfFile !== undefined) pdfFile = s.pdfFile;
        if (s.scannedText !== undefined) scannedText = s.scannedText;
        if (s.cands !== undefined) cands = s.cands;
        if (s.scanFailed !== undefined) scanFailed = s.scanFailed;
        if (s.decided !== undefined) decided = s.decided;
        if (s.lastUnmappedFonts !== undefined) lastUnmappedFonts = s.lastUnmappedFonts;
        if (s.lastLowText !== undefined) lastLowText = s.lastLowText;
        if (s.scanProvenanceFile !== undefined) scanProvenanceFile = s.scanProvenanceFile;
        if (s.scanProvenanceText !== undefined) scanProvenanceText = s.scanProvenanceText;
      },
      getScanState: function(){
        return {
          mode: mode, pdfFile: pdfFile, scannedText: scannedText,
          cands: cands, decided: decided, scanFailed: scanFailed,
          lastUnmappedFonts: lastUnmappedFonts, lastLowText: lastLowText,
          scanProvenanceFile: scanProvenanceFile, scanProvenanceText: scanProvenanceText
        };
      },
      // BATCH (folder) seam — so a harness can prove the PER-FILE REVIEW ISOLATION invariant:
      // capturing file A's decision + preparing to switch WIPES all live scan state (cands/
      // decided/provenance) so file B can never inherit it, while A's captured decision stays
      // on A's entry and B's entry is untouched. All plain-data / DOM-free enough to unit-test.
      batch: {
        prepareSwitch: batchPrepareSwitch,
        captureCurrentDecision: captureCurrentDecision,
        currentDecision: currentDecision,
        // RE-OPEN RESTORE seam (leak-class fix): the PURE accept-set matcher (span/id ->
        // accepted indices, with the honest "candidate no longer exists" degradation) + the
        // DOM restorer, so a harness can prove a re-opened file's stored deviations are
        // RESTORED (not reset to defaults, which a later exit-capture would then persist).
        computeRestoreAccept: computeRestoreAccept,
        restoreDecision: batchRestoreDecision,
        // candidate-set FINGERPRINT check (re-open only restores when the fresh scan yields the
        // SAME candidates; otherwise the file drops to 'recheck', never silently 'reviewed') +
        // the dirty-flag setter/getter so a harness can prove the capture GUARD: an un-edited
        // re-opened reviewed file keeps its authoritative decision; an edit re-captures it.
        candidateSetMatches: candidateSetMatches,
        setDirty: function(v){ batchDirty = !!v; },
        getDirty: function(){ return batchDirty; },
        entry: batchEntry,
        setState: function(files, active){
          if (files !== undefined) batchFiles = files;
          if (active !== undefined) batchActiveRel = active;
        },
        getFiles: function(){ return batchFiles; },
        getActive: function(){ return batchActiveRel; }
      }
    };
  }
})();
