/* ==== CONCATENATION FRAGMENT 6 of 11 — app/ui/redaction.gates.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- Re-identification EXPOSURE meter (before -> after tracker) ----------------
  // Renders the document-level re-identification EXPOSURE read from privilege.score_*:
  // a BEFORE gauge (band + 0-100 index), an AFTER gauge once a redaction is applied, the
  // delta, and which quasi-identifier CATEGORIES still survive. EVERY value is a COUNT-
  // DERIVED integer (no document cleartext) — but every rendered string is still esc()'d
  // (defense in depth). HONEST FRAMING: this is an EXPOSURE indicator that prompts review,
  // NOT an anonymity guarantee and NOT a "safe to send" measure (the permanent caption in
  // the HTML says so; nothing here ever prints the word "safe" as a state).
  var REID_BANDS = ['none', 'low', 'medium', 'high', 'critical'];
  var CAT_LABELS = {time: 'date', roles: 'role term', locations: 'location', organisations: 'organisation'};
  // Render order is fixed + deterministic so the breakdown text is stable for a given score.
  var CAT_ORDER = ['time', 'roles', 'locations', 'organisations'];

  function reidBandClass(band){
    // Allowlist the band -> a safe class suffix (never interpolate raw server text into a
    // class). An unknown band degrades to 'none' (neutral), never an injected string.
    return REID_BANDS.indexOf(String(band || '')) >= 0 ? String(band) : 'none';
  }
  function reidIndex(score){
    var n = score && typeof score.index === 'number' ? score.index : 0;
    n = Math.round(n);
    return n < 0 ? 0 : (n > 100 ? 100 : n);
  }
  function reidCounts(score){
    var c = (score && score.counts) || {};
    var out = {};
    CAT_ORDER.forEach(function(k){
      var v = (typeof c[k] === 'number' && c[k] > 0) ? Math.round(c[k]) : 0;
      out[k] = v < 0 ? 0 : v;
    });
    return out;
  }
  // Build ONE labelled gauge bar (when = 'Before' | 'After'). All ints; band drives colour.
  function reidBar(when, score){
    var band = reidBandClass(score && score.band);
    var idx = reidIndex(score);
    // ARIA: counts only — never document cleartext. A screen reader hears the band + index.
    var aria = esc(when) + ' re-identification exposure: ' + esc(band) + ', ' + idx + ' out of 100';
    return '<div class="reid-bar" role="img" aria-label="' + aria + '">' +
      '<div class="rb-head">' +
        '<span class="rb-when">' + esc(when) + '</span>' +
        '<span class="chip reid-b-' + band + '">' + esc(band) + '</span>' +
        '<span class="rb-idx">' + idx + '<span class="u">/100</span></span>' +
      '</div>' +
      '<div class="reid-track"><div class="reid-fill reid-f-' + band + '" style="width:' + idx + '%"></div></div>' +
    '</div>';
  }
  // The "after not run yet" placeholder bar (shown before any redaction is applied).
  function reidPendingBar(){
    return '<div class="reid-bar reid-pending" role="img" ' +
      'aria-label="After redaction: not measured yet — apply a redaction to compare">' +
      '<div class="rb-head"><span class="rb-when">After</span>' +
        '<span class="rb-pending-note">runs once you apply a redaction</span></div>' +
      '<div class="reid-track"></div></div>';
  }

  function renderReidMeter(before, after){
    var card = $('reidMeter');
    if (!card) return;
    reidBefore = before || null;
    reidAfter = after || null;
    var bars = $('reidBars'), delta = $('reidDelta'), survive = $('reidSurvive');
    var chip = $('reidBandChip');
    // No before-score at all (PDF flow / scorer omitted) -> keep the whole meter hidden.
    if (!before){
      card.classList.add('hidden');
      if (bars) bars.innerHTML = '';
      if (delta) delta.innerHTML = '';
      if (survive) survive.innerHTML = '';
      if (chip){ chip.textContent = '—'; chip.className = 'chip'; }
      return;
    }
    card.classList.remove('hidden');
    var bBand = reidBandClass(before.band), bIdx = reidIndex(before);
    if (chip){ chip.textContent = bBand; chip.className = 'chip reid-b-' + bBand; }
    if (bars){
      bars.innerHTML = reidBar('Before', before) + (after ? reidBar('After', after) : reidPendingBar());
    }
    // Delta line: only meaningful once an after-score exists.
    if (delta){
      if (after){
        var aIdx = reidIndex(after);
        var diff = aIdx - bIdx;   // <= 0 expected (removing identifiers never adds quasi-ids)
        var cls = diff < 0 ? 'rd-down' : 'rd-flat';
        var word = diff < 0 ? ('down ' + Math.abs(diff)) : (diff > 0 ? ('up ' + diff) : 'unchanged');
        var tail = diff === 0
          ? ' The redaction removed named identifiers, but the quasi-identifiers that drive ' +
            'this score (dates, roles, locations, organisations) are not removed — so the ' +
            'exposure is unchanged. Read the surviving context yourself.'
          : ' This reflects fewer detected quasi-identifiers in the redacted text — it does ' +
            'NOT mean the document is anonymous.';
        delta.className = 'reid-delta ' + cls;
        delta.innerHTML = 'Exposure index <span class="rd-num">' + word + '</span> after redaction (' +
          bIdx + ' → ' + aIdx + ').' + esc(tail);
      } else {
        delta.className = 'reid-delta rd-flat';
        delta.innerHTML = 'Apply a redaction to see whether the exposure changes. Removing names ' +
          'and IDs does not remove dates, roles, locations or organisations, so it often will not.';
      }
    }
    // Surviving-category breakdown: read off the AFTER score when present (what STILL
    // remains after redaction), else the BEFORE score (what is present now). Counts only.
    if (survive){
      var src = after || before;
      var counts = reidCounts(src);
      var chips = [], any = false;
      CAT_ORDER.forEach(function(k){
        var n = counts[k];
        if (n > 0){
          any = true;
          var lbl = CAT_LABELS[k] || k;
          chips.push('<span class="rs-cat">' + n + ' ' + esc(lbl) + (n === 1 ? '' : 's') + '</span>');
        }
      });
      if (any){
        var lead = after
          ? '<b>Named identifiers removed — but these quasi-identifiers remain:</b> '
          : '<b>Quasi-identifiers present:</b> ';
        survive.className = 'reid-survive';
        survive.innerHTML = lead + chips.join('') +
          '<div style="margin-top:7px;color:var(--fg3)">Together these can still ' +
          'point to a specific person. They are not removed automatically — read the ' +
          'passages below and decide.</div>';
      } else {
        survive.className = 'reid-survive rs-clear';
        survive.innerHTML = after
          ? 'No remaining dates, roles, locations or organisations were detected in the ' +
            'redacted text. This is not a guarantee of anonymity — review it yourself.'
          : 'No quasi-identifiers detected. This is not a guarantee — review the text yourself.';
      }
    }
  }

  // ---- the SENSITIVE-passages acknowledge gate -----------------------------------
  // Export is locked until EVERY flagged passage is acknowledged (or there are none).
  function passagesAllAcked(){
    var arr = passageList || [];
    if (arr.length === 0) return true;
    // If the toggle hides the list, the user can't tick — treat as not-acked unless empty.
    var boxes = passages.querySelectorAll('input.ackbox');
    if (boxes.length === 0) return false;
    var all = true;
    boxes.forEach(function(b){ if (!b.checked) all = false; });
    return all;
  }
  function ackedCount(){
    var n = 0;
    passages.querySelectorAll('input.ackbox:checked').forEach(function(){ n++; });
    return n;
  }
  function updateAckGate(){
    var arr = passageList || [];
    var total = arr.length;
    var on = ackedCount();
    var all = passagesAllAcked();
    var ackCount = $('ackCount');
    if (ackCount){
      ackCount.textContent = total === 0 ? 'Nothing flagged'
        : (on + ' of ' + total + ' acknowledged');
      ackCount.className = 'chip ' + (all ? 'ok' : 'med');
    }
    var ackHint = $('ackHint');
    if (ackHint) ackHint.textContent = total === 0
      ? 'Nothing flagged — you can continue.'
      : (all ? 'All reviewed — you can continue.' : 'Tick each box above to continue.');
    var ackDone = $('ackDone');
    if (ackDone) ackDone.classList.toggle('hidden', !all || total === 0);
    // The sensitive passages folded INTO Review: the acknowledge gate no longer owns its own
    // stage button — the SINGLE Review "Continue to Export" button (#toExportBtn) is gated on
    // BOTH gates via updateReviewContinue (careful-review complete AND all passages acked),
    // the SAME conditions canEnter('export') enforces (the Export hard-lock is unchanged).
    updateReviewContinue();
    updateStatusChips();
    refreshStepper();
  }

  // The SINGLE Review continue button (#toExportBtn -> Export). Gated on BOTH real gates —
  // careful-review completeness AND every sensitive passage acknowledged — so it is visibly
  // DISABLED until both are satisfied, matching canEnter('export') exactly (no silent no-op;
  // the data-go click handler also refuses an aria-disabled target). The hard-lock semantics
  // are byte-identical to the pre-fold Review->Sensitive->Export chain, just one button.
  function updateReviewContinue(){
    var reviewOk = reviewComplete();
    var passOk = passagesAllAcked();
    var ok = reviewOk && passOk;
    var btn = $('toExportBtn');
    if (btn){ btn.disabled = !ok; btn.setAttribute('aria-disabled', ok ? 'false' : 'true'); }
    var rh = $('reviewNextHint');
    if (rh){
      if (ok){
        rh.textContent = 'Everything reviewed — continue to Export.';
        rh.className = 'hint ok';
      } else {
        var msgs = [];
        if (!reviewOk){
          var u = carefulUnresolved();
          msgs.push('decide these first — ' + u + ' item' + (u === 1 ? '' : 's') + ' still to review');
        }
        if (!passOk){
          var pend = (passageList || []).length - ackedCount();
          msgs.push('acknowledge ' + pend + ' sensitive passage' + (pend === 1 ? '' : 's'));
        }
        rh.textContent = 'Before Export: ' + msgs.join('; ') + '.';
        rh.className = 'hint warn';
      }
    }
  }

  // Refresh the top status chip strip from REAL state: `N findings` (last scan result) and
  // `Human review required` (flagged passages still un-acknowledged). Both hidden when they
  // don't apply — a chip is decisive, not decorative. `Local only` is static; `OCR
  // unavailable` is driven by the health probe (setOcrAvailable). Count-derived, esc-free
  // (integers only).
  function updateStatusChips(){
    var fc = $('findingsChip');
    if (fc){
      var scanned = (cands !== undefined) && !scanFailed;
      if (scanned){
        var n = (cands || []).length;
        fc.textContent = n + ' finding' + (n === 1 ? '' : 's');
        fc.classList.remove('hidden');
      } else {
        fc.classList.add('hidden');
      }
    }
    var hr = $('humanReviewChip'), hrs = $('humanReviewSummaryChip');
    if (hr || hrs){
      var total = (passageList || []).length;
      var pending = total > 0 && !passagesAllAcked();
      if (hr) hr.classList.toggle('hidden', !pending);
      // The static duplicate chip inside the Review "human review required" disclosure
      // (redaction.html #humanReviewSummaryChip): wired to the SAME real state as the top
      // status-bar chip above, updated in the same place. Hidden when nothing was flagged;
      // "Acknowledged" once every flagged passage is ticked; otherwise the same decisive
      // "Human review required" label.
      if (hrs){
        hrs.classList.toggle('hidden', total === 0);
        if (total > 0){
          hrs.textContent = pending ? 'Human review required' : 'Acknowledged';
          hrs.className = 'chip ' + (pending ? 'med' : 'ok');
        }
      }
    }
  }

  // ---- the CAREFUL-REVIEW gate ---------------------------------------------------
  // Every Tier-2 ("Please review") candidate must be DECIDED (kept or dismissed) before
  // Export unlocks. In PDF mode tier-2 defaults to decided (the untick-to-keep model).
  function tier2Indices(){
    var out = [];
    (cands || []).forEach(function(c, idx){
      if (c.tier !== 'quick-confirm') out.push(idx);
    });
    return out;
  }
  function carefulUnresolved(){
    var idxs = tier2Indices();
    var n = 0;
    idxs.forEach(function(idx){ if (!decided[idx]) n++; });
    return n;
  }
  function reviewComplete(){
    return (cands || []).length === 0 ? true : carefulUnresolved() === 0;
  }

  // Called on every selection / decision change: refresh the unresolved bar, the review
  // "next" hint, the export gate, and the stepper.
  function onSelectionChanged(){
    // BATCH dirty-tracking (leak-class guard): a USER selection change on the open batch file
    // marks it dirty so captureCurrentDecision may (re)capture the lawyer's live choices; the
    // PROGRAMMATIC changes during a re-open (initial render + saved-decision restore) are masked
    // by batchSuppressDirty so they never fabricate a defaults capture that would drop the
    // lawyer's saved opt-ins. No-op outside batch mode (batchActiveRel null / pre-scan).
    if (batchActiveRel && cands !== undefined && !batchSuppressDirty){ batchDirty = true; }
    // (was `var cands = window.__cands || [];` — `cands` is now the outer closure var
    // itself, so this local re-binding is no longer needed; read it directly.)
    var total = (cands || []).length;
    var t1 = (cands || []).filter(function(c){ return c.tier === 'quick-confirm'; }).length;
    var t2 = total - t1;
    var unresolved = carefulUnresolved();
    var bar = $('unresolvedBar');
    var n = $('unresolvedN'), title = $('unresolvedTitle'), sub = $('unresolvedSub');
    if (n) n.textContent = unresolved;
    if (bar) bar.classList.toggle('clear', unresolved === 0);
    if (title) title.textContent = unresolved === 0
      ? (total === 0 ? 'no findings' : 'all findings reviewed')
      : ('item' + (unresolved === 1 ? '' : 's') + ' still to review');
    if (sub) sub.textContent = total === 0
      ? 'Nothing was detected. Review the document yourself before relying on this.'
      : (t1 + ' ready · ' + t2 + ' to review · ' + total + ' found. ' +
         (unresolved === 0 ? 'Sensitive passages next.' : 'Decide the ' + unresolved + ' amber item' +
           (unresolved === 1 ? '' : 's') + ' (keep or dismiss) to unlock Export.'));
    // The Review "Continue to Export" button (#toExportBtn) is the SINGLE gate button now
    // that the sensitive passages fold into Review — updateReviewContinue disables it until
    // BOTH gates pass (careful-review complete AND all passages acknowledged), matching
    // canEnter('export'). It gives a plain-language reason; the data-go click handler also
    // blocks an aria-disabled target with a spoken gate message.
    updateReviewContinue();
    // Refresh the top status chip strip (N findings / Human review required) from real state.
    updateStatusChips();
    // Keep the on-page PDF preview boxes in sync with the findings selection (display-only).
    syncAllPreviewBoxes();
    // Refresh the live "N of M will be redacted" figure (PDF mode) so it always reflects the
    // exact selected apply set after any toggle / bulk select / box click.
    updatePdfRedactCount();
    updateExportGate();
    refreshStepper();
  }

