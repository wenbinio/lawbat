/* ==== CONCATENATION FRAGMENT 9 of 11 — app/ui/redaction.export.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- EXPORT (apply only accepted, real endpoints) ------------------------------
  function replStyle(){
    var r = document.querySelector('input[name="replstyle"]:checked');
    return r ? r.value : 'redacted';
  }

  // FEATURE 1 per-export toggle. Default ON (the checkbox ships checked); the value is sent on
  // every export so the SERVER runs (or skips) the two-pass expansion. Absent element -> ON.
  function redactEverywhere(){ var el = $('redactEverywhere'); return el ? !!el.checked : true; }

  // The honest one-line summary of which mode ran + how many extra occurrences fell to it —
  // built from the SERVER's `expansion` (counts only). HONESTY (do not weaken): says
  // TARGETED, never "removed" — the count is selection-time, and `couldNot`
  // (could_not_remove, PDF path) may mean some targeted items are STILL IN the file; when
  // couldNot > 0 this note references that caveat so the two can never contradict.
  function expansionNote(exp, couldNot){
    if (!exp || typeof exp !== 'object') return '';
    couldNot = couldNot || 0;
    if (exp.on){
      var add = exp.additional_targeted || 0;
      var s = ' <span class="hint">Redact everywhere: ON &mdash; ' + (add
        ? '<b>' + add + '</b> additional occurrence' + (add === 1 ? '' : 's') +
          ' of accepted values ' + (add === 1 ? 'was' : 'were') + ' also targeted for removal.'
        : 'no additional occurrences of accepted values were found.') + '</span>';
      if (couldNot > 0) s += ' <span class="hint warn">Not every targeted item could be ' +
        'removed &mdash; see the &ldquo;could not be removed&rdquo; warning and review the saved copy.</span>';
      (exp.not_expanded_reasons || []).forEach(function(reason){
        s += ' <span class="hint warn">' + esc(String(reason)) +
          ' &mdash; those keep only their reviewed occurrences.</span>';
      });
      return s;
    }
    return ' <span class="hint">Redact everywhere: OFF &mdash; only the occurrences you reviewed were targeted for removal.</span>';
  }

  // ---- "Redact everywhere" expansion refusal (apply-specific copy) ----------------
  // The server's everywhere-expansion 400s are EXPORT-stage refusals (nothing was saved;
  // the original is untouched) — NOT scan problems. They used to fall through friendlyError
  // into the generic "Something went wrong with that scan." banner (wrong words — the
  // 2026-07-17 audit flag). The server marks the class with `error_kind` so no string
  // matching is needed; render the honest server message + the one-click remedy instead.
  function isExpansionBlocked(data){
    return !!(data && (data.error_kind === 'expand_failed' || data.error_kind === 'terms_cap'));
  }
  function showExpansionBlocked(data){
    var detail = String((data && data.error) ||
      'The accepted values could not be safely expanded to every occurrence.');
    engineNote.innerHTML =
      '<div class="banner error engine-err">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>Nothing was saved — “Redact accepted values everywhere” could not ' +
          'be completed safely.</b>' +
        '<p>' + esc(detail) + '</p>' +
        '<p>Quickest fix: untick <b>Redact accepted values everywhere</b> above and save again — ' +
          'that exports exactly the occurrences you reviewed. Your original file is untouched.</p>' +
        '</div>' +
      '</div>';
    var hint = $('exportHint');
    if (hint){
      hint.textContent = 'Nothing was saved. Untick “Redact accepted values everywhere” and save again.';
      hint.className = 'hint warn';
    }
    announce('Nothing was saved — the redact-everywhere expansion could not be completed safely. ' +
      'Untick “Redact accepted values everywhere” and save again.');
  }

  // ---- Export result strip (features A/B/C) --------------------------------------
  // The optional REVIEWER NAME, persisted in localStorage like the detection options. It is
  // a name the user types; it stays on this computer (written only into the LOCAL report).
  var REVIEWER_KEY = 'lawbat.redaction.reviewer';
  function loadReviewerName(){
    var el = $('reviewerName');
    if (!el) return;
    try { var v = localStorage.getItem(REVIEWER_KEY); if (v) el.value = v; } catch(e){ /* best-effort */ }
    el.addEventListener('input', function(){
      try { localStorage.setItem(REVIEWER_KEY, el.value || ''); } catch(e){ /* best-effort */ }
    });
  }
  function reviewerName(){
    var el = $('reviewerName');
    return el ? (el.value || '').trim() : '';
  }

  // The three HONEST post-export verdicts. Load-bearing wording invariant: this is a CHECK,
  // not a guarantee — the copy NEVER uses the words "safe" or "verified". A found residual
  // (residuals_possible) tells the user NOT to rely on the copy; a clean check still says to
  // read it themselves; an incomplete check says so plainly.
  var VERDICT_COPY = {
    no_residuals_detected: {
      cls: 'ok',
      title: 'No residual text detected',
      body: 'This is a check, not a guarantee — read the document yourself before you rely on it.'
    },
    residuals_possible: {
      cls: 'error',
      title: 'Possible residual text — do NOT rely on this copy',
      body: 'Open Review and check the items below before you send this copy anywhere.'
    },
    could_not_fully_verify: {
      cls: 'warn',
      title: 'Could not fully verify this copy',
      body: 'The check could not read the whole file. Read the copy yourself before relying on it.'
    }
  };

  // A verdict is NON-CLEAN when the post-export check found a possible residual OR could not
  // rule one out — either state must keep the user on Export with the loud strip (never let
  // auto-advance read as "all clear"). Shared by the text and PDF export paths (the OCR path
  // never auto-advances at all, so it has no equivalent gap).
  function verdictIsCaveat(v){
    return !!(v && (v.state === 'residuals_possible' || v.state === 'could_not_fully_verify'));
  }

  // Render the verification verdict (A) + the "Cleaned / Not removed" line (C) + the workflow
  // report filename (B) into #exportResultStrip. Matter-free: verdict CLASSES are recognizer
  // labels + counts, never a cleartext value; every string is esc()'d before innerHTML.
  function renderExportStrip(data, opts){
    opts = opts || {};
    var strip = $('exportResultStrip');
    if (!strip) return;
    var html = '';
    var v = data && data.verification;
    if (v && v.state){
      var vc = VERDICT_COPY[v.state] || VERDICT_COPY.could_not_fully_verify;
      html += '<div class="banner ' + vc.cls + '"><span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>' + esc(vc.title) + '</b><p>' + esc(vc.body) + '</p>';
      var classes = (v.classes && typeof v.classes === 'object') ? v.classes : {};
      var keys = Object.keys(classes);
      if (keys.length){
        var parts = keys.map(function(k){ return esc(k) + ' ×' + classes[k]; });
        html += '<p>Possible residual by type: ' + parts.join(', ') + '.</p>';
      }
      (v.reasons || []).forEach(function(r){ html += '<p>' + esc(String(r)) + '</p>'; });
      html += '</div></div>';
    }
    // Feature C — what the engine actually cleaned, and its honest gaps. For a text export
    // metadata cleaning does not apply (there is no document metadata to remove).
    if (opts.metadataNa || (data && data.metadata_na)){
      html += '<div class="hint" style="margin-top:8px">Metadata cleaning: not applicable for a ' +
        'text export (there is no document metadata to remove).</div>';
    } else {
      var cleaned = (data && data.cleaned) || [];
      var notRemoved = (data && data.not_removed) || [];
      if (cleaned.length){
        html += '<div class="hint" style="margin-top:8px"><b>Cleaned:</b> ' +
          cleaned.map(esc).join('; ') + '.</div>';
      }
      if (notRemoved.length){
        html += '<div class="hint warn" style="margin-top:6px"><b>Not removed by this tool:</b> ' +
          notRemoved.map(esc).join('; ') + ' — review these yourself.</div>';
      }
    }
    // Feature B — the local workflow record written beside the export.
    if (data && data.report_filename){
      html += '<div class="hint" style="margin-top:8px">A workflow record was saved next to your ' +
        'copy: <span class="rtok">' + esc(data.report_filename) + '</span> — a local record of what ' +
        'was done, not a tamper-evident audit log.</div>';
    }
    strip.innerHTML = html;
    strip.classList.toggle('hidden', !html);
  }

  // ---- Report stage (post-export) -----------------------------------------------
  // Flip the `exported` flag (unlocks the Report stage + marks Export 'done'), capture the
  // matter-free `lastExport` descriptor the Report stage's buttons act on, render the Report
  // stage, and navigate to it. Called ONLY after a redacted copy is actually written to disk
  // (a text file-save, a PDF apply, or an OCR apply).
  // `navigate` (default true) advances to the Report stage. It is passed FALSE when the
  // export carried loud error-class caveats (a could_not_remove red banner, a scanned/
  // unmapped-font warning, an OCR best-effort note) — those live in the Export stage and
  // must stay IMPOSSIBLE TO MISS, so we keep the user on Export (Report still unlocks and is
  // one stepper click away). A clean export advances straight to Report.
  function markExported(data, kind, navigate){
    data = data || {};
    exported = true;
    lastExport = {
      filename: data.filename || null,
      report_filename: data.report_filename || null,
      // the local .report.txt (readable copy) — "View report" reveals/opens THIS file.
      report_txt_filename: data.report_txt_filename || null,
      kind: kind || 'text'
    };
    renderReportStage(data);
    // BATCH: if this export happened for a file loaded from a folder batch, mark that entry
    // exported in the file list (no-op in the single-file flow — batchActiveRel is null).
    if (typeof batchOnExported === 'function') batchOnExported(data, kind);
    refreshStepper();
    if (navigate !== false) goStage('report');
  }

  // Render the Report stage from the export response: status CHIPS wired to real artifacts +
  // the post-export verification verdict. The chip is a short, decisive label; the verdict's
  // EXACT honest wording (VERDICT_COPY — which NEVER says "safe"/"verified") is relocated
  // verbatim into the expandable banner below it. Every rendered string is esc()'d.
  function renderReportStage(data){
    data = data || {};
    var saved = $('repSavedChip'), repRep = $('repReportChip'), repChk = $('repCheckChip');
    if (saved){
      saved.classList.remove('hidden');
      saved.title = data.filename ? ('Saved: ' + data.filename) : 'Redacted copy saved';
    }
    if (repRep){
      var hasReport = !!data.report_filename;
      repRep.classList.toggle('hidden', !hasReport);
      if (hasReport) repRep.title = 'Workflow record: ' + data.report_filename;
    }
    var v = data.verification;
    var vc = (v && v.state && VERDICT_COPY[v.state]) || null;
    if (repChk){
      if (vc){
        repChk.classList.remove('hidden');
        // Short chip label; the FULL honest wording lives in #reportVerdict below.
        repChk.textContent = v.state === 'no_residuals_detected' ? 'Post-check passed'
          : (v.state === 'residuals_possible' ? 'Post-check: possible residual'
            : 'Post-check: incomplete');
        repChk.className = 'chip ' + vc.cls;
        repChk.title = vc.title;
      } else {
        repChk.classList.add('hidden');
      }
    }
    var verdictEl = $('reportVerdict');
    if (verdictEl){
      verdictEl.innerHTML = vc
        ? ('<div class="banner ' + vc.cls + '"><span class="ic" aria-hidden="true">&#9888;</span>' +
           '<div class="body"><b>' + esc(vc.title) + '</b><p>' + esc(vc.body) + '</p></div></div>')
        : '';
    }
    var detailEl = $('reportDetail');
    if (detailEl){
      var html = '';
      if (data.metadata_na){
        html += '<div class="hint">Metadata cleaning: not applicable for a text export ' +
          '(there is no document metadata to remove).</div>';
      } else {
        var cleaned = data.cleaned || [], notRemoved = data.not_removed || [];
        if (cleaned.length) html += '<div class="hint"><b>Cleaned:</b> ' +
          cleaned.map(esc).join('; ') + '.</div>';
        if (notRemoved.length) html += '<div class="hint warn" style="margin-top:6px">' +
          '<b>Not removed by this tool:</b> ' + notRemoved.map(esc).join('; ') +
          ' — review these yourself.</div>';
      }
      if (data.report_filename){
        html += '<div class="hint" style="margin-top:6px">A workflow record was saved next to your ' +
          'copy: <span class="rtok">' + esc(data.report_filename) + '</span> — a local record of what ' +
          'was done, not a tamper-evident audit log.</div>';
      }
      detailEl.innerHTML = html;
    }
    // Enable the actions only for artifacts that exist (a missing .report.txt disables View).
    var of = $('openFolderBtn'); if (of) of.disabled = !data.filename;
    var vr = $('viewReportBtn'); if (vr) vr.disabled = !data.report_txt_filename;
    var ah = $('reportActionsHint'); if (ah){ ah.textContent = ''; ah.className = 'hint'; }
  }

  // Report-stage actions: reveal the saved copy / open its local .report.txt. Both POST the
  // exact saved filename to the CONFINED server route (open-export), which rejects any path
  // outside the exports dir — the browser never touches the filesystem itself.
  async function openExportFolder(){
    if (!lastExport || !lastExport.filename) return;
    var hint = $('reportActionsHint');
    var r = await post('/api/redaction/open-export', {filename: lastExport.filename, action: 'reveal'});
    if (hint) hint.textContent = (r.ok && r.data && r.data.ok)
      ? 'Opened the exports folder.' : 'Could not open the folder — find it in your exports folder.';
  }
  async function openExportReport(){
    if (!lastExport || !lastExport.report_txt_filename) return;
    var hint = $('reportActionsHint');
    var r = await post('/api/redaction/open-export', {filename: lastExport.report_txt_filename, action: 'open'});
    if (hint) hint.textContent = (r.ok && r.data && r.data.ok)
      ? 'Opened the report.' : 'Could not open the report — find it in your exports folder.';
  }

  // Labels (AI-safe pseudonymization) is a TEXT-PATH feature only — the variable-length
  // placeholders break the format-preserving PDF byte-splice, so the PDF flow ships only
  // the [REDACTED] style. For a PDF document we DISABLE the labels radio, force-select
  // [REDACTED], and show a short why-disabled hint, so it can never be chosen for a PDF.
  function syncReplStyleForMode(){
    var labelsRadio = document.querySelector('input[name="replstyle"][value="labels"]');
    var redactedRadio = document.querySelector('input[name="replstyle"][value="redacted"]');
    var labelsOpt = labelsRadio ? labelsRadio.closest('.repl-opt') : null;
    var isPdf = mode === 'pdf';
    if (labelsRadio){
      labelsRadio.disabled = isPdf;
      labelsRadio.setAttribute('aria-disabled', isPdf ? 'true' : 'false');
      if (isPdf && labelsRadio.checked && redactedRadio){ redactedRadio.checked = true; }
    }
    if (labelsOpt){
      labelsOpt.classList.toggle('disabled', isPdf);
      labelsOpt.title = isPdf
        ? 'Labels aren’t available for PDFs — a PDF keeps [REDACTED] so its layout stays intact.'
        : '';
    }
    var hint = $('replPdfHint');
    if (hint) hint.classList.toggle('hidden', !isPdf);
  }

  function updateExportGate(){
    syncReplStyleForMode();   // keep the labels radio disabled for a PDF document
    var reviewOk = reviewComplete();
    var passOk = passagesAllAcked();
    // An unscanned/reset document has zero candidates, making reviewOk/passOk vacuously
    // true — never let that enable Export or claim "Ready" (Finding #4); a fresh scan is
    // the precondition (the stage gate already enforces this, this is defense-in-depth).
    var canExport = (cands !== undefined) && reviewOk && passOk;
    var btn = $('exportBtn');
    if (btn){ btn.disabled = !canExport; btn.setAttribute('aria-disabled', canExport ? 'false' : 'true'); }
    // The SECOND, clearly-separate export affordance (labeled Markdown for AI use) rides the
    // SAME readiness gate — never exportable before the review is complete.
    var lmb = $('labeledMdBtn');
    if (lmb){ lmb.disabled = !canExport; lmb.setAttribute('aria-disabled', canExport ? 'false' : 'true'); }
    var hint = $('exportHint');
    if (hint){
      if (cands === undefined) hint.textContent = 'Scan a document first, then review the findings.';
      else if (canExport) hint.textContent = 'Ready — choose a style above, then save.';
      else {
        var msgs = [];
        if (!reviewOk) msgs.push(carefulUnresolved() + ' item(s) still to review');
        if (!passOk) msgs.push('sensitive passages not acknowledged');
        hint.textContent = 'Resolve: ' + msgs.join(' · ') + '.';
      }
      hint.className = 'hint' + (canExport ? ' ok' : (cands === undefined ? '' : ' warn'));
    }
    buildExportChecklist();
  }

  function buildExportChecklist(){
    var list = $('exportChecklist'), banner = $('exportBanner');
    if (!list) return;
    // No fresh scan (a reset / unscanned document): reviewComplete()/passagesAllAcked() are
    // VACUOUSLY true with zero candidates, so paint a NEUTRAL "scan first" state rather than
    // a green "everything reviewed" for a document that was never scanned (Finding #4).
    if (cands === undefined){
      if (banner){
        banner.innerHTML = '<div class="banner"><span class="ic" aria-hidden="true">&#128269;</span>' +
          '<div class="body"><b>Nothing to export yet.</b><p>Scan a document first, then review the ' +
          'findings. Nothing has been written, and your original is untouched.</p></div></div>';
      }
      list.innerHTML = '';
      return;
    }
    var reviewOk = reviewComplete();
    var passOk = passagesAllAcked();
    var unresolved = carefulUnresolved();
    var passTotal = (passageList || []).length;
    var canExport = reviewOk && passOk;
    if (banner){
      banner.innerHTML = canExport
        ? '<div class="banner ok"><span class="ic" aria-hidden="true">&#10003;</span>' +
            '<div class="body"><b>Ready to export.</b><p>Everything has been reviewed. Choose how the ' +
            'gaps should read, then save below. Nothing is written until you click Save.</p></div></div>'
        : '<div class="banner error"><span class="ic" aria-hidden="true">&#128274;</span>' +
            '<div class="body"><b>Not ready to export yet.</b><p>Saving is paused until the items below ' +
            'are handled. Nothing has been written, and your original is untouched.</p></div></div>';
    }
    var items = [];
    items.push(reviewOk
      ? {cls:'ok', mark:'✓', title:'All findings decided', body:'The careful-review items were all kept or dismissed.'}
      : {cls:'block', mark:'!', title:unresolved + ' item' + (unresolved === 1 ? '' : 's') + ' still to review',
         body:'In Review, decide each amber “Please review” item (keep or dismiss).', go:'review', goLabel:'Go to Review'});
    items.push(passOk
      ? {cls:'ok', mark:'✓', title:'Sensitive passages acknowledged',
         body:(passTotal === 0 ? 'Nothing was flagged.' : 'All ' + passTotal + ' flagged passage(s) were read.')}
      : {cls:'block', mark:'!', title:'Sensitive passages not acknowledged',
         body:'Read the flagged sensitive / re-identification passages and tick that you’ve seen them.',
         go:'review', goLabel:'Go to sensitive passages'});
    // The unmapped-font caveat surfaces here as a non-blocking warning when the last PDF
    // scan flagged it — honest framing (we do not silently cover; we flag it).
    if (mode === 'pdf' && lastUnmappedFonts){
      items.push({cls:'warn', mark:'!', title:'Some pages use an unusual font',
        body:'Those pages were read best-effort — an item there may not be fully removable. ' +
          'You’ll see this called out in the report; read those pages before relying on the copy.'});
    }
    if (mode === 'pdf' && lastLowText){
      items.push({cls:'warn', mark:'!', title:'This looks like a scanned PDF',
        body:'Text baked into the page image is not reached by text redaction. Use “OCR & redact ' +
          'scanned PDF” in Review for those pages.'});
    }
    list.innerHTML = '';
    items.forEach(function(it){
      var div = document.createElement('div');
      div.className = 'cl-item ' + it.cls;
      div.innerHTML =
        '<span class="ci" aria-hidden="true">' + esc(it.mark) + '</span>' +
        '<div class="clbody"><b>' + esc(it.title) + '</b><p>' + esc(it.body) + '</p></div>' +
        (it.go ? '<div class="clact"><button type="button" class="btn ghost sm" data-go="' +
          esc(it.go) + '">' + esc(it.goLabel) + '</button></div>' : '');
      list.appendChild(div);
    });
  }

  async function doExport(){
    if (mode === 'pdf') return doPdfExport();
    return doTextExport();
  }

  async function doTextExport(){
    // Don't "export nothing" silently. With no scanned text there is nothing to save;
    // with no accepted spans the output would equal the original (no redactions) — warn
    // the user rather than handing back an unchanged copy as if it were redacted.
    if (scannedText == null || !String(scannedText).trim()){
      $('exportHint').textContent = 'There is no text to export. Go back, paste or upload a document, then scan it.';
      $('exportHint').className = 'hint warn';
      return;
    }
    // PROVENANCE FAIL-SAFE: the candidates must belong to the text we're about to redact.
    // If the text changed since the scan, refuse rather than apply stale spans/flags.
    if (!scanProvenanceMatches()){
      $('exportHint').textContent = 'The text changed since it was scanned. Scan it again before saving — Lawbat won’t reuse the previous scan’s results on changed text.';
      $('exportHint').className = 'hint warn';
      announce('Export blocked — the text changed since the scan. Scan it again first.');
      return;
    }
    var accept = acceptedSpans();
    if (accept.length === 0){
      var ok = window.confirm('Nothing is selected to redact, so the exported text will be ' +
        'identical to the original (no redactions). Export it anyway?');
      if (!ok){
        $('exportHint').textContent = 'Tick at least one finding to redact, or use “Add a redaction”.';
        $('exportHint').className = 'hint warn';
        return;
      }
    }
    var style = replStyle();
    var btn = $('exportBtn');
    btn.disabled = true; $('exportHint').textContent = 'Saving…'; $('exportHint').className = 'hint';
    var r = await post('/api/redaction/apply',
      {text:scannedText, accept:accept, options:scanOptions, replacement_style:style,
       redact_everywhere:redactEverywhere(), keep:parseKeep()});
    btn.disabled = false; $('exportHint').textContent = '';
    if (!r.ok || r.data.error){
      // Gate refresh FIRST — updateExportGate repaints #exportHint, so the apply-specific
      // "Nothing was saved…" hint must be written after it (never clobbered by "Ready —…").
      updateExportGate();
      if (isExpansionBlocked(r.data)) showExpansionBlocked(r.data);
      else showEngineError(r.data.error || ('Apply failed (HTTP ' + r.status + ').'));
      return;
    }
    outHead.style.display = ''; output.classList.remove('hidden'); copyBtn.classList.remove('hidden');
    output.value = r.data.redacted != null ? r.data.redacted : '';
    var applied = r.data.applied || 0, stale = r.data.stale || 0;
    var styleNote = style === 'labels'
      ? ' Each removed item became a readable label so the draft still reads clearly.'
      : '';
    applySummary.innerHTML = '<b>' + applied + '</b> redaction' + (applied === 1 ? '' : 's') +
      ' applied.' + (stale ? ' <span class="hint warn">' + stale +
      ' span(s) were stale (text changed) and skipped.</span>' : '') + styleNote +
      expansionNote(r.data.expansion, 0) +
      ' Review the result below before you use it.';
    renderLegend(style === 'labels' ? (r.data.legend || []) : null);
    // Update the re-identification EXPOSURE meter with the AFTER score (the residual /
    // redacted text scored server-side). The engine removes named identifiers but NOT
    // dates/roles/locations/orgs, so after ~= before is EXPECTED and HONEST — the delta
    // line + surviving-category breakdown say exactly that.
    renderReidMeter(reidBefore || null, r.data.reid_score_after || null);
    // Capture the produced result so "Save to a file" can format + write it WITHOUT
    // re-redacting. The redacted text is already free of original values; the legend is
    // cleartext kept LOCAL (only posted to the local export route to write the key file).
    lastTextApply = {
      redacted: r.data.redacted != null ? r.data.redacted : '',
      applied: applied, stale: stale, labeled: style === 'labels',
      legend: style === 'labels' ? (r.data.legend || []) : [],
      // FEATURE 1 — echo the mode/counts to /text-export so the WORKFLOW RECORD states them.
      expansion: r.data.expansion || null,
      // POST-CHECK wiring (2026-07-17 audit): the ORIGINAL text + the accept spans THAT
      // PRODUCED this redacted text, captured AT APPLY TIME so the save's post-export check
      // verifies the real accepted values (never a selection changed after the apply). The
      // text is matter cleartext — it only travels to the LOCAL export route, like the apply.
      text: scannedText,
      accept: accept
    };
    showTextSaveSeam();
    outwrap.classList.remove('hidden');
    output.scrollIntoView({behavior:'smooth', block:'nearest'});
    announce(applied + ' redactions applied. Read the result below, then save it to a file if you like.');
  }

  // ---- SAVE the redacted text to a file (exports dir; the text-path file export) --------
  function textFmt(){
    var r = document.querySelector('input[name="textfmt"]:checked');
    return r ? r.value : 'txt';
  }

  // Reveal the "Save to a file" section after a TEXT apply. Hidden in PDF mode (the PDF flow
  // writes its own file). Shows the key-warning banner ONLY when labels produced a legend.
  function showTextSaveSeam(){
    var seam = $('textSaveSeam');
    if (!seam) return;
    if (mode === 'pdf' || !lastTextApply){ hideTextSaveSeam(); return; }
    seam.classList.remove('hidden');
    var kw = $('keyWarn');
    var hasKey = !!(lastTextApply.labeled && lastTextApply.legend && lastTextApply.legend.length);
    if (kw) kw.classList.toggle('hidden', !hasKey);
    var res = $('textSaveResult');
    if (res){ res.classList.add('hidden'); res.innerHTML = ''; }
    var hint = $('textSaveHint');
    if (hint){ hint.textContent = ''; hint.className = 'hint'; }
  }
  function hideTextSaveSeam(){
    var seam = $('textSaveSeam');
    if (seam) seam.classList.add('hidden');
  }

  async function doTextSave(){
    if (!lastTextApply){ return; }
    // PROVENANCE FAIL-SAFE (defense in depth): the redacted text we hold belongs to the
    // text that was scanned + applied. If the document changed since (a stale redaction),
    // refuse — do not write an old redaction's output against a changed document. Mirrors
    // the apply guard so a "scan A -> change text -> save" sequence can't slip through.
    if (!scanProvenanceMatches()){
      var h0 = $('textSaveHint');
      if (h0){ h0.textContent = 'The text changed since it was redacted. Redact it again before saving.';
        h0.className = 'hint warn'; }
      announce('Save blocked — the text changed since it was redacted. Redact it again first.');
      return;
    }
    var fmt = textFmt();
    var btn = $('textSaveBtn'), hint = $('textSaveHint');
    if (btn) btn.disabled = true;
    if (hint){ hint.textContent = 'Saving…'; hint.className = 'hint'; }
    var body = {
      redacted_text: lastTextApply.redacted,
      format: fmt,
      labeled: lastTextApply.labeled,
      applied: lastTextApply.applied,
      stale: lastTextApply.stale,
      // The SAME detection options the apply used, so the post-export re-scan (feature A)
      // matches; plus the optional reviewer name for the workflow report (feature B).
      options: scanOptions,
      reviewer: reviewerName(),
      // FEATURE 1 — the mode the /apply above ran, so the workflow record states it (the
      // redacted text is ALREADY expanded; this only records which mode + how many extra).
      expansion: lastTextApply.expansion,
      // POST-CHECK wiring (2026-07-17 audit): the original text + the accept spans that
      // produced the redacted text, so the server re-derives the accepted VALUES and the
      // post-export check returns a REAL verdict on the flat [REDACTED] flow too (it used
      // to say "incomplete — the accepted values were not available" on every clean run).
      text: lastTextApply.text,
      accept: lastTextApply.accept
    };
    // The legend (cleartext) is posted to the LOCAL export route ONLY in labels mode, so the
    // server can write the SEPARATE key file. It never leaves the machine.
    if (lastTextApply.labeled) body.legend = lastTextApply.legend;
    var r = await post('/api/redaction/text-export', body);
    if (btn) btn.disabled = false;
    if (!r.ok || r.data.error){
      if (hint){ hint.textContent = ''; }
      showEngineError(r.data.error || ('Could not save the file (HTTP ' + r.status + ').'));
      return;
    }
    if (hint){ hint.textContent = ''; }
    var res = $('textSaveResult');
    if (res){
      var name = esc(r.data.filename || 'redacted.txt');
      var keyName = r.data.key_filename;
      var html = '✓ Saved <b>' + name + '</b> to your exports folder. Opened the folder for you.';
      if (r.data.key_failed){
        // The labeled copy needs a key to be reversed, but the key write FAILED — warn
        // loudly. Never let the success line imply a recoverable label pair exists.
        html += '<div class="banner warn" style="margin-top:10px">' +
          '<span class="ic" aria-hidden="true">&#9888;</span>' +
          '<div class="body"><b>The label key could NOT be saved.</b><p>' +
          esc('Your labeled copy cannot be reversed without it. Redact and save again to ' +
          'get a matching key file.') + '</p></div></div>';
      } else if (keyName){
        html += '<div class="banner warn" style="margin-top:10px">' +
          '<span class="ic" aria-hidden="true">&#128274;</span>' +
          '<div class="body"><b>A key file was also saved: <span class="rtok">' + esc(keyName) +
          '</span></b><p>' + esc('It maps the labels back to the real names. Keep it on this ' +
          'computer — do NOT send it with the redacted document or paste it into an AI tool.') +
          '</p></div></div>';
      }
      res.innerHTML = html;
      res.classList.remove('hidden');
    }
    // Features A/B/C for the text export: verification verdict + report path, with metadata
    // cleaning flagged N/A (a text file has no document metadata to scrub).
    renderExportStrip(r.data, {metadataNa: true});
    // Advance to the Report stage — UNLESS the post-export check flagged a possible residual
    // OR could not fully verify the copy (either is non-clean): then stay on Export so the
    // loud verdict stays impossible to miss.
    var textCaveat = verdictIsCaveat(r.data.verification) || !!r.data.key_failed;
    markExported(r.data, 'text', !textCaveat);
    announce(r.data.key_failed
      ? 'Saved the redacted file, but the label key could not be saved — the labeled copy cannot be reversed.'
      : (r.data.key_filename
        ? 'Saved the redacted file and a separate key file. Keep the key on this computer.'
        : 'Saved the redacted file to your exports folder.'));
  }

  // ---- LABELED MARKDOWN (AI working copy) — a SECOND, clearly-separate export ----------
  // Rebuilds the reviewed document as a .md with each identifier replaced by a LABEL, for
  // AI-assisted drafting. This is NOT the production redacted document — the .md header + the
  // card say so. The SERVER owns the single apply (labels) + the Markdown assembly + the
  // SEPARATE re-identification key file; the host only posts the reviewed accept-set (text
  // path) or the file bytes (PDF -> extract + accept-all, over-labeling is the safe side for
  // a working copy). Same provenance fail-safe + Report-stage handoff as the other exports.
  async function doLabeledMarkdownExport(){
    if (!scanProvenanceMatches()){
      var h = $('labeledMdHint');
      if (h){ h.textContent = 'This document changed since it was scanned. Scan it again before exporting.'; h.className = 'hint warn'; }
      announce('Labeled Markdown export blocked — the document changed since the scan. Scan it again first.');
      return;
    }
    var btn = $('labeledMdBtn'), hint = $('labeledMdHint');
    var body = {options: scanOptions, reviewer: reviewerName(),
                redact_everywhere: redactEverywhere(), keep: parseKeep()};
    if (mode === 'pdf'){
      if (!pdfFile) return;
      if (btn) btn.disabled = true;
      if (hint){ hint.textContent = 'Building the working copy…'; hint.className = 'hint'; }
      var b64;
      try { b64 = await fileToBase64(pdfFile); }
      catch(e){ if (btn) btn.disabled = false; if (hint) hint.textContent = ''; showEngineError('Could not read that file.'); return; }
      body.filename = pdfFile.name; body.data_b64 = b64;
    } else {
      if (scannedText == null || !String(scannedText).trim()){
        if (hint){ hint.textContent = 'There is no text to export. Scan a document first.'; hint.className = 'hint warn'; }
        return;
      }
      if (btn) btn.disabled = true;
      if (hint){ hint.textContent = 'Building the working copy…'; hint.className = 'hint'; }
      body.text = scannedText; body.accept = acceptedSpans();
    }
    var r = await post('/api/redaction/labeled-markdown', body);
    if (btn) btn.disabled = false;
    if (hint){ hint.textContent = ''; }
    if (!r.ok || r.data.error){
      if (isExpansionBlocked(r.data)) showExpansionBlocked(r.data);
      else showEngineError(r.data.error || ('Could not build the labeled copy (HTTP ' + r.status + ').'));
      return;
    }
    renderLabeledMdResult(r.data);
    // Unlock + record the artifact for the Report stage. Stay on Export when the post-export
    // check flagged a caveat (or the key failed) so the loud verdict can't be missed — the
    // SAME auto-advance rule the production exports use.
    var caveat = verdictIsCaveat(r.data.verification) || !!r.data.key_failed;
    markExported(r.data, 'labeled-markdown', !caveat);
    announce(r.data.key_failed
      ? 'Saved the labeled Markdown, but the label key could not be saved — the labeled copy cannot be reversed.'
      : (r.data.key_filename
        ? 'Saved the labeled Markdown and a separate key file. Keep the key on this computer.'
        : 'Saved the labeled Markdown working copy to your exports folder.'));
  }

  // Render the labeled-MD save result: the saved .md name (with the boundary restated), the
  // SEPARATE key-file keep-local warning, and the honest post-export verdict (VERDICT_COPY,
  // which never says "safe"/"verified"). Every string esc()'d before innerHTML.
  function renderLabeledMdResult(data){
    var res = $('labeledMdResult');
    if (!res) return;
    var name = esc(data.filename || 'document.labeled.md');
    var html = '✓ Saved <b>' + name + '</b> to your exports folder — a working copy for AI use, ' +
      'NOT the production redacted document.';
    if (data.key_failed){
      html += '<div class="banner warn" style="margin-top:10px"><span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>The label key could NOT be saved.</b><p>' +
        esc('Your labeled copy cannot be reversed without it. Export again to get a matching key file.') +
        '</p></div></div>';
    } else if (data.key_filename){
      html += '<div class="banner warn" style="margin-top:10px"><span class="ic" aria-hidden="true">&#128274;</span>' +
        '<div class="body"><b>A key file was also saved: <span class="rtok">' + esc(data.key_filename) +
        '</span></b><p>' + esc('It maps the labels back to the real names. Keep it on this computer — ' +
        'do NOT send it with the labeled copy or paste it into an AI tool.') + '</p></div></div>';
    }
    var v = data.verification;
    var vc = (v && v.state && VERDICT_COPY[v.state]) || null;
    if (vc){
      html += '<div class="banner ' + vc.cls + '" style="margin-top:10px"><span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>' + esc(vc.title) + '</b><p>' + esc(vc.body) + '</p></div></div>';
    }
    res.innerHTML = html;
    res.classList.remove('hidden');
  }

  // Render the LOCAL-ONLY re-identification KEY (labels style). EVERY value is cleartext
  // matter data and is esc()'d before innerHTML. The key never leaves the machine.
  function renderLegend(legend){
    var seam = $('reidentKeySeam');
    if (!seam) return;
    if (!legend || !legend.length){
      seam.innerHTML = ''; seam.classList.add('hidden'); seam.setAttribute('aria-hidden', 'true');
      return;
    }
    var rows = legend.map(function(e){
      var count = (typeof e.count === 'number' && e.count > 1) ? ' (×' + e.count + ')' : '';
      return '<div class="keyrow"><span class="k lbl-tok">' + esc(e.label) + '</span>' +
        '<span class="arr">=</span><span class="v">' + esc(e.value) + esc(count) + '</span></div>';
    }).join('');
    seam.innerHTML =
      '<div class="keycard">' +
        '<div class="keyhead"><span class="ic" aria-hidden="true">&#128274;</span>' +
          '<div><b>Key — what each label really means</b>' +
            '<p><span class="keystrong">This key stays on your computer. Never paste it into an AI ' +
            'or send it anywhere.</span> It is the only thing that turns the labels back into real ' +
            'people — keep it to yourself, and delete it when you are done.</p></div>' +
        '</div>' +
        '<div class="keytable">' + rows + '</div>' +
      '</div>';
    seam.classList.remove('hidden'); seam.setAttribute('aria-hidden', 'false');
  }

  async function doPdfExport(){
    if (!pdfFile) return;
    // PROVENANCE FAIL-SAFE: the loaded PDF must be the one these candidates + flags came
    // from. A mismatch (a new document loaded without a re-scan) => REFUSE; never apply A's
    // findings/flags against B's bytes, never inherit A's "clean" unmapped-font flag.
    if (!scanProvenanceMatches()){
      $('exportHint').textContent = 'This file changed since it was scanned. Go back and scan it again before saving — Lawbat won’t reuse the previous scan’s results on a different file.';
      $('exportHint').className = 'hint warn';
      announce('Export blocked — the file changed since the scan. Scan it again first.');
      return;
    }
    var sel = selectedPdfCandidates();
    var ids = sel.ids;
    // #7 FAIL-CLOSED: a SELECTED candidate with NO usable engine id cannot be sent in
    // accept_ids (the engine accepts purely by id membership — no ordinal fallback), so it
    // would be COUNTED as "will be redacted" yet silently OMITTED from removal = a leak
    // (fail-OPEN). Refuse the whole apply rather than write a "redacted" PDF that quietly
    // left a selected identifier in. In practice pdf_scan always assigns an id, so this is
    // belt-and-braces — but if it ever fires we stop, honestly, instead of under-removing.
    if (sel.missingId > 0){
      $('exportHint').textContent = 'Lawbat can’t safely remove one or more selected items from ' +
        'this PDF (they’re missing the internal reference it needs). To avoid leaving them in by ' +
        'mistake, saving is blocked — scan this PDF again, then try once more. Your original is untouched.';
      $('exportHint').className = 'hint warn';
      announce('Export blocked — ' + sel.missingId + ' selected item' + (sel.missingId === 1 ? '' : 's') +
        ' can’t be removed safely. Scan the PDF again and retry.');
      return;
    }
    // EMPTY-SELECTION FAIL-SAFE: if every detection is deselected, REFUSE — never write a
    // clean, unredacted PDF to exports labelled "redacted". (The engine is default-deny too:
    // an empty accept_ids removes nothing — so this also prevents an honest-but-useless
    // "0 removed" file being presented as a redaction.)
    if (ids.length === 0){
      $('exportHint').textContent = 'You’ve excluded all detections — nothing would be removed. ' +
        'Re-select at least one in Review, or cancel.';
      $('exportHint').className = 'hint warn';
      announce('Export blocked — all detections are deselected, so nothing would be redacted. ' +
        'Re-select at least one.');
      return;
    }
    var btn = $('exportBtn');
    btn.disabled = true; $('exportHint').textContent = 'Redacting & saving…'; $('exportHint').className = 'hint';
    var b64;
    try { b64 = await fileToBase64(pdfFile); }
    catch(e){ btn.disabled = false; $('exportHint').textContent = ''; showEngineError('Could not read that file.'); return; }
    var r = await post('/api/redaction/pdf-apply',
      {filename:pdfFile.name, data_b64:b64, accept_ids:ids, options:scanOptions, reviewer:reviewerName(),
       redact_everywhere:redactEverywhere(), keep:parseKeep()});
    btn.disabled = false; $('exportHint').textContent = '';
    if (!r.ok || r.data.error){
      // Gate refresh FIRST — updateExportGate repaints #exportHint, so the apply-specific
      // "Nothing was saved…" hint must be written after it (never clobbered by "Ready —…").
      updateExportGate();
      if (isExpansionBlocked(r.data)) showExpansionBlocked(r.data);
      else showEngineError(r.data.error || 'Could not save the redacted PDF.');
      return;
    }
    outHead.style.display = 'none'; output.classList.add('hidden'); copyBtn.classList.add('hidden');
    renderLegend(null);
    hideTextSaveSeam();   // the PDF path writes its own file — no text-file export here
    lastTextApply = null;
    var red = r.data.redactions || 0;
    // could_not_remove: accepted spans that resolved to ZERO removable bytes (the unmapped-
    // font apply gap). This is the LEAK DIRECTION — those items are still in the saved file.
    // It comes from pdf_apply. unmapped_fonts is NOT emitted on apply (the engine only flags
    // it on scan), so reuse the retained scan-time flag — same bytes + config, honest.
    var couldNot = r.data.could_not_remove || 0;
    var lowText = !!r.data.low_text;
    var unmapped = !!lastUnmappedFonts;
    // The post-export verification verdict is ITS OWN caveat source — a clean could_not_remove/
    // low_text/unmapped-font picture must NOT read as "all clear" if the independent re-scan
    // found (or couldn't rule out) a residual.
    var verdictCaveat = verdictIsCaveat(r.data.verification);
    var hasCaveat = couldNot > 0 || lowText || unmapped || verdictCaveat;
    var warn = '';
    if (couldNot > 0) warn +=
      '<div class="banner error" style="margin-top:12px">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>' + couldNot + ' item' + (couldNot === 1 ? '' : 's') +
          ' could NOT be removed from this PDF.</b>' +
        '<p>' + esc('They were detected but an unusual font meant the text couldn’t be taken out, ' +
          'so ' + (couldNot === 1 ? 'it is' : 'they are') + ' still in the saved file. Review and ' +
          'handle ' + (couldNot === 1 ? 'it' : 'these') + ' manually — open the saved copy and check, ' +
          'or redact ' + (couldNot === 1 ? 'it' : 'them') + ' by hand. Do not rely on this copy as-is.') +
        '</p></div>' +
      '</div>';
    if (lowText) warn +=
      '<div class="banner warn" style="margin-top:10px">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>This PDF looks like a scan.</b>' +
        '<p>' + esc('Text baked into the page images was NOT removed by text redaction — use ' +
          '“OCR & redact scanned PDF” for those pages.') + '</p></div>' +
      '</div>';
    if (unmapped) warn +=
      '<div class="banner warn" style="margin-top:10px">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>Some pages use an unusual font.</b>' +
        '<p>' + esc('Those pages were read best-effort, so an identifier there may not have been ' +
          'seen or fully removed. Read those pages yourself before relying on the result.') +
        '</p></div>' +
      '</div>';
    // ANTI-OVER-CLAIM: never headline a clean "✓ Saved … removed" when there are caveats.
    // With caveats the headline says "saved WITH N caveat(s) — review the warnings".
    var savedName = esc(r.data.filename || 'redacted.pdf');
    var head;
    if (hasCaveat){
      var caveats = (couldNot > 0 ? 1 : 0) + (lowText ? 1 : 0) + (unmapped ? 1 : 0) + (verdictCaveat ? 1 : 0);
      // When the ONLY caveat is the post-export verdict (no could_not_remove/low_text/unmapped
      // finding), name it explicitly in the headline rather than a bare "N caveat(s)" that
      // points at warnings which, in that case, live only in the result strip below.
      var verdictNote = '';
      if (verdictCaveat){
        var vc0 = VERDICT_COPY[r.data.verification.state];
        if (vc0) verdictNote = ' ' + esc(vc0.title) + '.';
      }
      head = '<b>Saved <span class="rtok">' + savedName + '</span> with ' + caveats + ' caveat' +
        (caveats === 1 ? '' : 's') + ' — review the warnings below.</b>' + verdictNote + ' <b>' + red + '</b> identifier' +
        (red === 1 ? '' : 's') + ' removed; this is a first pass, not “safe to send.” ' +
        'Your original file was not changed.';
    } else {
      head = '✓ Saved <b>' + savedName + '</b> to your exports folder (<b>' + red + '</b> identifier' +
        (red === 1 ? '' : 's') + ' removed). Opened the folder for you. This is a first pass — ' +
        'read it before you rely on it. Your original file was not changed.';
    }
    applySummary.innerHTML = '<div class="summary">' + head +
      expansionNote(r.data.expansion, r.data.could_not_remove || 0) + '</div>' + warn;
    // Features A/B/C — the post-export verification verdict, the cleaned/not-removed line,
    // and the workflow-report filename, rendered from the response into the result strip.
    renderExportStrip(r.data);
    // Unlock + render the Report stage. Advance to it ONLY when the export was CLEAN — with
    // caveats (could_not_remove / scanned / unmapped font / a non-clean verification verdict)
    // we stay on Export so those loud banners stay impossible to miss (Report is still one
    // stepper click away).
    markExported(r.data, 'pdf', !hasCaveat);
    outwrap.classList.remove('hidden');
    applySummary.scrollIntoView({behavior:'smooth', block:'nearest'});
    announce(hasCaveat
      ? ('Saved the redacted PDF with caveats. ' + red + ' identifiers removed' +
         (couldNot > 0 ? '; ' + couldNot + ' could not be removed' : '') + '. Review the warnings.')
      : ('Saved the redacted PDF. ' + red + ' identifiers removed. Read it before you rely on it.'));
  }

