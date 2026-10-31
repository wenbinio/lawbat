/* ==== CONCATENATION FRAGMENT — app/ui/redaction.batch.js ====
   This file is NOT standalone-valid JavaScript. Like the other redaction.*.js files it is
   ONE slice of the single outer IIFE (opened by app/ui/redaction.core.js, closed by
   app/ui/redaction.stepper.js). Its position in the concatenation is defined ONLY by
   REDACTION_JS_PARTS in app/ui_manifest.py — it is inserted AFTER the per-file review/
   export/ocr fragments and BEFORE redaction.stepper.js (which wires its buttons + closes the
   IIFE). Never reorder without re-verifying the assembled script.

   TWO increment-1 capabilities:
     A. TERMS import — parse an uploaded .csv/.txt names list (server side, no cleartext
        logged) and MERGE it into the terms textarea (which stays the source of truth).
     B. BATCH (folder) mode — enumerate a chosen folder (server side; the browser can't read
        a folder), scan each file in a sequential queue, load a file into the EXISTING per-file
        review flow on click (FULL reset between files, so one file's decisions/acks NEVER leak
        into another — the load-bearing batch invariant), and export ALL fully-reviewed files
        into one never-overwrite subdir with a batch-summary report.

   Air-gapped: every server call is the local /api/redaction/* surface; every cleartext
   (filenames, terms) is esc()'d before innerHTML or set via textContent. */

  // ---- TERMS import (.csv / .txt -> merge into the terms textarea) ---------------
  async function importTermsFromFile(file){
    var hint = $('termsImportHint');
    if (!file){ return; }
    var b64;
    try { b64 = await fileToBase64(file); }
    catch(e){ if (hint) hint.textContent = 'Could not read that file.'; return; }
    var r;
    try { r = await post('/api/redaction/import-terms', {filename: file.name, data_b64: b64}); }
    catch(e){ r = {ok:false, data:{}}; }
    if (!r.ok || !r.data || r.data.error || !Array.isArray(r.data.terms)){
      if (hint) hint.textContent = (r.data && r.data.error) || 'Could not import that list.';
      return;
    }
    var box = $('termsBox');
    if (!box){ return; }
    // MERGE (never replace): the textarea stays the source of truth — the user always sees the
    // full list. De-dupe against what's already there, case-insensitively, honouring MAX_TERMS.
    var existing = parseTerms(box.value);
    var seen = {};
    existing.forEach(function(t){ seen[t.toLowerCase()] = 1; });
    var added = 0, already = 0;
    r.data.terms.forEach(function(t){
      var k = String(t).toLowerCase();
      if (seen[k]){ already++; return; }
      if (existing.length >= MAX_TERMS){ return; }
      seen[k] = 1; existing.push(t); added++;
    });
    box.value = existing.join('\n');
    saveOptions();   // persist + refresh the terms summary line
    // Honest feedback: imported / duplicates skipped (in-file dupes + already-present) / dropped.
    var dupes = (r.data.duplicates || 0) + already;
    var dropped = r.data.dropped || 0;
    if (hint){
      var msg = added + ' term' + (added === 1 ? '' : 's') + ' imported';
      if (dupes) msg += ', ' + dupes + ' duplicate' + (dupes === 1 ? '' : 's') + ' skipped';
      if (dropped) msg += ', ' + dropped + ' dropped (too long or too short)';
      hint.textContent = msg + '.';
    }
    announce(added + ' term' + (added === 1 ? '' : 's') + ' imported from the list.');
  }

  // ---- BATCH (folder) state ------------------------------------------------------
  // batchFiles: [{rel, name, size, status, findings, error, kind, decision, reviewed, exported}]
  //   status: 'pending' | 'scanning' | 'scanned' | 'error' | 'reviewed' | 'exported' | 'recheck'
  //   decision: null | {kind:'pdf', accept_ids, options, decided, cand_key}
  //                  | {kind:'text', accept:[[s,e]...], options, format, decided, cand_key}
  // The decision is PLAIN DATA tied to one file's rel — it is the ONLY per-file review state
  // that persists across a file switch, and it is used ONLY by that file's own batch export.
  // `cand_key` is the fingerprint of the candidate set the decision was made against (see
  // candidateSetMatches) — a re-open only RESTORES the decision if the fresh scan yields the
  // SAME candidates; otherwise the file drops to 'recheck' rather than silently staying reviewed.
  // The LIVE review state (cands/decided/scanProvenance/…) is fully RESET on every switch, so
  // it can never carry from one file to the next.
  var batchFolder = null;   // the chosen absolute folder path (server-validated)
  var batchName = '';       // the folder's basename (the export subdir label)
  var batchFiles = [];
  var batchActiveRel = null;   // the rel currently loaded into the live review flow (or null)
  // DIRTY-tracking (leak-class guard): true once the LAWYER actually changes a selection on the
  // OPEN batch file this session. It gates captureCurrentDecision so the defaults-only DOM a
  // re-open renders BEFORE its saved decision is restored can NEVER overwrite an authoritative
  // saved review (which would drop the lawyer's opt-ins from the export). `batchSuppressDirty`
  // masks the PROGRAMMATIC changes (a re-open's initial render + decision restore) so only a
  // genuine user edit sets `batchDirty`.
  var batchDirty = false;
  var batchSuppressDirty = false;

  function batchEntry(rel){
    for (var i = 0; i < batchFiles.length; i++){ if (batchFiles[i].rel === rel) return batchFiles[i]; }
    return null;
  }
  function batchIndex(rel){
    for (var i = 0; i < batchFiles.length; i++){ if (batchFiles[i].rel === rel) return i; }
    return -1;
  }
  function nextPending(){
    for (var i = 0; i < batchFiles.length; i++){ if (batchFiles[i].status === 'scanned') return batchFiles[i]; }
    return null;
  }

  // A plain shallow copy of the careful-review DECIDED set — captured into a decision so a
  // re-open can RESTORE the exact gate state (a PARTIAL review stays partial, a finished one
  // stays finished), not just the accept-set. Own-keys only; ints coerced to a stable shape.
  function decidedSnapshot(){
    var out = {};
    for (var k in decided){
      if (Object.prototype.hasOwnProperty.call(decided, k) && decided[k]) out[k] = true;
    }
    return out;
  }

  // The FINGERPRINT of the current candidate set — the ordered list of each candidate's identity
  // (byte SPAN for text, stable ID for pdf). Stored in a decision so a re-open can verify the
  // fresh scan surfaced the SAME candidates before it trusts (re-projects) the saved accept-set.
  // Detection is deterministic over (bytes + options); a changed fingerprint means the options
  // (or engine) drifted since capture, so the stored indices/decided-set no longer align.
  function candKeys(candList, kind){
    return (candList || []).map(function(c){
      if (!c) return '';
      return kind === 'pdf' ? String(c.id) : (c.start + ':' + c.end);
    });
  }

  // PURE: does the freshly re-scanned candidate list have the SAME identity+order the decision
  // was captured against? Ordered, exact compare of the candidate fingerprints. A decision with
  // NO fingerprint (or a length/element mismatch) is treated as CHANGED — the safe, over-blocking
  // answer (force a fresh review) rather than mis-projecting a stale accept-set onto new findings.
  function candidateSetMatches(candList, dec){
    if (!dec) return false;
    var saved = dec.cand_key;
    if (!Array.isArray(saved)) return false;
    var fresh = candKeys(candList, dec.kind === 'pdf' ? 'pdf' : 'text');
    if (fresh.length !== saved.length) return false;
    for (var i = 0; i < fresh.length; i++){ if (fresh[i] !== saved[i]) return false; }
    return true;
  }

  // The current file's accepted-set as a plain, serialisable decision (no DOM). `decided` is a
  // SNAPSHOT of the careful-review gate state and `cand_key` the candidate fingerprint, so a
  // re-open restores it faithfully (and only when the candidate set still matches); the server
  // batch export never reads either (doBatchExport rebuilds a lean spec), so both are host-only.
  function currentDecision(){
    if (mode === 'pdf'){
      if (!pdfFile) return null;
      var sel = selectedPdfCandidates();
      return {kind: 'pdf', accept_ids: sel.ids, options: scanOptions,
              decided: decidedSnapshot(), cand_key: candKeys(cands, 'pdf')};
    }
    return {kind: 'text', accept: acceptedSpans(), options: scanOptions, format: 'txt',
            decided: decidedSnapshot(), cand_key: candKeys(cands, 'text')};
  }

  // PURE (DOM-free, unit-testable): given the freshly re-scanned candidates + a stored decision,
  // compute which candidate INDICES should be ACCEPTED (checked) on restore. Detection is
  // deterministic over (bytes + options), so a re-scan with the SAME options yields the SAME
  // candidates; we match each candidate to the stored accept-set by byte SPAN (text) or stable
  // ID (pdf). A candidate whose span/id is absent from the decision — or that no longer exists
  // because the options changed since capture — is simply not accepted (honest, safe
  // degradation: you cannot restore a decision about a finding that is no longer there).
  function computeRestoreAccept(candList, decKind, dec){
    var accepted = {};
    if (!dec || !candList) return accepted;
    if (decKind === 'pdf'){
      var ids = {};
      (dec.accept_ids || []).forEach(function(id){ ids[String(id)] = 1; });
      candList.forEach(function(c, idx){
        if (c && c.id != null && ids[String(c.id)] === 1) accepted[idx] = 1;
      });
    } else {
      var spans = {};
      (dec.accept || []).forEach(function(sp){
        if (sp && sp.length >= 2) spans[sp[0] + ':' + sp[1]] = 1;
      });
      candList.forEach(function(c, idx){
        if (c && spans[c.start + ':' + c.end] === 1) accepted[idx] = 1;
      });
    }
    return accepted;
  }

  // RESTORE a stored per-file DECISION onto the freshly re-scanned #review DOM (called after
  // re-opening a batch file that already carries a captured decision). WHY (leak-class): without
  // this, a re-open re-scans and shows engine DEFAULTS, so the lawyer's manual deviations
  // (advisory opt-INs, precise opt-OUTs) vanish — and the NEXT exit-capture
  // (captureCurrentDecision) then overwrites the stored decision with those defaults, silently
  // DROPPING opt-in redactions the lawyer had chosen = a leak. We set each candidate checkbox
  // from the accept-set (by span/id) and restore the careful-review DECIDED set so the gate
  // reflects the prior review, then re-sync the group controls + the live counts/gates.
  // No-op unless a fresh scan rendered candidate rows and the decision kind matches the mode.
  function batchRestoreDecision(dec){
    if (!dec || cands === undefined) return;
    if (dec.kind === 'pdf' ? mode !== 'pdf' : mode !== 'text') return;
    var boxes = document.querySelectorAll('#review input.memberbox');
    if (!boxes.length) return;
    var accepted = computeRestoreAccept(cands, dec.kind, dec);
    boxes.forEach(function(box){
      box.checked = accepted[+box.getAttribute('data-idx')] === 1;
    });
    // Restore the DECIDED gate: prefer the captured snapshot (faithful for a partial review);
    // fall back to marking every rendered candidate decided (a captured decision means the file
    // was reviewed at least once, so the gate should not read as untouched).
    decided = {};
    var snap = dec.decided && typeof dec.decided === 'object' ? dec.decided : null;
    boxes.forEach(function(box){
      var idx = +box.getAttribute('data-idx');
      if (snap ? snap[idx] : true) decided[idx] = true;
    });
    resyncGroups(document);
    onSelectionChanged();
  }

  // Snapshot the CURRENT batch file's decision into its entry, and — if its review gates
  // pass — mark it reviewed. Called before every switch. No-op in the single-file flow
  // (batchActiveRel null) or before a scan (cands undefined).
  function captureCurrentDecision(){
    if (!batchActiveRel) return;
    var e = batchEntry(batchActiveRel);
    if (!e || cands === undefined) return;
    // GUARD (leak-class, defense-in-depth): NEVER let a defaults-only capture the lawyer did not
    // actually interact with overwrite an authoritative saved review. A re-opened reviewed/
    // exported file has its decision RESTORED onto the fresh scan (openBatchFile), and
    // `batchDirty` stays false until the lawyer changes a selection — so until then the stored
    // decision is authoritative and must not be clobbered by the current (possibly default) DOM.
    if (e.decision && !batchDirty && (e.status === 'reviewed' || e.status === 'exported')) return;
    var dec = currentDecision();
    if (dec) e.decision = dec;
    if (reviewComplete() && passagesAllAcked() && e.status !== 'exported'){
      e.status = 'reviewed'; e.reviewed = true;
    }
  }

  // The ISOLATION seam (load-bearing): capture the outgoing file's decision, then FULLY wipe
  // the live review state so the incoming file starts clean. resetScanState() clears cands,
  // decided, scanProvenance*, the acknowledge gate, the #review DOM — everything scan-derived —
  // so file A's decisions/acks can NEVER be inherited by file B. Synchronous + DOM-free enough
  // to unit-test via the __redactionInternals seam.
  function batchPrepareSwitch(){
    captureCurrentDecision();
    batchActiveRel = null;
    resetScanState();
  }

  // ---- folder picking + enumeration ----------------------------------------------
  async function chooseBatchFolder(){
    var path = null;
    try {
      // Native folder dialog lives in the desktop layer (pywebview). In a plain browser (dev)
      // there is no such API, so accept a TYPED path — the batch/enumerate route validates it.
      if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_folder){
        path = await window.pywebview.api.pick_folder();
      } else {
        path = window.prompt('Folder path to redact (the installed app shows a folder picker):');
      }
    } catch(e){ path = null; }
    if (!path){ return; }
    await enumerateBatchFolder(path);
  }

  async function enumerateBatchFolder(path){
    var hint = $('chooseFolderHint');
    if (hint) hint.textContent = 'Reading the folder…';
    var r;
    try { r = await post('/api/redaction/batch/enumerate', {folder: path}); }
    catch(e){ r = {ok:false, data:{}}; }
    if (!r.ok || !r.data || r.data.error || !r.data.ok){
      if (hint) hint.textContent = (r.data && r.data.error) || 'That folder can’t be used for batch redaction.';
      return;
    }
    if (hint) hint.textContent = 'Redact a whole folder — each file is scanned, then you review and save them one at a time.';
    batchFolder = r.data.folder; batchName = r.data.name || 'batch';
    batchFiles = (r.data.files || []).map(function(f){
      return {rel: f.rel, name: f.name, size: f.size || 0, status: 'pending',
              findings: 0, error: null, kind: null, decision: null,
              reviewed: false, exported: false};
    });
    batchActiveRel = null;
    showBatchPanel(r.data);
  }

  // ---- batch panel render --------------------------------------------------------
  function showBatchPanel(en){
    var panel = $('batchPanel');
    if (!panel) return;
    panel.classList.remove('hidden');
    var nm = $('batchFolderName');
    if (nm) nm.textContent = (en && en.name) || batchFolder || '';
    var est = $('batchEstimate');
    var result = $('batchExportResult'); if (result){ result.classList.add('hidden'); result.innerHTML = ''; }
    var sk = (en && en.skipped) || {};
    var skipParts = [];
    if (sk.unsupported) skipParts.push(sk.unsupported + ' unsupported');
    if (sk.oversize) skipParts.push(sk.oversize + ' too large');
    if (sk.placeholders) skipParts.push(sk.placeholders + ' not downloaded (cloud)');
    if (sk.unreadable) skipParts.push(sk.unreadable + ' unreadable');
    var skipMsg = skipParts.length ? (' Skipped: ' + skipParts.join(', ') + '.') : '';
    var count = (en && en.count) || 0;
    var mb = ((en && en.total_bytes) || 0) / 1048576;
    if (est){
      if (!count){
        est.innerHTML = '<div class="banner"><span class="ic" aria-hidden="true">&#128193;</span>' +
          '<div class="body"><b>No supported files found in that folder.</b>' +
          '<p>Batch mode reads .pdf, .docx, .txt, .csv, .eml and .msg files.' + esc(skipMsg) + '</p></div></div>';
      } else {
        est.innerHTML = '<div class="banner"><span class="ic" aria-hidden="true">&#128193;</span>' +
          '<div class="body"><b>' + count + ' file' + (count === 1 ? '' : 's') + ' found (' +
          esc(mb.toFixed(1)) + ' MB' + (en && en.truncated ? '+' : '') + ').</b>' +
          '<p>Everything happens on this computer. You review and save each file yourself — ' +
          'nothing is written until you do.' + esc(skipMsg) + '</p>' +
          '<div class="row" style="margin-top:10px">' +
          '<button type="button" id="batchStartBtn" class="btn primary sm">Scan all ' + count +
          ' file' + (count === 1 ? '' : 's') + '</button></div></div></div>';
        var sb = $('batchStartBtn');
        if (sb) sb.addEventListener('click', startBatchQueue);
      }
    }
    var acts = $('batchActions');
    if (acts) acts.classList.toggle('hidden', !count);
    updateBatchStrip();
    renderBatchList();
    updateBatchExportBtn();
  }

  function batchStatusChip(e){
    var map = {
      pending: {cls: 'neutral', txt: 'Waiting'},
      scanning: {cls: 'neutral', txt: 'Scanning…'},
      scanned: {cls: 'neutral', txt: 'Scanned'},
      error: {cls: 'high', txt: 'Could not read'},
      reviewed: {cls: 'ok', txt: 'Reviewed'},
      exported: {cls: 'ok', txt: 'Exported'},
      recheck: {cls: 'med', txt: 'Re-check needed'}
    };
    var m = map[e.status] || map.pending;
    return '<span class="chip ' + m.cls + '">' + esc(m.txt) + '</span>';
  }

  function renderBatchList(){
    var list = $('batchList');
    if (!list) return;
    if (!batchFiles.length){ list.innerHTML = ''; return; }
    list.innerHTML = batchFiles.map(function(e, i){
      var findings = '';
      if (e.status === 'scanned' || e.status === 'reviewed' || e.status === 'exported' ||
          e.status === 'recheck'){
        findings = e.findings + ' finding' + (e.findings === 1 ? '' : 's');
      }
      var canReview = (e.status === 'scanned' || e.status === 'reviewed' ||
                       e.status === 'exported' || e.status === 'recheck');
      var reviewLbl = (e.status === 'reviewed' || e.status === 'exported') ? 'Re-open' : 'Review';
      var btn = canReview
        ? '<button type="button" class="btn ghost sm" data-batch-review="' + i + '">' + reviewLbl + '</button>'
        : '';
      var err = e.status === 'error'
        ? '<div class="batch-err hint warn">' + esc(e.error || 'could not read this file') + '</div>' : '';
      return '<div class="batch-item ' + esc(e.status) + (e.rel === batchActiveRel ? ' active' : '') + '">' +
        '<div class="bi-main"><span class="bi-name">' + esc(e.name) + '</span> ' + batchStatusChip(e) +
        ' <span class="bi-find hint">' + esc(findings) + '</span></div>' +
        '<div class="bi-act">' + btn + '</div>' + err + '</div>';
    }).join('');
  }

  function updateBatchStrip(){
    var strip = $('batchStrip');
    if (!strip) return;
    if (!batchFiles.length){ strip.classList.add('hidden'); strip.innerHTML = ''; return; }
    strip.classList.remove('hidden');
    var scanned = 0, errors = 0, reviewed = 0, exported = 0, rechecks = 0;
    batchFiles.forEach(function(e){
      if (e.status === 'error'){ errors++; return; }
      if (e.status === 'exported'){ exported++; reviewed++; scanned++; return; }
      if (e.status === 'reviewed'){ reviewed++; scanned++; return; }
      if (e.status === 'recheck'){ rechecks++; scanned++; return; }
      if (e.status === 'scanned'){ scanned++; }
    });
    var total = batchFiles.length;
    strip.innerHTML =
      '<span class="chip neutral">' + scanned + ' of ' + total + ' scanned</span>' +
      (errors ? '<span class="chip high">' + errors + ' could not be read</span>' : '') +
      '<span class="chip ok">' + reviewed + ' reviewed</span>' +
      (rechecks ? '<span class="chip med">' + rechecks + ' need re-check</span>' : '') +
      (exported ? '<span class="chip ok">' + exported + ' exported</span>' : '');
  }

  function updateBatchExportBtn(){
    var btn = $('batchExportBtn');
    if (!btn) return;
    var n = 0;
    batchFiles.forEach(function(e){ if (e.status === 'reviewed' && e.decision) n++; });
    var total = batchFiles.length;
    btn.disabled = n === 0;
    btn.setAttribute('aria-disabled', n === 0 ? 'true' : 'false');
    btn.textContent = 'Export ' + n + ' reviewed of ' + total;
  }

  // ---- the sequential scan queue -------------------------------------------------
  async function startBatchQueue(){
    if (!batchFolder || !batchFiles.length) return;
    var sb = $('batchStartBtn'); if (sb) sb.disabled = true;
    var opts = readOptions();   // the SAME detection options/terms for every file in the batch
    for (var i = 0; i < batchFiles.length; i++){
      var e = batchFiles[i];
      if (e.status === 'reviewed' || e.status === 'exported') continue;
      e.status = 'scanning'; renderBatchList(); updateBatchStrip();
      var r;
      try { r = await post('/api/redaction/batch/scan-file', {folder: batchFolder, rel: e.rel, options: opts}); }
      catch(err){ r = {ok:false, data:{}}; }
      if (r.ok && r.data && r.data.ok){
        e.status = 'scanned'; e.findings = r.data.findings || 0; e.kind = r.data.kind || null;
        e.low_text = !!r.data.low_text; e.unmapped = !!r.data.unmapped_fonts; e.error = null;
      } else {
        // A file that FAILS scan shows an error and is excluded from batch export — never
        // silently skipped (the strip counts it).
        e.status = 'error'; e.error = (r.data && r.data.error) || 'could not scan this file';
      }
      renderBatchList(); updateBatchStrip(); updateBatchExportBtn();
    }
    var est = $('batchEstimate'); if (est) est.innerHTML = '';
    announce('Folder scan complete. Click a file to review it.');
  }

  // ---- load a batch file into the EXISTING per-file review flow ------------------
  async function openBatchFile(rel){
    var e = batchEntry(rel);
    if (!e) return;
    if (e.status === 'error'){ announce('That file could not be read.'); return; }
    // Snapshot THIS file's stored decision BEFORE the switch, so a re-open can RESTORE the
    // lawyer's prior choices onto the fresh scan (batchPrepareSwitch captures the OUTGOING
    // file, never this one — but snapshot up front to be robust to any future reordering).
    var priorDecision = e.decision;
    // ISOLATION: capture the current file's decision, then wipe ALL live scan state so the
    // incoming file starts clean (no cross-file leak).
    batchPrepareSwitch();
    batchActiveRel = rel;
    var r;
    try { r = await post('/api/redaction/batch/read-file', {folder: batchFolder, rel: rel}); }
    catch(err){ r = {ok:false, data:{}}; }
    if (!r.ok || !r.data || !r.data.ok || !r.data.data_b64){
      e.status = 'error'; e.error = (r.data && r.data.error) || 'could not read this file';
      batchActiveRel = null; renderBatchList(); updateBatchBar();
      announce('Could not open that file.');
      return;
    }
    var file;
    try {
      var bytes = b64ToBytes(r.data.data_b64);
      file = new File([bytes], r.data.filename || e.name,
        {type: r.data.kind === 'pdf' ? 'application/pdf' : 'text/plain'});
    } catch(err){
      batchActiveRel = null; announce('Could not open that file on this device.');
      return;
    }
    // SAME path as a user upload (reset + adopt), then run the normal scan — which lands on
    // Review and drives the real candidates/gates/provenance for THIS file only.
    registerUpload(file);
    renderBatchList();
    updateBatchBar();
    // The scan + render + decision restore below are PROGRAMMATIC — mask dirty so they can't
    // fabricate a defaults capture that the exit-capture would then persist over the saved review.
    batchSuppressDirty = true; batchDirty = false;
    await scanUpload();
    // RESTORE the stored decision onto the fresh scan (leak-class fix): a re-opened reviewed
    // file must show the lawyer's manual deviations, not engine defaults — else the next
    // exit-capture would overwrite the decision with defaults and drop opt-in redactions.
    if (priorDecision){
      if (cands !== undefined && candidateSetMatches(cands, priorDecision)){
        batchRestoreDecision(priorDecision);
      } else if (cands !== undefined){
        // The candidate set changed since capture (detection options / engine drifted), so the
        // saved accept-set CANNOT be faithfully re-projected onto the new findings. Drop to
        // NEEDS-RECHECK (honest over-block): clear the stale decision + downgrade a reviewed/
        // exported file so it can NEVER export as 'reviewed' on engine defaults; the list flags
        // it for a fresh review. (cands===undefined = a failed re-scan: leave the entry as-is.)
        e.decision = null;
        if (e.status === 'reviewed' || e.status === 'exported'){ e.status = 'recheck'; e.reviewed = false; }
        announce('“' + e.name + '” has changed since it was reviewed — please review it again.');
      }
    }
    batchSuppressDirty = false; batchDirty = false;   // a just-opened, un-edited file is not dirty
    renderBatchList(); updateBatchStrip(); updateBatchExportBtn();
    updateBatchBar();
  }

  // ---- batch context bar (shown while a file is loaded) --------------------------
  function updateBatchBar(){
    var wrap = $('batchBarWrap');
    if (!wrap) return;
    var active = !!batchActiveRel && currentStage !== 'document';
    wrap.hidden = !active;
    if (!active) return;
    var e = batchEntry(batchActiveRel);
    var idx = batchIndex(batchActiveRel);
    var label = $('batchBarLabel');
    if (label) label.textContent = 'Reviewing “' + (e ? e.name : '') + '” — file ' +
      (idx + 1) + ' of ' + batchFiles.length;
    var mb = $('batchMarkBtn');
    if (mb){
      var okmark = (cands !== undefined) && reviewComplete() && passagesAllAcked();
      mb.disabled = !okmark;
      mb.setAttribute('aria-disabled', okmark ? 'false' : 'true');
    }
  }

  function backToBatchList(){
    captureCurrentDecision();
    updateBatchExportBtn();
    renderBatchList();
    goStage('document');   // the batch panel lives on the Document stage
    updateBatchBar();
  }

  function markBatchReviewed(){
    if (!batchActiveRel) return;
    if (!((cands !== undefined) && reviewComplete() && passagesAllAcked())){
      announce('Finish reviewing this file first, then mark it reviewed.');
      return;
    }
    var e = batchEntry(batchActiveRel);
    if (e){ e.decision = currentDecision(); e.status = 'reviewed'; e.reviewed = true; }
    updateBatchExportBtn();
    var nxt = nextPending();
    if (nxt){ openBatchFile(nxt.rel); }
    else {
      backToBatchList();
      announce('All files reviewed. You can export the reviewed files now.');
    }
  }

  // Called by markExported() (redaction.export.js) after a redacted copy is written, so an
  // INDIVIDUAL per-file export inside a batch marks that entry exported in the list. No-op in
  // the single-file flow.
  function batchOnExported(data, kind){
    if (!batchActiveRel) return;
    var e = batchEntry(batchActiveRel);
    if (e){
      e.decision = currentDecision();
      e.status = 'exported'; e.exported = true; e.reviewed = true;
    }
    updateBatchExportBtn(); renderBatchList(); updateBatchStrip();
  }

  // ---- batch export (all reviewed files) -----------------------------------------
  function setBatchExportHint(msg, warn){
    var h = $('batchExportHint');
    if (h){ h.textContent = msg || ''; h.className = 'hint' + (warn ? ' warn' : ''); }
  }

  async function doBatchExport(){
    // Capture the currently-open file first (so a just-finished review is included).
    captureCurrentDecision();
    var reviewed = batchFiles.filter(function(e){ return e.status === 'reviewed' && e.decision; });
    if (!reviewed.length){ setBatchExportHint('Review at least one file first.', true); return; }
    var specs = reviewed.map(function(e){
      var d = e.decision;
      var s = {rel: e.rel, kind: d.kind, options: d.options};
      if (d.kind === 'pdf') s.accept_ids = d.accept_ids || [];
      else { s.accept = d.accept || []; s.format = d.format || 'txt'; }
      return s;
    });
    var btn = $('batchExportBtn'); if (btn) btn.disabled = true;
    setBatchExportHint('Redacting & saving the reviewed files…');
    var r;
    try {
      r = await post('/api/redaction/batch/export', {
        folder: batchFolder, batch_name: batchName, files: specs,
        reviewer: (typeof reviewerName === 'function' ? reviewerName() : ''),
        // FEATURE 1 (per-batch) + FEATURE 2 (per-batch keep list) — the SAME controls the
        // single-file export uses, applied to every reviewed file in the batch.
        redact_everywhere: (typeof redactEverywhere === 'function' ? redactEverywhere() : true),
        keep: (typeof parseKeep === 'function' ? parseKeep() : [])
      });
    } catch(err){ r = {ok:false, data:{}}; }
    if (btn) btn.disabled = false;
    setBatchExportHint('');
    if (!r.ok || !r.data || r.data.error){
      setBatchExportHint((r.data && r.data.error) || 'Could not export the batch.', true);
      return;
    }
    // Mark the just-exported entries (the server report is the record of truth).
    var exportedRels = {};
    reviewed.forEach(function(e){ e.status = 'exported'; e.exported = true; exportedRels[e.rel] = 1; });
    renderBatchExportResult(r.data);
    renderBatchList(); updateBatchStrip(); updateBatchExportBtn();
    announce('Saved ' + (r.data.exported || 0) + ' redacted file(s) to your exports folder.');
  }

  function renderBatchExportResult(data){
    var el = $('batchExportResult');
    if (!el) return;
    var n = data.exported || 0;
    var failed = data.failed || [];
    var html = '✓ Saved <b>' + n + '</b> redacted file' + (n === 1 ? '' : 's') +
      ' to <span class="rtok">' + esc(data.batch_dir || '') + '</span> in your exports folder. ' +
      'A batch summary was written alongside them.';
    if (failed.length){
      html += '<div class="banner warn" style="margin-top:10px">' +
        '<span class="ic" aria-hidden="true">&#9888;</span>' +
        '<div class="body"><b>' + failed.length + ' file' + (failed.length === 1 ? '' : 's') +
        ' could NOT be processed</b><p>' +
        failed.map(function(f){ return esc(f.filename || '') + ' — ' + esc(f.error || ''); }).join('<br>') +
        '</p></div></div>';
    }
    html += '<p class="hint" style="margin-top:8px">This is a first pass — read each redacted ' +
      'copy before relying on it. Your originals were not changed.</p>';
    el.innerHTML = html;
    el.classList.remove('hidden');
  }

  // Detach the batch context WITHOUT closing the folder: a SINGLE-file entry (a manual
  // upload / paste / the sample) means the user is no longer reviewing a batch file, so the
  // next export must NOT mutate a batch entry (batchOnExported keys off batchActiveRel). The
  // folder list stays available on the Document stage. openBatchFile re-sets batchActiveRel
  // for a real batch open, so this only ever fires on a genuine single-file takeover.
  function batchDetach(){
    if (!batchActiveRel) return;
    batchActiveRel = null;
    updateBatchBar();
  }

  function closeBatch(){
    batchFolder = null; batchName = ''; batchFiles = []; batchActiveRel = null;
    var panel = $('batchPanel'); if (panel) panel.classList.add('hidden');
    var res = $('batchExportResult'); if (res){ res.classList.add('hidden'); res.innerHTML = ''; }
    var hint = $('chooseFolderHint');
    if (hint) hint.textContent = 'Redact a whole folder — each file is scanned, then you review and save them one at a time. Nothing leaves this machine.';
    updateBatchBar();
    announce('Closed the folder.');
  }

