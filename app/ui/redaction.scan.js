/* ==== CONCATENATION FRAGMENT 8 of 11 — app/ui/redaction.scan.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- scan actions --------------------------------------------------------------
  async function doScan(){
    var text = input.value;
    if (engineDown) return;
    if (mode === 'pdf' && pdfFile){ doPdfScan(pdfFile); return; }
    if (!text.trim()){ refreshScanEnabled(); return; }
    scanToken++;   // invalidate any in-flight PDF preview from a prior scan
    mode = 'text'; pdfFile = null;
    clearEngineError();
    showScanning('Scanning your text…');
    scanOptions = readOptions();
    var r;
    try {
      r = await post('/api/redaction/scan', {text:text, options:scanOptions});
    } catch(e){
      // A REJECTED fetch (transport down, aborted, etc.) never reaches the ok/data branch
      // below — without this catch the spinner hangs forever and nothing tells the lawyer
      // anything happened. Treat it exactly like an engine-unreachable failure: markScanFailed
      // re-locks the downstream gates and flips the chip, and the SAME friendly
      // tool-unavailable banner the offline chip uses is shown (not the generic error copy).
      hideScanning();
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      markScanFailed(true);
      showEngineOffline();
      renderPassages([], text);
      renderReidMeter(null, null);
      warnTermDrops();
      return;
    }
    hideScanning();
    if (!r.ok || r.data.error){
      var emsg = r.data.error || 'Scan failed.';
      // A transport failure that DID get an HTTP response back (not ok, no parseable
      // {"error":...} body) reads the same as an unreachable engine to the lawyer — show the
      // SAME tool-unavailable banner the offline chip uses, not the generic "something went
      // wrong" copy (which would otherwise contradict the chip flipping offline below).
      var transportFailure = !r.ok && !r.data.error;
      if (transportFailure) showEngineOffline(); else showEngineError(emsg);
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      // Fail SAFE: block the downstream stages + flip the chip when the engine is/looks
      // unavailable (an engine-class error, or a transport failure with no parseable body).
      // Never let this errored scan look like a clean empty result.
      markScanFailed(transportFailure || friendlyError(emsg).engineOffline);
      renderPassages(r.data.passages || [], text);
      // The reid_score travels in the body even on an engine error (best-effort, pure-
      // Python) — surface the BEFORE meter; the AFTER side comes on apply.
      renderReidMeter(r.data.reid_score || null, null);
      warnTermDrops();   // an over-long term must warn even when the engine errors
      return;
    }
    scanFailed = false;   // a real result -> clear any prior error state
    cands = r.data.candidates || [];
    scannedText = text;
    scanProvenanceText = text; scanProvenanceFile = null;   // these candidates belong to THIS text
    lastLowText = false; lastUnmappedFonts = false;
    resetPdfPreview();   // a text scan has no on-page PDF preview
    outwrap.classList.add('hidden');
    renderReview(r.data);
    warnTermDrops();   // warn CLIENT-side (browser pre-filters terms, so the textarea is truth)
    renderPassages(r.data.passages || [], text);
    renderReidMeter(r.data.reid_score || null, null);   // BEFORE side; AFTER appears on apply
    goStage('review');
  }

  function fileToBase64(file){
    return new Promise(function(resolve, reject){
      var r = new FileReader();
      r.onerror = function(){ reject(new Error('read failed')); };
      r.onload = function(){
        var s = String(r.result || '');
        var comma = s.indexOf(',');
        resolve(comma >= 0 ? s.slice(comma + 1) : s);
      };
      r.readAsDataURL(file);
    });
  }

  // WARN-ON-DROP: render a `terms_dropped` report — a user "names to redact" TERM exceeded the
  // byte cap and was NOT sent to the engine, so without this the name would silently never be
  // redacted = a leak-class MISS. The report is computed CLIENT-side from the textarea
  // (warnTermDrops/clientTermDropReport) because the browser pre-filters before sending; the
  // server's terms_dropped is belt-and-suspenders for direct API callers. esc() every cleartext
  // term (matter data); hide the banner when nothing was dropped.
  function renderTermDrops(data){
    var el = $('termDrops');
    if (!el) return;
    var rep = data && data.terms_dropped;
    var n = rep && +rep.count;
    if (!n){ el.classList.add('hidden'); el.innerHTML = ''; return; }
    var head = '<b>' + n + ' term' + (n === 1 ? '' : 's') + ' too long to redact</b> — ' +
      'they were NOT removed. Shorten ' + (n === 1 ? 'it' : 'them') +
      ' (under 200 bytes each) and scan again, or they will stay in the document.';
    var listed = (rep.terms || []);
    var body = '';
    if (listed.length){
      body = '<ul>' + listed.map(function(t){ return '<li>' + esc(t) + '</li>'; }).join('') + '</ul>';
    }
    el.innerHTML = head + body;
    el.classList.remove('hidden');
    announce(n + ' term' + (n === 1 ? '' : 's') + ' too long to redact — not removed.');
  }

  function renderFileNote(name, format, warnings, chars){
    var html = 'Extracted <b>' + chars + '</b> character' + (chars === 1 ? '' : 's') +
      ' from <b>' + esc(name) + '</b> (' + esc(format) + ').';
    if (warnings && warnings.length){
      html += '<ul class="warns">' +
        warnings.map(function(w){ return '<li>' + esc(w) + '</li>'; }).join('') + '</ul>';
    }
    fileNote.innerHTML = '<div class="filenote">' + html + '</div>';
  }

  // ---- new-document RESET (leak-direction fail-safe) -----------------------------
  // EVERY new document (a fresh upload, or "Redact another document") must drop ALL
  // scan-derived state and RE-LOCK the stage gates, so a new file can NEVER inherit the
  // prior file's "clean" flags or its already-open Export gate. Without this, scan A
  // (clean, unmapped_fonts=false) -> load B (unmapped) without re-scan -> apply/export B
  // would read the stale lastUnmappedFonts=false and drop B's caveat (the leak direction).
  function resetScanState(){
    scanToken++;                  // invalidate any in-flight PDF preview from a prior scan
    cands = undefined;   // no candidates until the NEW document is freshly scanned
    scanFailed = false;           // a fresh document clears any prior scan-error state
    decided = {};                 // careful-review decisions belonged to the old document
    scannedText = null;           // the old scanned text no longer indexes anything
    lastLowText = false;          // scan diagnostics belong to the OLD document — clear them
    lastUnmappedFonts = false;
    scanProvenanceFile = null;    // provenance unknown until the new document is scanned
    scanProvenanceText = null;
    pendingTextFile = null;       // a not-yet-extracted upload belonged to the OLD document
    lastReport = null;
    lastTextApply = null;         // the prior document's redacted-text export source is gone
    // POST-EXPORT state: a NEW document has not been exported, so re-lock the Report stage +
    // drop the prior export descriptor and clear the Report stage's chips/panels (leak-
    // direction fail-safe: the new document must never inherit the old export's Report).
    exported = false;
    lastExport = null;
    ['repSavedChip', 'repReportChip', 'repCheckChip'].forEach(function(id){
      var el = $(id); if (el) el.classList.add('hidden');
    });
    if ($('reportVerdict')) $('reportVerdict').innerHTML = '';
    if ($('reportDetail')) $('reportDetail').innerHTML = '';
    // Wipe the prior document's findings from the #review DOM so a switch can never apply
    // A's ids (acceptedPdfIds) against B's bytes (Finding #2, same root cause).
    if (tier1) tier1.innerHTML = '';
    if (tier2) tier2.innerHTML = '';
    if (t1count) t1count.textContent = '0';
    if (t2count) t2count.textContent = '0';
    if (summary) summary.innerHTML = '';
    renderTermDrops(null);        // drop the prior document's "term too long" warning
    if (review) review.classList.add('hidden');
    if (outwrap) outwrap.classList.add('hidden');
    if (imgreview) imgreview.classList.add('hidden');
    // Wipe the prior document's OCR page RASTERS (matter-content page images) + their
    // summary out of the DOM — hiding #imgreview alone left #imgPages populated until the
    // next OCR review (in-memory matter residue).
    if (imgPages) imgPages.innerHTML = '';
    if (imgSummary) imgSummary.innerHTML = '';
    if (applySummary) applySummary.innerHTML = '';
    if (output) output.value = '';
    // Wipe the prior document's re-identification KEY ([A] = <real name>…) out of the DOM.
    // Hiding the seam's parent left the cleartext key in innerHTML until the next apply;
    // renderLegend(null) is the same clear+hide+aria-hide path every apply already uses.
    renderLegend(null);
    hideTextSaveSeam();           // drop the prior document's text-file save section
    resetPdfPreview();            // drop any previous PDF's on-page preview
    renderPassages([], '');       // clear the sensitive-passages list + its ack gate
    // Clear + hide the re-identification EXPOSURE meter so a NEW document never inherits the
    // prior document's before/after read (same leak-direction fail-safe as the rest of this
    // reset: a fresh scan repopulates it).
    renderReidMeter(null, null);
    reidBefore = null; reidAfter = null;
    // Re-lock the gates: with no fresh scan, review/sensitive/export are NOT reachable.
    onSelectionChanged();
    refreshStepper();
  }

  // ---- "Try it with a sample document" -------------------------------------------
  // Fetch a made-up practice PDF (CLEARLY-FAKE identifiers, synthesized server-side) and
  // feed it into the EXACT SAME upload->scan path a user file takes: build a File from the
  // returned base64 and run it through registerUpload(), so it inherits the full reset /
  // provenance / gate behavior (it is treated as a normal upload — nothing special). Then
  // advance to Detection just like a real upload, so the user drives scan->review->apply
  // themselves. Air-gap safe: the bytes come from the LOCAL server, never the network.
  function b64ToBytes(b64){
    var bin = atob(String(b64 || ''));
    var len = bin.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  async function loadSample(){
    // The sample is a SINGLE-file demo — detach from any open batch so its export can't
    // mutate a batch entry (no-op in the single-file flow).
    if (typeof batchDetach === 'function') batchDetach();
    var btn = $('sampleBtn'), hint = $('sampleHint');
    if (engineDown){
      if (hint){ hint.textContent = 'The redaction tool is offline — the sample needs it to scan. Try again once it’s available.'; }
      return;
    }
    if (btn) btn.disabled = true;
    if (hint) hint.textContent = 'Loading the sample…';
    var r;
    try { r = await get('/api/redaction/sample'); }
    catch(e){ r = {ok:false, data:{}}; }
    if (btn) btn.disabled = false;
    if (!r.ok || !r.data || r.data.error || !r.data.data_b64){
      if (hint) hint.textContent = 'Couldn’t load the sample. You can still paste text or upload a file.';
      showEngineError((r.data && r.data.error) || 'Could not load the sample document.');
      return;
    }
    var name = r.data.filename || 'sample.pdf';
    var file;
    try {
      var bytes = b64ToBytes(r.data.data_b64);
      // A real File so it flows through the IDENTICAL upload path (FileReader -> base64 ->
      // pdf-scan); provenance keys off this exact File object, so apply is never wrongly
      // blocked. (Blob/File are available in the WebView2 / browser host.)
      file = new File([bytes], name, {type:'application/pdf'});
    } catch(e){
      if (hint) hint.textContent = 'Couldn’t prepare the sample on this device. Try uploading a file instead.';
      return;
    }
    if (hint) hint.textContent = 'Loaded a made-up practice file. Continue to detection settings to scan it.';
    registerUpload(file);     // SAME path as a user upload: reset + adopt + re-lock gates
    goStage('detection');     // mirror the upload UX — the user then clicks Scan
    announce('Loaded the sample document. Continue to detection settings to scan it.');
  }

  // An uploaded file is registered on the DOCUMENT stage; the scan runs from DETECTION.
  function registerUpload(file){
    // A new document: reset ALL scan-derived state + re-lock the gates BEFORE adopting it,
    // so the new file cannot inherit the prior file's findings, "clean" flags, or gates.
    resetScanState();
    if (/\.pdf$/i.test(file.name)){ mode = 'pdf'; pdfFile = file; }
    else {
      // A text-bearing file: hold it for extraction at Scan time (doTextUpload posts it to
      // /api/redaction/scan-file). Clear the box so it shows empty until the real text lands.
      mode = 'text'; pdfFile = null; pendingTextFile = file; input.value = '';
    }
    var sub = $('docSub');
    if (sub) sub.textContent = file.name;
    fileNote.innerHTML = '<div class="filenote">Ready: <b>' + esc(file.name) + '</b>. ' +
      (mode === 'pdf' ? 'A PDF keeps its layout — it is redacted in place.' :
        'Its text is pulled out for review.') +
      ' Continue to detection settings.</div>';
    $('scanWarn').innerHTML = '';
    refreshScanEnabled();
    announce('Loaded ' + file.name + '. Continue to detection settings.');
  }

  // Run the actual scan for an uploaded file (called from the Detection stage).
  async function scanUpload(){
    if (mode === 'pdf' && pdfFile){ return doPdfScan(pdfFile); }
    // A non-PDF upload is extracted to text NOW (on the Scan step): extract -> scan, the
    // documented upload path. Capture + clear pendingTextFile so a later re-scan of the
    // resulting in-box text goes through the plain text path.
    if (pendingTextFile){ var f = pendingTextFile; pendingTextFile = null; return doTextUpload(f); }
    // No pending upload: pasted/typed text already sits in the box — scan it in place.
    return doScan();
  }

  async function doTextUpload(file){
    clearEngineError();
    showScanning('Reading “' + file.name + '”…');
    var b64;
    try { b64 = await fileToBase64(file); }
    catch(e){ hideScanning(); showEngineError('Could not read that file.'); return; }
    scanOptions = readOptions();
    var r;
    try {
      r = await post('/api/redaction/scan-file', {filename:file.name, data_b64:b64, options:scanOptions});
    } catch(e){
      // A REJECTED fetch: see doScan's identical catch for the full rationale — without it
      // the spinner hangs and the failure is never surfaced.
      hideScanning();
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      markScanFailed(true);
      showEngineOffline();
      renderPassages([], '');
      renderReidMeter(null, null);
      warnTermDrops();
      return;
    }
    hideScanning();
    if (!r.ok || r.data.error){
      var emsg = r.data.error || 'Could not extract that file.';
      var transportFailure = !r.ok && !r.data.error;
      // Same tool-unavailable copy as doScan's transport-failure branch — never the generic
      // "something went wrong" banner beside a chip that just flipped offline.
      if (transportFailure) showEngineOffline(); else showEngineError(emsg);
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      markScanFailed(transportFailure || friendlyError(emsg).engineOffline);
      renderPassages(r.data.passages || [], (r.data && r.data.text) || '');
      renderReidMeter((r.data && r.data.reid_score) || null, null);
      warnTermDrops();   // an over-long term must warn even when extraction errors
      return;
    }
    scanFailed = false;   // a real result -> clear any prior error state
    var text = r.data.text != null ? r.data.text : '';
    input.value = text;
    scannedText = text;
    mode = 'text'; pdfFile = null;
    refreshScanEnabled();
    cands = r.data.candidates || [];
    scanProvenanceText = text; scanProvenanceFile = null;   // candidates belong to THIS file's text
    lastLowText = false; lastUnmappedFonts = false;
    resetPdfPreview();   // a text-file scan has no on-page PDF preview
    renderFileNote(file.name, r.data.format || 'file', r.data.warnings || [], text.length);
    outwrap.classList.add('hidden');
    renderReview(r.data);
    warnTermDrops();   // warn CLIENT-side (browser pre-filters terms, so the textarea is truth)
    renderPassages(r.data.passages || [], text);
    renderReidMeter(r.data.reid_score || null, null);   // BEFORE side; AFTER appears on apply
    goStage('review');
  }

  async function doPdfScan(file){
    scanToken++;   // a new scan: any in-flight preview from a prior scan is now stale
    clearEngineError();
    applySummary.innerHTML = ''; output.value = '';
    scannedText = null;
    resetPdfPreview();   // drop any previous PDF's preview before the new scan
    showScanning('Reading “' + file.name + '”…');
    var b64;
    try { b64 = await fileToBase64(file); }
    catch(e){ hideScanning(); showEngineError('Could not read that file.'); return; }
    scanOptions = readOptions();
    var r;
    try {
      r = await post('/api/redaction/pdf-scan', {data_b64:b64, options:scanOptions});
    } catch(e){
      // A REJECTED fetch: see doScan's identical catch for the full rationale — without it
      // the spinner hangs and the failure is never surfaced.
      hideScanning();
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      markScanFailed(true);
      showEngineOffline();
      warnTermDrops();
      return;
    }
    hideScanning();
    if (!r.ok || r.data.error){
      var emsg = r.data.error || 'Could not read that PDF.';
      var transportFailure = !r.ok && !r.data.error;
      // Same tool-unavailable copy as doScan's transport-failure branch — never the generic
      // "something went wrong" banner beside a chip that just flipped offline.
      if (transportFailure) showEngineOffline(); else showEngineError(emsg);
      review.classList.add('hidden'); outwrap.classList.add('hidden'); imgreview.classList.add('hidden');
      markScanFailed(transportFailure || friendlyError(emsg).engineOffline);
      warnTermDrops();   // an over-long term must warn even when the PDF read errors
      return;
    }
    scanFailed = false;   // a real result -> clear any prior error state
    cands = r.data.candidates || [];
    mode = 'pdf'; pdfFile = file;
    scanProvenanceFile = file; scanProvenanceText = null;   // candidates + flags belong to THIS file
    lastLowText = !!r.data.low_text; lastUnmappedFonts = !!r.data.unmapped_fonts;
    outwrap.classList.add('hidden');
    // PDF file-note: format + the load-bearing low_text + unmapped_fonts caveats.
    var warns = [];
    if (r.data.low_text) warns.push('This looks like a scan or photo — the words are part of the ' +
      'image, so the normal text redaction can’t reach them. Use “OCR & redact scanned PDF” to ' +
      'read the page images and black out what we find (you check every box first).');
    if (r.data.unmapped_fonts) warns.push('Some pages use an unusual font we could only read ' +
      'best-effort, so a low count here does NOT mean the page is clean. Read those pages yourself ' +
      'before relying on the result.');
    (r.data.diagnostics || []).forEach(function(d){ warns.push(d); });
    var loud = r.data.low_text || r.data.unmapped_fonts;
    var note = 'PDF: <b>' + esc(file.name) + '</b>.';
    if (warns.length) note += '<ul class="warns">' +
      warns.map(function(w){ return '<li>' + esc(w) + '</li>'; }).join('') + '</ul>';
    fileNote.innerHTML = '<div class="filenote' + (loud ? ' scanwarn' : '') + '">' + note + '</div>';
    renderPdfReview(r.data, file);
    warnTermDrops();   // warn CLIENT-side (browser pre-filters terms, so the textarea is truth)
    renderPassages([], '');   // PDF flow does not surface passages (text-layer follow-up owed)
    // PDF flow has no readily-available residual text, so the re-id EXPOSURE meter is hidden
    // here rather than fabricating a score (honest: see the PDF-residual TODO in web.py).
    renderReidMeter(null, null);
    goStage('review');
    // Phase 2: load the on-page visual preview (display-only). It renders asynchronously
    // and replaces the list-only note in place; a failure leaves the note (flat-list
    // fallback). Not awaited so the review is interactive immediately.
    loadPdfPreview(file);
  }

  // ---- ADD A REDACTION (text terms -> re-scan) -----------------------------------
  // "Hide everywhere" appends the typed name to the terms textarea + re-scans, so every
  // occurrence is found by the engine's reliable literal-TERMS feature. Works on text AND
  // PDF documents (terms feed both scan paths).
  async function hideEverywhere(){
    var inp = $('hideEverywhere'), hint = $('hideEverywhereHint');
    var term = (inp.value || '').trim();
    if (!term){ if (hint) hint.textContent = 'Type a word or name first, then click Hide everywhere.'; inp.focus(); return; }
    if (byteLen(term) > MAX_TERM_BYTES){ if (hint) hint.textContent = 'That’s too long to add as a single term.'; return; }
    var box = $('termsBox');
    if (box){
      var existing = parseTerms(box.value);
      if (existing.indexOf(term) === -1){
        existing.push(term);
        box.value = existing.join('\n');
        saveOptions();
      }
    }
    inp.value = '';
    if (hint) hint.textContent = 'Added “' + term + '”. Re-scanning to find every occurrence…';
    announce('Added ' + term + ' to hide everywhere. Re-scanning.');
    // Re-scan with the updated terms so the new occurrences appear as findings.
    if (mode === 'pdf' && pdfFile){ await doPdfScan(pdfFile); }
    else { await doScan(); }
    if (hint) hint.textContent = 'Every exact match of “' + term + '” is now in the findings list.';
  }

