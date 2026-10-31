/* ==== CONCATENATION FRAGMENT 10 of 11 — app/ui/redaction.ocr.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- OCR scanned-PDF flow (per-span image review) ------------------------------
  // Per-page geometry from the last pdf-ocr-scan ({pageIndex: {rotate, deskew}}).
  // The server corrected each page (OSD rotation + deskew) BEFORE OCR, so the
  // preview + box fractions live in that corrected space; apply-selection echoes
  // this back so the burn replays the identical geometry (scan<->apply parity).
  var pageGeo = {};
  async function doPdfOcrScan(){
    if (!pdfFile) return;
    ocrBtn.disabled = true;
    applyHint.textContent = 'OCR + scanning (this can take a while)…';
    applyHint.className = 'hint';
    var b64;
    try { b64 = await fileToBase64(pdfFile); }
    catch(e){ ocrBtn.disabled = false; applyHint.textContent = ''; showEngineError('Could not read that file.'); return; }
    var r = await post('/api/redaction/pdf-ocr-scan', {data_b64:b64, options:readOptions()});
    ocrBtn.disabled = false; applyHint.textContent = '';
    if (!r.ok || r.data.error){
      if (r.data && r.data.too_many){
        if (window.confirm(r.data.error + '\n\nRedact ALL detected identifiers without per-box review?')) doPdfOcrApply();
        return;
      }
      showEngineError(r.data.error || ('Could not scan the PDF (HTTP ' + r.status + ').'));
      return;
    }
    var pages = r.data.pages || [];
    if (pages.length === 0){
      showEngineError('No scanned pages found to review. If this PDF has a text layer, use “Save redacted copy” instead.');
      return;
    }
    renderImgReview(pages, r.data.report || {});
    goStage('image');
  }

  async function doPdfOcrApply(){
    if (!pdfFile) return;
    ocrBtn.disabled = true;
    applyHint.textContent = 'OCR + redacting (this can take a while)…';
    applyHint.className = 'hint';
    var b64;
    try { b64 = await fileToBase64(pdfFile); }
    catch(e){ ocrBtn.disabled = false; applyHint.textContent = ''; showEngineError('Could not read that file.'); return; }
    var r = await post('/api/redaction/pdf-ocr-apply', {filename:pdfFile.name, data_b64:b64, options:readOptions(), reviewer:reviewerName()});
    ocrBtn.disabled = false; applyHint.textContent = '';
    if (!r.ok || r.data.error){
      showEngineError(r.data.error || ('Could not OCR-redact the PDF (HTTP ' + r.status + ').'));
      return;
    }
    showOcrResult(r.data);
    goStage('export');
  }

  function showOcrResult(data){
    outHead.style.display = 'none'; output.classList.add('hidden'); copyBtn.classList.add('hidden');
    renderLegend(null);
    hideTextSaveSeam();   // the OCR/image path writes its own PDF — no text-file export here
    lastTextApply = null;
    var rep = data.report || {};
    var boxes = rep.boxes || 0, pages = rep.redacted_pages || 0;
    // ANTI-OVER-CLAIM (Finding #3): OCR is inherently best-effort, so the headline never
    // promises a clean result — it frames this as a FIRST PASS to read before relying on,
    // and reassures the original is untouched (parity with the doPdfExport copy).
    var note = 'Saved <b>' + esc(data.filename || 'redacted.pdf') + '</b> to your exports folder &mdash; <b>' +
      boxes + '</b> region' + (boxes === 1 ? '' : 's') + ' burned out across <b>' + pages + '</b> page' +
      (pages === 1 ? '' : 's') + '. Opened the folder for you. This is a best-effort first pass, not ' +
      '“safe to send” — OCR can miss text, so read the saved copy before you rely on it. Your original ' +
      'file was not changed.';
    if (rep.digital_skipped) note += ' <span class="hint warn">' + rep.digital_skipped +
      ' page(s) with a text layer were NOT image-redacted — use Save redacted copy for their text.</span>';
    if (rep.mixed_pages) note += ' <span class="hint warn">' + rep.mixed_pages +
      ' page(s) had BOTH text and a scanned image — flattened to an image to redact safely.</span>';
    if (rep.ocr_empty_pages) note += ' <span class="hint warn">' + rep.ocr_empty_pages +
      ' scanned page(s) yielded no OCR text — review them; OCR may have missed content.</span>';
    // Honest per-page OCR-quality caveat: low mean word confidence = the text OCR fed the
    // detector may be misread, so detection there is less trustworthy. Never "safe" copy —
    // the flag asks for human eyes; the low-confidence text was still scanned and burned.
    var lcp = rep.low_conf_pages || [];
    if (lcp.length){
      var lcList = lcp.map(function(p){
        return esc(String(p.page)) + ' (OCR confidence ' + esc(String(p.conf)) + '%)';
      }).join(', ');
      note += ' <span class="hint warn">Page' + (lcp.length === 1 ? ' ' : 's ') + lcList +
        ' scanned poorly — review those pages yourself; OCR may have misread text there.</span>';
    }
    applySummary.innerHTML = note;
    // Features A/B/C — the OCR export's verification verdict (image-only output typically
    // reads as "could not fully verify"), the cleaned/not-removed line, and the report path.
    renderExportStrip(data);
    outwrap.classList.remove('hidden');
    // Unlock + render the Report stage but STAY on Export — OCR is inherently best-effort, so
    // its "read the saved copy" note must stay visible (Report is one stepper click away).
    markExported(data, 'ocr', false);
  }

  function renderImgReview(pages, report){
    // UNHIDE the panel it is about to fill: every scan path adds `hidden` to #imgreview
    // as a stale-content reset, and goStage('image') only shows the PARENT stage — without
    // this remove the per-box review renders into an invisible card (a dead end: the
    // reviewer sees the scanned-PDF banner and no boxes, no save button; audit-caught).
    if (imgreview) imgreview.classList.remove('hidden');
    imgPages.innerHTML = '';
    pageGeo = {};
    var total = 0;
    pages.forEach(function(p){
      // Remember each page's server-side geometry for the apply echo (parity).
      pageGeo[p.index] = p.geo || {rotate: 0, deskew: 0};
      var pageDiv = document.createElement('div'); pageDiv.className = 'img-page';
      var nc = (p.candidates || []).length; total += nc;
      var cap = document.createElement('div'); cap.className = 'img-cap';
      cap.innerHTML = '<span>Page <b>' + (p.index + 1) + '</b></span>' +
        '<span>' + nc + ' detected' + (p.mixed ? ' · had a text layer (flattened)' : '') + '</span>';
      pageDiv.appendChild(cap);
      if (p.ocr_empty){
        var em = document.createElement('div'); em.className = 'img-empty';
        em.textContent = 'No OCR text on this page — review it; OCR may have missed content.';
        pageDiv.appendChild(em);
      }
      if (p.low_conf && p.ocr_conf != null){
        // Honest OCR-quality flag (never a filter): detection ran on possibly-misread
        // text, so this page needs human eyes more than most.
        var lc = document.createElement('div'); lc.className = 'img-empty';
        lc.textContent = 'This page scanned poorly (OCR confidence ' +
          Math.round(p.ocr_conf) + '%) — review it yourself; OCR may have misread text.';
        pageDiv.appendChild(lc);
      }
      var frame = document.createElement('div'); frame.className = 'img-frame';
      var img = document.createElement('img');
      img.src = 'data:image/png;base64,' + p.preview;
      img.alt = 'Page ' + (p.index + 1) + ' preview';
      frame.appendChild(img);
      (p.candidates || []).forEach(function(c){
        var bb = c.bbox || [0, 0, 0, 0];
        var b = document.createElement('div');
        // FEATURE 3 completion (advisory parity): an ADVISORY (aggressive-recognizer) hit is
        // SURFACED but DEFAULT-OFF ('skip'), mirroring the born-digital review — the human
        // opts in by clicking it filled. A precise hit stays default-selected ('keep').
        var advisory = !!c.advisory;
        b.className = 'img-box ' + (advisory ? 'skip advisory' : 'keep');
        if (advisory) b.title = 'Possible match (aggressive recognizer) — NOT removed unless you click it filled.';
        b.style.left = (bb[0] * 100) + '%';
        b.style.top = (bb[1] * 100) + '%';
        b.style.width = ((bb[2] - bb[0]) * 100) + '%';
        b.style.height = ((bb[3] - bb[1]) * 100) + '%';
        b.setAttribute('data-page', p.index);
        b.__rects = c.rects || [];
        if (c.label){
          var tag = document.createElement('span'); tag.className = 'img-tag';
          tag.textContent = c.label + (advisory ? ' — possible' : '');
          b.appendChild(tag);
        }
        b.addEventListener('click', function(){ b.classList.toggle('keep'); b.classList.toggle('skip'); });
        frame.appendChild(b);
      });
      pageDiv.appendChild(frame);
      imgPages.appendChild(pageDiv);
    });
    imgSummary.innerHTML = '<b>' + total + '</b> identifier' + (total === 1 ? '' : 's') +
      ' detected across <b>' + (report.scanned || 0) + '</b> scanned page' + (report.scanned === 1 ? '' : 's') +
      '. Click a box to keep (filled = removed) or skip (outline). ' +
      (report.digital_skipped ? '<span class="hint warn">' + report.digital_skipped +
        ' text page(s) are not shown here — use “Save redacted copy” for those.</span> ' : '') +
      '<span class="hint warn">Best-effort OCR — review before relying on it; OCR can miss text.</span>';
    imgApplyBtn.disabled = false;
    imgApplyHint.textContent = '';
    imgApplyHint.className = 'hint';
  }

  function setAllBoxes(keep){
    document.querySelectorAll('#imgPages .img-box').forEach(function(b){
      b.classList.toggle('keep', keep);
      b.classList.toggle('skip', !keep);
    });
  }
  function gatherAccepted(){
    var acc = {};
    document.querySelectorAll('#imgPages .img-box.keep').forEach(function(b){
      var pg = b.getAttribute('data-page');
      if (!acc[pg]) acc[pg] = [];
      (b.__rects || []).forEach(function(rr){ acc[pg].push(rr); });
    });
    return acc;
  }
  async function doPdfOcrApplySelection(){
    if (!pdfFile) return;
    var kept = document.querySelectorAll('#imgPages .img-box.keep').length;
    if (kept === 0 && !window.confirm('No boxes selected — save a copy with NOTHING redacted?')) return;
    var accepted = gatherAccepted();
    imgApplyBtn.disabled = true; imgApplyHint.textContent = 'Redacting & saving…'; imgApplyHint.className = 'hint';
    var b64;
    try { b64 = await fileToBase64(pdfFile); }
    catch(e){ imgApplyBtn.disabled = false; imgApplyHint.textContent = ''; showEngineError('Could not read that file.'); return; }
    var r = await post('/api/redaction/pdf-ocr-apply-selection', {filename:pdfFile.name, data_b64:b64, accepted:accepted, geo:pageGeo, options:readOptions(), reviewer:reviewerName()});
    imgApplyBtn.disabled = false; imgApplyHint.textContent = '';
    if (!r.ok || r.data.error){
      showEngineError(r.data.error || ('Could not save the redacted PDF (HTTP ' + r.status + ').'));
      return;
    }
    showOcrResult(r.data);
    goStage('export');
  }

  // ---- group resync (after bulk changes) -----------------------------------------
  function resyncGroups(root){
    (root || document).querySelectorAll('.candgroup').forEach(function(grp){
      var gb = grp.querySelector('.groupbox');
      if (!gb) return;
      var boxes = grp.querySelectorAll('input.memberbox');
      var on = 0;
      boxes.forEach(function(b){ if (b.checked) on++; });
      if (on === 0){ gb.checked = false; gb.indeterminate = false; }
      else if (on === boxes.length){ gb.checked = true; gb.indeterminate = false; }
      else { gb.checked = false; gb.indeterminate = true; }
    });
  }
  function setTier(selector, checked){
    var root = document.querySelector(selector);
    if (!root) return;
    root.querySelectorAll('input.memberbox').forEach(function(b){
      // FEATURE 2: "Select all"/"Keep all" never bulk-SELECTS a kept value — it stays
      // dismissed unless the reviewer overturns it deliberately. "Dismiss all" still unchecks.
      if (checked){
        var c = (cands || [])[+b.getAttribute('data-idx')];
        if (c && candIsKept(c)) return;
      }
      b.checked = checked; markDecidedFromBox(b);
    });
    resyncGroups(root);
    syncAllPreviewSpans();
    onSelectionChanged();
  }

  function copyOut(){
    var text = output.value;
    function done(){ copyBtn.textContent = 'Copied'; setTimeout(function(){ copyBtn.textContent = 'Copy'; }, 1500); }
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done, fallback);
    } else { fallback(); }
    function fallback(){
      output.removeAttribute('readonly');
      output.select();
      try { document.execCommand('copy'); done(); } catch(e){ /* ignore */ }
      output.setAttribute('readonly', 'readonly');
      window.getSelection().removeAllRanges();
    }
  }

  // ---- FLAGGED-passage popover (on this page; does not navigate) ------------------
  var lastFlagTrigger = null;
  function openFlagModal(pid){
    var modal = $('flagModal'), body = $('flagModalBody'), title = $('flagModalTitle');
    var p = (passageList || [])[pid];
    if (!modal || !p) return;
    lastFlagTrigger = document.activeElement;
    var ptext = sliceByBytes(passText, p.start, p.end);
    var kw = (p.keywords || []).map(function(k){ return '<span class="pkw">' + esc(k) + '</span>'; }).join(' ');
    if (title) title.textContent = 'Flagged for your eyes — ' + catLabel(p.category);
    if (body) body.innerHTML =
      '<p>This isn’t an identifier, so it’s <b>not removed automatically</b>. We flagged it because ' +
        esc(p.reason) + '. You decide what to do.</p>' +
      '<div class="mquote">' + esc(ptext) + '</div>' +
      (kw ? '<div class="mwhy">' + kw + '</div>' : '') +
      '<p class="help">Detection is rule-based — a flag here does not make the passage safe to send.</p>';
    modal.classList.remove('hidden');
    var c = $('flagModalClose'); if (c) c.focus();
    announce('Opened: why this passage is flagged. Press Escape to close.');
  }
  function closeFlagModal(){
    var modal = $('flagModal');
    if (!modal) return;
    modal.classList.add('hidden');
    if (lastFlagTrigger && lastFlagTrigger.focus) lastFlagTrigger.focus();
  }

