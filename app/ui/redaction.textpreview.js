/* ==== CONCATENATION FRAGMENT 5 of 11 — app/ui/redaction.textpreview.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- TEXT document preview (live, in-place highlights) --------------------------
  // The text preview rebuilds the document text into the canvas with each candidate span
  // wrapped in a clickable highlight. Ticking a finding swaps the value for [REDACTED] live.
  // For a PDF document there is NO canvas (Phase 2 owes the visual preview) — we show the
  // list-only note instead.
  function setPreviewKind(){
    var pdf = mode === 'pdf';
    $('pvText').classList.toggle('hidden', pdf);
    $('previewLiveNote').classList.toggle('hidden', pdf);
    $('previewLegend').classList.toggle('hidden', pdf);
    // PDF: show the on-page VISUAL preview when it rendered, else the list-only note.
    var showVisual = pdf && pdfPreviewReady;
    if (pdfPreview) pdfPreview.classList.toggle('hidden', !showVisual);
    $('pvPdfNote').classList.toggle('hidden', !pdf || showVisual);
    var k = $('previewKind');
    if (k){ k.textContent = pdf ? 'PDF document' : 'Text document';
      k.className = 'chip ' + (pdf ? 'accent' : 'neutral'); }
  }

  // Build the highlighted text canvas from scannedText + cands (text mode only).
  // Spans are placed by their [start,end] BYTE offsets — map to a JS-string slice via the
  // shared byte<->string helpers. Non-overlapping spans are assumed (the engine emits a
  // sorted, merged candidate set); we render in start order and skip any that overlap.
  function buildTextPreview(){
    setPreviewKind();
    if (mode === 'pdf') return;
    var canvas = $('textCanvas');
    if (!canvas) return;
    var text = scannedText != null ? scannedText : (input.value || '');
    // (was `var cands = window.__cands || [];` — renamed to candList to avoid shadowing
    // the outer closure `cands` var now that window.__cands is gone.)
    var candList = (cands || []).slice();
    // Order by start; carry the original idx for the data-idx key.
    var items = [];
    candList.forEach(function(c, idx){
      if (typeof c.start === 'number' && typeof c.end === 'number' && c.end > c.start){
        items.push({start: c.start, end: c.end, idx: idx, c: c});
      }
    });
    items.sort(function(a, b){ return a.start - b.start || a.end - b.end; });
    canvas.innerHTML = '';
    var bytePos = 0, lastEnd = 0;
    items.forEach(function(it){
      if (it.start < lastEnd) return;   // skip an overlapping span (defensive)
      if (it.start > bytePos){
        canvas.appendChild(document.createTextNode(sliceByBytes(text, bytePos, it.start)));
      }
      var span = document.createElement('span');
      var checked = isChecked(it.idx);
      var tier = it.c.tier === 'quick-confirm' ? 'ready' : 'review';
      span.className = 'hl ' + tier + (checked ? ' redacted-preview' : '');
      span.setAttribute('data-idx', it.idx);
      span.setAttribute('tabindex', '0');
      span.setAttribute('role', 'button');
      span.setAttribute('title', 'Click to ' + (checked ? 'keep' : 'redact') + ' this');
      var orig = sliceByBytes(text, it.start, it.end);
      span.setAttribute('data-orig', orig);
      span.innerHTML = checked
        ? '<span class="hlmark">[REDACTED]</span>'
        : '<span class="hlval">' + esc(orig) + '</span>';
      span.addEventListener('click', function(){ onPreviewClick(it.idx); });
      span.addEventListener('keydown', function(ev){
        if (ev.key === 'Enter' || ev.key === ' '){ ev.preventDefault(); onPreviewClick(it.idx); }
      });
      canvas.appendChild(span);
      bytePos = it.end;
      lastEnd = it.end;
    });
    if (text && bytePos < byteLength(text)){
      canvas.appendChild(document.createTextNode(sliceByBytes(text, bytePos, byteLength(text))));
    }
    if (!text){
      canvas.innerHTML = '<span class="hint">No text to preview.</span>';
    }
  }

  function isChecked(idx){
    var b = document.querySelector('#review input.memberbox[data-idx="' + idx + '"]');
    return !!(b && b.checked);
  }

  // Clicking a highlight toggles its candidate's checkbox + records the decision, then the
  // preview + findings + gates all re-sync.
  function onPreviewClick(idx){
    var b = document.querySelector('#review input.memberbox[data-idx="' + idx + '"]');
    if (!b) return;
    b.checked = !b.checked;
    markDecidedFromBox(b);
    resyncGroups(document);
    onSelectionChanged();
    syncPreviewSpan(idx);
    // FE M-2: announce a NON-cleartext description — the recognizer label + the finding's
    // position/count — never the matched value (it is cleartext PII; even though this is
    // local-only, the matched value must not enter the ARIA live region / a11y tree).
    var all = cands || [];
    var cand = all[idx] || {};
    var pos = idx + 1, total = all.length;
    var what = (cand.recognizer || 'finding') + ' (finding ' + pos + ' of ' + total + ')';
    announce((b.checked ? 'Redaction previewed in place for ' : 'Restored ') + what + '.');
  }

  // Reflect ONE candidate's checked-state into its preview highlight (live swap).
  function syncPreviewSpan(idx){
    if (mode === 'pdf') return;
    var span = document.querySelector('#textCanvas .hl[data-idx="' + idx + '"]');
    if (!span) return;
    var checked = isChecked(idx);
    span.classList.toggle('redacted-preview', checked);
    span.setAttribute('title', 'Click to ' + (checked ? 'keep' : 'redact') + ' this');
    span.innerHTML = checked
      ? '<span class="hlmark">[REDACTED]</span>'
      : '<span class="hlval">' + esc(span.getAttribute('data-orig') || '') + '</span>';
  }

  // Reflect ALL candidates' checked-state into the preview (after a bulk select/clear).
  function syncAllPreviewSpans(){
    if (mode === 'pdf') return;
    document.querySelectorAll('#textCanvas .hl[data-idx]').forEach(function(span){
      syncPreviewSpan(+span.getAttribute('data-idx'));
    });
  }

  // ---- byte<->string helpers (UTF-8) for span placement + passages ---------------
  var _encoder = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
  var _decoder = (typeof TextDecoder !== 'undefined') ? new TextDecoder() : null;
  function byteLength(text){
    if (!_encoder) return String(text == null ? '' : text).length;
    return _encoder.encode(String(text == null ? '' : text)).length;
  }
  function sliceByBytes(text, start, end){
    if (!_encoder || !_decoder){ return String(text).slice(start, end); }
    var bytes = _encoder.encode(String(text == null ? '' : text));
    var a = Math.max(0, Math.min(start | 0, bytes.length));
    var b = Math.max(a, Math.min(end | 0, bytes.length));
    try { return _decoder.decode(bytes.subarray(a, b)); }
    catch(e){ return String(text).slice(start, end); }
  }

  // ---- Confidentiality / privilege passages (SURFACE-ONLY) ----
  var PASS_KEY = 'lawbat.redaction.passtoggle';
  function catLabel(cat){
    if (cat === 're_identification') return 'Re-identification';
    if (cat === 'privilege') return 'Privilege';
    if (cat === 'confidentiality') return 'Confidentiality';
    return String(cat || '');
  }

  function renderPassages(list, text){
    passageList = list || [];
    passText = text != null ? text : '';
    var on = !passToggle || passToggle.checked;
    var arr = passageList;
    passcount.textContent = arr.length;
    passages.innerHTML = '';
    if (!on){ updateAckGate(); return; }
    if (arr.length === 0){
      passages.innerHTML = '<div class="pass-empty">No confidentiality, sensitive-content or ' +
        're-identification passages flagged. This does NOT mean the text is safe — review it yourself.</div>';
      updateAckGate();
      return;
    }
    arr.forEach(function(p, i){
      var cat = String(p.category || '');
      var sev = String(p.severity || 'medium');
      var ptext = sliceByBytes(passText, p.start, p.end);
      var kw = (p.keywords || []).map(function(k){
        return '<span class="pkw">' + esc(k) + '</span>';
      }).join(' ');
      var div = document.createElement('div');
      div.className = 'passage ' + (cat === 'privilege' || cat === 'confidentiality' ||
        cat === 're_identification' ? cat : '');
      div.setAttribute('data-pid', i);
      div.innerHTML =
        '<div class="preason">' +
          '<span class="pcat">' + esc(catLabel(cat)) + '</span>' +
          '<span class="psev ' + esc(sev) + '">' + esc(sev) + '</span>' +
          '<span>' + esc(p.reason) + '</span>' +
        '</div>' +
        (kw ? '<div class="preason" style="font-weight:400">' + kw + '</div>' : '') +
        '<div class="ptext">' + esc(ptext) + '</div>' +
        '<div class="pacts">' +
          '<button type="button" class="linkbtn pwhy" data-pid="' + i + '">Why is this flagged?</button>' +
          '<span style="flex:1"></span>' +
          '<label class="check ack"><input type="checkbox" class="ackbox" data-pid="' + i + '">' +
            '<span class="box"></span> I&rsquo;ve reviewed this</label>' +
        '</div>';
      passages.appendChild(div);
    });
    // wire ack boxes + the "why" popovers
    passages.querySelectorAll('input.ackbox').forEach(function(b){
      b.addEventListener('change', updateAckGate);
    });
    passages.querySelectorAll('.pwhy').forEach(function(btn){
      btn.addEventListener('click', function(){ openFlagModal(+btn.getAttribute('data-pid')); });
    });
    updateAckGate();
  }

  function onPassToggle(){
    try { localStorage.setItem(PASS_KEY, passToggle.checked ? '1' : '0'); } catch(e){ /* best-effort */ }
    renderPassages(passageList || [], passText || '');
  }
  function restorePassToggle(){
    var v = null;
    try { v = localStorage.getItem(PASS_KEY); } catch(e){ v = null; }
    if (passToggle) passToggle.checked = (v == null) ? true : (v === '1');
  }

