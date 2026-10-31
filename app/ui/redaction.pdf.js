/* ==== CONCATENATION FRAGMENT 4 of 11 — app/ui/redaction.pdf.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- on-page VISUAL PDF preview (Phase 2, DISPLAY-ONLY) -------------------------
  // After a PDF scan, fetch the rendered finding-pages + highlight boxes (page-fraction
  // coords) from /api/redaction/pdf-preview and draw them. The boxes cross-reference the
  // findings list by each candidate's cands index. This NEVER drives removal —
  // ticking a finding in the list dims its box (kept, not removed); the accept/reject +
  // Save still come from the list. On preview:false we keep the existing list-only note.
  function resetPdfPreview(){
    pdfPreviewReady = false;
    if (pdfPreview){ pdfPreview.innerHTML = ''; pdfPreview.classList.add('hidden'); }
    if ($('pdfPreviewNote')) $('pdfPreviewNote').textContent = 'Loading the on-page preview…';
  }

  async function loadPdfPreview(file){
    if (!file) return;
    // Capture the scan token at the START of this load. The candidate list (cands)
    // and value_ref indices belong to THIS scan; if another scan starts before the preview
    // returns, the token advances and we drop the now-misaligned preview below.
    var myToken = scanToken;
    resetPdfPreview();
    setPreviewKind();   // show the list-only note while the preview loads
    // (was `var cands = window.__cands || [];` — renamed to candList to avoid shadowing
    // the outer closure `cands` var now that window.__cands is gone.)
    var candList = cands || [];
    // Nothing to place on a page -> keep the list-only note (no preview needed).
    if (!candList.length){
      if ($('pdfPreviewNote')) $('pdfPreviewNote').textContent =
        'No findings to show on the page — review is from the list above.';
      return;
    }
    var b64;
    try { b64 = await fileToBase64(file); }
    catch(e){ if ($('pdfPreviewNote')) $('pdfPreviewNote').textContent =
      'The on-page preview is unavailable — use the findings list.'; return; }
    var r;
    try {
      r = await post('/api/redaction/pdf-preview',
        {data_b64:b64, candidates:candList, unmapped_fonts:!!lastUnmappedFonts});
    } catch(e){ r = {ok:false, data:{}}; }
    // A different scan started while we were loading — drop this stale preview. The token
    // check catches a SAME-File re-scan (changed settings) that file-identity alone misses;
    // the mode/file checks still guard a switch to a different document or to text mode.
    if (myToken !== scanToken || mode !== 'pdf' || pdfFile !== file) return;
    if (!r.ok || !r.data || r.data.preview !== true){
      // Graceful fallback: keep the existing list-only note (the flat-list flow).
      if ($('pdfPreviewNote')) $('pdfPreviewNote').textContent =
        'The on-page preview isn’t available for this PDF — review is from the findings list above.';
      pdfPreviewReady = false;
      setPreviewKind();
      return;
    }
    renderPdfPreview(r.data);
  }

  function renderPdfPreview(data){
    if (!pdfPreview) return;
    var pages = data.pages || [];
    pdfPreview.innerHTML = '';
    if (!pages.length){ pdfPreviewReady = false; setPreviewKind(); return; }

    var cap = document.createElement('div'); cap.className = 'pp-cap';
    cap.innerHTML = '<span><b>On-page preview</b> — the highlighted boxes are what will be removed.</span>' +
      '<span class="hint">Click a box to jump to it in the list. Untick a finding to keep it (its box dims).</span>';
    pdfPreview.appendChild(cap);
    if (data.note){
      var nt = document.createElement('div'); nt.className = 'pp-note';
      nt.textContent = data.note;   // honest page-virtualization overflow message
      pdfPreview.appendChild(nt);
    }

    var pagesWrap = document.createElement('div'); pagesWrap.className = 'pp-pages';
    pages.forEach(function(p){
      var pageDiv = document.createElement('div'); pageDiv.className = 'pp-page';
      var boxes = p.boxes || [];
      var located = boxes.filter(function(b){ return b.located; }).length;
      var unlocated = boxes.length - located;
      var pcap = document.createElement('div'); pcap.className = 'pp-pcap';
      pcap.innerHTML = '<span>Page <b>' + ((p.index | 0) + 1) + '</b> — ' + boxes.length +
        ' finding' + (boxes.length === 1 ? '' : 's') +
        (unlocated ? ' (' + unlocated + ' couldn’t be pinpointed)' : '') + '</span>';
      pageDiv.appendChild(pcap);

      var frame = document.createElement('div'); frame.className = 'pp-frame';
      var img = document.createElement('img');
      // p.png is an inline data: URI (no external fetch — air-gap safe).
      img.src = p.png;
      img.alt = 'Page ' + ((p.index | 0) + 1) + ' preview';
      frame.appendChild(img);

      boxes.forEach(function(b){
        if (!b.located) return;   // box-less unlocated findings are listed below the frame
        var el = document.createElement('div');
        el.className = 'pp-box';
        el.style.left = (b.x * 100) + '%';
        el.style.top = (b.y * 100) + '%';
        el.style.width = (b.w * 100) + '%';
        el.style.height = (b.h * 100) + '%';
        var idx = b.value_ref;
        if (idx != null) el.setAttribute('data-idx', idx);
        if (b.recognizer){
          var tag = document.createElement('span'); tag.className = 'pp-tag';
          tag.textContent = b.recognizer;   // a config label, not matter data
          el.appendChild(tag);
        }
        el.addEventListener('click', function(){ onPreviewBoxClick(idx); });
        frame.appendChild(el);
      });
      pageDiv.appendChild(frame);

      // Box-less, HONEST markers for findings the page-search + OCR couldn't pinpoint.
      if (unlocated){
        var u = document.createElement('div'); u.className = 'pp-unlocated';
        u.innerHTML = '<b>' + unlocated + ' finding' + (unlocated === 1 ? '' : 's') +
          '</b> on this page couldn’t be pinpointed on the image (an unusual font) — ' +
          'see ' + (unlocated === 1 ? 'it' : 'them') + ' in the findings list and check the page yourself.';
        pageDiv.appendChild(u);
      }
      pagesWrap.appendChild(pageDiv);
    });
    pdfPreview.appendChild(pagesWrap);
    pdfPreviewReady = true;
    setPreviewKind();
    syncAllPreviewBoxes();
  }

  // Clicking a preview box TOGGLES its candidate's selection (deselect = keep it in the PDF),
  // then reveals + flashes the matching list row. Toggling here keeps the box, the list
  // checkbox, the live count and the export gate in lockstep — the box is just another way to
  // reach the SAME memberbox the apply set reads. The box dims (via syncPreviewBox) when its
  // candidate is deselected; re-clicking re-selects it.
  function onPreviewBoxClick(idx){
    if (idx == null) return;
    var box = document.querySelector('#review input.memberbox[data-idx="' + idx + '"]');
    if (!box) return;
    // TOGGLE the selection (deselect = exclude this id from the apply set). markDecidedFromBox
    // records the decision so the careful-review gate stays consistent; resyncGroups keeps a
    // parent group control's tri-state correct if this candidate sits in a group.
    box.checked = !box.checked;
    markDecidedFromBox(box);
    resyncGroups(document);
    var row = box.closest('.cand') || box.parentElement;
    // If the candidate sits inside a collapsed group, expand it so the row is visible.
    var grp = box.closest('.candgroup');
    if (grp){
      var body = grp.querySelector('.groupmembers');
      var tog = grp.querySelector('.grouptoggle');
      if (body && body.classList.contains('hidden') && tog) tog.click();
    }
    if (row && row.scrollIntoView) row.scrollIntoView({behavior:'smooth', block:'center'});
    if (row){
      row.classList.add('cross-flash');
      setTimeout(function(){ row.classList.remove('cross-flash'); }, 1200);
    }
    // Refresh the live count + box dim-state + gate (onSelectionChanged also re-syncs boxes).
    onSelectionChanged();
    syncPreviewBox(idx);
    var cand = (cands || [])[idx] || {};
    announce((box.checked ? 'Will redact ' : 'Keeping ') + (cand.recognizer || 'finding') +
      ' — ' + (box.checked ? 'selected' : 'deselected') + ' in the list.');
  }

  // Reflect ONE candidate's checked-state into its preview box: accepted (checked) = a
  // solid "will be removed" box; kept (unchecked) = a dimmed/dashed box. Display-only.
  function syncPreviewBox(idx){
    if (mode !== 'pdf' || !pdfPreviewReady) return;
    var el = pdfPreview.querySelector('.pp-box[data-idx="' + idx + '"]');
    if (!el) return;
    el.classList.toggle('kept', !isChecked(idx));
  }
  function syncAllPreviewBoxes(){
    if (mode !== 'pdf' || !pdfPreviewReady || !pdfPreview) return;
    pdfPreview.querySelectorAll('.pp-box[data-idx]').forEach(function(el){
      syncPreviewBox(+el.getAttribute('data-idx'));
    });
  }

