/* ==== CONCATENATION FRAGMENT 3 of 11 — app/ui/redaction.review.js ====
   This file is NOT standalone-valid JavaScript. It is one slice of app/ui/redaction.js,
   split at the ORIGINAL file's own "---- section ----" comment boundaries. Together the
   11 fragments form ONE outer IIFE (app/ui/redaction.core.js opens it with
   `(function(){`; app/ui/redaction.stepper.js closes it with `})();`). The order they
   concatenate in is defined ONLY by REDACTION_JS_PARTS in app/ui_manifest.py (consumed by
   app/web.py's _build_redaction_page()) — never reorder these files without re-verifying
   the assembled script. See app/ui_manifest.py for the full fragment list + what each
   contains. */
  // ---- rendering of candidate rows / groups --------------------------------------
  function candRow(c, idx, checked, inGroup){
    var div = document.createElement('label');
    // ADVISORY (an aggressive-recognizer hit): surfaced for review but DEFAULT-OFF — the
    // human opts IN. It is never auto-checked, even in the PDF "untick to keep" model.
    var advisory = !!c.advisory;
    // FEATURE 2 "kept": a value on the Keep list is SHOWN (never suppressed) but auto-dismissed
    // and left in the document — unchecked regardless of the tier default, marked "kept", and
    // one click (this checkbox) overturns it. markDecidedFromBox on render treats it as decided.
    var kept = candIsKept(c);
    div.className = (inGroup ? 'cand member' : 'cand') + (advisory ? ' advisory' : '') + (kept ? ' kept' : '');
    div.setAttribute('data-idx', idx);
    var conf = String(c.confidence || 'low');
    var advChip = advisory ? '<span class="chip advisory" title="' +
      esc('Possible match from an aggressive recognizer — review-only, NOT redacted unless you tick it.') +
      '">possible — review</span>' : '';
    var keptChip = kept ? '<span class="chip kept" title="' +
      esc('On your Keep list — shown but NOT redacted. Tick to redact it anyway.') +
      '">kept — not redacted</span>' : '';
    var chips = inGroup
      ? '<span class="chip ' + esc(conf) + '">' + esc(conf) + '</span>' + advChip + keptChip
      : '<span class="chip rec">' + esc(c.recognizer) + '</span>' +
        '<span class="chip ' + esc(conf) + '">' + esc(conf) + '</span>' + advChip + keptChip;
    div.innerHTML =
      '<input type="checkbox" class="memberbox" data-idx="' + idx + '"' +
        (checked && !advisory && !kept ? ' checked' : '') + '>' +
      '<div class="meta">' +
        '<div class="chips">' + chips + '</div>' +
        '<div class="val">' + esc(c.value) + '</div>' +
        '<div class="ctx">' + esc(c.context) + '</div>' +
      '</div>';
    return div;
  }

  function groupRow(g, defaultChecked){
    var wrap = document.createElement('div');
    // A group is keyed by recognizer (+digit template), so every member shares the SAME
    // advisory state — an advisory group is uniformly default-OFF (the human opts in).
    var advisory = !!(g.members[0] && g.members[0].c.advisory);
    var groupChecked = defaultChecked && !advisory;
    wrap.className = 'candgroup' + (advisory ? ' advisory' : '');
    var conf = String((g.members[0] && g.members[0].c.confidence) || 'low');
    var advChip = advisory ? '<span class="chip advisory" title="' +
      esc('Possible matches from an aggressive recognizer — review-only, NOT redacted unless you tick them.') +
      '">possible — review</span>' : '';
    var examples = g.members.slice(0, 2).map(function(m){
      return '<span class="ex">' + esc(m.c.value) + '</span>';
    }).join('');
    var more = g.count > 2 ? '<span class="exmore">+' + (g.count - 2) + ' more</span>' : '';

    var head = document.createElement('div');
    head.className = 'cand grouphead';
    head.innerHTML =
      '<input type="checkbox" class="groupbox"' + (groupChecked ? ' checked' : '') + '>' +
      '<div class="meta">' +
        '<div class="chips">' +
          '<span class="chip rec">' + esc(g.recognizer) + '</span>' +
          '<span class="chip ' + esc(conf) + '">' + esc(conf) + '</span>' +
          '<span class="chip n">&times;' + g.count + '</span>' + advChip +
        '</div>' +
        '<div class="val">' + examples + more + '</div>' +
        '<div class="ctx grouphint">Repeated / boilerplate — same shape, differs only by ' +
          'numbers. Keep all or dismiss all in one click, or expand to override individuals.</div>' +
      '</div>' +
      '<button type="button" class="grouptoggle link" aria-expanded="false">Expand</button>';
    wrap.appendChild(head);

    var body = document.createElement('div');
    body.className = 'groupmembers hidden';
    g.members.forEach(function(m){
      body.appendChild(candRow(m.c, m.idx, groupChecked, true));
    });
    wrap.appendChild(body);

    var groupbox = head.querySelector('.groupbox');
    var toggle = head.querySelector('.grouptoggle');

    function setMembers(checked){
      body.querySelectorAll('input.memberbox').forEach(function(b){
        b.checked = checked;
        markDecidedFromBox(b);
      });
    }
    function syncGroup(){
      var boxes = body.querySelectorAll('input.memberbox');
      var on = 0;
      boxes.forEach(function(b){ if (b.checked) on++; });
      if (on === 0){ groupbox.checked = false; groupbox.indeterminate = false; }
      else if (on === boxes.length){ groupbox.checked = true; groupbox.indeterminate = false; }
      else { groupbox.checked = false; groupbox.indeterminate = true; }
    }
    groupbox.addEventListener('change', function(){
      groupbox.indeterminate = false;
      setMembers(groupbox.checked);
      onSelectionChanged();
    });
    body.addEventListener('change', function(e){
      if (e.target && e.target.classList && e.target.classList.contains('memberbox')){
        markDecidedFromBox(e.target);
        syncGroup();
        onSelectionChanged();
      }
    });
    toggle.addEventListener('click', function(){
      var open = body.classList.toggle('hidden') === false;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.textContent = open ? 'Collapse' : 'Expand';
    });
    syncGroup();
    return wrap;
  }

  function renderTierGrouped(container, members, defaultChecked){
    container.innerHTML = '';
    var localCands = members.map(function(m){ return m.c; });
    var groups = groupCandidates(localCands);
    groups.forEach(function(g){
      g.members.forEach(function(gm){ gm.idx = members[gm.idx].idx; });
    });
    var rendered = 0;
    groups.forEach(function(g){
      if (g.count === 1){
        var m = g.members[0];
        container.appendChild(candRow(m.c, m.idx, defaultChecked, false));
      } else {
        container.appendChild(groupRow(g, defaultChecked));
      }
      rendered += g.count;
    });
    return rendered;
  }

  // A toggle on a candidate box is a DECISION (text mode): record the idx as decided so the
  // careful-review gate clears. (PDF mode untick=keep semantics; we still mark decided so the
  // gate is consistent — every touched item counts as addressed.)
  function markDecidedFromBox(box){
    var idx = box && box.getAttribute && box.getAttribute('data-idx');
    if (idx != null) decided[+idx] = true;
  }

  // ---- review rendering (text + PDF) ---------------------------------------------
  function renderReview(result){
    var cands = result.candidates || [];
    decided = {};
    // FEATURE 2: a kept candidate is auto-dismissed — pre-mark it DECIDED so the careful-review
    // gate never blocks Export on a value the reviewer chose to keep (it is still shown).
    cands.forEach(function(c, i){ if (candIsKept(c)) decided[i] = true; });
    var m1 = [], m2 = [];
    cands.forEach(function(c, idx){
      // ADVISORY (aggressive-recognizer) hits are NEVER quick-confirmed — they route to
      // careful review and are default-OFF (candRow leaves an advisory box unchecked even
      // when the tier defaults checked), so the human opts IN to redact them.
      if (c.tier === 'quick-confirm' && !c.advisory) m1.push({c: c, idx: idx});
      else m2.push({c: c, idx: idx});
    });
    var n1 = renderTierGrouped(tier1, m1, true);
    var n2 = renderTierGrouped(tier2, m2, false);
    if (n1 === 0) tier1.innerHTML = '<div class="empty-tier">No high-confidence matches.</div>';
    if (n2 === 0) tier2.innerHTML = '<div class="empty-tier">Nothing needs careful review.</div>';
    t1count.textContent = n1;
    t2count.textContent = n2;
    summary.innerHTML = cands.length
      ? 'Found <b>' + cands.length + '</b> potential identifier' + (cands.length === 1 ? '' : 's') +
        ': <b>' + n1 + '</b> to quick-confirm, <b>' + n2 + '</b> to review.'
      : 'No identifiers found. Review the text yourself before relying on this.';
    toggleTierActions(true);
    ocrBtn.classList.add('hidden');
    imgreview.classList.add('hidden');
    review.classList.remove('hidden');
    applyHint.textContent = '';
    applyHint.className = 'hint';
    buildTextPreview();
    onSelectionChanged();
  }

  function renderPdfReview(result, file){
    var cands = result.candidates || [];
    decided = {};
    // FEATURE 2: kept candidates are auto-dismissed + pre-marked decided (shown, not redacted).
    cands.forEach(function(c, i){ if (candIsKept(c)) decided[i] = true; });
    var m1 = [], m2 = [];
    cands.forEach(function(c, idx){
      // ADVISORY (aggressive-recognizer) hits route to careful review and are default-OFF —
      // candRow leaves them UNCHECKED even though the PDF tier defaults checked, so they are
      // surfaced but never removed unless the human ticks them.
      if (c.tier === 'quick-confirm' && !c.advisory) m1.push({c: c, idx: idx});
      else m2.push({c: c, idx: idx});
    });
    // PDF path defaults PRECISE detections checked (untick what you want to KEEP); ADVISORY
    // detections stay UNCHECKED (candRow guards on c.advisory), so the human opts them in.
    var n1 = renderTierGrouped(tier1, m1, true);
    var n2 = renderTierGrouped(tier2, m2, true);
    if (n1 === 0) tier1.innerHTML = '<div class="empty-tier">No high-confidence matches.</div>';
    if (n2 === 0) tier2.innerHTML = '<div class="empty-tier">Nothing in the careful-review tier.</div>';
    // PDF defaults are pre-checked; treat all tier-2 as decided (kept) by default so the
    // export gate does not block on the PDF "untick to keep" model.
    m2.forEach(function(m){ decided[m.idx] = true; });
    t1count.textContent = n1;
    t2count.textContent = n2;
    var total = cands.length;
    summary.innerHTML = '<b>' + total + '</b> identifier' + (total === 1 ? '' : 's') +
      ' detected. Untick any you want to KEEP; the rest are removed from the PDF ' +
      '(true text removal). <span class="hint">Only the TEXT layer is redacted &mdash; ' +
      'text baked into scanned images is not.</span>' +
      // Live "N of M detections will be redacted" count + the non-located honesty note:
      // a detection with NO preview box (subset-font "couldn’t pinpoint", or a page past
      // the preview cap) is STILL removed unless explicitly DESELECTED here in the list —
      // so the user never reads "no box" as "not removed". updatePdfRedactCount() refreshes
      // the <b> figure on every toggle (it is the SELECTED-id count, the exact apply set).
      '<div class="pdf-redact-count" id="pdfRedactCount" style="margin-top:10px"></div>' +
      '<div class="hint" id="pdfNonLocatedNote" style="margin-top:6px">' +
        esc('Tip: not every detection shows as a box on the page — some can’t be pinpointed ' +
          '(an unusual font) or sit on a page beyond the preview. Those are STILL removed ' +
          'unless you deselect them here in the list.') + '</div>';
    toggleTierActions(true);
    imgreview.classList.add('hidden');
    review.classList.remove('hidden');
    applyHint.textContent = total === 0 ? 'No text-layer identifiers to remove.' : '';
    applyHint.className = 'hint';
    if (result.low_text){
      ocrBtn.classList.remove('hidden');
      summary.innerHTML += ' <span class="hint">This looks like a scanned PDF — use ' +
        '“OCR &amp; redact scanned PDF” to OCR the page images and review each detected ' +
        'box before removing it (best-effort).</span>';
    } else {
      ocrBtn.classList.add('hidden');
    }
    // unmapped_fonts: surfaced as LOUDLY as low_text. Subset/CID-font pages have text the
    // engine can’t fully see, so a low/zero count on those pages is NOT “clean”. A warn
    // banner above the list (not just a hint) so the lawyer can’t miss it.
    if (result.unmapped_fonts){
      summary.innerHTML +=
        '<div class="banner warn" style="margin-top:12px">' +
          '<span class="ic" aria-hidden="true">&#9888;</span>' +
          '<div class="body"><b>Some pages use an unusual font we could only read best-effort.</b>' +
          '<p>' + esc('On those pages there may be text the scan can’t see, so a low or zero ' +
            'count here does NOT mean the page is clean. For those pages, use “OCR & redact ' +
            'scanned PDF” — it reads the pages as images and can remove text this scan missed — ' +
            'and read them yourself before relying on the result.') + '</p></div>' +
        '</div>';
    }
    buildTextPreview();   // shows the PDF list-only note (mode === 'pdf') until preview loads
    onSelectionChanged();
  }

