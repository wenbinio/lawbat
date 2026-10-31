/*
  Lawbat — Re-identification RISK estimator (host shell JS). Trusted first-party (not a
  sandboxed module). Drives the deterministic pure-Python estimator over
  /api/reidrisk/{score,batch} (app/reidrisk.py) and renders a k-VALUE ESTIMATE.

  HONESTY (load-bearing — a reviewer rejects violations):
    * The number is ALWAYS labelled a "k-ESTIMATE", never a guarantee/percentage/"safe to send".
    * We LEAD with the prosecutor (worst-case) metric.
    * The word "safe" appears ONLY negated. There is no "clear"/"safe"/"OK to send" state.
    * concern can only ever RAISE; an unknown/hostile concern degrades to a safe default.

  Confidentiality: the score carries cleartext QI VALUES (entity name, matched values) BY
  DESIGN — those are LOCAL only (never egressed, never persisted). Every cleartext string is
  escaped via esc() before any innerHTML. The text travels only the local pipe to the
  estimator; it is not persisted or logged.
*/
(function(){
  'use strict';

  // esc / $ / post / announce now live in the SHARED app/ui/base.js (window.LB, inlined
  // into this page via the __BASE_JS__ marker BEFORE this script) — aliased here so the
  // rest of this file is otherwise UNCHANGED. See base.js for the implementations (esc() is
  // byte-identical to the copy this file used to carry, copied EXACTLY from redaction.js).
  var esc = LB.esc, $ = LB.$, post = LB.post, announce = LB.announce;

  // ---- concern -> allowlisted CSS class suffix ---------------------------------
  // A known concern maps to its suffix; an UNKNOWN/hostile string degrades to the SAFE
  // default 'insufficient' — the raw string NEVER reaches a class attribute.
  var CONCERN_CLASSES = {
    looks_unique: 'looks_unique',
    small_cohort: 'small_cohort',
    elevated: 'elevated',
    insufficient_data: 'insufficient'
  };
  function concernClass(concern){
    var key = String(concern == null ? '' : concern);
    return Object.prototype.hasOwnProperty.call(CONCERN_CLASSES, key)
      ? CONCERN_CLASSES[key] : 'insufficient';
  }

  // Plain-language concern label (never a "safe"/"clear" word).
  var CONCERN_LABELS = {
    looks_unique: 'Looks unique',
    small_cohort: 'Small cohort',
    elevated: 'Elevated',
    insufficient_data: 'Insufficient data'
  };
  function concernLabel(concern){
    var key = String(concern == null ? '' : concern);
    return Object.prototype.hasOwnProperty.call(CONCERN_LABELS, key)
      ? CONCERN_LABELS[key] : 'Insufficient data';
  }

  // ---- number formatting -------------------------------------------------------
  function fmtInt(n){
    // thousands-separated integer, deterministic (no locale surprises).
    var s = String(Math.round(n));
    var neg = s.charAt(0) === '-';
    if (neg) s = s.slice(1);
    var out = '';
    while (s.length > 3){ out = ',' + s.slice(-3) + out; s = s.slice(0, -3); }
    return (neg ? '-' : '') + s + out;
  }
  function fmtK(k){
    // Returns a human "k-estimate" string. <=1 reads as population-unique.
    if (k == null || !isFinite(k)) return null;
    if (k <= 1) return '≈ 1 (population-unique)';
    if (k < 10) return '≈ ' + (Math.round(k * 10) / 10);
    return '≈ ' + fmtInt(k);
  }
  function fmtRisk(r){
    // a 1/k worst-case probability rendered as "1 in N" (deterministic, honest).
    if (r == null || !isFinite(r) || r <= 0) return null;
    if (r >= 1) return '1 in 1 (population-unique)';
    return '1 in ' + fmtInt(1 / r);
  }

  // ---- render a single-document estimate --------------------------------------
  function renderEstimate(score){
    var s = score || {};
    var card = $('estCard');
    var badge = $('concernBadge');
    var lead = $('estProsecutor');
    var kEl = $('estK');
    var metaEl = $('estMeta');
    var contribsEl = $('estContribs');
    var medicalEl = $('estMedical');
    var medicalBlock = $('estMedicalBlock');
    var coverageEl = $('estCoverage');
    var caveatEl = $('estCaveat');
    var covNote = $('coverageNote');

    if (card && card.classList) card.classList.remove('hidden');
    // Reset the OTHER review surface: hide the cross-doc release card so its prior doc's QI
    // cleartext can't linger on screen next to this fresh single-doc estimate (CONFIDENTIALITY —
    // a prior doc's values must not bleed into a new doc's review). The single-doc card's own
    // sub-sections are each fully reassigned below, so a stale contribution/medical row from a
    // previous score is overwritten, never appended.
    var relCardEl = $('relCard');
    if (relCardEl && relCardEl.classList) relCardEl.classList.add('hidden');
    // Belt-and-suspenders (leak class): also EMPTY the hidden release card's cleartext list so a
    // prior doc's QI values don't even linger in the (hidden) DOM, devtools-recoverable.
    var relEntitiesEl = $('relEntities');
    if (relEntitiesEl) relEntitiesEl.innerHTML = '';

    // concern badge (class via the allowlist; label is a fixed map — never raw server text).
    if (badge){
      badge.className = 'chip concern-' + concernClass(s.concern);
      badge.textContent = concernLabel(s.concern);
    }

    var insufficient = (s.k_estimate == null) || (String(s.concern) === 'insufficient_data');

    // LEAD with the prosecutor (worst-case) metric.
    if (lead){
      if (insufficient){
        lead.innerHTML = '<b>k could not be estimated &mdash; insufficient data ' +
          '(NOT a low-risk finding).</b>';
      } else {
        var riskTxt = fmtRisk(s.prosecutor_risk);
        lead.innerHTML = 'Worst-case (prosecutor) re-identification risk: ' +
          '<span class="big">' + esc(riskTxt || '—') + '</span> ' +
          '<span class="est-meta">&mdash; an attacker who knows the target is in the data.</span>';
      }
    }

    // the k-ESTIMATE number, always LABELLED an estimate (never a guarantee/percentage).
    if (kEl){
      if (insufficient){
        kEl.innerHTML = '<div class="est-insufficient"><b>k could not be estimated</b>' +
          'No quasi-identifier could be priced against the bundled reference data. This is ' +
          'INSUFFICIENT DATA &mdash; it is NOT a low-risk finding, and never &ldquo;safe to send.&rdquo;</div>';
      } else {
        kEl.innerHTML = '<b>k-estimate:</b> ' + esc(fmtK(s.k_estimate) || '—') +
          ' &mdash; an OPTIMISTIC lower bound, never a guarantee.';
      }
    }

    if (metaEl){
      var bits = [];
      if (s.jurisdiction) bits.push('jurisdiction ' + esc(String(s.jurisdiction)));
      if (s.population_N != null && isFinite(s.population_N))
        bits.push('population N ≈ ' + esc(fmtInt(s.population_N)));
      bits.push(esc(String(s.direction || 'optimistic — may under-state risk')));
      metaEl.innerHTML = bits.join(' &middot; ');
    }

    // contributing quasi-identifiers
    if (contribsEl){
      var contribs = Array.isArray(s.contributions) ? s.contributions : [];
      if (!contribs.length){
        contribsEl.innerHTML = '<p class="help mt0">No quasi-identifiers were detected.</p>';
      } else {
        var rows = '';
        for (var i = 0; i < contribs.length; i++){
          var c = contribs[i] || {};
          var probTxt = '';
          if (c.prob != null && isFinite(c.prob)){
            probTxt = '<span class="qi-prob">P ≈ ' + esc(String(c.prob)) + '</span>';
          } else if (!c.in_product){
            probTxt = '<span class="qi-prob">not priced</span>';
          }
          var tail = c.estimated_from_tail
            ? ' <span class="qi-tail">(estimated from tail)</span>' : '';
          var note = c.note ? '<span class="qi-note">' + esc(String(c.note)) + '</span>' : '';
          rows += '<div class="qi-row' + (c.in_product ? '' : ' qi-excluded') + '">' +
            '<span class="qi-cat">' + esc(String(c.category)) + '</span>' +
            '<span class="qi-val">' + esc(String(c.value)) + '</span>' +
            probTxt + tail + note + '</div>';
        }
        contribsEl.innerHTML = rows;
      }
    }

    // medical tiers (common/rare only — never priced)
    if (medicalEl){
      var med = Array.isArray(s.medical_tiers) ? s.medical_tiers : [];
      if (!med.length){
        if (medicalBlock && medicalBlock.classList) medicalBlock.classList.add('hidden');
        medicalEl.innerHTML = '';
      } else {
        if (medicalBlock && medicalBlock.classList) medicalBlock.classList.remove('hidden');
        var mrows = '';
        for (var j = 0; j < med.length; j++){
          var m = med[j] || {};
          var tierKey = (String(m.tier) === 'common') ? 'common' : 'rare';
          mrows += '<div class="med-row">' +
            '<span class="qi-val">' + esc(String(m.condition)) + '</span> ' +
            '<span class="med-tier ' + tierKey + '">' + esc(String(m.tier)) + '</span>' +
            '<div class="med-note">' + esc(String(m.note || '')) + '</div></div>';
        }
        medicalEl.innerHTML = mrows;
      }
    }

    // coverage disclosure (in-card AND the permanent banner area)
    var coverageText = String(s.coverage_note || '');
    if (coverageEl){
      coverageEl.innerHTML = '<div class="est-coverage">' + esc(coverageText) + '</div>';
    }
    if (covNote){ covNote.innerHTML = esc(coverageText); }

    // the always-present honesty caveat
    if (caveatEl){ caveatEl.innerHTML = esc(String(s.caveat || '')); }

    announce('k estimate ready');
  }

  // ---- render a cross-document release report ---------------------------------
  function renderRelease(report){
    var r = report || {};
    var card = $('relCard');
    var summaryChip = $('relSummaryChip');
    var entitiesEl = $('relEntities');
    var caveatEl = $('relCaveat');

    if (card && card.classList) card.classList.remove('hidden');
    // Reset the OTHER review surface: hide the single-doc estimate card so its prior doc's QI
    // cleartext can't linger next to this cross-doc release report (CONFIDENTIALITY — same reason
    // as renderEstimate hides the release card). The release entities list is rebuilt wholesale
    // below (entitiesEl.innerHTML = html), so no prior entity's values survive into this render.
    var estCardEl = $('estCard');
    if (estCardEl && estCardEl.classList) estCardEl.classList.add('hidden');
    // Belt-and-suspenders (leak class): EMPTY the hidden single-doc card's cleartext-bearing
    // lists (QI contributions + medical rows) so a prior doc's values don't linger in the
    // hidden DOM, devtools-recoverable.
    var estContribsEl = $('estContribs');
    if (estContribsEl) estContribsEl.innerHTML = '';
    var estMedicalEl = $('estMedical');
    if (estMedicalEl) estMedicalEl.innerHTML = '';

    if (summaryChip){
      var nd = (r.n_docs != null && isFinite(r.n_docs)) ? r.n_docs : 0;
      var ne = (r.n_linked_entities != null && isFinite(r.n_linked_entities)) ? r.n_linked_entities : 0;
      summaryChip.textContent = fmtInt(ne) + ' linked entit' + (ne === 1 ? 'y' : 'ies') +
        ' across ' + fmtInt(nd) + ' doc' + (nd === 1 ? '' : 's');
    }

    if (entitiesEl){
      var list = Array.isArray(r.linked_entities) ? r.linked_entities : [];
      if (!list.length){
        entitiesEl.innerHTML = '<p class="help mt0">No linkable entity was found across the ' +
          'documents. ABSENCE of linkage is NOT proof the documents are independent.</p>';
      } else {
        var html = '';
        for (var i = 0; i < list.length; i++){
          var le = list[i] || {};
          var est = le.estimate || {};
          var name = (le.name != null && le.name !== '') ? String(le.name) : '(unnamed entity)';
          var docIds = Array.isArray(le.doc_ids) ? le.doc_ids : [];
          var docHtml = '';
          for (var d = 0; d < docIds.length; d++){
            docHtml += (d ? ' ' : '') + '<code>' + esc(String(docIds[d])) + '</code>';
          }
          var insufficient = (est.k_estimate == null) ||
            (String(est.concern) === 'insufficient_data');
          var leadTxt, kTxt;
          if (insufficient){
            leadTxt = 'k could not be estimated &mdash; insufficient data (NOT a low-risk finding).';
            kTxt = '';
          } else {
            leadTxt = 'Worst-case (prosecutor) risk: ' + esc(fmtRisk(est.prosecutor_risk) || '—');
            kTxt = '<div class="re-k"><b>k-estimate:</b> ' + esc(fmtK(est.k_estimate) || '—') +
              ' &mdash; an OPTIMISTIC lower bound, never &ldquo;safe to send.&rdquo;</div>';
          }
          html += '<div class="rel-entity">' +
            '<div class="re-head">' +
              '<span class="re-name">' + esc(name) + '</span>' +
              '<span class="chip concern-' + concernClass(est.concern) + '">' +
                esc(concernLabel(est.concern)) + '</span>' +
              '<span class="re-docs">in ' + (docHtml || '<code>—</code>') + '</span>' +
            '</div>' +
            '<div class="re-lead">' + leadTxt + '</div>' +
            kTxt +
            '<div class="est-coverage">' + esc(String(est.coverage_note || '')) + '</div>' +
          '</div>';
        }
        entitiesEl.innerHTML = html;
      }
    }

    if (caveatEl){ caveatEl.innerHTML = esc(String(r.linkage_caveat || '')); }
    announce('release k estimate ready');
  }

  // ---- error surface -----------------------------------------------------------
  function showError(id, raw){
    var el = $(id);
    if (!el) return;
    // CONFIDENTIALITY (#16): a failed re-score must not leave the PRIOR doc's QI
    // cleartext on screen (or in the hidden DOM, devtools-recoverable). Mirror the
    // success cross-clear: hide both result cards and EMPTY every cleartext-bearing
    // list before showing the error banner. (esc() still guards the message itself.)
    var estCardEl = $('estCard');
    if (estCardEl && estCardEl.classList) estCardEl.classList.add('hidden');
    var relCardEl = $('relCard');
    if (relCardEl && relCardEl.classList) relCardEl.classList.add('hidden');
    var estContribsEl = $('estContribs');
    if (estContribsEl) estContribsEl.innerHTML = '';
    var estMedicalEl = $('estMedical');
    if (estMedicalEl) estMedicalEl.innerHTML = '';
    var relEntitiesEl = $('relEntities');
    if (relEntitiesEl) relEntitiesEl.innerHTML = '';
    el.innerHTML = '<div class="banner error" style="margin-top:14px">' +
      '<span class="ic" aria-hidden="true">&#9888;</span>' +
      '<div class="body"><b>The estimate could not run.</b>' +
      '<p>' + esc(String(raw || 'Something went wrong. Nothing left this computer.')) + '</p></div></div>';
  }
  function clearError(id){ var el = $(id); if (el) el.innerHTML = ''; }

  // ---- file -> base64 (strip the data:...;base64, prefix) ----------------------
  function fileToB64(file){
    return new Promise(function(resolve, reject){
      var rd = new FileReader();
      rd.onload = function(){
        var res = String(rd.result || '');
        var comma = res.indexOf(',');
        resolve(comma >= 0 ? res.slice(comma + 1) : res);
      };
      rd.onerror = function(){ reject(new Error('could not read the file')); };
      try { rd.readAsDataURL(file); } catch(e){ reject(e); }
    });
  }

  // ============================================================================
  // WIRING (the real page; the harness only drives the renderers above)
  // ============================================================================
  function wire(){
    var scoreText = $('scoreText'), scoreFile = $('scoreFile'), scoreFileNote = $('scoreFileNote');
    var scoreBtn = $('scoreBtn');
    var pendingScoreFile = null;

    // Clear the staged upload (and its note + the file input) so a stale file can't be
    // re-scored after the user switches to the paste box. Used both when the paste box gets
    // input and after a successful score (so the next click re-reads the CURRENT input). (#2)
    function clearPendingFile(){
      pendingScoreFile = null;
      if (scoreFile) { try { scoreFile.value = ''; } catch(e){ /* ignore */ } }
      if (scoreFileNote) scoreFileNote.textContent = '';
    }

    if (scoreFile){
      scoreFile.addEventListener('change', function(){
        pendingScoreFile = (scoreFile.files && scoreFile.files[0]) || null;
        if (scoreFileNote){
          scoreFileNote.textContent = pendingScoreFile ? ('Selected: ' + pendingScoreFile.name) : '';
        }
      });
    }
    // When the user types into the paste box, DROP any staged file — otherwise the file silently
    // wins (the score path checks pendingScoreFile first) and the just-typed text is ignored,
    // re-scoring the OLD file. Clearing it makes the visible input the one that gets scored. (#2)
    if (scoreText){
      scoreText.addEventListener('input', function(){
        if (pendingScoreFile && scoreText.value && scoreText.value.length){
          clearPendingFile();
        }
      });
    }

    if (scoreBtn){
      scoreBtn.addEventListener('click', async function(){
        clearError('scoreError');
        var body = null;
        if (pendingScoreFile){
          try {
            var b64 = await fileToB64(pendingScoreFile);
            body = {filename: pendingScoreFile.name, data_b64: b64};
          } catch(e){ showError('scoreError', 'could not read the selected file'); return; }
        } else {
          var t = scoreText ? scoreText.value : '';
          if (!t || !t.trim()){ showError('scoreError', 'Paste some text or choose a file first.'); return; }
          body = {text: t};
        }
        var r = await post('/api/reidrisk/score', body);
        if (!r.ok || (r.data && r.data.error)){
          showError('scoreError', (r.data && r.data.error) || ('request failed (' + r.status + ')'));
          return;
        }
        // Clear the staged file AFTER a score so the next click re-reads the CURRENT input
        // (a paste edit, or a freshly chosen file) instead of silently re-scoring this one. (#2)
        clearPendingFile();
        renderEstimate(r.data);
      });
    }

    // ---- batch ----
    var batchDocs = $('batchDocs'), addTextBtn = $('addTextBtn'), batchFile = $('batchFile');
    var batchBtn = $('batchBtn'), batchCountHint = $('batchCountHint'), linkTerms = $('linkTerms');
    var items = [];   // {kind:'text', el} | {kind:'file', file, name}
    var seq = 0;

    function refreshCount(){
      if (batchCountHint){
        batchCountHint.textContent = items.length
          ? (items.length + ' document' + (items.length === 1 ? '' : 's') + ' added.')
          : 'No documents added yet.';
      }
    }
    function removeItem(id){
      items = items.filter(function(it){ return it.id !== id; });
      var node = $('batchItem-' + id);
      if (node && node.parentNode && node.parentNode.removeChild) node.parentNode.removeChild(node);
      refreshCount();
    }
    function addTextItem(){
      var id = ++seq;
      var wrap = document.createElement('div');
      wrap.className = 'batch-doc';
      wrap.id = 'batchItem-' + id;
      wrap.innerHTML = '<div class="bd-head"><span class="bd-name">Text block ' + id + '</span>' +
        '<button type="button" class="bd-remove" data-rm="' + id + '">Remove</button></div>' +
        '<textarea spellcheck="false" placeholder="Paste a document here&hellip;"></textarea>';
      if (batchDocs && batchDocs.appendChild) batchDocs.appendChild(wrap);
      var ta = wrap.querySelector ? wrap.querySelector('textarea') : null;
      var rm = wrap.querySelector ? wrap.querySelector('[data-rm]') : null;
      if (rm && rm.addEventListener) rm.addEventListener('click', function(){ removeItem(id); });
      items.push({id:id, kind:'text', name:'Text block ' + id, el:ta});
      refreshCount();
    }
    function addFileItem(file){
      var id = ++seq;
      var wrap = document.createElement('div');
      wrap.className = 'batch-doc';
      wrap.id = 'batchItem-' + id;
      wrap.innerHTML = '<div class="bd-head"><span class="bd-name">' + esc(file.name) + '</span>' +
        '<button type="button" class="bd-remove" data-rm="' + id + '">Remove</button></div>' +
        '<div class="bd-file">file &mdash; text extracted on estimate</div>';
      if (batchDocs && batchDocs.appendChild) batchDocs.appendChild(wrap);
      var rm = wrap.querySelector ? wrap.querySelector('[data-rm]') : null;
      if (rm && rm.addEventListener) rm.addEventListener('click', function(){ removeItem(id); });
      items.push({id:id, kind:'file', name:file.name, file:file});
      refreshCount();
    }

    if (addTextBtn) addTextBtn.addEventListener('click', addTextItem);
    if (batchFile){
      batchFile.addEventListener('change', function(){
        var fs = batchFile.files || [];
        for (var i = 0; i < fs.length; i++) addFileItem(fs[i]);
        batchFile.value = '';
      });
    }

    if (batchBtn){
      batchBtn.addEventListener('click', async function(){
        clearError('batchError');
        if (!items.length){ showError('batchError', 'Add at least one text block or file first.'); return; }
        var docs = [];
        for (var i = 0; i < items.length; i++){
          var it = items[i];
          if (it.kind === 'text'){
            docs.push({name: it.name, text: (it.el ? it.el.value : '') || ''});
          } else {
            try {
              var b64 = await fileToB64(it.file);
              docs.push({name: it.name, filename: it.name, data_b64: b64});
            } catch(e){ showError('batchError', 'could not read ' + it.name); return; }
          }
        }
        var terms = [];
        if (linkTerms && linkTerms.value){
          terms = linkTerms.value.split(',').map(function(x){ return x.trim(); })
            .filter(function(x){ return x.length > 0; });
        }
        var r = await post('/api/reidrisk/batch', {docs: docs, link_terms: terms});
        if (!r.ok || (r.data && r.data.error)){
          showError('batchError', (r.data && r.data.error) || ('request failed (' + r.status + ')'));
          return;
        }
        renderRelease(r.data);
      });
    }
  }

  if (document.getElementById && document.getElementById('scoreBtn')){
    wire();
  }

  if (document.body && document.body.getAttribute('data-demo') === '1' && $('scoreText') && !$('scoreText').value) {
    LB.get('/api/demo/sample').then(function(r){
      if (r.ok && r.data && r.data.directors && $('scoreText') && !$('scoreText').value) {
        $('scoreText').value = r.data.directors;
      }
    }).catch(function(){});
  }

  // ---- test seam (drives tests/reidrisk_render.test.js) ----
  window.__reidriskInternals = {
    esc: esc,
    renderEstimate: renderEstimate,
    renderRelease: renderRelease,
    concernClass: concernClass,
    showError: showError
  };
})();
