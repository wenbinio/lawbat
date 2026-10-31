/*
  Lawbat — Redaction reviewer (host shell JS). Trusted first-party (not a sandboxed
  module). Drives the deterministic Rust engine over /api/redaction/{scan,scan-file,
  pdf-scan,apply,pdf-apply,pdf-ocr-*} and surfaces app/privilege.py's sensitive passages.

  STAGED flow: Document -> Detection -> Review -> Sensitive passages -> Export, with a
  persistent stepper that GATES Export until Review's uncertain items are addressed AND the
  sensitive passages are acknowledged. Real backend wiring throughout — no mock theater.

  Confidentiality: candidate values + context + the legend are CLEARTEXT matter data. They
  are escaped via esc() before any innerHTML, shown only in this local window, and never
  sent anywhere but the local backend (which pipes them to the local bin). The text and the
  re-identification legend are not persisted. Matter terms are session-only; stored settings
  contain only allowlisted non-sensitive preferences.

  CONCATENATION FRAGMENT 1 of 11 (app/ui/redaction.core.js): this file was split at its own
  "---- section ----" comment boundaries into 11 ordered fragments forming ONE outer IIFE —
  see app/ui_manifest.py (REDACTION_JS_PARTS) for the full list + order, and each other
  fragment's own header comment.
*/
(function(){
  'use strict';

  // esc / $ / post / get / announce now live in the SHARED app/ui/base.js (window.LB,
  // inlined into this page via the __BASE_JS__ marker BEFORE this script) — aliased here
  // so the rest of this file (and its split parts, listed in app/ui_manifest.py) is
  // otherwise UNCHANGED. See base.js for the implementations (identical behavior: esc()
  // covers & < > " ' `; post()/get() carry the per-session X-DRR-Token header and resolve
  // {ok, status, data}).
  var esc = LB.esc, $ = LB.$, post = LB.post, get = LB.get, announce = LB.announce;

  // ---- helpers ----
  // UTF-8 BYTE length of a string. The TERM length cap is measured in BYTES (matching the
  // Python bridge + the Rust bin — `MAX_TERM_BYTES`), NOT UTF-16 `.length`: a CJK / accented
  // party name can be short in UTF-16 code units yet exceed the byte cap, so a `.length`
  // pre-check would let it through here only to be dropped downstream = a silent un-redaction.
  // TextEncoder is available in every WebView2 build; the fallback (encodeURIComponent byte
  // count) keeps the page working air-gapped if it is ever absent.
  function byteLen(s){
    s = String(s == null ? '' : s);
    try {
      if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s).length;
    } catch(e){ /* fall through */ }
    try { return unescape(encodeURIComponent(s)).length; } catch(e){ return s.length; }
  }

  // ---- DOM ----
  var input = $('input'), scanBtn = $('scanBtn'), scanHint = $('scanHint');
  var review = $('review'), summary = $('summary');
  var tier1 = $('tier1'), tier2 = $('tier2'), t1count = $('t1count'), t2count = $('t2count');
  var applyBtn = $('applyBtn'), applyHint = $('applyHint'), ocrBtn = $('ocrBtn');
  var outwrap = $('outwrap'), output = $('output'), applySummary = $('applySummary'), copyBtn = $('copyBtn');
  var outHead = $('outHead'), engineNote = $('engineNote'), fileInput = $('file'), fileNote = $('fileNote');
  var scanning = $('scanning'), scanningTitle = $('scanningTitle'), pasteHint = $('pasteHint');
  var engineChip = $('engineChip'), footDot = $('footDot'), footState = $('footState');
  var dropzone = $('dropzone');
  // per-span IMAGE review (scanned PDFs)
  var imgreview = $('imgreview'), imgPages = $('imgPages'), imgSummary = $('imgSummary');
  var imgApplyBtn = $('imgApplyBtn'), imgApplyHint = $('imgApplyHint');
  // Confidentiality / sensitive-content review (SURFACE-ONLY passage highlights)
  var passwrap = $('passwrap'), passages = $('passages'), passcount = $('passcount');
  var passToggle = $('passToggle');
  // Phase 2: on-page VISUAL PDF preview (display-only). pdfPreview holds the rendered
  // page images + highlight boxes; the boxes cross-reference the findings list by the
  // candidate's cands index (a box's data-idx).
  var pdfPreview = $('pdfPreview');

  var engineDown = false;

  // ---- friendly error copy (client-side mapping) --------------------------------
  function friendlyError(raw){
    var s = String(raw == null ? '' : raw).toLowerCase();
    function has(){ for (var i=0;i<arguments.length;i++){ if (s.indexOf(arguments[i]) >= 0) return true; } return false; }
    if (has('export blocked:'))
      return {title:'Export blocked.',
        body:'Lawbat could not confirm that all requested redactions were removed. No new copy was saved. ' +
          'Return to Review and resolve the affected items before exporting again.'};
    if (has('not installed','not be started','could not be located','unavailable','not found','unreadable response','unexpected response'))
      // engineOffline:true — this class means the ENGINE itself is unusable (not a per-file
      // input error), so the caller flips the "Tool ready" chip to offline. The other
      // branches are input-level problems (the engine ran fine and rejected THIS input), so
      // they leave engineOffline falsy and the chip stays honest-green.
      return {engineOffline:true, title:'The redaction tool isn’t available right now.',
        body:'Lawbat couldn’t find the part that searches for identifiers, so scanning is paused. ' +
          'Your files are untouched and nothing has left this computer. Try restarting Lawbat — if it ' +
          'keeps happening, your IT contact may need to reinstall it.'};
    if (has('too large','exceeds','too big'))
      return {title:'That file is a bit too big.',
        body:'Lawbat can redact files up to about 10 MB here. For a larger file, open it, copy the text, and ' +
          'paste it into the box above instead.'};
    if (has('open in another','open somewhere','open elsewhere','being used','locked','permission denied','access is denied','sharing violation'))
      return {title:'That file is open somewhere else.',
        body:'Lawbat couldn’t read the file because it’s open in another program (often Word or Acrobat). ' +
          'Close it there and try again.'};
    if (has('password','encrypted','protected'))
      return {title:'That PDF is password-protected.',
        body:'Lawbat can’t open a password-protected or encrypted PDF. Open it in your PDF reader, save an ' +
          'unprotected copy, and try that copy instead.'};
    if (has('unsupported','cannot read that file','could not extract','not a supported','unknown format','bad extension'))
      return {title:'Lawbat can’t read that kind of file.',
        body:'We can read PDF, Word (.docx), and plain-text files (.txt, .csv, .eml, .msg, .md). If your file is ' +
          'one of those but still won’t open, try copying its text and pasting it above.'};
    if (has('empty','no text','corrupt','damaged','malformed','unreadable pdf','invalid file','invalid pdf'))
      return {title:'That file looks empty or damaged.',
        body:'Lawbat couldn’t find any readable text in it. Make sure it opens normally in its usual program, ' +
          'or copy the text and paste it above.'};
    if (has('could not save','save the redacted'))
      return {title:'Couldn’t save the redacted copy.',
        body:'Lawbat read the file but couldn’t save the redacted version. Make sure there’s room on the ' +
          'disk and that the exports folder isn’t open in another program, then try again. Your original is unchanged.'};
    return {title:'Something went wrong with that scan.',
      body:'Nothing was changed and nothing left this computer. Try again — if it keeps happening, the file may ' +
        'be unusual; try copying its text and pasting it above instead.'};
  }

  // ---- detection options (OPT-IN packs) ----
  var OPTS_KEY = 'lawbat.redaction.opts';
  var ALLOWED_LOCALES = {sg:1, us:1, uk:1, au:1, ca:1};
  var ALLOWED_PROFILES = {'pci-dss-cardholder':1};
  var ALLOWED_BUILTINS = {email:1, phone:1, id:1, name:1, 'credit-card':1, iban:1, ip:1, url:1, address:1, bic:1, isin:1};
  var MAX_TERMS = 1000;
  // Per-term cap in UTF-8 BYTES (matches the Python bridge + Rust bin `MAX_TERM_BYTES`).
  var MAX_TERM_BYTES = 200;

  function parseTerms(raw){
    var out = [], seen = {};
    String(raw == null ? '' : raw).split(/\r?\n/).forEach(function(line){
      var t = line.trim();
      // Byte cap (not UTF-16 .length) so the browser pre-check agrees with the bin: a term
      // that survives here survives there, and one dropped here would have been dropped there.
      if (!t || byteLen(t) > MAX_TERM_BYTES) return;
      if (seen[t]) return;
      seen[t] = 1;
      if (out.length < MAX_TERMS) out.push(t);
    });
    return out;
  }

  // CLIENT-side WARN-ON-DROP (leak class): the browser pre-filters over-byte terms in
  // parseTerms BEFORE they are sent, so the SERVER's term_drop_report never sees them — the
  // warning MUST be computed here from the textarea, else an over-long "name to redact" is
  // dropped SILENTLY and never redacted. Returns the server `terms_dropped` shape (count +
  // the non-blank over-byte terms, deduped, listing bounded) so renderTermDrops stays the
  // single renderer.
  function clientTermDropReport(){
    var box = $('termsBox');
    var dropped = [], seen = {};
    if (box){
      String(box.value == null ? '' : box.value).split(/\r?\n/).forEach(function(line){
        var t = line.trim();
        if (!t || byteLen(t) <= MAX_TERM_BYTES) return;   // blank or within-cap: not a drop
        if (seen[t]) return;
        seen[t] = 1;
        if (dropped.length < MAX_TERMS) dropped.push(t);
      });
    }
    return {count: dropped.length, terms: dropped};
  }

  // Surface the CLIENT-computed drop report on the page. Call on EVERY scan path — success AND
  // engine-error — so an over-long term is never dropped without the lawyer being told.
  function warnTermDrops(){ renderTermDrops({terms_dropped: clientTermDropReport()}); }

  // ---- FEATURE 2: "Keep (never redact)" list ------------------------------------
  // Parsed like TERMS (byte cap, dedup) but NEVER sent to the engine — it drives ONLY the
  // review-layer auto-dismiss (candIsKept below) and is POSTED to the export routes so the
  // server EXCLUDES kept values from Feature 1's everywhere-expansion. Cleartext (a party
  // name): esc()'d before any display, never logged, never egressed.
  function parseKeep(){ return $('keepBox') ? parseTerms($('keepBox').value) : []; }
  // Whitespace-insensitive + lowercased normal form for value-matching (mirrors the server's
  // _norm_value: drop ALL whitespace + casefold) so a kept value matches a candidate that was
  // re-wrapped across spaces/newlines or re-cased.
  function normValue(s){ return String(s == null ? '' : s).replace(/\s+/g, '').toLowerCase(); }
  var _keepNorms = null;
  function keepNorms(){
    if (_keepNorms) return _keepNorms;
    var m = {};
    parseKeep().forEach(function(t){ var n = normValue(t); if (n) m[n] = 1; });
    _keepNorms = m;
    return m;
  }
  function refreshKeepNorms(){ _keepNorms = null; keepNorms(); updateKeepSummary(); }
  // A candidate whose VALUE ws-normalizes to a keep-list entry: it is SHOWN (never suppressed
  // from detection) but auto-dismissed + marked "kept" in Review, and excluded from accept-all
  // and from Feature 1's expansion.
  function candIsKept(c){ return !!(c && keepNorms()[normValue(c && c.value)]); }
  function updateKeepSummary(){
    var el = $('keepSummary');
    if (!el) return;
    var n = parseKeep().length;
    el.textContent = n
      ? (n + ' value' + (n === 1 ? '' : 's') + ' will be kept (shown in Review, left in the document).')
      : 'No keep list — everything found can be redacted.';
  }

  function readOptions(){
    var locales = [], profiles = [], disable = [];
    document.querySelectorAll('input.loc:checked').forEach(function(b){
      if (ALLOWED_LOCALES[b.value]) locales.push(b.value);
    });
    document.querySelectorAll('input.prof:checked').forEach(function(b){
      if (ALLOWED_PROFILES[b.value]) profiles.push(b.value);
    });
    document.querySelectorAll('input.bi').forEach(function(b){
      if (ALLOWED_BUILTINS[b.value] && !b.checked) disable.push(b.value);
    });
    var ctx = !!($('ctxToggle') && $('ctxToggle').checked);
    var lei = !!($('leiToggle') && $('leiToggle').checked);
    var sgLoose = !!($('sgNricLooseToggle') && $('sgNricLooseToggle').checked);
    var org = !!($('orgToggle') && $('orgToggle').checked);
    var addrFull = !!($('addrFullToggle') && $('addrFullToggle').checked);
    var terms = $('termsBox') ? parseTerms($('termsBox').value) : [];
    var o = {};
    if (locales.length) o.locales = locales;
    if (profiles.length) o.profiles = profiles;
    if (ctx) o.context = true;
    if (lei) o.lei = true;
    if (sgLoose) o.sg_nric_loose = true;
    if (org) o.organisations = true;
    if (addrFull) o.addresses_full = true;
    if (disable.length) o.disable_builtins = disable;
    if (terms.length) o.terms = terms;
    return o;
  }

  // Persist preferences, NEVER the request object: it contains cleartext party names.
  // Rebuild from a typed allowlist so future matter-specific fields cannot leak by default.
  function preferenceOptions(raw){
    var out = {};
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
    function own(obj, key){ return Object.prototype.hasOwnProperty.call(obj, key); }
    function allowedList(key, allowed){
      var values = own(raw, key) ? raw[key] : null, kept = [];
      if (!Array.isArray(values)) return;
      values.forEach(function(v){
        if (typeof v === 'string' && own(allowed, v) && kept.indexOf(v) < 0) kept.push(v);
      });
      if (kept.length) out[key] = kept;
    }
    allowedList('locales', ALLOWED_LOCALES);
    allowedList('profiles', ALLOWED_PROFILES);
    allowedList('disable_builtins', ALLOWED_BUILTINS);
    ['context', 'lei', 'sg_nric_loose', 'organisations', 'addresses_full'].forEach(function(key){
      if (own(raw, key) && raw[key] === true) out[key] = true;
    });
    return out;
  }

  function persistPreferences(options){
    try {
      localStorage.setItem(OPTS_KEY, JSON.stringify(preferenceOptions(options)));
      return true;
    } catch(e){
      // A failed rewrite must not leave an older, sensitive value behind when removal works.
      try { localStorage.removeItem(OPTS_KEY); return true; } catch(ignored){ return false; }
    }
  }

  function saveOptions(){
    var o = readOptions();
    var storageCleared = persistPreferences(o);
    var parts = [];
    if (o.locales) parts.push(o.locales.length + ' jurisdiction' + (o.locales.length === 1 ? '' : 's'));
    if (o.context) parts.push('context');
    if (o.lei) parts.push('LEI');
    if (o.sg_nric_loose) parts.push('SG NRIC net');
    if (o.organisations) parts.push('organisations');
    if (o.addresses_full) parts.push('full addresses');
    if (o.profiles) parts.push('PCI');
    if (o.disable_builtins) parts.push(o.disable_builtins.length + ' recognizer' +
      (o.disable_builtins.length === 1 ? '' : 's') + ' off');
    if (o.terms) parts.push(o.terms.length + ' name' + (o.terms.length === 1 ? '' : 's'));
    if (!storageCleared) parts.push('WARNING: saved settings could not be cleared');
    var sum = $('optsSummary');
    if (sum) sum.textContent = parts.length ? '— ' + parts.join(', ') : '— built-ins only';
    var tsum = $('termsSummary');
    if (tsum) {
      var n = o.terms ? o.terms.length : 0;
      tsum.textContent = n ? (n + ' name' + (n === 1 ? '' : 's') + ' will be redacted literally.')
                           : 'No names added.';
    }
  }

  function restoreOptions(){
    // Migrate the old key in place. Remove it BEFORE parsing; restore only typed,
    // non-sensitive preferences. Stored terms must never reach the DOM or a new scan.
    var raw = null, saved = {};
    try { raw = localStorage.getItem(OPTS_KEY); } catch(e){ /* storage unavailable */ }
    try { localStorage.removeItem(OPTS_KEY); } catch(e){ /* safe rewrite attempted below */ }
    try { saved = preferenceOptions(JSON.parse(raw || '{}')); } catch(e){ saved = {}; }
    raw = null;
    var locs = {}; (saved.locales || []).forEach(function(v){ if (ALLOWED_LOCALES[v]) locs[v] = 1; });
    document.querySelectorAll('input.loc').forEach(function(b){ b.checked = !!locs[b.value]; });
    var profs = {}; (saved.profiles || []).forEach(function(v){ if (ALLOWED_PROFILES[v]) profs[v] = 1; });
    document.querySelectorAll('input.prof').forEach(function(b){ b.checked = !!profs[b.value]; });
    var dis = {}; (saved.disable_builtins || []).forEach(function(v){ if (ALLOWED_BUILTINS[v]) dis[v] = 1; });
    document.querySelectorAll('input.bi').forEach(function(b){ b.checked = !dis[b.value]; });
    if ($('ctxToggle')) $('ctxToggle').checked = saved.context === true;
    if ($('leiToggle')) $('leiToggle').checked = saved.lei === true;
    if ($('sgNricLooseToggle')) $('sgNricLooseToggle').checked = saved.sg_nric_loose === true;
    if ($('orgToggle')) $('orgToggle').checked = saved.organisations === true;
    if ($('addrFullToggle')) $('addrFullToggle').checked = saved.addresses_full === true;
    if ($('termsBox')) $('termsBox').value = '';
    saveOptions();
  }

  // ---- quick group selectors ("All" / "Default") on the detection-options groups -------
  // Two togglable GROUPS get a compact "All" + "Default" pair on their fieldset header:
  //   loc — the jurisdiction multiselect (input.loc: SG/US/UK/AU/CA).
  //   bi  — the per-recognizer type toggles (input.bi) PLUS the closely-related opt-in
  //         detection toggles that live in their own <fieldset>s only for explanatory copy:
  //         context (#ctxToggle), LEI (#leiToggle) and the PCI compliance profile
  //         (input.prof). "All" on this group deliberately reaches ALL of them — an
  //         explicit "All" click is explicit consent, and more detection is always the
  //         recall-safe direction, so an opt-in like LEI is not quietly left out.
  //         (input.prof currently has exactly one box: pci-dss-cardholder.)
  //   The Aggressive SG NRIC net (#sgNricLooseToggle) is OUT of scope on purpose: it is an
  //   advisory-only, higher-false-positive net the user must deliberately switch on for
  //   itself, not a plain "more detection" recognizer toggle these buttons bulk-set.
  //
  // DELIBERATELY NO "None" button anywhere here (do not add one): a one-click
  // deselect-everything is the MISS direction. An empty detection selection does not fail
  // or warn — it "succeeds" quietly, scanning to a clean-looking document with nothing
  // flagged, so a reviewer who trusts that report never learns detection was switched off.
  // "All" only ever ADDS detection (always the safe side of a miss-vs-overflag tradeoff);
  // there must be no equally-easy one-click way to blindly remove it.
  var GROUP_BOXES = {
    loc: function(){ return toArray(document.querySelectorAll('input.loc')); },
    bi: function(){
      var els = toArray(document.querySelectorAll('input.bi'));
      if ($('ctxToggle')) els.push($('ctxToggle'));
      if ($('leiToggle')) els.push($('leiToggle'));
      return els.concat(toArray(document.querySelectorAll('input.prof')));
    }
  };
  function toArray(nodeList){ return Array.prototype.slice.call(nodeList || []); }

  // Captured ONCE, at init (see the wiring call in redaction.stepper.js), AFTER
  // restoreOptions() has applied any localStorage-persisted settings — so "Default" always
  // restores what was actually on screen when this page loaded (a returning user's own
  // saved choices, or the plain HTML defaults on a first run), never a hardcoded guess.
  var groupInitial = {};
  function captureGroupDefault(key){
    var boxes = GROUP_BOXES[key] ? GROUP_BOXES[key]() : [];
    groupInitial[key] = boxes.map(function(el){ return {el: el, checked: !!el.checked}; });
  }

  // "All" / "Default" both just set .checked on every box in the group, then call
  // saveOptions() ONCE — the SAME shared handler every one of these boxes' own 'change'
  // listener already runs (see the wiring in redaction.stepper.js: `b.addEventListener(
  // 'change', saveOptions)`), so persistence (localStorage) and the on-page summary line
  // end up exactly as if the reviewer had clicked each box by hand.
  function selectAllGroup(key){
    (GROUP_BOXES[key] ? GROUP_BOXES[key]() : []).forEach(function(el){ el.checked = true; });
    saveOptions();
  }
  function restoreGroupDefault(key){
    (groupInitial[key] || []).forEach(function(snap){ snap.el.checked = snap.checked; });
    saveOptions();
  }

