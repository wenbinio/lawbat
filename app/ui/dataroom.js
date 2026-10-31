/*
  Data-room (search + Tools) renderer — the TRUSTED HOST shell (not a sandboxed
  module, so host JS is fine here). Drives the first-run -> indexing -> search
  states client-side against the JSON API, plus the Tools panel (read-only
  document index + reversible batch rename). Every server-derived string is
  escaped via esc() before it touches innerHTML. No external resources are
  fetched. Inlined into dataroom.html at startup so the page is one air-gapped
  document.

  Normalized onto the shared function+var+IIFE idiom (app/ui/base.js's window.LB) the
  other three pages already use. The rendered page relies on inline onclick="..." handlers
  (e.g. onclick="startIndex()") that the browser looks up as GLOBAL functions at click
  time, so every function an onclick references is explicitly exposed on window at the
  bottom of this file — everything else here is closure-local to the IIFE.
*/
(function(){
  'use strict';

  // esc() (byte-identical escaping: & < > " ' `; C2) and get()/post() (the token-carrying
  // fetch wrappers) now live in the SHARED app/ui/base.js (window.LB, inlined into this page
  // via the __BASE_JS__ marker BEFORE this script) — aliased here so the rest of this file
  // is otherwise UNCHANGED. See base.js for the implementations.
  var esc = LB.esc;

  // $(h): build a DOM element from an HTML string — a DIFFERENT helper from LB.$
  // (getElementById); this file never needed getElementById-by-id shorthand (it calls
  // document.getElementById directly throughout), so the name is kept local/unaliased on
  // purpose — it shadows LB.$ within this closure without colliding at runtime.
  function $(h){ var d = document.createElement('div'); d.innerHTML = h.trim(); return d.firstChild; }

  async function pickFolder(){
    // Native folder dialog lives in the desktop layer (pywebview). In a plain
    // browser (dev) there is no such API, so fall back to a prompt.
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_folder){
      return await window.pywebview.api.pick_folder();
    }
    return prompt("Folder path to index (dev fallback — the installed app shows a real dialog):");
  }

  async function pickFiles(){
    // Native multi-file dialog (desktop layer). Returns an array of paths, or null.
    // Dev fallback: a newline-separated prompt.
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_files){
      return await window.pywebview.api.pick_files();
    }
    var raw = prompt("File paths to add, one per line (dev fallback — the installed app shows a real dialog):");
    if (!raw) return null;
    return raw.split(/\r?\n/).map(function(s){ return s.trim(); }).filter(Boolean);
  }

  async function startIndex(){
    var folder = await pickFolder();
    if (!folder) return;
    var r = (await LB.post('/api/index', {folder: folder})).data;
    if (r.error){ alert('Could not index: ' + r.error); return; }
    render();
  }

  function ftsWarning(state){
    if (state.fts5) return '';
    return '<div class="warn">⚠ Full-text search engine (FTS5) is not available in this' +
      ' build. Search will not work until the bundled SQLite is fixed. (Developer note.)</div>';
  }

  async function render(){
    var state = (await LB.get('/api/state')).data;
    var app = document.getElementById('app');
    var job = state.job || {};

    if (job.status === 'running'){
      app.innerHTML = '';
      var pct = job.total ? Math.round(100 * job.done / job.total) : 0;
      app.appendChild($('<div class="center">' +
        '<h2>Indexing…</h2>' +
        '<p>' + job.done + ' / ' + job.total + ' files</p>' +
        '<div class="bar"><div style="width:' + pct + '%"></div></div>' +
        '<p class="note">' + esc(job.current || '') + '</p>' +
        '<button class="big" onclick="cancelIndex()">Cancel</button>' +
        '</div>'));
      setTimeout(render, 400);
      return;
    }

    if (!state.has_matter){
      app.innerHTML = '';
      var matters = '';
      if (state.matters && state.matters.length){
        // Defence in depth (C2): never inline a matter DB path into an onclick
        // attribute — even with esc() hardened, an index-based dispatch keeps the
        // path out of the markup entirely. Stash the list and reference by position,
        // exactly like the file-action buttons do with _rows / openRow(i).
        _matters = state.matters;
        matters = '<div class="matters"><p class="note">Or reopen a matter:</p>' +
          _matters.map(function(m, i){ return '<a onclick="openMatterRow(' + i + ')">' + esc(m.name) + '</a>'; }).join('') +
          '</div>';
      }
      app.appendChild($('<div class="center">' +
        ftsWarning(state) +
        '<h2>Lawbat</h2>' +
        '<p>Local-only search over an exported data room.<br>Nothing leaves this machine.</p>' +
        '<button class="big" onclick="startIndex()">Open data room folder…</button>' +
        matters +
        '<p class="note" style="margin-top:18px"><a href="/">← Home</a> ·' +
        ' <a onclick="showAbout()">About this app</a></p>' +
        '</div>'));
      return;
    }

    // search view
    var st = state.stats || {};
    app.innerHTML = '';
    app.appendChild($('<header>' +
      '<div class="brand"><div class="logo" aria-hidden="true">L</div>' +
      '<div><h1>Lawbat — ' + esc(state.matter_name) + '</h1>' +
      '<div class="stats">' +
      '<a onclick="showFiles(\'all\',\'All files\')">' + st.total + ' files</a> ·' +
      ' <a onclick="showFiles(\'searchable\',\'Searchable\')">' + st.ok + ' searchable</a> ·' +
      ' <a onclick="showFiles(\'needs_ocr\',\'Need OCR\')">' + (st.needs_ocr || 0) + ' need OCR</a> ·' +
      ' <a onclick="showFiles(\'duplicates\',\'Duplicates\')">' + (st.duplicates || 0) + ' duplicate</a> ·' +
      ' <a onclick="showFiles(\'errors\',\'Errors\')">' + st.errors + ' errors</a> · local only' +
      '</div></div></div>' +
      '<div>' +
      '<button onclick="location.href=\'/\'">Home</button>' +
      '<button onclick="reindexCurrent()">Re-index</button>' +
      '<button onclick="renderTools()">Tools</button>' +
      '<button onclick="closeMatter()">Open another folder</button>' +
      '<button onclick="showAbout()">About</button>' +
      '</div>' +
      '</header>'));
    var wrap = $('<div class="wrap">' +
      '<form onsubmit="event.preventDefault();doSearch()">' +
      '<input type="text" id="q" placeholder="Search the data room…" autofocus>' +
      '<button class="search" type="submit">Search</button>' +
      '</form>' +
      '<div class="syntax">FTS syntax: <code>change of control</code> ·' +
      ' <code>"material adverse"</code> (phrase) · <code>indemnif*</code> (prefix) ·' +
      ' <code>tax NOT property</code></div>' +
      '<div id="sourcesBar"></div>' +
      '<div id="results"></div>' +
      '</div>');
    app.appendChild(wrap);
    renderSources(state.sources || []);
    document.getElementById('q').focus();
  }

  // ---------------------------------------------------------------- Sources ---
  // Multi-source ingestion: the open matter can pull files/folders from OTHER
  // locations into its document schedule. Each added source extends the read-only
  // set the server-side confinement guards enforce (the rename tool refuses to
  // write inside ANY source). This bar lets the user add / see / remove them.
  var _sources = [];

  function renderSources(sources){
    _sources = sources || [];
    var bar = document.getElementById('sourcesBar');
    if (!bar) return;
    var list = _sources.map(function(s, i){
      var tag = s.primary ? ' <span class="loc">primary</span>'
                          : '<button class="mini" onclick="removeSource(' + i + ')">Remove</button>';
      var miss = (s.status === 'missing') ? ' <span class="loc" style="color:var(--crit)">missing</span>' : '';
      return '<div class="hit"><div class="snip">' + esc(s.display) + miss +
        '<span class="loc">' + esc(String(s.files || 0)) + ' file(s) · ' + esc(s.kind || '') + '</span>' + tag + '</div>' +
        '<div class="path">' + esc(s.root) + '</div></div>';
    }).join('');
    bar.innerHTML = '<fieldset style="border:1px solid var(--hair);border-radius:8px;padding:10px 14px;margin:8px 0">' +
      '<legend class="note">Sources <span class="note">(read-only)</span></legend>' +
      '<p class="note" style="margin-top:0">Files and folders from other locations,' +
      ' added into this matter’s document schedule. Everything stays read-only.</p>' +
      '<p><button class="mini" onclick="addSourceFolder()">Add folder…</button>' +
      ' <button class="mini" onclick="addSourceFiles()">Add files…</button></p>' +
      list +
      '</fieldset>';
  }

  async function refreshSources(){
    var st = (await LB.get('/api/state')).data;
    renderSources(st.sources || []);
  }

  async function addSourceFolder(){
    var folder = await pickFolder();
    if (!folder) return;
    var r = (await LB.post('/api/sources/add', {root: folder})).data;
    // warn-level root (whole drive / profile / network share): confirm, then retry.
    if (r.needs_confirm){
      if (!confirm((r.reason || 'This is a large/remote location.') + '\n\nAdd it anyway?')) return;
      r = (await LB.post('/api/sources/add', {root: folder, confirm: true})).data;
    }
    if (r.error){ alert('Could not add source: ' + r.error); return; }
    // The add now runs in the BACKGROUND (like the primary index): render() picks up
    // the running job and polls /api/state, showing the progress bar; when the job
    // finishes the search/stats/sources view reflects the newly-added files.
    render();
  }

  async function addSourceFiles(){
    var files = await pickFiles();
    if (!files || !files.length) return;
    var r = (await LB.post('/api/sources/add-files', {files: files})).data;
    if (r.error){ alert('Could not add files: ' + r.error); return; }
    // Background add (see addSourceFolder): render() shows the progress bar + polls.
    render();
  }

  async function removeSource(i){
    var s = _sources[i];
    if (!s || s.primary) return;
    if (!confirm('Remove this source from the matter?\n\n' + s.display +
                 '\n\nThis drops its entries from the index (the original files are not touched).')) return;
    var r = (await LB.post('/api/sources/remove', {id: s.id})).data;
    if (r.error){ alert('Could not remove source: ' + r.error); return; }
    render();
  }

  // Files referenced by the current result/list, so action buttons can index in
  // by position — avoids quoting Windows paths (backslashes) into onclick attrs.
  var _rows = [];
  // Matters offered on the first-run screen, referenced by index from onclick so a
  // DB path (which can contain ' or \ on Windows) never gets inlined into markup (C2).
  var _matters = [];
  var _openCautionAck = false;  // show the "Open hands off to the OS" caution once per session

  async function openByPath(path){
    if (!_openCautionAck){
      var ok = confirm(
        "“Open” launches this file in your computer’s default app (PDF viewer, Word, "
        + "or possibly a web browser).\n\nThat app is outside this tool — its "
        + "no-network guarantee does not extend to it. “Reveal in folder” is safer if "
        + "you only need to locate the file.\n\nOpen anyway?");
      if (!ok) return;
      _openCautionAck = true;
    }
    var r = (await LB.post('/api/file/open', {path: path})).data;
    if (r.error) alert('Could not open: ' + r.error);
  }
  async function revealByPath(path){
    var r = (await LB.post('/api/file/reveal', {path: path})).data;
    if (r.error) alert('Could not reveal: ' + r.error);
  }
  async function showAbout(){
    var a = (await LB.get('/api/about')).data;
    if (a.error){ alert('Could not load About info.'); return; }
    alert(
      "Lawbat  —  version " + a.version + "\n\n"
      + "Full-text search: " + (a.fts5 ? "available" : "UNAVAILABLE (SQLite build lacks FTS5)") + "\n"
      + "Python " + a.python + "  ·  " + a.platform + "\n\n"
      + "Your matter data is stored locally at:\n" + a.data_dir + "\n\n"
      + "If you need support, send this log file:\n" + a.log_file + "\n\n"
      + "Local only — nothing on this screen leaves your computer.");
  }
  function openRow(i){ openByPath(_rows[i].path); }
  function revealRow(i){ revealByPath(_rows[i].path); }

  async function reindexCurrent(){
    var st = (await LB.get('/api/state')).data;
    if (!st.source_root){
      alert('This matter was indexed by an older version without a recorded source folder.\n\nUse “Open another folder…” and pick the data room again to re-index.');
      return;
    }
    var r = (await LB.post('/api/index', {folder: st.source_root})).data;
    if (r.error){ alert('Could not re-index: ' + r.error); return; }
    render();
  }

  async function showFiles(category, title){
    var r = (await LB.get('/api/files?category=' + encodeURIComponent(category))).data;
    var box = document.getElementById('results');
    if (!box) return;
    if (r.error){ box.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    _rows = r.files || [];
    if (!_rows.length){ box.innerHTML = '<p class="count">' + esc(title) + ': none</p>'; return; }
    var ocrNote = (category === 'needs_ocr')
      ? '<div class="warn">These have no searchable text yet (scanned PDFs / images).' +
        ' Local OCR is a later increment — for now this is your OCR worklist; you can' +
        ' still open the originals.</div>' : '';
    box.innerHTML = '<p class="count">' + esc(title) + ': ' + r.count + ' file(s)</p>' + ocrNote + _rows.map(function(f, i){
      var err = f.extract_error ? '<div class="path">' + esc(f.extract_error) + '</div>' : '';
      return '<div class="hit">' +
        '<div class="hit-file">' + esc(f.filename) + '<span class="loc">' + esc(f.extract_status || '') + '</span></div>' +
        '<div class="path">' + esc(f.path) + '</div>' + err +
        '<div class="actions"><button class="mini primary" onclick="revealRow(' + i + ')">Reveal in folder</button>' +
        ' <button class="mini" onclick="openRow(' + i + ')">Open…</button></div>' +
        '</div>';
    }).join('');
  }

  async function doSearch(){
    var q = document.getElementById('q').value.trim();
    var box = document.getElementById('results');
    if (!q){ box.innerHTML = ''; return; }
    var r = (await LB.get('/api/search?q=' + encodeURIComponent(q))).data;
    if (r.error){ box.innerHTML = '<p class="note">Query error: ' + esc(r.error) + '</p>'; return; }
    var rows = r.results || [];
    if (!rows.length){ box.innerHTML = '<p class="note">No matches.</p>'; return; }
    _rows = rows;
    box.innerHTML = '<p class="count">' + rows.length + ' hit(s)</p>' + rows.map(function(row, i){
      // The server marks matches with PRIVATE-USE sentinels (U+E000/U+E001) instead of [[/]],
      // so literal '[[' or ']]' in the document text no longer turns into stray <mark> tags
      // (mis-highlight). esc() runs FIRST (XSS-safe), then the sentinels — which esc() leaves
      // untouched — become the highlight tags. Document content never contains these codepoints.
      var snip = esc(row.snip).replaceAll('\uE000', '<mark>').replaceAll('\uE001', '</mark>');
      return '<div class="hit">' +
        '<div class="hit-file">' + esc(row.filename) + '<span class="loc">' + esc(row.locator) + '</span></div>' +
        '<div class="snip">' + snip + '</div>' +
        '<div class="path">' + esc(row.path) + '</div>' +
        '<div class="actions"><button class="mini primary" onclick="revealRow(' + i + ')">Reveal in folder</button>' +
        ' <button class="mini" onclick="openRow(' + i + ')">Open…</button></div>' +
        '</div>';
    }).join('');
  }

  // ---------------------------------------------------------------- Tools ----
  var toolFolder = null;
  var lastManifest = null;
  // The plan token from the last Preview, binding Apply to the exact previewed set
  // (C3). Cleared whenever the inputs change so a stale token can't be applied.
  var lastPlanToken = null;

  async function renderTools(){
    var app = document.getElementById('app');
    app.innerHTML = '';
    app.appendChild($('<header>' +
      '<div class="brand"><div class="logo" aria-hidden="true">L</div>' +
      '<div><h1>Tools</h1>' +
      '<div class="stats">Document index (read-only) · batch rename (reversible) · local only</div></div></div>' +
      '<button onclick="render()">← Back to search</button>' +
      '</header>'));

    // --- Document index (Tier 1): read-only report over the open matter ---
    app.appendChild($('<div class="wrap" style="padding-bottom:0">' +
      '<fieldset style="border:1px solid var(--hair);border-radius:8px;padding:12px 16px;margin:0 0 8px">' +
      '<legend class="note">Document index</legend>' +
      '<p class="note" style="margin-top:0">A line-by-line schedule of every file in this matter —' +
      ' name, type, size, date, hash, duplicates, and whether it’s searchable or still needs OCR.' +
      ' Reads the index only; nothing on disk changes. Exports to Excel-friendly CSV.</p>' +
      '<p><button class="search" onclick="toolManifest()">Build index</button>' +
      ' <button class="mini" onclick="toolExportManifest()">Export to CSV…</button>' +
      ' <label style="margin-left:8px">Sort by' +
      ' <select id="manifestOrder" onchange="if(document.getElementById(\'manifestOut\').innerHTML.trim()) toolManifest()">' +
      '<option value="folder">folder</option>' +
      '<option value="name">name</option>' +
      '<option value="type">type</option>' +
      '<option value="date">date</option>' +
      '<option value="sequence">as listed</option>' +
      '</select></label></p>' +
      '<div id="manifestOut"></div>' +
      '</fieldset>' +
      '</div>'));

    app.appendChild($('<div class="wrap" style="padding-top:8px">' +
      '<div class="warn">The section below <b>changes files on disk</b>. It runs a' +
      ' preview first and writes an undo record before any change, so you can revert. Point it at' +
      ' your <b>working copy</b> of the data room, never the only original.</div>' +
      '<p><button class="search" onclick="toolPick()">Choose folder…</button>' +
      ' <span id="toolFolder" class="note"></span></p>' +
      '<fieldset style="border:1px solid var(--hair);border-radius:8px;padding:12px 16px;margin:12px 0">' +
      '<legend class="note">Naming norms</legend>' +
      '<label><input type="checkbox" id="r_collapse" checked> Collapse repeated spaces</label><br>' +
      '<label><input type="checkbox" id="r_lowext" checked> Lowercase extensions (.PDF → .pdf)</label><br>' +
      '<label><input type="checkbox" id="r_spaces"> Spaces → underscores</label><br>' +
      '<label><input type="checkbox" id="r_strip"> Strip special characters</label><br>' +
      '<label><input type="checkbox" id="r_lower"> Lowercase whole name</label><br>' +
      '<label><input type="checkbox" id="r_seq"> Number files (001_, 002_, …)</label><br>' +
      '<label>Prefix: <input type="text" id="r_prefix" style="width:200px" placeholder="e.g. ProjectX_"></label><br>' +
      '<label><input type="checkbox" id="r_recursive"> Include subfolders</label>' +
      '</fieldset>' +
      '<p><button class="search" onclick="toolPreview()">Preview</button>' +
      ' <button class="mini" onclick="toolApply()">Apply</button>' +
      ' <button class="mini" id="toolUndo" onclick="toolUndoLast()" disabled>Undo last run</button></p>' +
      '<div id="toolOut"></div>' +
      '</div>'));
    document.getElementById('toolFolder').textContent = toolFolder || 'no folder chosen';
    document.getElementById('toolUndo').disabled = !lastManifest;
  }

  function toolRules(){
    return {
      collapse_whitespace: document.getElementById('r_collapse').checked,
      lowercase_ext: document.getElementById('r_lowext').checked,
      spaces_to_underscores: document.getElementById('r_spaces').checked,
      strip_special: document.getElementById('r_strip').checked,
      lowercase_name: document.getElementById('r_lower').checked,
      sequence: document.getElementById('r_seq').checked,
      prefix: document.getElementById('r_prefix').value
    };
  }
  function toolRecursive(){ return document.getElementById('r_recursive').checked; }

  async function toolPick(){
    var f = await pickFolder();
    if (f){ toolFolder = f; document.getElementById('toolFolder').textContent = f; }
  }

  // ---- Document index (Tier 1, read-only) ----
  function manifestOrder(){
    var sel = document.getElementById('manifestOrder');
    return sel ? sel.value : 'folder';
  }

  async function toolManifest(){
    var out = document.getElementById('manifestOut');
    out.innerHTML = '<p class="note">Building…</p>';
    var r = (await LB.get('/api/tools/manifest?order=' + encodeURIComponent(manifestOrder()))).data;
    if (r.error){ out.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    var s = r.summary;
    var exts = Object.entries(s.by_ext).sort(function(a, b){ return b[1] - a[1]; })
                 .map(function(kv){ return esc(kv[0]) + ' ' + kv[1]; }).join(' · ');
    var head = '<p class="count">' + s.total_files + ' files · ' + s.total_size + ' ·' +
       ' ' + s.searchable + ' searchable · ' + s.need_ocr + ' need OCR · ' + s.no_text + ' no text ·' +
       ' ' + s.unsupported + ' unsupported · ' + s.errors + ' errors ·' +
       ' ' + s.duplicate_files + ' duplicate(s) in ' + s.duplicate_groups + ' group(s)</p>' +
       '<p class="syntax">By type: ' + exts + '</p>';
    var rows = r.rows.map(function(row){
      var ocr = row.content_status.includes('OCR');
      var tag = ocr ? ' style="color:var(--warn)"' : '';
      var dup = row.duplicate ? ' <span class="loc">duplicate</span>' : '';
      // pages is blank ("") for non-paginated / scanned files — never show 0.
      var pages = (row.pages === '' || row.pages === null || row.pages === undefined)
                      ? '' : String(row.pages);
      return '<tr>' +
        '<td class="loc">' + esc(String(row.no)) + '</td>' +
        '<td>' + esc(row.filename) + dup + '</td>' +
        '<td class="loc">' + esc(row.source || '') + '</td>' +
        '<td class="loc">' + esc(row.extension) + '</td>' +
        '<td' + tag + '>' + esc(row.content_status) + '</td>' +
        '<td class="loc">' + esc(pages) + '</td>' +
        '<td class="loc">' + esc(row.size) + '</td>' +
        '<td class="loc">' + esc(row.modified) + '</td></tr>';
    }).join('');
    out.innerHTML = head + '<table class="idx">' +
      '<thead><tr><th>No.</th><th>File</th><th>Source</th><th>Type</th><th>Content</th><th>Pages</th><th>Size</th><th>Modified</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' +
      (r.truncated ? '<p class="note">Showing first 1000 rows — export for the full list.</p>' : '');
  }

  async function toolExportManifest(){
    var out = document.getElementById('manifestOut');
    var r = (await LB.post('/api/tools/manifest/export?order=' + encodeURIComponent(manifestOrder()))).data;
    if (r.error){ out.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    out.innerHTML = '<p class="count">Saved ' + r.rows + ' rows to:</p>' +
      '<div class="hit"><div class="path">' + esc(r.path) + '</div></div>';
  }

  async function toolPreview(){
    if (!toolFolder){ alert('Choose a folder first.'); return; }
    lastPlanToken = null;  // invalidate any prior token until this preview returns
    var r = (await LB.post('/api/tools/rename/plan',
      {folder: toolFolder, recursive: toolRecursive(), rules: toolRules()})).data;
    var out = document.getElementById('toolOut');
    if (r.error){ out.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    lastPlanToken = r.plan_token || null;  // binds the next Apply to THIS plan (C3)
    var s = r.summary;
    var rows = r.items.filter(function(it){ return it.status !== 'unchanged'; }).map(function(it){
      var parts = it.src.split(/[\\/]/), a = parts[parts.length - 1];
      var parts2 = it.dst.split(/[\\/]/), b = parts2[parts2.length - 1];
      var tag = it.status === 'collision' ? ' <b style="color:var(--crit)">(collision — skipped)</b>' : '';
      return '<div class="hit"><div class="snip">' + esc(a) + ' → <b>' + esc(b) + '</b>' + tag + '</div></div>';
    }).join('');
    out.innerHTML = '<p class="count">' + s.rename + ' to rename · ' + s.unchanged + ' unchanged · ' +
      s.collision + ' collisions' + (r.truncated ? ' · (showing first 1000)' : '') + '</p>' + rows;
  }

  async function toolApply(){
    if (!toolFolder){ alert('Choose a folder first.'); return; }
    // C3: Apply runs ONLY the plan the user previewed. Require a fresh preview token.
    if (!lastPlanToken){ alert('Preview first — Apply runs exactly the previewed plan.'); return; }
    if (!confirm('Rename files in:\n' + toolFolder + '\n\nAn undo record is saved first. Proceed?')) return;
    var r = (await LB.post('/api/tools/rename/apply',
      {folder: toolFolder, recursive: toolRecursive(), rules: toolRules(), plan_token: lastPlanToken})).data;
    var out = document.getElementById('toolOut');
    // A stale token (folder changed since preview) comes back as an error: clear it so
    // the user must Preview again before another Apply.
    if (r.error){ lastPlanToken = null; out.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    lastPlanToken = null;  // single-use: a token applies once, then re-preview
    lastManifest = r.manifest;
    document.getElementById('toolUndo').disabled = false;
    out.innerHTML = '<p class="count">Renamed ' + r.renamed + ' file(s). ' + r.errors.length + ' error(s).</p>' +
      r.errors.map(function(e){ return '<div class="hit"><div class="snip">' + esc(e.src) + ' — ' + esc(e.error) + '</div></div>'; }).join('');
  }

  async function toolUndoLast(){
    if (!lastManifest) return;
    var r = (await LB.post('/api/tools/rename/undo', {manifest: lastManifest})).data;
    var out = document.getElementById('toolOut');
    if (r.error){ out.innerHTML = '<p class="note">' + esc(r.error) + '</p>'; return; }
    out.innerHTML = '<p class="count">Reverted ' + r.reverted + ' file(s). ' + r.errors.length + ' error(s).</p>';
    lastManifest = null; document.getElementById('toolUndo').disabled = true;
  }

  async function cancelIndex(){ await LB.post('/api/index/cancel'); }
  async function openMatter(db){ await LB.post('/api/open', {db: db}); render(); }
  function openMatterRow(i){ var m = _matters[i]; if (m) openMatter(m.db); }
  async function closeMatter(){ await LB.post('/api/close'); render(); }

  // The rendered page relies on inline onclick="..." handlers (see the file header note),
  // so every function one references must be a real GLOBAL, not just a closure-local.
  window.startIndex = startIndex;
  window.cancelIndex = cancelIndex;
  window.openMatterRow = openMatterRow;
  window.openRow = openRow;
  window.revealRow = revealRow;
  window.showAbout = showAbout;
  window.renderTools = renderTools;
  window.closeMatter = closeMatter;
  window.reindexCurrent = reindexCurrent;
  window.showFiles = showFiles;
  window.doSearch = doSearch;
  window.addSourceFolder = addSourceFolder;
  window.addSourceFiles = addSourceFiles;
  window.removeSource = removeSource;
  window.toolPick = toolPick;
  window.toolManifest = toolManifest;
  window.toolExportManifest = toolExportManifest;
  window.toolPreview = toolPreview;
  window.toolApply = toolApply;
  window.toolUndoLast = toolUndoLast;
  window.render = render;

  var boot = render();
  if (location.hash === '#tools' && boot && typeof boot.then === 'function') {
    boot.then(function(){ renderTools(); });
  }
})();
