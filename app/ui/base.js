/*
  Lawbat — shared trusted-HOST shell JS (base.js). This is NOT a sandboxed module — it is
  first-party shell code shared by all four served pages (Home / data-room / redaction /
  reid-risk), so a shared base.js is fine (the "no module JS" platform rule is about
  sandboxed third-party MODULES, not first-party shell code — see CLAUDE.md).

  Defines ONE namespace, window.LB, so each page's own script consumes it without adding
  new globals: LB.esc / LB.$ / LB.get / LB.post / LB.announce. Every page's `_build_*_page()`
  in app/web.py inlines this file FIRST (via the shared __BASE_JS__ marker, placed before
  the page's own JS marker in the same <script> block), so LB exists before any page script
  runs.

  esc(): escapes every character that can break out of an HTML element OR attribute
  context, including the single quote (') and backtick (`) — e.g. a matter/folder name like
  O'Brien would otherwise close an attribute string and inject markup (C2). Byte-identical
  to the esc() every page used to carry locally.

  get()/post(): fetch wrappers that attach the per-session X-DRR-Token header (minted by
  the server and embedded in this page's <meta name="drr-token">; a foreign origin can't
  read this page, so it can't forge the header) and resolve to {ok, status, data} — never
  throwing on a non-2xx or an unparsable body (data stays {} then). This is the SAME
  contract redaction.js/reidrisk.js already used; dataroom.js/home.js used a thinner
  raw-fetch `api()` and are migrated onto this one here.
*/
'use strict';

// Assigned explicitly onto window (rather than relying on a bare top-level `var LB`
// promoting itself onto the global object) so this also works when a harness loads this
// file via indirect eval() with its own 'use strict' — the strict-mode eval spec gives
// `var` its own throwaway variable environment, so an implicit global promotion would
// silently vanish the moment eval() returns. An explicit `window.LB =` assignment sets a
// real property on the (real, or test-shimmed) window object either way.
window.LB = (function(){

  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/`/g,'&#96;');
  }

  function $(id){ return document.getElementById(id); }

  // Per-session token minted by the server and embedded in this page; attached to every
  // request. A foreign origin can't read this page (same-origin policy), so it can't forge
  // the header.
  var TOKEN = (document.querySelector('meta[name="drr-token"]') || {}).content || '';

  async function _send(path, opts){
    opts = opts || {};
    opts.headers = Object.assign({}, opts.headers || {}, {'X-DRR-Token': TOKEN});
    var res = await fetch(path, opts);
    var data = {};
    try { data = await res.json(); } catch(e){ /* leave {} */ }
    return {ok: res.ok, status: res.status, data: data};
  }

  async function get(path, opts){
    return _send(path, Object.assign({}, opts || {}, {method: (opts && opts.method) || 'GET'}));
  }

  // `body` is JSON-stringified automatically (Content-Type set for the caller) unless it is
  // already a string, in which case it is sent as-is. `body` may be omitted entirely (a
  // bodyless POST, e.g. a cancel/close action).
  async function post(path, body, opts){
    var o = Object.assign({method: 'POST'}, opts || {});
    if (body !== undefined){
      if (typeof body === 'string'){
        o.body = body;
      } else {
        o.headers = Object.assign({'Content-Type': 'application/json'}, o.headers || {});
        o.body = JSON.stringify(body);
      }
    }
    return _send(path, o);
  }

  function announce(msg){ var l = $('live'); if (l) l.textContent = msg; }

  return {esc: esc, $: $, get: get, post: post, announce: announce};
})();
