/*
  firmOS HOME renderer — the TRUSTED HOST shell (not a sandboxed module, so host JS
  is fine here). It fetches the typed view-model (the "firmos.view/0" contract) from
  /api/home and renders it into the DOM. Every matter-derived string is escaped via
  esc() before it ever touches innerHTML. No external resources are fetched.

  The contract (rendered, never invented):
    { schema, generated_label, preview?, sections:[
        { title, caveats:[{id,message,dismissible}],
          cards:[{ title, subtitle,
                   badges:[{kind,label}],
                   due:{kind,text}|null,
                   actions:[{action_id,label,target}] }] } ] }
*/
(function(){
  'use strict';

  // esc() (ALL cleartext from the contract — titles, subtitles, badge/due/caveat text, and
  // action data-* attrs — goes through this before insertion; C2) and the token-carrying
  // get() now live in the SHARED app/ui/base.js (window.LB, inlined into this page via the
  // __BASE_JS__ marker BEFORE this script) — aliased here so the rest of this file is
  // otherwise UNCHANGED. See base.js for the implementations.
  var esc = LB.esc;

// --- dismissed caveats: persisted locally, keyed by caveat id ----------------
// The honest-limit banner nags ONCE, then "ignore all further warnings" silences
// THAT id forever (a new caveat kind still surfaces). Persisted in localStorage so
// it survives restarts; falls back to an in-memory set if storage is unavailable
// (e.g. a locked-down WebView) so the control still works for the session.
var _memDismissed = {};
function dismissedKey(id){ return 'ldm.caveat.dismissed.' + id; }
function isDismissed(id){
  try { if (localStorage.getItem(dismissedKey(id)) === '1') return true; } catch(e){ /* ignore */ }
  return !!_memDismissed[id];
}
function setDismissed(id){
  try { localStorage.setItem(dismissedKey(id), '1'); } catch(e){ /* ignore */ }
  _memDismissed[id] = true;
}

// --- per-due-kind styling map (drives colour + the question/needs-confirm tone) -
// Honest framing: the non-factual kinds (ambiguous/needs_confirm/vague) get the
// "question" treatment, never a confident committed-date colour.
var DUE_CLASS = {
  overdue: 'ov', due_today: 'td', due_soon: 'up',
  ambiguous: 'q', needs_confirm: 'q', vague: 'q', none: 'none'
};
// Border accent per section (best-effort, by the strongest due kind present).
function cardAccent(card){
  var k = (card.due && card.due.kind) || 'none';
  if (k === 'overdue') return ' ov';
  if (k === 'due_today') return ' td';
  if (k === 'due_soon') return ' up';
  return '';
}

// --- badge -------------------------------------------------------------------
// The contract kinds: origin|category|priority|protected|warning (+ a tolerated
// "neutral"). Internal origin gets a green variant; everything else maps to a
// class. A ⚠ glyph is prepended for warnings (host decoration, not contract text).
//
// SECURITY (#4): the kind drives a CSS class attribute. An UNEXPECTED/hostile kind
// string must never reach that attribute raw (it could break out of the class
// context). We map a known kind to its class via an ALLOWLIST and degrade an unknown
// kind to the safe 'neutral' class — the raw server string never lands in the markup
// unescaped. (The label is already esc()'d.)
var KIND_CLASS = {
  origin: 'origin', category: 'category', priority: 'priority',
  protected: 'protected', warning: 'warning', neutral: 'neutral'
};
function badgeHtml(b){
  var kind = (b && b.kind) || 'neutral';
  var label = esc((b && b.label) || '');
  var base = Object.prototype.hasOwnProperty.call(KIND_CLASS, kind)
      ? KIND_CLASS[kind] : 'neutral';
  // Internal origin keeps its green variant (computed from the allowlisted base).
  var cls = 'chip ' + (base === 'origin'
      ? (/^internal/i.test((b && b.label) || '') ? 'origin-int' : 'origin')
      : base);
  var glyph = (kind === 'warning') ? '⚠ ' : (kind === 'protected') ? '🔒 ' : '';
  return '<span class="' + cls + '">' + glyph + label + '</span>';
}

// --- due ---------------------------------------------------------------------
function dueHtml(due){
  if (!due) return '';
  var cls = DUE_CLASS[due.kind] || 'none';
  return '<span class="due ' + cls + '">' + esc(due.text) + '</span>';
}

// --- action ------------------------------------------------------------------
// A typed action: a host-routed on-invoke (NO module JS). We render a button whose
// data-* carries the action id + opaque target; the host's click handler routes it.
// The primary (first) action is a filled pill; the rest are ghost buttons.
function actionHtml(a, primary){
  return '<button class="' + (primary ? 'pill' : 'ghost') + '" '
       + 'data-action-id="' + esc(a.action_id) + '" '
       + 'data-target="' + esc(a.target) + '">' + esc(a.label) + '</button>';
}

// --- card --------------------------------------------------------------------
function cardHtml(card){
  var badges = (card.badges || []).map(badgeHtml).join(' ');
  var actions = (card.actions || []).map(function(a, i){ return actionHtml(a, i === 0); }).join(' ');
  var subtitle = card.subtitle ? '<span class="subtitle">' + esc(card.subtitle) + '</span>' : '';
  return '<div class="card' + cardAccent(card) + '">'
       +   '<div class="r1">' + badges + subtitle + '</div>'
       +   '<div class="excerpt"><span class="lbl">excerpt</span>' + esc(card.title) + '</div>'
       +   '<div class="r3">' + dueHtml(card.due)
       +     '<span class="act">' + actions + '</span>'
       +   '</div>'
       + '</div>';
}

// --- caveat (dismissible honest-limit banner) --------------------------------
function renderCaveats(sections){
  var host = document.getElementById('caveats');
  host.innerHTML = '';
  var seen = {};
  var items = [];
  (sections || []).forEach(function(sec){
    (sec.caveats || []).forEach(function(cav){
      if (!cav || seen[cav.id]) return;
      seen[cav.id] = true;
      if (cav.dismissible && isDismissed(cav.id)) return;
      items.push(cav);
    });
  });
  if (!items.length) return;
  var el = document.createElement('details');
  el.className = 'caveat compact';
  var lis = items.map(function(cav){
    return '<li data-caveat-id="' + esc(cav.id) + '">' + esc(cav.message) + '</li>';
  }).join('');
  var dismissible = items.some(function(cav){ return cav.dismissible; });
  var btn = dismissible
    ? '<button type="button" data-dismiss-caveat="' + esc(items[0].id) + '">Ignore all further warnings</button>'
    : '';
  el.innerHTML = '<summary>Assistive worklist — not a deadline calendar. ' + items.length
    + ' note' + (items.length === 1 ? '' : 's') + '.</summary>'
    + '<div class="body"><ul>' + lis + '</ul>' + btn + '</div>';
  host.appendChild(el);
}

// --- global strip + matters rail + deadlines + greeting ----------------------
function deadlineCounts(sections){
  var c = {overdue: 0, due_today: 0, due_soon: 0};
  (sections || []).forEach(function(sec){
    (sec.cards || []).forEach(function(card){
      var k = card.due && card.due.kind;
      if (k === 'overdue') c.overdue++;
      else if (k === 'due_today') c.due_today++;
      else if (k === 'due_soon') c.due_soon++;
    });
  });
  return c;
}

function renderDeadlines(sections){
  var c = deadlineCounts(sections);
  document.getElementById('deadlines').innerHTML =
      '<div class="dl"><span class="lab"><span class="dot ov"></span> Overdue</span><span class="num">' + c.overdue + '</span></div>'
    + '<div class="dl"><span class="lab"><span class="dot td"></span> Today</span><span class="num">' + c.due_today + '</span></div>'
    + '<div class="dl"><span class="lab"><span class="dot up"></span> Next 7 days</span><span class="num">' + c.due_soon + '</span></div>';
}

function renderWorklist(view){
  var sections = view.sections || [];
  var total = 0;
  var html = '';
  sections.forEach(function(sec){
    var cards = sec.cards || [];
    total += cards.length;
    html += '<div class="grp">' + esc(sec.title) + ' <span class="cnt">' + cards.length + '</span></div>';
    if (!cards.length){
      html += '<div class="empty">Nothing here.</div>';
    } else {
      html += cards.map(cardHtml).join('');
    }
  });
  var box = document.getElementById('worklist');
  if (!sections.length){
    box.innerHTML = '<div class="empty">No worklist yet. Open a data room to get started.</div>';
  } else {
    box.innerHTML = html;
  }
  document.getElementById('worklistSub').textContent = total + ' item' + (total === 1 ? '' : 's') + ' · triaged from your inbox';
}

async function renderGlobal(){
  // The global strip + matters list come from the EXISTING /api/state (the data-room
  // pilot's own endpoint) — the Home composes them around the worklist.
  var st;
  try { st = (await LB.get('/api/state')).data; } catch(e){ st = {}; }
  var stats = st.stats || {};
  var matters = st.matters || [];
  var docs = stats.total || 0;
  var attention = (stats.needs_ocr || 0) + (stats.errors || 0);
  document.getElementById('global').innerHTML =
      '<div class="stat"><div class="n">' + matters.length + '</div><div class="l">matters</div></div>'
    + '<div class="stat"><div class="n">' + docs + '</div><div class="l">documents indexed</div></div>'
    + '<div class="stat"><div class="n">' + attention + '</div><div class="l">need attention &middot; <a href="/app">open data room</a></div></div>';

  var nav = document.getElementById('navMatters');
  if (matters.length){
    nav.innerHTML = matters.map(function(m){
      return '<a href="/app" title="' + esc(m.name) + '"><span class="ic" aria-hidden="true">&bull;</span> ' + esc(m.name) + '</a>';
    }).join('');
  } else {
    nav.innerHTML = '<div style="color:var(--fg3);font-size:var(--t-cap);padding:6px 10px">No matters yet.</div>';
  }
}

// --- host action routing (typed on-invoke; NO module JS) ---------------------
// The view-model's ActionRefs are pure data; the HOST decides what each does. For
// this increment dismiss removes the card locally and the rest open the relevant
// module. Real broker routing lands when the modules are wired.
function routeAction(actionId, target, btn){
  if (actionId === 'dismiss'){
    var card = btn.closest('.card');
    if (card) card.remove();
    return;
  }
  // respond/review/pay/open etc. — for now, take the user to the data room module.
  // (A future increment routes these through the core broker per the typed target.)
  window.location.href = '/app';
}

// Delegated click handling — set up ONCE, covers re-rendered content. No inline
// handlers in the served HTML (CSP-friendly + keeps the contract data inert).
function wireEvents(){
  document.body.addEventListener('click', function(ev){
    var t = ev.target.closest('[data-dismiss-caveat]');
    if (t){
      ev.preventDefault();
      var id = t.getAttribute('data-dismiss-caveat');
      setDismissed(id);
      var banner = t.closest('.caveat');
      if (banner) banner.remove();
      // One merged notice: silencing the control clears every dismissible id on it.
      document.querySelectorAll('#caveats [data-caveat-id]').forEach(function(li){
        var cid = li.getAttribute('data-caveat-id');
        if (cid) setDismissed(cid);
      });
      return;
    }
    var a = ev.target.closest('[data-action-id]');
    if (a){
      ev.preventDefault();
      routeAction(a.getAttribute('data-action-id'), a.getAttribute('data-target'), a);
      return;
    }
  });
  // Module-launcher links that point at "#" are placeholders (Inbox/Timesheet not
  // built yet) — keep them inert rather than scrolling the page. (Redaction now
  // points at /redaction, so it navigates and is not matched here.)
  document.querySelectorAll('a[href="#"]').forEach(function(el){
    el.addEventListener('click', function(ev){ ev.preventDefault(); });
  });
}

async function loadHome(){
  var view;
  try {
    view = (await LB.get('/api/home')).data;
  } catch(e){
    document.getElementById('worklist').innerHTML =
      '<div class="empty">Could not load the worklist. The app is still usable — open the data room.</div>';
    await renderGlobal();
    return;
  }
  // Honest framing: surface the generator's own label, and flag a sample/preview.
  document.getElementById('genLabel').textContent = view.generated_label || '';
  var pn = document.getElementById('previewNote');
  pn.innerHTML = view.preview
    ? '<div class="preview"><b>Preview.</b> The worklist generator is not wired yet — this is bundled sample data, not your inbox. The data room search and tools below are fully live.</div>'
    : '';
  renderCaveats(view.sections);
  renderWorklist(view);
  renderDeadlines(view.sections || []);
  await renderGlobal();
}

document.addEventListener('DOMContentLoaded', function(){
  document.getElementById('greeting').textContent = 'Home';
  wireEvents();
  loadHome();
});
})();
