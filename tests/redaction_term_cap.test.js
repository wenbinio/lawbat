'use strict';
/*
  Harness for the user-TERM BYTE-cap + WARN-ON-DROP on the redaction page. Loads the REAL
  app/ui/redaction.js (the IIFE) under a minimal DOM shim and drives the actual byteLen() /
  parseTerms() / renderTermDrops() via the window.__redactionInternals test seam.
  Air-gapped, deterministic, no network.

  This locks Finding #1 (the leak class — a silent un-redaction): the browser must cap a
  user "names to redact" TERM in UTF-8 BYTES (matching the Python bridge + Rust bin
  `MAX_TERM_BYTES`), NOT UTF-16 `.length`, and a server `terms_dropped` report must be
  SURFACED (esc()'d, never the name silently dropped).

  Proves:
    * byteLen() counts UTF-8 bytes (a CJK / accented char is multi-byte), not UTF-16 units;
    * parseTerms() DROPS a term over the byte cap that would PASS a UTF-16 .length cap
      (the exact leak the cast closes) and KEEPS one just under the byte cap;
    * renderTermDrops() surfaces a `terms_dropped` report (count + esc()'d offending terms),
      hides when nothing was dropped, and ESCAPES cleartext (no markup injection);
    * renderTermDrops(null) clears the banner (the reset / leak-direction fail-safe).

  Usage: node tests/redaction_term_cap.test.js <path-to-redaction.js>
  Exits 0 on all-pass, 1 on any failure (driven by tests/test_smoke.py).
*/
const fs = require('fs');

function makeEl(id){
  const listeners = {};
  let _classes = {};
  const el = {
    id: id || '', value: '', files: [],
    classList: {
      add(c){ _classes[c] = true; },
      remove(c){ delete _classes[c]; },
      toggle(c, on){ if (on === undefined){ _classes[c] = !_classes[c]; } else { if (on){ _classes[c] = true; } else { delete _classes[c]; } } return !!_classes[c]; },
      contains(c){ return !!_classes[c]; }
    },
    style: {},
    setAttribute(k, v){ this['__attr_' + k] = v; }, getAttribute(k){ return this['__attr_' + k] != null ? this['__attr_' + k] : null; }, removeAttribute(){},
    addEventListener(ev, fn){ (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener(){},
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    appendChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
    __listeners: listeners
  };
  let _t = '', _h = '';
  Object.defineProperty(el, 'textContent', { get(){ return _t; }, set(v){ _t = v; } });
  Object.defineProperty(el, 'innerHTML', { get(){ return _h; }, set(v){ _h = v; } });
  Object.defineProperty(el, 'className', { get(){ return Object.keys(_classes).join(' '); }, set(v){ _classes = {}; String(v || '').split(/\s+/).forEach(function(c){ if (c) _classes[c] = true; }); } });
  return el;
}
const elements = {};
function getEl(id){ return (elements[id] = elements[id] || makeEl(id)); }

global.window = global;
global.addEventListener = function(){};
global.removeEventListener = function(){};
global.document = {
  getElementById(id){ return getEl(id); },
  querySelector(){ return null; },
  querySelectorAll(){ return []; },
  addEventListener(){}, createElement(){ return makeEl(''); },
  get activeElement(){ return null; }, body: makeEl('body')
};
global.localStorage = { getItem(){ return null; }, setItem(){}, removeItem(){} };
try { Object.defineProperty(global, 'navigator', { value: {}, configurable: true }); } catch (e){ /* keep node's */ }
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
global.fetch = async function(){ return { ok: false, status: 0, json: async () => ({}) }; };
global.setTimeout = function(){ return 0; };
global.FileReader = function(){ this.readAsDataURL = function(){ if (this.onload) this.onload(); }; };
global.scrollTo = function(){};

const jsPath = process.argv[2];
if (!jsPath){ console.error('usage: node redaction_term_cap.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I || typeof I.renderTermDrops !== 'function' || typeof I.byteLen !== 'function' || typeof I.parseTerms !== 'function'){
  console.error('FAIL: __redactionInternals.{byteLen,parseTerms,renderTermDrops} not exposed'); process.exit(1);
}

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

const MAX_TERM_BYTES = 200;

console.log('Scenario 1: byteLen() counts UTF-8 bytes (not UTF-16 units)');
{
  ok(I.byteLen('abc') === 3, 'ASCII: 3 chars = 3 bytes');
  ok(I.byteLen('café') === 5, 'accented é is 2 bytes (café = 5 bytes, 4 chars)');
  ok(I.byteLen('名') === 3, 'a CJK char is 3 UTF-8 bytes (1 UTF-16 unit)');
  ok(I.byteLen('') === 0, 'empty string is 0 bytes');
}

console.log('Scenario 2: parseTerms() caps in BYTES — the leak the cast closes');
{
  // 67 CJK chars = 201 UTF-8 bytes. char/.length = 67 (PASSES a UTF-16 cap of 200) but the
  // BYTE length 201 > 200 (DROPPED). This is the exact silent-drop Finding #1 describes.
  const overByte = '名'.repeat(67);
  ok(overByte.length === 67 && I.byteLen(overByte) === 201, 'fixture: 67 UTF-16 units but 201 bytes');
  const kept1 = I.parseTerms(overByte);
  ok(kept1.length === 0, 'an over-BYTE term (would pass a UTF-16 cap) is DROPPED');

  // 66 CJK chars = 198 bytes — just under the cap, KEPT.
  const underByte = '名'.repeat(66);
  ok(I.byteLen(underByte) === 198, 'fixture: 66 CJK chars = 198 bytes (under cap)');
  const kept2 = I.parseTerms(underByte);
  ok(kept2.length === 1 && kept2[0] === underByte, 'an under-cap multibyte term is KEPT');

  // mixed lines: a short ASCII name kept, the over-byte one dropped, blanks dropped, dupes deduped.
  const raw = ['Massimo Greco', overByte, '   ', 'Massimo Greco', underByte].join('\n');
  const kept = I.parseTerms(raw);
  ok(kept.indexOf('Massimo Greco') >= 0, 'a normal ASCII name survives');
  ok(kept.indexOf(overByte) < 0, 'the over-byte name is not in the kept set');
  ok(kept.filter(function(t){ return t === 'Massimo Greco'; }).length === 1, 'duplicates are deduped');
  ok(kept.length === 2, 'kept = {ASCII name, under-cap multibyte}; blanks/over/dupe dropped');
}

console.log('Scenario 3: renderTermDrops() surfaces a server report (esc()d, never silent)');
{
  const el = getEl('termDrops');
  // No report -> hidden + empty (byte-identical to the historical no-warning behavior).
  I.renderTermDrops({ candidates: [] });
  ok(el.classList.contains('hidden') && el.innerHTML === '', 'no terms_dropped -> banner hidden + empty');

  // A report -> visible, count surfaced, the offending term shown.
  I.renderTermDrops({ terms_dropped: { count: 1, terms: ['名'.repeat(67)] } });
  ok(!el.classList.contains('hidden'), 'a drop report shows the banner');
  ok(el.innerHTML.indexOf('1 term') >= 0, 'the dropped COUNT is surfaced');
  ok(el.innerHTML.toLowerCase().indexOf('too long to redact') >= 0, 'message says the term was too long to redact');
  ok(el.innerHTML.toLowerCase().indexOf('not removed') >= 0, 'message states it was NOT removed (honest)');
  ok(el.innerHTML.indexOf('名'.repeat(67)) >= 0, 'the offending term is listed for the lawyer');

  // Pluralisation.
  I.renderTermDrops({ terms_dropped: { count: 3, terms: ['a', 'b', 'c'] } });
  ok(el.innerHTML.indexOf('3 terms') >= 0, 'plural count rendered');
}

console.log('Scenario 4: cleartext is ESCAPED — no markup injection from a term');
{
  const el = getEl('termDrops');
  const hostile = '<img src=x onerror=alert(1)>"\'`&';
  I.renderTermDrops({ terms_dropped: { count: 1, terms: [hostile] } });
  ok(el.innerHTML.indexOf('<img') < 0, 'raw <img> never appears (escaped)');
  ok(el.innerHTML.indexOf('onerror=alert(1)') < 0 || el.innerHTML.indexOf('&lt;img') >= 0, 'the payload is escaped, not live markup');
  ok(el.innerHTML.indexOf('&lt;img') >= 0, 'the angle bracket is HTML-escaped');
}

console.log('Scenario 5: renderTermDrops(null) clears the banner (reset / fail-safe)');
{
  const el = getEl('termDrops');
  I.renderTermDrops({ terms_dropped: { count: 2, terms: ['x', 'y'] } });   // populate
  I.renderTermDrops(null);                                                  // reset
  ok(el.classList.contains('hidden') && el.innerHTML === '', 'banner hidden + cleared on null');
}

console.log('Scenario 6: CLIENT-side drop is computed from the textarea (the real-UI leak the review caught)');
{
  // The browser pre-filters over-byte terms in parseTerms BEFORE sending, so the SERVER never
  // reports them — the warning MUST come from the textarea. clientTermDropReport reads it.
  if (typeof I.clientTermDropReport !== 'function'){
    ok(false, '__redactionInternals.clientTermDropReport must be exposed (client-side warn source)');
  } else {
    const box = getEl('termsBox');
    const over = '名'.repeat(67);          // 201 bytes -> over the byte cap
    box.value = ['Massimo Greco', over, '   ', 'Carla Ruiz', 'Massimo Greco'].join('\n');
    const rep = I.clientTermDropReport();
    ok(rep.count === 1, 'exactly the one over-byte term is reported as dropped (from the textarea)');
    ok(rep.terms.length === 1 && rep.terms[0] === over, 'the offending term is listed from the textarea');
    box.value = 'Massimo Greco\nCarla Ruiz';   // all within cap
    ok(I.clientTermDropReport().count === 0, 'no over-byte term -> nothing reported');
  }
}

if (failures === 0){ console.log('ALL PASS'); process.exit(0); }
console.log(failures + ' FAILURE(S)'); process.exit(1);
