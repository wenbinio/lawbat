'use strict';
/*
  Differential harness for the RE-IDENTIFICATION EXPOSURE meter (before -> after tracker)
  on the redaction page. Loads the REAL app/ui/redaction.js (the IIFE) under a minimal DOM
  shim and drives the actual renderReidMeter() / reidBandClass() via the
  window.__redactionInternals test seam. Air-gapped, deterministic, no network.

  Proves the load-bearing invariants:
    * deterministic render — the same before/after scores produce byte-identical innerHTML;
    * BEFORE-only renders a gauge + "runs once you apply a redaction" placeholder;
    * BEFORE + AFTER renders both gauges, the delta, and the surviving-category breakdown;
    * an equal after (quasi-identifiers survive) reads "unchanged" — the HONEST message;
    * cleartext is ESCAPED — a hostile band string can never inject markup, and an unknown
      band degrades to a safe 'none' class (no raw server text in a class attribute);
    * the meter HIDES when there is no before-score (PDF flow), and on reset;
    * the rendered figures are COUNT-derived ints only (no document cleartext appears).

  Usage: node tests/redaction_reid_meter.test.js <path-to-redaction.js>
  Exits 0 on all-pass, 1 on any failure (drives tests/test_smoke.py).
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
if (!jsPath){ console.error('usage: node redaction_reid_meter.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I || typeof I.renderReidMeter !== 'function'){
  console.error('FAIL: __redactionInternals.renderReidMeter not exposed'); process.exit(1);
}

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

function ids(){
  return {
    card: getEl('reidMeter'),
    bars: getEl('reidBars'),
    delta: getEl('reidDelta'),
    survive: getEl('reidSurvive'),
    chip: getEl('reidBandChip')
  };
}

const before = {
  index: 85, band: 'critical',
  counts: { time: 3, roles: 4, locations: 3, organisations: 3 },
  distinct: 4, total: 13, privilege_markers: false
};
// After redaction the engine removed named identifiers but the quasi-identifiers survive,
// so the after-score is identical (the HONEST "unchanged" case the meter must report).
const afterUnchanged = JSON.parse(JSON.stringify(before));
// A second, lower after (fewer quasi-identifiers detected after removal) -> a "down" delta.
const afterLower = {
  index: 60, band: 'high',
  counts: { time: 2, roles: 2, locations: 1, organisations: 1 },
  distinct: 4, total: 6, privilege_markers: false
};

console.log('Scenario 1: BEFORE-only render (no after yet)');
{
  I.renderReidMeter(before, null);
  const d = ids();
  ok(!d.card.classList.contains('hidden'), 'meter is shown when a before-score exists');
  ok(d.chip.textContent === 'critical', 'band chip shows the before band');
  ok(d.chip.className.indexOf('reid-b-critical') >= 0, 'band chip carries the band class');
  ok(d.bars.innerHTML.indexOf('>Before<') >= 0, 'a BEFORE gauge is rendered');
  ok(d.bars.innerHTML.indexOf('85') >= 0, 'the before index (85) is shown');
  ok(d.bars.innerHTML.indexOf('reid-pending') >= 0, 'the AFTER gauge is a pending placeholder');
  ok(d.bars.innerHTML.indexOf('runs once you apply') >= 0, 'pending note prompts to apply a redaction');
  ok(d.delta.innerHTML.indexOf('Apply a redaction') >= 0, 'delta line prompts an apply');
  // surviving categories shown off the before-score (counts only).
  ok(d.survive.innerHTML.indexOf('3 dates') >= 0, 'surviving breakdown lists 3 dates');
  ok(d.survive.innerHTML.indexOf('4 role terms') >= 0, 'surviving breakdown lists 4 role terms');
  ok(d.survive.innerHTML.indexOf('3 organisations') >= 0, 'surviving breakdown lists 3 organisations');
}

console.log('Scenario 2: BEFORE + AFTER (unchanged) — the honest residual message');
{
  I.renderReidMeter(before, afterUnchanged);
  const d = ids();
  ok(d.bars.innerHTML.indexOf('>Before<') >= 0 && d.bars.innerHTML.indexOf('>After<') >= 0, 'both gauges render');
  ok(d.bars.innerHTML.indexOf('reid-pending') < 0, 'no pending placeholder once after exists');
  ok(d.delta.innerHTML.indexOf('unchanged') >= 0, 'unchanged delta when quasi-identifiers survive');
  ok(d.delta.innerHTML.indexOf('85 → 85') >= 0, 'delta shows before -> after indices');
  // The honest message: names removed but quasi-identifiers remain.
  ok(d.survive.innerHTML.indexOf('Named identifiers removed') >= 0, 'after-breakdown leads with names-removed framing');
  ok(d.survive.innerHTML.toLowerCase().indexOf('not removed automatically') >= 0, 'says quasi-identifiers are not auto-removed');
  // never claims safety/anonymity as a state.
  ok(d.delta.innerHTML.toLowerCase().indexOf('does not mean the document is anonymous') >= 0 ||
     d.delta.innerHTML.toLowerCase().indexOf('exposure is unchanged') >= 0, 'no anonymity claim in the delta');
}

console.log('Scenario 3: BEFORE + AFTER (lower) — a down delta');
{
  I.renderReidMeter(before, afterLower);
  const d = ids();
  ok(d.delta.innerHTML.indexOf('down 25') >= 0, 'down delta is 85 - 60 = 25');
  ok(d.delta.innerHTML.indexOf('85 → 60') >= 0, 'delta shows the indices');
  ok(d.delta.className.indexOf('rd-down') >= 0, 'down delta carries the rd-down class');
  ok(d.survive.innerHTML.indexOf('2 dates') >= 0, 'after-breakdown reads off the AFTER counts (2 dates)');
}

console.log('Scenario 4: determinism — same input, byte-identical innerHTML');
{
  I.renderReidMeter(before, afterUnchanged);
  const h1 = getEl('reidBars').innerHTML + '||' + getEl('reidDelta').innerHTML + '||' + getEl('reidSurvive').innerHTML;
  I.renderReidMeter(before, afterUnchanged);
  const h2 = getEl('reidBars').innerHTML + '||' + getEl('reidDelta').innerHTML + '||' + getEl('reidSurvive').innerHTML;
  ok(h1 === h2, 'identical scores render byte-identical innerHTML');
}

console.log('Scenario 5: hostile band string is ESCAPED + degraded to a safe class');
{
  const hostile = {
    index: 50, band: '"><img src=x onerror=alert(1)>',
    counts: { time: 1, roles: 1, locations: 0, organisations: 0 },
    distinct: 2, total: 2, privilege_markers: false
  };
  I.renderReidMeter(hostile, null);
  const d = ids();
  // The raw tag must NOT survive into innerHTML — esc() turns < into &lt;.
  ok(d.bars.innerHTML.indexOf('<img src=x') < 0, 'a hostile band string is not rendered as raw markup');
  ok(d.chip.textContent.indexOf('<img') < 0, 'the chip textContent is not raw markup');
  // The CLASS must be the allowlisted safe suffix (unknown band -> 'none'), never injected.
  ok(I.reidBandClass('"><img>') === 'none', 'an unknown band degrades to the safe none class');
  ok(I.reidBandClass('critical') === 'critical' && I.reidBandClass('low') === 'low', 'known bands pass through');
  ok(d.chip.className.indexOf('onerror') < 0, 'no hostile text reaches the chip class');
}

console.log('Scenario 6: no before-score (PDF flow) -> meter hidden; reset clears it');
{
  I.renderReidMeter(before, afterUnchanged);   // populate it first
  I.renderReidMeter(null, null);               // PDF flow: no score
  const d = ids();
  ok(d.card.classList.contains('hidden'), 'meter hides when there is no before-score');
  ok(d.bars.innerHTML === '' && d.delta.innerHTML === '' && d.survive.innerHTML === '', 'meter content is cleared');
  ok(d.chip.textContent === '—', 'band chip reset to an em-dash');
}

console.log('Scenario 7: counts-only — no document cleartext in the rendered meter');
{
  // The score carries no cleartext (only ints), so nothing the engine matched can appear.
  I.renderReidMeter(before, afterUnchanged);
  const d = ids();
  const all = (d.bars.innerHTML + d.delta.innerHTML + d.survive.innerHTML + d.chip.textContent).toLowerCase();
  // sanity: a representative quasi-identifier token never appears (the score has none anyway).
  ok(all.indexOf('acme') < 0 && all.indexOf('london') < 0 && all.indexOf('director') < 0,
    'rendered meter contains no document cleartext (counts only)');
}

if (failures === 0){ console.log('ALL PASS'); process.exit(0); }
console.log(failures + ' FAILURE(S)'); process.exit(1);
