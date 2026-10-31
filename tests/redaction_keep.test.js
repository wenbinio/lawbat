'use strict';
/*
  Behavioral harness for FEATURE 2 "Keep (never redact)" — drives the REAL app/ui/redaction.js
  IIFE under a minimal DOM shim via window.__redactionInternals (parseKeep / normValue /
  candIsKept / refreshKeepNorms / redactEverywhere). Proves the keep PREDICATE + the Feature-1
  toggle read: a value on the Keep list matches a candidate whose value differs only by
  whitespace / case (so it will be auto-dismissed + excluded from expansion), a non-listed
  value does not, edits to the Keep box are picked up, and the everywhere toggle defaults ON.
  Air-gapped, deterministic, no network.

  The DOM-level auto-dismiss / accept-all-exclusion / overturn / "still shown" behaviors are
  asserted structurally in tests/smoke/test_review_consistency.py (they need the full review
  DOM, which this shim deliberately does not build) — the SAME mixed structural+harness pattern
  the other redaction features use.

  Usage: node tests/redaction_keep.test.js <assembled-redaction.js>
*/
const fs = require('fs');

function makeStubEl(id){
  let _t = '', _h = '', _v = '', _classes = {};
  return {
    id: id || '', get value(){ return _v; }, set value(x){ _v = String(x == null ? '' : x); },
    checked: false, files: [],
    classList: { add(c){ _classes[c] = true; }, remove(c){ delete _classes[c]; },
      toggle(c){ _classes[c] = !_classes[c]; return !!_classes[c]; }, contains(c){ return !!_classes[c]; } },
    style: {}, setAttribute(){}, getAttribute(){ return null; }, removeAttribute(){},
    addEventListener(){}, removeEventListener(){},
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    appendChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
    get textContent(){ return _t; }, set textContent(v){ _t = v; },
    get innerHTML(){ return _h; }, set innerHTML(v){ _h = v; }
  };
}

const els = {};
function getEl(id){
  if (!els[id]){
    els[id] = makeStubEl(id);
    if (id === 'redactEverywhere') els[id].checked = true;   // ships CHECKED (default ON)
  }
  return els[id];
}

global.window = global;
global.addEventListener = function(){};
global.removeEventListener = function(){};
global.document = {
  getElementById(id){ return getEl(id); },
  querySelector(){ return null; },
  querySelectorAll(){ return []; },
  addEventListener(){}, createElement(){ return makeStubEl(''); },
  get activeElement(){ return null; }, body: makeStubEl('body')
};
let lsStore = {};
global.localStorage = {
  getItem(k){ return Object.prototype.hasOwnProperty.call(lsStore, k) ? lsStore[k] : null; },
  setItem(k, v){ lsStore[k] = String(v); }, removeItem(k){ delete lsStore[k]; }
};
try { Object.defineProperty(global, 'navigator', { value: {}, configurable: true }); } catch (e){ /* keep */ }
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
global.fetch = async function(){ return { ok: false, status: 0, json: async () => ({}) }; };
global.setTimeout = function(){ return 0; };
global.FileReader = function(){ this.readAsDataURL = function(){ if (this.onload) this.onload(); }; };

const jsPath = process.argv[2];
if (!jsPath){ console.error('usage: node redaction_keep.test.js <redaction.js>'); process.exit(2); }
(0, eval)(fs.readFileSync(jsPath, 'utf8'));

const API = window.__redactionInternals;
let failures = 0, checks = 0;
function ok(cond, msg){ checks++; if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

ok(API && typeof API.candIsKept === 'function', 'keep seam is exposed');

// normValue: whitespace-insensitive + case-insensitive (mirrors the server _norm_value).
ok(API.normValue('Investment  Manager') === API.normValue('investment manager'),
   'normValue collapses whitespace + casefolds');

// Empty keep list -> nothing is kept.
API.refreshKeepNorms();
ok(API.candIsKept({ value: 'Acme Capital' }) === false, 'empty keep list keeps nothing');

// Add a keep entry -> a ws/case variant of it is "kept"; an unrelated value is not.
getEl('keepBox').value = 'Acme Capital\nS1234567A';
API.refreshKeepNorms();
ok(API.candIsKept({ value: 'ACME  CAPITAL' }) === true, 'ws/case variant of a kept value is kept');
ok(API.candIsKept({ value: 's1234567a' }) === true, 'second kept entry (case variant) is kept');
ok(API.candIsKept({ value: 'Other Party' }) === false, 'a non-listed value is NOT kept');

// parseKeep is the source list (byte-cap + dedup like TERMS).
const kept = API.parseKeep();
ok(kept.length === 2 && kept.indexOf('Acme Capital') >= 0, 'parseKeep returns the entered values');

// FEATURE 1 toggle: defaults ON (checkbox ships checked); reads the live checkbox state.
ok(API.redactEverywhere() === true, 'redact-everywhere defaults ON');
getEl('redactEverywhere').checked = false;
ok(API.redactEverywhere() === false, 'unticking the toggle reads OFF');

if (failures){ console.log('redaction keep harness: ' + failures + ' FAILURE(S)'); process.exit(1); }
console.log('redaction keep harness: all ' + checks + ' checks passed');
