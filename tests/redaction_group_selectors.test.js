'use strict';
/*
  Behavioral harness for the quick GROUP SELECTORS ("All" / "Default") on the redaction
  detection-options page: the jurisdiction multiselect (input.loc) and the recognizer types
  + closely-related opt-ins (input.bi, #ctxToggle, #leiToggle, input.prof). Drives the REAL
  app/ui/redaction.js (the IIFE) under a minimal DOM shim via the window.__redactionInternals
  seam (selectAllGroup / restoreGroupDefault / captureGroupDefault). Air-gapped, deterministic,
  no network.

  Proves:
    (a) "All" checks EVERY box in a group — including the group's own opt-in members (LEI,
        PCI) — and calls the SAME shared handler (saveOptions) a manual click's 'change'
        listener runs, so the persisted localStorage state matches what the checkboxes show.
    (b) "Default" restores the group's state exactly as CAPTURED AT INIT — and that capture
        happens AFTER any localStorage-persisted settings were restored (never a hardcoded
        "all built-ins on" / "no jurisdictions" guess): preset a saved config, prove
        "Default" comes back to THAT saved config, not the bare HTML defaults.
    (c) Neither "All" nor "Default" ever calls the network (no scan is auto-triggered) — a
        fetch spy stays at 0 calls across every scenario.
    (d) There is no "None"/"deselect all" counterpart anywhere on the seam or the page (the
        deliberate omission — see the code comments in redaction.core.js / redaction.html).

  Usage: node tests/redaction_group_selectors.test.js <path-to-redaction.js>
  Exits 0 on all-pass, 1 on any failure (driven by tests/test_smoke.py).
*/
const fs = require('fs');

// ---- a small DOM: generic stub elements (existing pattern) + real checkbox fixtures ----
function makeStubEl(id){
  const listeners = {};
  let _t = '', _h = '', _classes = {};
  return {
    id: id || '', value: '', files: [],
    classList: {
      add(c){ _classes[c] = true; }, remove(c){ delete _classes[c]; },
      toggle(c){ _classes[c] = !_classes[c]; return !!_classes[c]; },
      contains(c){ return !!_classes[c]; }
    },
    style: {}, setAttribute(){}, getAttribute(){ return null; }, removeAttribute(){},
    addEventListener(ev, fn){ (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener(){},
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    appendChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
    get textContent(){ return _t; }, set textContent(v){ _t = v; },
    get innerHTML(){ return _h; }, set innerHTML(v){ _h = v; },
    __listeners: listeners
  };
}

// A real checkbox: settable `.checked`, a `classList.contains` that answers the ONE class it
// carries, and an addEventListener that actually stores listeners (harmless here — the
// group-selector functions call saveOptions() directly rather than relying on a dispatched
// 'change' event, but keeping this real lets the harness also prove nothing ELSE regressed
// if that ever changes).
function makeCheckbox(cls, value, checkedDefault){
  const listeners = {};
  return {
    tagName: 'INPUT', type: 'checkbox', value: value || '',
    checked: !!checkedDefault,
    classList: { contains(c){ return c === cls; } },
    addEventListener(ev, fn){ (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener(){},
    getAttribute(name){ return name === 'value' ? this.value : null; },
    closest(){ return null; },
    __listeners: listeners
  };
}

let locBoxes, biBoxes, profBoxes, ctxToggle, leiToggle, sgNricLooseToggle;
function resetFixture(){
  locBoxes = ['sg', 'us', 'uk', 'au', 'ca'].map(function(v){ return makeCheckbox('loc', v, false); });
  biBoxes = ['email', 'phone', 'id', 'name', 'credit-card', 'iban', 'ip', 'url']
    .map(function(v){ return makeCheckbox('bi', v, true); });   // recognizers default ON
  profBoxes = [makeCheckbox('prof', 'pci-dss-cardholder', false)];
  ctxToggle = makeCheckbox('', '', false);
  leiToggle = makeCheckbox('', '', false);
  sgNricLooseToggle = makeCheckbox('', '', false);
}
resetFixture();

const stubEls = {};
function getEl(id){
  if (id === 'ctxToggle') return ctxToggle;
  if (id === 'leiToggle') return leiToggle;
  if (id === 'sgNricLooseToggle') return sgNricLooseToggle;
  return (stubEls[id] = stubEls[id] || makeStubEl(id));
}

function selectOne(token){
  token = token.trim();
  // readOptions() queries with a trailing :checked pseudo (e.g. 'input.loc:checked') —
  // strip it and filter afterwards, same as a real browser would.
  var checkedOnly = false;
  if (/:checked$/.test(token)){ checkedOnly = true; token = token.replace(/:checked$/, ''); }
  var out;
  if (token === 'input.loc') out = locBoxes.slice();
  else if (token === 'input.bi') out = biBoxes.slice();
  else if (token === 'input.prof') out = profBoxes.slice();
  else if (token === '#ctxToggle') out = [ctxToggle];
  else if (token === '#leiToggle') out = [leiToggle];
  else out = [];
  return checkedOnly ? out.filter(function(el){ return el.checked; }) : out;
}
function queryAll(sel){
  const seen = [];
  String(sel).split(',').forEach(function(tok){
    selectOne(tok).forEach(function(el){ if (seen.indexOf(el) === -1) seen.push(el); });
  });
  return seen;
}

// fetch spy: proves "All"/"Default" never trigger a scan (no network call at all).
let fetchCalls = 0;
global.window = global;
global.addEventListener = function(){};
global.removeEventListener = function(){};
global.document = {
  getElementById(id){ return getEl(id); },
  querySelector(){ return null; },
  querySelectorAll(sel){ return queryAll(sel); },
  addEventListener(){}, createElement(){ return makeStubEl(''); },
  get activeElement(){ return null; }, body: makeStubEl('body')
};

// localStorage: a real in-memory store + a call log, so a test can (a) PRESET a saved
// config before the script loads (proving "Default" captures the AS-LOADED state, not a
// hardcoded one) and (b) prove saveOptions() (the SAME shared handler a manual click runs)
// actually persisted the new state after "All"/"Default".
let lsStore = {};
let lsSetCalls = 0;
global.localStorage = {
  getItem(k){ return Object.prototype.hasOwnProperty.call(lsStore, k) ? lsStore[k] : null; },
  setItem(k, v){ lsStore[k] = String(v); lsSetCalls++; },
  removeItem(k){ delete lsStore[k]; }
};
try { Object.defineProperty(global, 'navigator', { value: {}, configurable: true }); } catch (e){ /* keep */ }
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
global.fetch = async function(){ fetchCalls++; return { ok: false, status: 0, json: async () => ({}) }; };
global.setTimeout = function(){ return 0; };
global.FileReader = function(){ this.readAsDataURL = function(){ if (this.onload) this.onload(); }; };
global.scrollTo = function(){};

const jsPath = process.argv[2];
if (!jsPath){ console.error('usage: node redaction_group_selectors.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

// ---------------------------------------------------------------------------------------
// Scenario A: a FIRST-RUN page load (no saved localStorage) — HTML defaults apply.
// ---------------------------------------------------------------------------------------
console.log('Scenario A: first-run load — HTML defaults (no jurisdictions, all recognizers on, opt-ins off)');
lsStore = {}; lsSetCalls = 0; fetchCalls = 0;
resetFixture();
(0, eval)(src);   // the whole IIFE runs (top-level wiring, restoreOptions(), captureGroupDefault(), etc.)
// The page-load health probe (checkEngineHealth) fires its OWN fetch on load — reset the
// spy so the assertion below is scoped to "All"/"Default" button actions only, not page load.
fetchCalls = 0;

const I = global.__redactionInternals;
if (!I || typeof I.selectAllGroup !== 'function' || typeof I.restoreGroupDefault !== 'function'){
  console.error('FAIL: __redactionInternals.{selectAllGroup,restoreGroupDefault,captureGroupDefault} not exposed');
  process.exit(1);
}

ok(locBoxes.every(function(b){ return b.checked === false; }), 'first-run: no jurisdiction pre-checked');
ok(biBoxes.every(function(b){ return b.checked === true; }), 'first-run: every recognizer type on by default');
ok(ctxToggle.checked === false && leiToggle.checked === false && profBoxes[0].checked === false,
  'first-run: context/LEI/PCI all off by default');

// (a) "All" on the JURISDICTION group checks every jurisdiction box, nothing else.
lsSetCalls = 0;
I.selectAllGroup('loc');
ok(locBoxes.every(function(b){ return b.checked === true; }), '(a) loc "All" checks every jurisdiction box');
ok(biBoxes.every(function(b){ return b.checked === true; }) && ctxToggle.checked === false && leiToggle.checked === false,
  '(a) loc "All" does not touch the recognizer/opt-in group');
ok(lsSetCalls >= 1, '(a) loc "All" persisted via the SAME shared handler (localStorage.setItem called)');
ok(JSON.parse(lsStore['lawbat.redaction.opts']).locales.length === 5,
  '(a) the persisted state actually lists all 5 locales (saveOptions read the live DOM, not a snapshot)');

// (a) "All" on the RECOGNIZER group checks every recognizer type PLUS the opt-ins it owns
// (context, LEI, PCI) — an opt-in like LEI is not quietly left out of "All".
lsSetCalls = 0;
I.selectAllGroup('bi');
ok(biBoxes.every(function(b){ return b.checked === true; }), '(a) bi "All" keeps every recognizer type checked');
ok(ctxToggle.checked === true, '(a) bi "All" also turns ON the context opt-in toggle');
ok(leiToggle.checked === true, '(a) bi "All" also turns ON the LEI opt-in toggle (opt-ins are NOT skipped)');
ok(profBoxes[0].checked === true, '(a) bi "All" also turns ON the PCI compliance-profile checkbox');
ok(sgNricLooseToggle.checked === false,
  '(a) bi "All" deliberately leaves the Aggressive SG NRIC advisory net untouched (out of scope)');
ok(lsSetCalls >= 1, '(a) bi "All" persisted via the shared handler too');

// (b) "Default" restores the group to its AS-LOADED (first-run HTML defaults) state.
locBoxes.forEach(function(b){ b.checked = true; });   // already true from above, but be explicit
I.restoreGroupDefault('loc');
ok(locBoxes.every(function(b){ return b.checked === false; }),
  '(b) loc "Default" restores every jurisdiction to its page-load state (all off)');

biBoxes[0].checked = false; biBoxes[3].checked = false;   // simulate a reviewer un-ticking two
I.restoreGroupDefault('bi');
ok(biBoxes.every(function(b){ return b.checked === true; }),
  '(b) bi "Default" restores every recognizer type to checked (the page-load state)');
ok(ctxToggle.checked === false && leiToggle.checked === false && profBoxes[0].checked === false,
  '(b) bi "Default" also restores context/LEI/PCI back to their page-load OFF state');

// ---------------------------------------------------------------------------------------
// Scenario B: a RETURNING user — localStorage already holds a saved config BEFORE load.
// "Default" must come back to THIS saved config, never the bare HTML defaults — proving
// captureGroupDefault() runs AFTER restoreOptions(), not a hardcoded snapshot.
// ---------------------------------------------------------------------------------------
console.log('\nScenario B: returning user — "Default" restores the SAVED config, not hardcoded HTML defaults');
lsStore = {
  'lawbat.redaction.opts': JSON.stringify({
    locales: ['sg', 'us'], disable_builtins: ['url'], lei: true
  })
};
lsSetCalls = 0; fetchCalls = 0;
resetFixture();
(0, eval)(src);   // reload fresh — restoreOptions() applies the saved config at init
fetchCalls = 0;   // ditto: exclude the on-load health probe's own fetch

ok(locBoxes.filter(function(b){ return b.checked; }).map(function(b){ return b.value; }).sort().join(',') === 'sg,us',
  'returning user: only sg + us start checked (restored from localStorage)');
ok(biBoxes.find(function(b){ return b.value === 'url'; }).checked === false,
  'returning user: "url" recognizer starts OFF (restored disable_builtins)');
ok(leiToggle.checked === true, 'returning user: LEI starts ON (restored)');

const I2 = global.__redactionInternals;
// Mess with the state (as if the reviewer clicked "All" then changed their mind).
I2.selectAllGroup('loc');
I2.selectAllGroup('bi');
ok(locBoxes.every(function(b){ return b.checked; }), 'sanity: loc "All" checked everything before we test Default');

// "Default" must come back to the SAVED config (sg+us only; url off; lei on) — not a
// hardcoded "nothing checked" / "everything on" guess.
I2.restoreGroupDefault('loc');
ok(locBoxes.filter(function(b){ return b.checked; }).map(function(b){ return b.value; }).sort().join(',') === 'sg,us',
  '(b) loc "Default" restores the SAVED sg+us config (captured at init AFTER restoreOptions), not a hardcoded guess');

I2.restoreGroupDefault('bi');
ok(biBoxes.find(function(b){ return b.value === 'url'; }).checked === false,
  '(b) bi "Default" restores the SAVED "url off" state, not the bare HTML "all checked" default');
ok(leiToggle.checked === true, '(b) bi "Default" restores the SAVED "LEI on" state');

// ---------------------------------------------------------------------------------------
// Scenario C: neither button ever triggers a network call (no scan is auto-triggered).
// ---------------------------------------------------------------------------------------
console.log('\nScenario C: "All" / "Default" never touch the network (no auto-triggered scan)');
ok(fetchCalls === 0, 'zero fetch() calls across every "All"/"Default" invocation above');

// ---------------------------------------------------------------------------------------
// Scenario D: there is no "None" seam anywhere (the deliberate omission).
// ---------------------------------------------------------------------------------------
console.log('\nScenario D: no "None"/deselect-all counterpart exists on the seam or the served page');
ok(typeof I2.selectNoneGroup !== 'function' && typeof I2.deselectAllGroup !== 'function' && typeof I2.clearGroup !== 'function',
  'no None/deselect-all function is exposed on the internals seam');
ok(src.indexOf('locNoneBtn') === -1 && src.indexOf('recNoneBtn') === -1,
  'no "None" button id appears anywhere in the assembled script');

console.log(failures === 0 ? '\nALL PASS' : '\n' + failures + ' FAILURE(S)');
process.exit(failures === 0 ? 0 : 1);
