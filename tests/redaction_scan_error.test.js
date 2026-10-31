'use strict';
/*
  Regression harness for the redaction reviewer's scan-error honesty fix (Defect 2):
  an errored scan must NEVER be visually indistinguishable from a clean, EMPTY scan.
  A red "scan failed / tool unavailable" banner sitting over green "Done / 0 findings /
  None flagged" steps would tell the lawyer the document was scanned-and-clean when it was
  never scanned at all. Over-blocking is the safe side.

  Loads the REAL redaction.js IIFE under a minimal DOM shim and drives the actual
  markScanFailed / canEnter / getScanState functions via window.__redactionInternals.
  This proves the STATE MACHINE (gates re-lock, error flag set, chip flips). The RENDER
  logic (the stepper paints 'error' not 'done', no stale "0 findings"/"None flagged") is
  pinned structurally in tests/smoke/test_redaction.py against the served page.

  Usage: node tests/redaction_scan_error.test.js <path-to-assembled-redaction.js>
  Exits 0 on all-pass, 1 on any failure (drives tests/test_smoke.py). Air-gapped, deterministic.
*/
const fs = require('fs');

function makeEl(id){
  const listeners = {};
  const el = {
    id: id || '', value: '', files: [], className: '',
    classList: { add(){}, remove(){}, toggle(){ return false; }, contains(){ return false; } },
    style: {},
    setAttribute(){}, getAttribute(){ return null; }, removeAttribute(){},
    addEventListener(ev, fn){ (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener(){},
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    appendChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
    __listeners: listeners
  };
  let _t = '', _h = '';
  Object.defineProperty(el, 'textContent', { get(){ return _t; }, set(v){ _t = v; } });
  Object.defineProperty(el, 'innerHTML', { get(){ return _h; }, set(v){ _h = v; } });
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
if (!jsPath){ console.error('usage: node redaction_scan_error.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I){ console.error('FAIL: __redactionInternals not exposed'); process.exit(1); }

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

const chip = getEl('engineChip');

// --------------------------------------------------------------------------------------
console.log('Scenario A: a SUCCESSFUL scan (0 findings) opens the review gate.');
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'hello',
  cands: [], decided: {}, scanFailed: false,
  scanProvenanceFile: null, scanProvenanceText: 'hello'
});
ok(I.canEnter('review') === true, 'after a successful (empty) scan, Review is reachable');

// --------------------------------------------------------------------------------------
console.log('\nScenario B: the ENGINE-UNAVAILABLE error path blocks everything + flips the chip.');
chip.textContent = '✓ Tool ready';   // pretend the on-load health probe had said ready
I.markScanFailed(true);              // engineOffline=true (e.g. "could not be started")
const b = I.getScanState();
ok(b.scanFailed === true, 'markScanFailed set the explicit scanFailed flag');
ok(b.cands === undefined, 'markScanFailed cleared cands (no successful scan to show)');
ok(I.canEnter('review') === false, 'Review is RE-LOCKED on a scan error (not a clean empty result)');
ok(I.canEnter('sensitive') === false, 'Sensitive passages RE-LOCKED on a scan error');
ok(I.canEnter('export') === false, 'Export RE-LOCKED on a scan error');
ok(chip.textContent === 'Tool offline',
  'the "✓ Tool ready" chip FLIPPED to "Tool offline" on an engine-unavailable scan error');

// Belt-and-suspenders: even if a future path forged candidates back WITHOUT clearing
// scanFailed, the gates must stay locked (the explicit flag guards canEnter).
console.log('Defense-in-depth: forge cands back but leave scanFailed set.');
I.setScanState({ cands: [{ id: 0, tier: 'quick-confirm', start: 0, end: 4 }] });
ok(I.getScanState().scanFailed === true, 'precondition: scanFailed still set');
ok(I.canEnter('review') === false,
  'forged cands with scanFailed set -> Review STILL locked (the flag guards the gate)');

// --------------------------------------------------------------------------------------
console.log('\nScenario C: a per-file INPUT error blocks the stages but does NOT lie about the tool.');
chip.textContent = '✓ Tool ready';
I.setScanState({ scanFailed: false, cands: [] });   // reset to a clean baseline
I.markScanFailed(false);                             // engineOffline=false (e.g. "damaged file")
ok(I.getScanState().scanFailed === true, 'input-error scan still sets scanFailed (stages block)');
ok(I.canEnter('export') === false, 'input-error scan still RE-LOCKS Export');
ok(chip.textContent === '✓ Tool ready',
  'a per-file input error does NOT flip the chip offline (the engine is still available)');

// --------------------------------------------------------------------------------------
console.log('\nScenario D: recovery — a later SUCCESSFUL scan clears the error state.');
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'ok now',
  cands: [{ id: 0, tier: 'quick-confirm', start: 0, end: 2 }],
  decided: {}, scanFailed: false,
  scanProvenanceFile: null, scanProvenanceText: 'ok now'
});
ok(I.getScanState().scanFailed === false, 'a successful scan cleared scanFailed');
ok(I.canEnter('review') === true, 'after recovery, Review is reachable again (no permanent block)');

console.log(failures === 0 ? '\nALL PASS' : '\n' + failures + ' FAILURE(S)');
process.exit(failures === 0 ? 0 : 1);
