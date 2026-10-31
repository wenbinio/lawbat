'use strict';
/*
  Regression harness for the redaction reviewer's leak-direction fix (review findings #1/#2):
  a NEW document must reset ALL scan-derived state + re-lock the gates, and an apply must be
  blocked by a provenance fail-safe when the loaded document isn't the one that was scanned.

  Loads app/ui/redaction.js (the real IIFE) under a minimal DOM shim and drives the actual
  resetScanState / registerUpload / scanProvenanceMatches / canEnter functions via the
  window.__redactionInternals test seam. Air-gapped, deterministic, no network.

  Usage: node tests/redaction_reset_guard.test.js <path-to-redaction.js>
  Exits 0 on all-pass, 1 on any failure (drives tests/test_smoke.py).
*/
const fs = require('fs');

function makeEl(id){
  const listeners = {};
  const el = {
    id: id || '', value: '', files: [],
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
if (!jsPath){ console.error('usage: node redaction_reset_guard.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I){ console.error('FAIL: __redactionInternals not exposed'); process.exit(1); }

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

const fileA = { name: 'A.pdf' };
const fileB = { name: 'B.pdf' };

console.log('Scenario: scan A (clean, unmapped_fonts=false) -> load B (unmapped) -> export');

// A completed CLEAN scan of A (mirrors doPdfScan's success path).
I.setScanState({
  mode: 'pdf', pdfFile: fileA, scannedText: null,
  cands: [{ id: 0, tier: 'quick-confirm', start: 0, end: 4 }],
  decided: {}, lastUnmappedFonts: false, lastLowText: false,
  scanProvenanceFile: fileA, scanProvenanceText: null
});
ok(I.scanProvenanceMatches() === true, 'after scanning A, provenance matches (apply would proceed)');
ok(I.canEnter('review') === true, 'after scanning A, Review is reachable');

// Load B via the REAL registerUpload (the path the bug took).
I.registerUpload(fileB);
const s = I.getScanState();

// Finding #1 — scan-derived state reset (no inherited findings / "clean" flags / decisions).
ok(s.cands === undefined, 'registerUpload(B) reset window.__cands to undefined (no inherited findings)');
ok(s.lastUnmappedFonts === false && s.scanProvenanceFile === null,
  'registerUpload(B) cleared scan flags + provenance (lastUnmappedFonts reset, provenance dropped)');
ok(Object.keys(s.decided).length === 0, 'registerUpload(B) reset the decided{} set');
ok(s.pdfFile === fileB, 'registerUpload(B) adopted B as the loaded file');

// Finding #1 — gates RE-LOCKED (Review/Export unreachable without a fresh scan).
ok(I.canEnter('review') === false, 'after loading B without a re-scan, Review is RE-LOCKED');
ok(I.canEnter('export') === false, 'after loading B without a re-scan, Export is RE-LOCKED');

// Provenance fail-safe — an apply now is BLOCKED.
ok(I.scanProvenanceMatches() === false,
  'after loading B without a re-scan, provenance does NOT match -> export FAILS SAFE');

// Defense-in-depth: even if a future path skips the reset, the guard still blocks. Forge
// A's candidates + A's clean flag but with B loaded, and confirm the guard refuses.
console.log('Defense-in-depth: forge stale A-state with B loaded (simulate a missed reset)');
I.setScanState({
  mode: 'pdf', pdfFile: fileB, scannedText: null,
  cands: [{ id: 0, tier: 'quick-confirm' }], lastUnmappedFonts: false,
  scanProvenanceFile: fileA, scanProvenanceText: null
});
ok(I.scanProvenanceMatches() === false,
  'stale A-provenance with B loaded -> provenance guard BLOCKS the apply (no inherited clean flag)');

// No false blocks: a legitimate matching scan+export proceeds.
I.setScanState({
  mode: 'pdf', pdfFile: fileB, scannedText: null,
  cands: [{ id: 0, tier: 'quick-confirm' }], lastUnmappedFonts: false,
  scanProvenanceFile: fileB, scanProvenanceText: null
});
ok(I.scanProvenanceMatches() === true, 'matching file provenance -> apply proceeds (no false block)');

// Text-mode provenance: unchanged text proceeds, changed text is blocked.
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'hello world',
  cands: [{ id: 0, tier: 'quick-confirm' }],
  scanProvenanceText: 'hello world', scanProvenanceFile: null
});
ok(I.scanProvenanceMatches() === true, 'text mode: unchanged scanned text -> apply proceeds');
I.setScanState({ scannedText: 'hello WORLD changed' });
ok(I.scanProvenanceMatches() === false, 'text mode: changed text after scan -> apply BLOCKED');

// ---------------------------------------------------------------------------------------
// Finding #1 — resetScanState() must WIPE the prior document's re-identification KEY out of
// the DOM (not just hide its parent). The key seam (#reidentKeySeam) holds [A] = <real name>
// cleartext until the next apply; hiding alone left it in innerHTML (in-memory matter residue).
console.log('\nFinding #1: resetScanState clears the re-identification KEY seam (#reidentKeySeam)');
const keySeam = getEl('reidentKeySeam');
keySeam.innerHTML = '<div class="keycard">[A] = Daniel J. Watkins</div>';   // a prior apply's key
ok(keySeam.innerHTML !== '', 'precondition: the key seam carries the prior document\'s key');
I.resetScanState();
ok(keySeam.innerHTML === '',
  'resetScanState() WIPED the re-identification key out of #reidentKeySeam (no cleartext residue)');

// ---------------------------------------------------------------------------------------
// Finding #2 — resetScanState() must CLEAR the prior document's OCR page RASTERS (matter-
// content page images in #imgPages) + their summary; hiding #imgreview alone left them.
console.log('Finding #2: resetScanState clears the OCR page RASTERS (#imgPages / #imgSummary)');
const imgPagesEl = getEl('imgPages');
const imgSummaryEl = getEl('imgSummary');
imgPagesEl.innerHTML = '<div class="img-page"><img src="data:image/png;base64,AAAA"></div>';  // a prior OCR review
imgSummaryEl.innerHTML = '<b>3</b> identifiers detected';
ok(imgPagesEl.innerHTML !== '', 'precondition: #imgPages carries the prior document\'s page rasters');
I.resetScanState();
ok(imgPagesEl.innerHTML === '',
  'resetScanState() CLEARED the OCR page rasters out of #imgPages (no matter-image residue)');
ok(imgSummaryEl.innerHTML === '', 'resetScanState() cleared #imgSummary too');

// ---------------------------------------------------------------------------------------
// Finding #3 — typing on the box after an ORPHANED scan must supersede it: route through
// resetScanState() so __cands/flags/decided drop and the gates re-lock — WITHOUT wiping the
// user's typed text. Two orphan triggers: (a) a PDF was scanned then Back+typed (wasPdf);
// (b) the scanned text itself was edited.
console.log('Finding #3: typing after an orphaned PDF scan supersedes it (clears __cands, re-locks, keeps text)');
const inputEl = getEl('input');
function fireInput(){ (inputEl.__listeners.input || []).forEach(function(fn){ fn(); }); }

// (a) Scanned a PDF (mode='pdf', __cands set), then navigated Back and typed in the box.
I.setScanState({
  mode: 'pdf', pdfFile: fileA, scannedText: null,
  cands: [{ id: 0, tier: 'quick-confirm', start: 0, end: 4 }],
  decided: {}, lastUnmappedFonts: true, lastLowText: false,
  scanProvenanceFile: fileA, scanProvenanceText: null
});
ok(I.canEnter('review') === true, 'precondition (a): after scanning A (PDF), Review is reachable');
inputEl.value = 'the user is now typing new text';   // the typed text the reset must NOT wipe
fireInput();
let s3 = I.getScanState();
ok(s3.cands === undefined,
  '(a) typing after an orphaned PDF scan cleared window.__cands (no inherited findings/caveat)');
ok(I.canEnter('review') === false, '(a) Review is RE-LOCKED after the orphaned-scan reset');
ok(I.canEnter('export') === false, '(a) Export is RE-LOCKED after the orphaned-scan reset');
ok(inputEl.value === 'the user is now typing new text',
  '(a) the user\'s typed text was PRESERVED (resetScanState did NOT wipe #input)');

// (b) Scanned text, then edited it (text diverged from scannedText) -> also supersedes.
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'original scanned text',
  cands: [{ id: 0, tier: 'quick-confirm' }], decided: {},
  scanProvenanceText: 'original scanned text', scanProvenanceFile: null
});
inputEl.value = 'original scanned text EDITED';
fireInput();
s3 = I.getScanState();
ok(s3.cands === undefined,
  '(b) editing scanned text cleared window.__cands (the old coordinates no longer match)');
ok(inputEl.value === 'original scanned text EDITED', '(b) the edited text was PRESERVED');

// No false supersede: typing with no prior scan (__cands undefined) is a no-op reset path.
I.setScanState({ mode: 'text', pdfFile: null, scannedText: null });
window.__cands = undefined;
inputEl.value = 'fresh typing, never scanned';
fireInput();
ok(I.getScanState().cands === undefined && inputEl.value === 'fresh typing, never scanned',
  'no prior scan -> typing is a benign no-op (text kept, gates already locked)');

console.log(failures === 0 ? '\nALL PASS' : '\n' + failures + ' FAILURE(S)');
process.exit(failures === 0 ? 0 : 1);
