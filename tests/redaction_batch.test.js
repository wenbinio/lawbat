'use strict';
/*
  Behavioral harness for BATCH (folder) mode's PER-FILE REVIEW ISOLATION invariant:
  switching from one batch file to another must FULLY wipe the live scan-derived state
  (candidates / decided decisions / provenance), so one file's review decisions or
  acknowledgements can NEVER leak into another file — the load-bearing batch invariant.

  It also proves each file's captured DECISION is plain per-file data: capturing file A's
  decision stores it on A's entry and leaves B's entry untouched.

  Loads the assembled redaction JS (base.js + every fragment) under a minimal DOM shim and
  drives the real __redactionInternals.batch seam + setScanState/getScanState. Air-gapped,
  deterministic, no network.

  Usage: node tests/redaction_batch.test.js <path-to-assembled-redaction.js>
  Exits 0 on all-pass ("ALL PASS"), 1 on any failure (driven by tests/test_smoke.py).
*/
const fs = require('fs');

function makeEl(id){
  const listeners = {};
  const el = {
    id: id || '', value: '', files: [], hidden: false, disabled: false,
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
if (!jsPath){ console.error('usage: node redaction_batch.test.js <assembled.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I || !I.batch){ console.error('FAIL: __redactionInternals.batch not exposed'); process.exit(1); }

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

console.log('Scenario: review file A -> switch to file B -> A\'s decisions must NOT leak into B');

// Two batch files, A currently active.
const A = { rel: 'a.txt', name: 'a.txt', status: 'scanned', decision: null, reviewed: false, exported: false };
const B = { rel: 'b.txt', name: 'b.txt', status: 'scanned', decision: null, reviewed: false, exported: false };
I.batch.setState([A, B], 'a.txt');

// A completed text scan of A, with a Tier-2 decision recorded (mirrors reviewing A).
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'file A secret text',
  cands: [{ start: 0, end: 4, tier: 'careful-review', recognizer: 'name' }],
  decided: { 0: true }, scanProvenanceText: 'file A secret text', scanProvenanceFile: null
});
ok(Object.keys(I.getScanState().decided).length === 1, 'precondition: A has a recorded decision');
ok(I.batch.getActive() === 'a.txt', 'precondition: A is the active batch file');

// The load-bearing switch: capture A's decision + wipe ALL live state before loading B.
I.batch.prepareSwitch();
const s = I.getScanState();

ok(s.cands === undefined, 'prepareSwitch WIPED live candidates (B cannot inherit A\'s findings)');
ok(Object.keys(s.decided).length === 0, 'prepareSwitch WIPED the decided{} set (B cannot inherit A\'s decisions)');
ok(s.scannedText === null && s.scanProvenanceText === null,
  'prepareSwitch cleared A\'s scanned text + provenance (a stale span can\'t apply to B)');
ok(I.batch.getActive() === null, 'prepareSwitch cleared the active-file pointer (set on the next open)');

// A's decision was CAPTURED onto A's entry; B's entry is UNTOUCHED (no cross-file write).
ok(A.decision !== null && A.decision.kind === 'text', 'A\'s decision was captured onto A\'s own entry');
ok(B.decision === null, 'B\'s entry was NOT written by capturing A (no cross-file leak)');

// Now "load" B (a fresh scan) and prove its live state is independent of A.
I.setScanState({
  mode: 'text', pdfFile: null, scannedText: 'file B different text',
  cands: [{ start: 0, end: 4, tier: 'quick-confirm', recognizer: 'email' }],
  decided: {}, scanProvenanceText: 'file B different text', scanProvenanceFile: null
});
const sb = I.getScanState();
ok(Object.keys(sb.decided).length === 0, 'B starts with an EMPTY decided{} (A\'s ack/keep never carried over)');
ok(sb.scannedText === 'file B different text', 'B\'s live text is its own, not A\'s');

// Switching back to A must AGAIN wipe live state (symmetry — no B->A leak either).
I.batch.setState([A, B], 'b.txt');
I.batch.prepareSwitch();
ok(I.getScanState().cands === undefined && Object.keys(I.getScanState().decided).length === 0,
  'switching B -> A also wipes live state (isolation is symmetric)');

// ---------------------------------------------------------------------------------------
console.log('\nScenario: re-opening a reviewed file RESTORES its stored decision (leak-class):');
console.log('  a re-open must show the lawyer\'s manual deviations, not engine DEFAULTS —');
console.log('  else the next exit-capture would overwrite the decision with defaults.');

// A captured decision now carries a DECIDED snapshot, so a re-open can restore the gate state.
I.setScanState({ mode: 'text', decided: { 0: true, 2: true } });
var capturedTextDec = I.batch.currentDecision();
ok(capturedTextDec && capturedTextDec.decided && capturedTextDec.decided[0] === true &&
   capturedTextDec.decided[2] === true,
  'currentDecision() captures the careful-review DECIDED snapshot (for faithful restore)');

// computeRestoreAccept (PURE): match a stored TEXT decision's accept-spans back onto a fresh
// re-scan's candidates by byte span. Here the lawyer opted IN #0 + #2 and OUT of #1.
var textCands = [
  { start: 0,  end: 4  }, // opted IN
  { start: 10, end: 15 }, // opted OUT (default was on)
  { start: 20, end: 24 }  // advisory opted IN
];
var textDec = { kind: 'text', accept: [[0, 4], [20, 24]] };
var accText = I.batch.computeRestoreAccept(textCands, 'text', textDec);
ok(accText[0] === 1 && accText[2] === 1 && accText[1] !== 1,
  'text restore accepts EXACTLY the stored spans (opt-INs kept, opt-OUT stays off)');

// PDF: match a stored decision's accept_ids back onto a fresh re-scan's candidate ids.
var pdfCands = [ { id: 'p1' }, { id: 'p2' }, { id: 'p3' } ];
var pdfDec = { kind: 'pdf', accept_ids: ['p1', 'p3'] };
var accPdf = I.batch.computeRestoreAccept(pdfCands, 'pdf', pdfDec);
ok(accPdf[0] === 1 && accPdf[2] === 1 && accPdf[1] !== 1,
  'pdf restore accepts EXACTLY the stored ids (by stable id, order-independent)');

// HONEST degradation: if the re-scan no longer surfaces a stored candidate (e.g. the options
// changed since capture), that decision is simply NOT restored — never mis-applied to a
// different span/id. The surviving finding is still restored.
var shrunk = [ { start: 0, end: 4 } ];   // the [20,24] finding is gone this scan
var accShrunk = I.batch.computeRestoreAccept(shrunk, 'text', textDec);
ok(accShrunk[0] === 1 && Object.keys(accShrunk).length === 1,
  'a stored decision for a now-absent candidate degrades safely (only present ones restore)');

// An empty / null decision restores NOTHING (default-deny; never invents an accept).
ok(Object.keys(I.batch.computeRestoreAccept(textCands, 'text', { kind: 'text', accept: [] })).length === 0,
  'an empty accept-set restores nothing');
ok(Object.keys(I.batch.computeRestoreAccept(textCands, 'text', null)).length === 0,
  'a null decision restores nothing');

// ---------------------------------------------------------------------------------------
console.log('\nScenario: candidate-set FINGERPRINT gates the restore (re-open never silently');
console.log('  stays "reviewed" when the findings changed) + currentDecision captures cand_key.');

// currentDecision() now fingerprints the candidate set so a re-open can verify identity.
I.setScanState({ mode: 'text', cands: [{ start: 0, end: 4 }, { start: 10, end: 15 }], decided: {} });
var fpDec = I.batch.currentDecision();
ok(Array.isArray(fpDec.cand_key) && fpDec.cand_key.join(',') === '0:4,10:15',
  'currentDecision() records the candidate fingerprint (cand_key) for re-open verification');

var savedText = { kind: 'text', accept: [[0, 4]], cand_key: ['0:4', '10:15'] };
ok(I.batch.candidateSetMatches([{ start: 0, end: 4 }, { start: 10, end: 15 }], savedText) === true,
  'candidateSetMatches: an identical fresh candidate set matches the stored fingerprint');
ok(I.batch.candidateSetMatches([{ start: 0, end: 4 }, { start: 99, end: 104 }], savedText) === false,
  'candidateSetMatches: a CHANGED candidate set does NOT match (re-open forces re-check)');
ok(I.batch.candidateSetMatches([{ start: 0, end: 4 }], { kind: 'text', accept: [] }) === false,
  'candidateSetMatches: a decision with NO fingerprint is treated as changed (safe over-block)');
var savedPdf = { kind: 'pdf', accept_ids: ['p1'], cand_key: ['p1', 'p2'] };
ok(I.batch.candidateSetMatches([{ id: 'p1' }, { id: 'p2' }], savedPdf) === true &&
   I.batch.candidateSetMatches([{ id: 'p1' }, { id: 'pX' }], savedPdf) === false,
  'candidateSetMatches: pdf id fingerprint matches identical ids, rejects changed ids');

// ---------------------------------------------------------------------------------------
console.log('\nScenario: re-open A after B — the lawyer\'s manual opt-in SURVIVES re-open AND the');
console.log('  export (the harness gap the review flagged): a defaults-only exit-capture the');
console.log('  lawyer did NOT interact with must NOT clobber the authoritative saved review.');

// A is reviewed with a RICH decision: the lawyer opted IN two spans (incl. an advisory), decided
// every careful-review item. This is the decision doBatchExport reads to build the export spec.
var richDec = { kind: 'text', accept: [[0, 4], [20, 24]], options: {}, format: 'txt',
                decided: { 0: true, 1: true, 2: true }, cand_key: ['0:4', '10:15', '20:24'] };
var RA = { rel: 'a.txt', name: 'a.txt', status: 'reviewed', decision: richDec, reviewed: true, exported: false };
var RB = { rel: 'b.txt', name: 'b.txt', status: 'scanned', decision: null, reviewed: false, exported: false };
I.batch.setState([RA, RB], 'a.txt');
// Simulate the re-open having restored A's decision onto a matching fresh scan (DOM==decision),
// with NO subsequent lawyer edit (dirty=false) — exactly the openBatchFile post-restore state.
I.setScanState({ mode: 'text', pdfFile: null,
  cands: [{ start: 0, end: 4 }, { start: 10, end: 15 }, { start: 20, end: 24 }], decided: {} });
I.batch.setDirty(false);
I.batch.captureCurrentDecision();
ok(RA.decision === richDec, 'un-edited re-opened reviewed file KEEPS its authoritative decision (opt-ins survive)');
ok(RA.decision.accept.length === 2 && RA.status === 'reviewed',
  'the stored opt-in accept-set is intact after the exit-capture (export reads THIS, so the opt-in exports)');
// And the guard is CONDITIONAL: once the lawyer actually edits (dirty), the capture refreshes
// the decision from the live review (so a genuine change is never lost either).
I.batch.setDirty(true);
I.batch.captureCurrentDecision();
ok(RA.decision !== richDec,
  'once the lawyer EDITS (dirty), capture refreshes the decision from the live review');

console.log(failures === 0 ? '\nALL PASS' : '\n' + failures + ' FAILURE(S)');
process.exit(failures === 0 ? 0 : 1);
