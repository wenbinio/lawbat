'use strict';
/*
  Behavioral harness for INTERACTIVE per-span PDF redaction (deselect before apply).

  The reviewer can DESELECT individual detections before applying. The selectable universe =
  ALL scan candidates; default = EVERY candidate SELECTED, so an untouched review is exactly
  today's apply-all. This harness drives the REAL redaction.js functions (acceptedPdfIds /
  updatePdfRedactCount) via the window.__redactionInternals seam under a minimal DOM that
  models the #review memberbox checkboxes, and proves the carrier-critical invariants:

    (a) default = ALL NON-ADVISORY ids -> apply-all equivalence over the PRECISE candidates
                                    (untouched == today's full precise id list); an ADVISORY
                                    (aggressive-recognizer) candidate is DEFAULT-OFF and is
                                    EXCLUDED from accept_ids unless the human opts it in.
    (b) subset selection         -> ONLY those ids are sent (a deselect EXCLUDES its id)
    (c) empty selection          -> acceptedPdfIds() == [] (the apply path REFUSES this -> no
                                    clean "redacted" file; default-deny in the engine too)
    (d) a toggle changes payload -> deselect then re-select round-trips the id set
    (e) the "N of M" count       -> tracks the SELECTED count, never disagrees with the payload
    (f) a no-id SELECTED cand     -> fail-CLOSED: counted in N + reported via missingId, NEVER
                                    silently dropped from accept_ids (the engine has no ordinal
                                    fallback, so an omitted-but-counted id would be a leak)
    (g) ADVISORY carrier invariant -> an advisory candidate is (i) EXCLUDED from accept_ids by
                                    default (default-OFF), (ii) ADDED to accept_ids when ticked
                                    (round-trip), (iii) NEVER in accept_ids while untouched
                                    (over-redaction proof — an aggressive hit is never redacted
                                    unless the human opts in).

  Air-gapped, deterministic, no network.

  Usage: node tests/redaction_pdf_selection.test.js <path-to-redaction.js>
  Exits 0 on all-pass, 1 on any failure (driven by tests/test_smoke.py).
*/
const fs = require('fs');

// ---- a small DOM that models the #review memberbox checkboxes -------------------------
// Each "candidate row" is a checkbox carrying data-idx (its window.__cands index). The DOM
// only needs to answer the two selectors redaction.js uses:
//   #review input.memberbox:checked     (acceptedPdfIds / updatePdfRedactCount)
//   #review input.memberbox[data-idx=N] (isChecked, etc — not exercised here)
// plus getElementById('pdfRedactCount') for the live count.

function makeCheckbox(idx, checkedDefault){
  return {
    // The DEFAULT checkbox state mirrors candRow: a PRECISE candidate is default-CHECKED
    // (the PDF "untick to keep" model); an ADVISORY (aggressive) candidate is default-OFF
    // (`checked && !advisory` in candRow) — so the harness models exactly what render emits.
    _checked: checkedDefault === undefined ? true : !!checkedDefault,
    classList: { contains(c){ return c === 'memberbox'; } },
    get checked(){ return this._checked; },
    set checked(v){ this._checked = !!v; },
    getAttribute(name){ return name === 'data-idx' ? String(idx) : null; },
    closest(){ return null; }
  };
}

const boxes = [];                   // one per candidate, by idx
const countEl = (function(){
  let _h = '', _c = '';
  return {
    id: 'pdfRedactCount',
    get innerHTML(){ return _h; }, set innerHTML(v){ _h = v; },
    get className(){ return _c; }, set className(v){ _c = v; },
    get textContent(){ return _h.replace(/<[^>]*>/g, ''); }
  };
}());

function makeStubEl(id){
  let _t = '', _h = '';
  return {
    id: id || '', value: '', files: [],
    classList: { add(){}, remove(){}, toggle(){ return false; }, contains(){ return false; } },
    style: {}, setAttribute(){}, getAttribute(){ return null; }, removeAttribute(){},
    addEventListener(){}, removeEventListener(){},
    querySelector(){ return null; }, querySelectorAll(){ return []; },
    appendChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
    get textContent(){ return _t; }, set textContent(v){ _t = v; },
    get innerHTML(){ return _h; }, set innerHTML(v){ _h = v; }
  };
}

const stubEls = {};
global.window = global;
global.addEventListener = function(){};
global.removeEventListener = function(){};
global.document = {
  getElementById(id){
    if (id === 'pdfRedactCount') return countEl;
    return (stubEls[id] = stubEls[id] || makeStubEl(id));
  },
  querySelector(){ return null; },
  querySelectorAll(sel){
    // The only selector the per-span code uses against the review list.
    if (sel === '#review input.memberbox:checked'){
      return boxes.filter(function(b){ return b && b.checked; });
    }
    return [];
  },
  addEventListener(){}, createElement(){ return makeStubEl(''); },
  get activeElement(){ return null; }, body: makeStubEl('body')
};
global.localStorage = { getItem(){ return null; }, setItem(){}, removeItem(){} };
try { Object.defineProperty(global, 'navigator', { value: {}, configurable: true }); } catch (e){ /* keep */ }
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
global.fetch = async function(){ return { ok: false, status: 0, json: async () => ({}) }; };
global.setTimeout = function(){ return 0; };
global.FileReader = function(){ this.readAsDataURL = function(){ if (this.onload) this.onload(); }; };
global.scrollTo = function(){};

const jsPath = process.argv[2];
if (!jsPath){ console.error('usage: node redaction_pdf_selection.test.js <redaction.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__redactionInternals;
if (!I){ console.error('FAIL: __redactionInternals not exposed'); process.exit(1); }
if (typeof I.acceptedPdfIds !== 'function' || typeof I.updatePdfRedactCount !== 'function'){
  console.error('FAIL: acceptedPdfIds / updatePdfRedactCount not exposed on the seam');
  process.exit(1);
}

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }
function eqArr(a, b){ return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every(function(x, i){ return x === b[i]; }); }

// Build a PDF scan of 4 candidates with stable ids [10, 11, 12, 13]. Each id maps to a
// checkbox (default SELECTED). Drive the REAL functions over this DOM.
function setupScan(){
  boxes.length = 0;
  const cands = [
    { id: 10, tier: 'quick-confirm', page: 1, value: 'a' },
    { id: 11, tier: 'careful',        page: 1, value: 'b' },
    { id: 12, tier: 'quick-confirm', page: 2, value: 'c' },
    { id: 13, tier: 'careful',        page: 3, value: 'd' }
  ];
  // Default-checked state mirrors candRow: precise -> checked, advisory -> unchecked.
  cands.forEach(function(c, idx){ boxes[idx] = makeCheckbox(idx, !c.advisory); });
  I.setScanState({ mode: 'pdf', pdfFile: { name: 'doc.pdf' }, cands: cands, decided: {} });
  return cands;
}

// A scan that ALSO carries an ADVISORY (aggressive-recognizer) candidate (id 14). It is
// default-OFF (its checkbox starts unchecked, exactly as candRow renders an advisory row).
function setupScanWithAdvisory(){
  boxes.length = 0;
  const cands = [
    { id: 10, tier: 'quick-confirm', page: 1, value: 'a' },
    { id: 11, tier: 'careful',        page: 1, value: 'b' },
    { id: 12, tier: 'quick-confirm', page: 2, value: 'c' },
    { id: 13, tier: 'careful',        page: 3, value: 'd' },
    { id: 14, tier: 'careful',        page: 3, value: 'e', recognizer: 'sg:nric-loose', advisory: true }
  ];
  cands.forEach(function(c, idx){ boxes[idx] = makeCheckbox(idx, !c.advisory); });
  I.setScanState({ mode: 'pdf', pdfFile: { name: 'doc.pdf' }, cands: cands, decided: {} });
  return cands;
}
function setChecked(idx, v){ boxes[idx].checked = v; }

console.log('Interactive per-span PDF redaction — selection -> accept_ids');

// (a) DEFAULT = ALL NON-ADVISORY ids -> apply-all equivalence over the PRECISE candidates. An
//     untouched review sends EXACTLY the full PRECISE id list (the same request today's
//     apply-all sends; redact-cli has NO ::all() path — apply-all IS the explicit id list — so
//     this all-precise-ids payload IS the equivalence). (All 4 here are precise -> all 4.)
setupScan();
const allIds = I.acceptedPdfIds();
ok(eqArr(allIds, [10, 11, 12, 13]),
  '(a) default (all precise, nothing changed) -> accept_ids = ALL precise ids [10,11,12,13] (apply-all equivalence)');

// (b) SUBSET -> only the selected ids. Deselect id 11 (idx 1) and id 13 (idx 3).
setChecked(1, false);
setChecked(3, false);
const subset = I.acceptedPdfIds();
ok(eqArr(subset, [10, 12]),
  '(b) deselecting two -> accept_ids = ONLY the remaining [10,12] (a deselect EXCLUDES its id)');

// (d) a TOGGLE changes the payload — re-select id 11, payload grows back.
setChecked(1, true);
const afterReselect = I.acceptedPdfIds();
ok(eqArr(afterReselect, [10, 11, 12]),
  '(d) re-selecting id 11 -> accept_ids becomes [10,11,12] (a toggle changes the apply payload)');
ok(!eqArr(afterReselect, subset),
  '(d) the payload genuinely DIFFERS before vs after the toggle (not a no-op)');

// (c) EMPTY selection -> acceptedPdfIds() == []. The apply path REFUSES this (no clean
//     "redacted" file written); the engine is default-deny on an empty set too.
setupScan();
[0, 1, 2, 3].forEach(function(i){ setChecked(i, false); });
const empty = I.acceptedPdfIds();
ok(eqArr(empty, []),
  '(c) deselecting EVERY detection -> accept_ids = [] (apply REFUSES -> no unredacted "redacted" file)');

// (e) the "N of M" count tracks the SELECTED count and never disagrees with the payload.
setupScan();
I.updatePdfRedactCount();
ok(/<b>4<\/b> of <b>4<\/b>/.test(countEl.innerHTML),
  '(e) count after scan = "4 of 4 detections will be redacted"');
ok(countEl.className.indexOf('warn') === -1, '(e) full selection -> count is NOT in the warn state');

setChecked(0, false);
I.updatePdfRedactCount();
ok(/<b>3<\/b> of <b>4<\/b>/.test(countEl.innerHTML),
  '(e) after one deselect -> count = "3 of 4"');
// The count N must equal the acceptedPdfIds length (single source of truth — they can't drift).
ok(I.acceptedPdfIds().length === 3, '(e) count N (3) matches the accept_ids length (3) — no drift');

[1, 2, 3].forEach(function(i){ setChecked(i, false); });
I.updatePdfRedactCount();
ok(/<b>0<\/b> of <b>4<\/b>/.test(countEl.innerHTML), '(e) all-deselected -> count = "0 of 4"');
ok(countEl.className.indexOf('warn') !== -1,
  '(e) zero-selected -> count enters the WARN state (re-select prompt shown)');
ok(/re-select/i.test(countEl.innerHTML), '(e) zero-selected -> count copy prompts a re-select');

// (#7) FAIL-CLOSED on a SELECTED candidate with NO usable id. The engine's PdfSelection
// accepts PURELY by id membership — there is NO ordinal/positional fallback (verified in
// core/crates/redaction/src/pdf.rs `PdfSelection::accepts`: `Only(s) => s.contains(&id.0)`).
// So a :checked no-id candidate that was COUNTED as "will be redacted" but OMITTED from
// accept_ids would be a SILENT UNDER-removal (fail-OPEN leak). The contract is therefore:
//   - the no-id candidate is STILL SELECTED + counted (the non-located-still-removed
//     invariant: the user sees it as "to be redacted"), AND
//   - it is surfaced via selectedPdfCandidates().missingId so the apply path FAILS CLOSED
//     (doPdfExport refuses the whole save) instead of dropping it from removal, AND
//   - acceptedPdfIds() carries only the id-bearing candidate (the count >= ids.length gap
//     is EXACTLY missingId — it can never be silently swallowed).
// This case is written so that a future change making ids "optional" (resolved by ordinal)
// can NOT be blessed by a green test: it would have to make missingId == 0 with a no-id
// candidate, which contradicts the assertions below.
boxes.length = 0;
const mixed = [{ id: 20, tier: 'quick-confirm', value: 'x' }, { tier: 'careful', value: 'y' /* no id */ }];
mixed.forEach(function(c, idx){ boxes[idx] = makeCheckbox(idx); });
I.setScanState({ mode: 'pdf', pdfFile: { name: 'm.pdf' }, cands: mixed, decided: {} });
I.updatePdfRedactCount();
ok(/<b>2<\/b> of <b>2<\/b>/.test(countEl.innerHTML),
  '(#7) a no-id candidate is still SELECTED + counted ("2 of 2") — not silently dropped from the tally');
const cls = I.selectedPdfCandidates();
ok(cls.selected === 2,
  '(#7) selectedPdfCandidates().selected counts BOTH checked candidates (= the displayed N)');
ok(cls.missingId === 1,
  '(#7) the no-id candidate is reported via missingId === 1 (fail-closed signal, NOT a silent drop)');
ok(eqArr(cls.ids, [20]) && eqArr(I.acceptedPdfIds(), [20]),
  '(#7) accept_ids carries ONLY the id-bearing candidate [20]; the no-id one is NOT in the payload');
ok(cls.selected - cls.ids.length === cls.missingId,
  '(#7) the count↔payload gap (selected - ids.length) is EXACTLY missingId — it can never be silently swallowed');

// (g) ADVISORY carrier invariant — the per-span default changes from "ALL ids ON" to "all
//     NON-ADVISORY ids ON; advisory ids OFF". An advisory (aggressive-recognizer) candidate is
//     surfaced but DEFAULT-OFF: it is EXCLUDED from accept_ids unless the human ticks it.
setupScanWithAdvisory();
// (g)(i) EXCLUDED by default: the advisory id 14 is NOT in the default accept_ids, while every
//        precise id IS — the default apply set is the precise universe only.
const defAdv = I.acceptedPdfIds();
ok(eqArr(defAdv, [10, 11, 12, 13]),
  '(g)(i) default accept_ids EXCLUDES the advisory id 14 -> [10,11,12,13] (advisory is default-OFF)');
ok(defAdv.indexOf(14) === -1,
  '(g)(iii) over-redaction proof: an UNTOUCHED advisory candidate is NEVER in accept_ids');
// The live count reflects 4 of 5 selected (the advisory one is not selected by default).
I.updatePdfRedactCount();
ok(/<b>4<\/b> of <b>5<\/b>/.test(countEl.innerHTML),
  '(g) count = "4 of 5" — the advisory detection is present but not selected by default');
ok(/possible|aggressive|not selected/i.test(countEl.innerHTML),
  '(g) the count note states the advisory hit is not selected unless opted into');
// (g)(ii) TICKING adds its id (round-trip): opt the advisory candidate in -> id 14 appears.
setChecked(4, true);
const optedIn = I.acceptedPdfIds();
ok(optedIn.indexOf(14) !== -1 && eqArr(optedIn, [10, 11, 12, 13, 14]),
  '(g)(ii) ticking the advisory candidate ADDS id 14 -> [10,11,12,13,14] (opt-in round-trip)');
// And un-ticking it removes it again (the round-trip is symmetric — never sticky-on).
setChecked(4, false);
ok(I.acceptedPdfIds().indexOf(14) === -1,
  '(g)(ii) un-ticking the advisory candidate REMOVES id 14 again (symmetric round-trip)');

console.log(failures === 0 ? '\nALL PASS' : '\n' + failures + ' FAILURE(S)');
process.exit(failures === 0 ? 0 : 1);
