'use strict';
/*
  Differential harness for the RE-IDENTIFICATION RISK estimator renderers on the reid-risk
  page. Loads the REAL app/ui/reidrisk.js (the IIFE) under a minimal DOM shim and drives the
  actual renderEstimate() / renderRelease() / concernClass() via the
  window.__reidriskInternals test seam. Air-gapped, deterministic, no network.

  Proves the load-bearing invariants:
    * deterministic render — the same score produces byte-identical innerHTML;
    * HONESTY present — the rendered output carries the estimate framing ("ESTIMATE",
      "under-state", "NOT a safety verdict" / "never 'safe to send'"); the word "safe" only
      ever appears NEGATED (never a standalone "safe to send");
    * concernClass — known concerns map to their suffix; a hostile string degrades to the
      safe default and never injects raw markup into a class;
    * escaping — a hostile entity_name / contribution.value is esc'd (no raw <img> tag);
    * insufficient_data — k=null / concern=insufficient_data renders the honest "insufficient
      data (NOT a low-risk finding)" message and NEVER a "safe"/"clear" state;
    * coverage shown — the "matched N of M" coverage_note appears;
    * release render — renderRelease shows the linked entity, its doc_ids, and the
      linkage_caveat ("ABSENCE of linkage is NOT proof").

  Usage: node tests/reidrisk_render.test.js <path-to-reidrisk.js>
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
    appendChild(){}, removeChild(){}, focus(){}, click(){}, closest(){ return null; }, scrollIntoView(){},
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
global.Promise = Promise;

const jsPath = process.argv[2];
if (!jsPath){ console.error('usage: node reidrisk_render.test.js <reidrisk.js>'); process.exit(2); }
const src = fs.readFileSync(jsPath, 'utf8');
(0, eval)(src);

const I = global.__reidriskInternals;
if (!I || typeof I.renderEstimate !== 'function' || typeof I.renderRelease !== 'function'
    || typeof I.concernClass !== 'function' || typeof I.esc !== 'function'){
  console.error('FAIL: __reidriskInternals not fully exposed'); process.exit(1);
}

let failures = 0;
function ok(cond, msg){ if (cond){ console.log('  PASS: ' + msg); } else { console.log('  FAIL: ' + msg); failures++; } }

// Collect ALL element innerHTML/textContent into one blob for honesty/escaping assertions.
function allHtml(){
  let blob = '';
  for (const k in elements){
    const e = elements[k];
    blob += (e.innerHTML || '') + '\n' + (e.textContent || '') + '\n';
  }
  return blob;
}
function allClasses(){
  let blob = '';
  for (const k in elements){ blob += (elements[k].className || '') + '\n'; }
  return blob;
}

// A representative /api/reidrisk/score response (the shape from the spec).
const score = {
  k_estimate: 9944.3, p_tuple: 0.00238, population_N: 4180000, jurisdiction: 'SG',
  prosecutor_risk: 0.0001, journalist_risk: 0.0001, concern: 'elevated',
  contributions: [
    {category:'sex', value:'male', prob:0.4863, estimated_from_tail:false, in_product:true, note:''},
    {category:'region', value:'California', prob:0.9273, estimated_from_tail:true, in_product:true, note:'probability estimated from the residual tail...'},
    {category:'medical_condition', value:'diabetes', prob:null, estimated_from_tail:false, in_product:false, note:'medical: common — ...'}
  ],
  medical_tiers: [{condition:'diabetes', tier:'common', note:'common condition (~10% national prevalence) — a WEAK quasi-identifier; excluded from the k product'}],
  matched_qi_count: 4, detected_qi_count: 5,
  coverage_note: 'matched 4 of 5 detected quasi-identifier(s) against reference data; 1 medical condition(s) TIERED only (never priced into k)',
  is_estimate: true, assumes_independence: true, direction: 'optimistic — may under-state risk', not_a_safety_verdict: true,
  caveat: "k is an ESTIMATE under an independence assumption — an OPTIMISTIC lower bound that may UNDER-STATE risk; it is NOT a safety verdict and never means 'safe to send'.",
  entity_name: 'Smith', detected_categories: ['medical_condition','occupation','region','sex','surname'], unmatched_categories: []
};

console.log('Scenario 1: renderEstimate — basic render + coverage + prosecutor lead');
{
  I.renderEstimate(score);
  ok(!getEl('estCard').classList.contains('hidden'), 'estimate card is shown');
  ok(getEl('estK').innerHTML.indexOf('k-estimate') >= 0, 'k is labelled a k-estimate');
  ok(getEl('estK').innerHTML.indexOf('9,944') >= 0, 'k value 9,944 is formatted');
  ok(getEl('estProsecutor').innerHTML.toLowerCase().indexOf('prosecutor') >= 0, 'prosecutor metric is LED with');
  ok(getEl('coverageNote').innerHTML.indexOf('matched 4 of 5') >= 0, 'coverage "matched 4 of 5" shown in banner');
  ok(getEl('estCoverage').innerHTML.indexOf('matched 4 of 5') >= 0, 'coverage shown in the card');
  ok(getEl('estContribs').innerHTML.indexOf('male') >= 0, 'a contribution value renders');
  ok(getEl('estContribs').innerHTML.indexOf('estimated from tail') >= 0, 'estimated-from-tail note shown');
  ok(getEl('estMedical').innerHTML.toLowerCase().indexOf('diabetes') >= 0, 'medical tier condition renders');
  ok(getEl('concernBadge').className.indexOf('concern-elevated') >= 0, 'concern badge carries the allowlisted class');
}

console.log('Scenario 2: HONESTY present in the rendered output');
{
  I.renderEstimate(score);
  const blob = allHtml();
  ok(blob.indexOf('ESTIMATE') >= 0 || blob.indexOf('estimate') >= 0, 'the word ESTIMATE/estimate appears');
  const low = blob.toLowerCase();
  ok(low.indexOf('under-state') >= 0 || low.indexOf('under state') >= 0, 'says it may UNDER-STATE risk');
  ok(low.indexOf('not a safety verdict') >= 0 || low.indexOf("never 'safe to send'") >= 0
     || low.indexOf('never “safe to send”') >= 0 || low.indexOf('never &ldquo;safe to send') >= 0,
     'carries a "NOT a safety verdict" / "never safe to send" framing');
  // The word "safe" must only ever appear NEGATED — never a bare "safe to send".
  const idx = low.indexOf('safe to send');
  if (idx >= 0){
    const before = low.slice(Math.max(0, idx - 30), idx);
    ok(before.indexOf('never') >= 0 || before.indexOf('not') >= 0,
       '"safe to send" only appears negated (a "never"/"not" precedes it)');
  } else {
    ok(true, '"safe to send" does not appear bare');
  }
}

console.log('Scenario 3: concernClass — allowlist + hostile degrade');
{
  ok(I.concernClass('looks_unique') === 'looks_unique', 'looks_unique maps to its suffix');
  ok(I.concernClass('small_cohort') === 'small_cohort', 'small_cohort maps to its suffix');
  ok(I.concernClass('elevated') === 'elevated', 'elevated maps to its suffix');
  ok(I.concernClass('insufficient_data') === 'insufficient', 'insufficient_data maps to insufficient');
  const hostile = '"><img src=x onerror=alert(1)>';
  const cls = I.concernClass(hostile);
  ok(cls === 'insufficient' || cls === 'none', 'a hostile concern degrades to the safe default');
  ok(cls.indexOf('<') < 0 && cls.indexOf('img') < 0 && cls.indexOf('onerror') < 0,
     'the safe class never contains raw markup');
  // render with the hostile concern and check no raw tag reaches any class attribute.
  const hs = JSON.parse(JSON.stringify(score)); hs.concern = hostile;
  I.renderEstimate(hs);
  ok(allClasses().indexOf('<img') < 0 && allClasses().indexOf('onerror') < 0,
     'no hostile tag reaches any class attribute');
}

console.log('Scenario 4: escaping — hostile cleartext is esc\'d');
{
  const hs = JSON.parse(JSON.stringify(score));
  hs.entity_name = '<img src=x onerror=alert(1)>';
  hs.contributions[0].value = '<img src=x onerror=alert(2)>';
  hs.medical_tiers[0].condition = '<img src=x onerror=alert(3)>';
  hs.coverage_note = 'matched 4 of 5 <img src=x onerror=alert(4)>';
  I.renderEstimate(hs);
  const blob = allHtml();
  ok(blob.indexOf('<img src=x') < 0, 'the raw <img src=x substring never appears in innerHTML');
  ok(blob.indexOf('&lt;img src=x') >= 0, 'the hostile value was escaped (appears as &lt;img)');
}

console.log('Scenario 5: insufficient_data — honest message, no safe/clear state');
{
  const ins = {
    k_estimate: null, p_tuple: null, population_N: null, jurisdiction: null,
    prosecutor_risk: null, journalist_risk: null, concern: 'insufficient_data',
    contributions: [], medical_tiers: [], matched_qi_count: 0, detected_qi_count: 1,
    coverage_note: 'matched 0 of 1 detected quasi-identifier(s) against reference data; no QI could be priced — this is INSUFFICIENT DATA, not a low-risk finding',
    is_estimate: true, assumes_independence: true, direction: 'optimistic — may under-state risk', not_a_safety_verdict: true,
    caveat: "k is an ESTIMATE — never means 'safe to send'.",
    entity_name: null, detected_categories: ['region'], unmatched_categories: ['region']
  };
  I.renderEstimate(ins);
  const blob = allHtml().toLowerCase();
  ok(blob.indexOf('insufficient data') >= 0, 'renders the insufficient-data message');
  ok(blob.indexOf('not a low-risk finding') >= 0, 'says it is NOT a low-risk finding');
  ok(blob.indexOf('clear') < 0 || blob.indexOf('not clear') >= 0, 'no "clear" safe state rendered');
  ok(getEl('concernBadge').className.indexOf('concern-insufficient') >= 0, 'badge uses the insufficient class');
  // ensure no bare positive "safe" appears.
  const idx = blob.indexOf('safe to send');
  if (idx >= 0){
    const before = blob.slice(Math.max(0, idx - 30), idx);
    ok(before.indexOf('never') >= 0 || before.indexOf('not') >= 0, '"safe to send" stays negated in insufficient state');
  } else { ok(true, 'no bare "safe to send" in insufficient state'); }
}

console.log('Scenario 6: determinism — same score, byte-identical innerHTML');
{
  I.renderEstimate(score);
  const h1 = getEl('estK').innerHTML + '||' + getEl('estProsecutor').innerHTML + '||' +
    getEl('estContribs').innerHTML + '||' + getEl('estMedical').innerHTML + '||' +
    getEl('estCoverage').innerHTML + '||' + getEl('estCaveat').innerHTML + '||' +
    getEl('concernBadge').className;
  I.renderEstimate(score);
  const h2 = getEl('estK').innerHTML + '||' + getEl('estProsecutor').innerHTML + '||' +
    getEl('estContribs').innerHTML + '||' + getEl('estMedical').innerHTML + '||' +
    getEl('estCoverage').innerHTML + '||' + getEl('estCaveat').innerHTML + '||' +
    getEl('concernBadge').className;
  ok(h1 === h2, 'identical scores render byte-identical innerHTML');
}

console.log('Scenario 7: renderRelease — linked entity, doc_ids, linkage caveat');
{
  const report = {
    linked_entities: [{
      link_key: 'name:SMITH', name: 'Smith', doc_ids: ['Memo A', 'Memo B'],
      estimate: {
        k_estimate: 12.0, p_tuple: 0.0000029, population_N: 4180000, jurisdiction: 'SG',
        prosecutor_risk: 0.0833, journalist_risk: 0.0833, concern: 'small_cohort',
        contributions: [], medical_tiers: [], matched_qi_count: 3, detected_qi_count: 3,
        coverage_note: 'matched 3 of 3 detected quasi-identifier(s) against reference data',
        is_estimate: true, assumes_independence: true, direction: 'optimistic — may under-state risk', not_a_safety_verdict: true,
        caveat: "k is an ESTIMATE — never 'safe to send'."
      }
    }],
    n_docs: 2, n_linked_entities: 1, is_estimate: true, assumes_independence: true,
    direction: 'optimistic — may under-state risk', not_a_safety_verdict: true,
    linkage_caveat: 'Linkage FOUND is real; ABSENCE of linkage is NOT proof the documents are independent. Linkage is deterministic EXACT-KEY only ... it UNDER-links, so the release k is itself OPTIMISTIC. No fuzzy / role coreference...'
  };
  I.renderRelease(report);
  ok(!getEl('relCard').classList.contains('hidden'), 'release card is shown');
  ok(getEl('relEntities').innerHTML.indexOf('Smith') >= 0, 'the linked entity name renders');
  ok(getEl('relEntities').innerHTML.indexOf('Memo A') >= 0 && getEl('relEntities').innerHTML.indexOf('Memo B') >= 0, 'the doc_ids render');
  ok(getEl('relEntities').innerHTML.indexOf('k-estimate') >= 0, 'the union-k is labelled a k-estimate');
  ok(getEl('relCaveat').innerHTML.indexOf('ABSENCE of linkage is NOT proof') >= 0, 'the linkage caveat renders');
  // hostile release name is esc'd.
  const hr = JSON.parse(JSON.stringify(report));
  hr.linked_entities[0].name = '<img src=x onerror=alert(9)>';
  hr.linked_entities[0].doc_ids = ['<img src=x onerror=alert(8)>'];
  I.renderRelease(hr);
  ok(getEl('relEntities').innerHTML.indexOf('<img src=x') < 0, 'hostile release name/doc_id is escaped');
}

console.log('Scenario 8: cleartext is present-but-ESCAPED (local-by-design)');
{
  I.renderEstimate(score);
  // The score carries cleartext QI values by design (LOCAL only) — they DO appear, escaped.
  const blob = allHtml();
  ok(blob.indexOf('male') >= 0 && blob.indexOf('California') >= 0,
     'QI cleartext values are present (local by design)');
  ok(blob.indexOf('<script') < 0, 'no script tag is ever produced from rendered cleartext');
}

console.log('Scenario 9: no cross-mode QI residue — switching single<->batch hides the other card (#3)');
{
  // Render a single-doc estimate carrying a distinctive cleartext QI value, then render a
  // (linkable-empty) batch: the single-doc card must be HIDDEN so its prior doc's QI cleartext
  // can't linger on screen next to the batch report (confidentiality — no A-into-B bleed).
  const single = JSON.parse(JSON.stringify(score));
  single.contributions = [{category:'surname', value:'RESIDUE_SECRET_VALUE', prob:0.1,
    estimated_from_tail:false, in_product:true, note:''}];
  single.medical_tiers = [];
  I.renderEstimate(single);
  ok(getEl('estContribs').innerHTML.indexOf('RESIDUE_SECRET_VALUE') >= 0,
     'the single-doc QI value renders first');
  ok(!getEl('estCard').classList.contains('hidden'), 'single card shown after renderEstimate');

  const emptyReport = { linked_entities: [], n_docs: 1, n_linked_entities: 0,
    is_estimate: true, linkage_caveat: 'ABSENCE of linkage is NOT proof ...' };
  I.renderRelease(emptyReport);
  ok(getEl('estCard').classList.contains('hidden'),
     'renderRelease HIDES the single-doc card (its prior QI cleartext no longer lingers)');
  ok(!getEl('relCard').classList.contains('hidden'), 'release card shown after renderRelease');

  // Going back the other way: renderEstimate hides the release card.
  I.renderEstimate(single);
  ok(getEl('relCard').classList.contains('hidden'),
     'renderEstimate HIDES the release card (its prior entity cleartext no longer lingers)');
  ok(!getEl('estCard').classList.contains('hidden'), 'single card shown again');

  // A fresh single-doc render with NO contributions overwrites (never appends) the prior value.
  const empty = JSON.parse(JSON.stringify(score));
  empty.contributions = []; empty.medical_tiers = [];
  I.renderEstimate(empty);
  ok(getEl('estContribs').innerHTML.indexOf('RESIDUE_SECRET_VALUE') < 0,
     'a fresh single-doc render clears the prior doc QI value (no residue)');
}

console.log('Scenario 10: error path clears prior QI residue (#16)');
{
  // Render a single-doc estimate carrying a distinctive cleartext value, then trip an
  // error: showError must HIDE both result cards AND empty the cleartext-bearing lists so
  // the prior doc's QI values can't linger on screen (or in the hidden DOM) next to the
  // error banner.
  if (typeof I.showError !== 'function'){
    ok(false, '__reidriskInternals.showError must be exposed for the error-path test');
  } else {
    const single = JSON.parse(JSON.stringify(score));
    single.contributions = [{category:'surname', value:'ERR_RESIDUE_VALUE', prob:0.1,
      estimated_from_tail:false, in_product:true, note:''}];
    single.medical_tiers = [{condition:'MED_RESIDUE', tier:'rare', note:'x'}];
    I.renderEstimate(single);
    ok(getEl('estContribs').innerHTML.indexOf('ERR_RESIDUE_VALUE') >= 0,
       'prior QI value rendered before the error');
    ok(!getEl('estCard').classList.contains('hidden'), 'estimate card shown before the error');

    I.showError('scoreError', 'the estimate could not run');
    ok(getEl('estCard').classList.contains('hidden'),
       'showError HIDES the single-doc card');
    ok(getEl('relCard').classList.contains('hidden'),
       'showError HIDES the release card');
    ok(getEl('estContribs').innerHTML.indexOf('ERR_RESIDUE_VALUE') < 0,
       'showError CLEARS the prior QI contribution residue');
    ok(getEl('estMedical').innerHTML.indexOf('MED_RESIDUE') < 0,
       'showError CLEARS the prior medical residue');
    ok(getEl('scoreError').innerHTML.toLowerCase().indexOf('could not run') >= 0,
       'the error banner message renders (escaped)');
  }
}

if (failures === 0){ console.log('ALL PASS'); process.exit(0); }
console.log(failures + ' FAILURE(S)'); process.exit(1);
