// Tests execute the actual first JS fragment in a VM with DOM/storage test doubles.
// They do not measure browser, WebView2, or real-document performance.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../app/ui/redaction.core.js'), 'utf8');
const KEY = 'lawbat.redaction.opts';

function harness(saved = null, faults = {}) {
  const boxes = {};
  const writes = [], removals = [];
  let stored = saved;
  const getBox = id => boxes[id] || (boxes[id] = { value: '', checked: false, textContent: '' });
  const groups = {
    loc: ['sg', 'us', 'uk', 'au', 'ca'].map(value => ({ value, checked: false })),
    prof: [{ value: 'pci-dss-cardholder', checked: false }],
    bi: ['email', 'phone', 'id', 'name', 'credit-card', 'iban', 'ip', 'url', 'address', 'bic', 'isin']
      .map(value => ({ value, checked: true })),
  };
  const context = {
    TextEncoder,
    document: { querySelectorAll(selector) {
      const match = /^input\.(loc|prof|bi)(:checked)?$/.exec(selector);
      if (!match) throw new Error(`unexpected selector ${selector}`);
      return groups[match[1]].filter(box => !match[2] || box.checked);
    } },
    LB: { $: getBox },
    localStorage: {
      getItem(key) { assert.equal(key, KEY); if (faults.read) throw new Error('read disabled'); return stored; },
      setItem(key, value) {
        assert.equal(key, KEY); writes.push(value);
        if (faults.write) throw new Error('write disabled');
        stored = value;
      },
      removeItem(key) {
        assert.equal(key, KEY); removals.push(key);
        if (faults.remove) throw new Error('remove disabled');
        stored = null;
      },
    },
  };
  vm.createContext(context);
  vm.runInContext(source + '\n globalThis.api = {readOptions, saveOptions, restoreOptions, preferenceOptions, friendlyError};\n})();', context);
  return { api: context.api, boxes, groups, writes, removals, stored: () => stored };
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

test('saving preserves active matter terms in memory but never persists them', () => {
  const h = harness();
  h.boxes.termsBox = { value: 'PRIVATE_TEST_PARTY_A\nPRIVATE_TEST_PARTY_B' };
  h.groups.loc[0].checked = true;
  h.api.saveOptions();
  assert.deepEqual(plain(h.api.readOptions().terms), ['PRIVATE_TEST_PARTY_A', 'PRIVATE_TEST_PARTY_B']);
  assert.deepEqual(JSON.parse(h.stored()), { locales: ['sg'] });
  assert.ok(h.writes.every(value => !value.includes('PRIVATE_TEST')));
  assert.match(h.boxes.termsSummary.textContent, /2 names/);
});

test('legacy party names are removed, not restored, while supported preferences survive', () => {
  const h = harness(JSON.stringify({ terms: ['PRIVATE_TEST_PARTY_A'], keep: ['PRIVATE_TEST_KEEP'],
    locales: ['sg', 'uk'], profiles: ['pci-dss-cardholder'], disable_builtins: ['phone'], context: true,
    lei: true, sg_nric_loose: true, organisations: true, addresses_full: true }));
  h.boxes.termsBox = { value: 'autofilled stale terms' };
  h.api.restoreOptions();
  assert.equal(h.boxes.termsBox.value, '');
  assert.equal(h.api.readOptions().terms, undefined);
  assert.ok(h.removals.length >= 1);
  const saved = JSON.parse(h.stored());
  assert.equal(saved.terms, undefined);
  assert.equal(saved.keep, undefined);
  assert.deepEqual(saved.locales, ['sg', 'uk']);
  assert.deepEqual(saved.disable_builtins, ['phone']);
  for (const key of ['context', 'lei', 'sg_nric_loose', 'organisations', 'addresses_full']) assert.equal(saved[key], true);
  assert.ok(h.writes.every(value => !value.includes('PRIVATE_TEST')));
});

test('unknown and future matter fields cannot enter the preference store', () => {
  const h = harness();
  const value = h.api.preferenceOptions({ terms: ['PRIVATE_TEST_PARTY'], text: 'PRIVATE_TEST_BODY',
    source: { filename: 'PRIVATE_TEST_FILE' }, reviewer: 'PRIVATE_TEST_REVIEWER', locale: 'sg', context: true });
  assert.deepEqual(plain(value), { context: true });
});

test('malformed saved preferences cannot abort startup or revive terms', () => {
  for (const stored of ['{broken', 'null', '42', '"string"', '[]',
    '{"locales":{},"profiles":"pci-dss-cardholder","disable_builtins":5,"terms":["PRIVATE_TEST"]}']) {
    const h = harness(stored);
    h.boxes.termsBox = { value: 'stale' };
    assert.doesNotThrow(() => h.api.restoreOptions());
    assert.equal(h.boxes.termsBox.value, '');
    assert.ok(!h.stored().includes('PRIVATE_TEST'));
    assert.ok(h.removals.length >= 1);
  }
});

test('preference arrays are typed, deduplicated and allowlisted', () => {
  const h = harness();
  assert.deepEqual(plain(h.api.preferenceOptions({
    locales: ['sg', 'sg', 'constructor', '__proto__', 5, null, 'unknown'],
    profiles: ['pci-dss-cardholder', 'toString'], disable_builtins: ['email', 'email', 'valueOf'],
    context: 'true', lei: 1, organisations: true,
  })), { locales: ['sg'], profiles: ['pci-dss-cardholder'], disable_builtins: ['email'], organisations: true });
});

test('inherited fields do not become saved preferences', () => {
  const h = harness();
  assert.deepEqual(plain(h.api.preferenceOptions(Object.create({ context: true, locales: ['sg'] }))), {});
});

test('failed preference rewrite falls back to removing the legacy key', () => {
  const h = harness('{"terms":["PRIVATE_TEST"]}', { write: true });
  h.api.saveOptions();
  assert.equal(h.stored(), null);
  assert.ok(h.removals.length >= 1);
});

test('failed removal is repaired by a successful sanitized rewrite', () => {
  const h = harness('{"terms":["PRIVATE_TEST"],"context":true}', { remove: true });
  h.api.restoreOptions();
  assert.deepEqual(JSON.parse(h.stored()), { context: true });
});

test('inaccessible storage is nonfatal and unsuccessful clearing is visible', () => {
  const h = harness('{"terms":["PRIVATE_TEST"]}', { read: true, write: true, remove: true });
  h.boxes.termsBox = { value: 'stale' };
  assert.doesNotThrow(() => h.api.restoreOptions());
  assert.equal(h.boxes.termsBox.value, '');
  assert.match(h.boxes.optsSummary.textContent, /saved settings could not be cleared/);
});

test('a refused PDF export is not mislabeled as a scan or engine-offline error', () => {
  const h = harness();
  for (const raw of ['Export blocked: some accepted redactions could not be removed.',
    'Export blocked: the engine did not report a valid removal outcome.']) {
    const result = h.api.friendlyError(raw);
    assert.equal(result.title, 'Export blocked.');
    assert.match(result.body, /No new copy was saved/);
    assert.equal(result.engineOffline, undefined);
  }
});
