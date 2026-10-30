'use strict';
// The page on a merged graph (graph.json 1.1, `aws-enumerator merge`; graph-json.md sections 4.2 and 10):
// the header names the source accounts, the coverage panel lists the source runs with their per-account
// coverage and tags every module, denied API, gap and analyzer with its account. The merged document is built
// by the real engine from example.json (111122223333) and hostile.json (123456789012), so the hostile
// account's strings must stay inert. Finding: F-126 (merge, dashboard half); F-146 (no single operator).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');
const P = require('./lib/page');

const pySkip = H.pythonSkip();
const CANARY = '<img src=x onerror=window.__aeXssCanary=1>';
const FORBIDDEN_TAGS = new Set(['script', 'iframe', 'style', 'object', 'embed', 'frame', 'base', 'link', 'meta', 'form']);

function assertInert(ui) {
  assert.equal(ui.window.__aeXssCanary, undefined, 'a canary executed');
  for (const el of ui.document.body.querySelectorAll('*')) {
    assert.ok(!FORBIDDEN_TAGS.has(el.localName), `<${el.localName}> in the page body`);
  }
}

async function openCoverage(ui) {
  ui.actions('tab').find(b => b.dataset.tab === 'coverage').click();
  await ui.settle();
  return P.panelText(ui, 'coverage');
}

describe('merged view (graph 1.1, F-126)', () => {
  test('[F-126] [F-146] the header lists the source accounts and says "merged view" instead of an operator', { skip: pySkip }, async (t) => {
    const raw = H.mergedGraph();
    const ui = await P.bootUi(t, { graph: raw });
    const header = P.panelText(ui, 'header');
    assert.match(header, /Accounts 111122223333, 123456789012 \(2 source runs\)/);
    assert.match(header, /merge \(merged view\)/);
    assert.match(header, /merged view \(each source run's operator is a default source\)/);
    assert.doesNotMatch(header, /caller not in graph/);
    assert.equal(header.includes('1.1.0'), true, 'the schema version is shown');
    ui.assertNoErrors();
  });

  test('[F-126] the coverage panel shows one row per source run with its own coverage status', { skip: pySkip }, async (t) => {
    const raw = H.mergedGraph();
    const ui = await P.bootUi(t, { graph: raw });
    const text = await openCoverage(ui);
    assert.match(text, /merged view of 2 accounts; per-account coverage below/);
    assert.match(text, /Source runs \(2\)/);
    const table = ui.panel('coverage').querySelector('[data-role="source-runs"]');
    assert.ok(table, 'no source-runs table');
    const rows = [...table.querySelectorAll('tbody tr')];
    assert.deepEqual(rows.map(r => r.dataset.account), ['111122223333', '123456789012']);
    for (const [i, s] of raw.run.sources.entries()) {
      const rowText = ui.text(rows[i]);
      assert.ok(rowText.includes(s.run_id), `row ${i} lacks the run id`);
      assert.ok(rowText.includes(s.graph_sha256.slice(0, 12)), `row ${i} lacks the digest`);
      for (const r of s.regions) assert.ok(rowText.includes(r), `row ${i} lacks region ${r}`);
      const mods = raw.coverage.modules.filter(m => m.account === s.account_id);
      const expected = mods.every(m => m.status === 'ok' || m.status === 'skipped') ? 'complete' : 'partial';
      assert.ok(rowText.includes(expected), `row ${i}: expected coverage ${expected} in ${rowText}`);
    }
    ui.assertNoErrors();
  });

  test('[F-126] modules, gaps, denied APIs and analyzers carry their account; hostile strings stay text', { skip: pySkip }, async (t) => {
    const raw = H.mergedGraph();
    const ui = await P.bootUi(t, { graph: raw });
    const text = await openCoverage(ui);
    const notOk = raw.coverage.modules.filter(m => m.status !== 'ok');
    assert.ok(notOk.length > 0);
    const modules = [...ui.panel('coverage').querySelectorAll('table')].find(tb => !tb.dataset.role);
    const heads = [...modules.querySelectorAll('thead th')].map(th => ui.text(th));
    assert.deepEqual(heads, ['Account', 'Module', 'Region', 'Status', 'Error', 'Detail']);
    for (const m of notOk) assert.ok(text.includes(m.account) && text.includes(m.module), m.module);
    assert.ok(text.includes(CANARY), 'the hostile module name is shown as text');
    const shared = raw.evaluation_gaps.find(g => g.accounts.length === 2);
    assert.ok(shared && text.includes(`accounts: ${shared.accounts.join(', ')}`), 'gap accounts');
    for (const d of raw.coverage.denied_apis || []) assert.ok(text.includes(`[${d.account}] ${d.api}`), d.api);
    for (const a of raw.analyzer_status.filter(x => x.status !== 'ok')) {
      assert.ok(text.includes(`[${a.account}] ${a.name}`), a.name);
    }
    assertInert(ui);
    ui.assertNoErrors();
  });

  test('a single-account 1.0 graph keeps the plain header and coverage panel', async (t) => {
    const ui = await P.bootUi(t, { graph: P.common.fixture('example') });
    assert.match(P.panelText(ui, 'header'), /Account 111122223333/);
    const text = await openCoverage(ui);
    assert.doesNotMatch(text, /Source runs|merged view/);
    const heads = [...ui.panel('coverage').querySelectorAll('thead th')].map(th => ui.text(th));
    assert.ok(!heads.includes('Account'));
    ui.assertNoErrors();
  });
});
