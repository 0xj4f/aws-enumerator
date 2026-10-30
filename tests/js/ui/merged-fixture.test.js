'use strict';
// The committed merged run tests/fixtures/dashboard-merge/ (an `aws-enumerator merge` output of two synthetic
// runs, graph.json 1.1; its README has the recipe) read through the real loader and shown by the page: the
// folder and the zip load with the digest verified, the header is the merge header, the coverage panel has
// one row per source run with that account's own coverage, and the findings of both accounts are listed.
// Unlike merged-view.test.js this needs no Python at test time. Finding: F-126 (merge, dashboard half),
// F-146 (no single operator in a merge), F-168 (digest against the manifest).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const H = require('../core/lib/helpers');
const P = require('./lib/page');

const { C, L } = H.modules();
const FIXTURE = path.join(H.targets.REPO_ROOT, 'tests', 'fixtures', 'dashboard-merge');
const RUN_ID = fs.readdirSync(path.join(FIXTURE, 'merged')).filter(n => !n.startsWith('.'));
const ROOT = `merged/${RUN_ID[0]}/`;
const FILES = ['manifest.json', 'HANDLING.txt', 'SHA256SUMS', 'analysis/graph.json'];

/** {relative path: text} of the committed run folder, below `prefix`. */
function entries(prefix = ROOT) {
  return Object.fromEntries(FILES.map(f => [prefix + f, fs.readFileSync(path.join(FIXTURE, ROOT, ...f.split('/')), 'utf8')]));
}

const RAW = JSON.parse(entries()[`${ROOT}analysis/graph.json`]);
const ACCOUNTS = RAW.run.sources.map(s => s.account_id);

async function openCoverage(ui) {
  ui.actions('tab').find(b => b.dataset.tab === 'coverage').click();
  await ui.settle();
  return P.panelText(ui, 'coverage');
}

describe('the committed merged run (tests/fixtures/dashboard-merge, F-126)', () => {
  test('[F-126] the fixture is one merged run of the two placeholder accounts', () => {
    assert.equal(RUN_ID.length, 1);
    assert.equal(RAW.schema_version, '1.1.0');
    assert.equal(RAW.run.mode, 'merge');
    assert.deepEqual([...ACCOUNTS].sort(), ['111122223333', '123456789012']);
  });

  test('[F-126] [F-168] the loader reads the folder, verifies the digest and the core accepts the graph', async () => {
    const read = [];
    const set = L.fromFolder(H.folderFiles(entries(), read));
    assert.deepEqual(L.findRoots(set).map(r => [r.root, r.hasGraph, r.hasManifest]), [[ROOT, true, true]]);
    const res = await L.load(set, undefined, { subtle: webcrypto.subtle });
    assert.equal(res.integrity, 'verified');
    assert.deepEqual(res.problems, []);
    assert.equal(res.manifest.run.kind, 'merge');
    assert.deepEqual([...new Set(read)].sort(), [`${ROOT}analysis/graph.json`, `${ROOT}manifest.json`],
      'only the allow-listed paths are read (F-093)');
    const { graph, problems } = C.validateGraph(res.raw);
    assert.ok(graph, JSON.stringify(problems));
    assert.deepEqual(problems.filter(p => p.level === 'error'), []);
    assert.equal(graph.run.sources.length, 2);
    assert.deepEqual(C.operatorNode(graph), { id: null, resolution: 'unavailable' });
  });

  test('[F-126] [F-168] the zip of the run loads the same way', { skip: H.jszipSkip() }, async () => {
    const set = await L.fromBytes(await H.zipBytes(entries('demo-merge/')), { JSZip: H.jszip() });
    const res = await L.load(set, undefined, { subtle: webcrypto.subtle });
    assert.equal(res.root, 'demo-merge/');
    assert.equal(res.integrity, 'verified');
    assert.deepEqual(res.raw, RAW);
  });

  test('[F-126] [F-146] the page shows the merge header, both accounts and the verified digest', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles(P.folder(ui, entries()), { folder: true });
    const s = await P.settled(ui);
    assert.equal(s.loaded, true, P.messages(ui));
    assert.equal(s.runId, RAW.run.run_id);
    const header = P.panelText(ui, 'header');
    assert.match(header, new RegExp(`Accounts ${[...ACCOUNTS].join(', ')} \\(2 source runs\\)`));
    assert.match(header, /Mode merge \(merged view\)/);
    assert.match(header, /merged view \(each source run's operator is a default source\)/);
    assert.match(header, /digest verified/);
    assert.match(header, /coverage partial \(1 module not ok\)/);
    assert.doesNotMatch(header, /caller not in graph/);
    assert.deepEqual(JSON.parse(JSON.stringify(s.owned)), [], 'no single operator to pre-mark in a merge (F-146)');
    ui.assertNoErrors();
  });

  test('[F-126] the coverage panel has one row per source run with its own coverage', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles(P.folder(ui, entries()), { folder: true });
    await P.settled(ui);
    const text = await openCoverage(ui);
    assert.match(text, /merged view of 2 accounts; per-account coverage below/);
    const rows = [...ui.panel('coverage').querySelector('[data-role="source-runs"]').querySelectorAll('tbody tr')];
    assert.deepEqual(rows.map(r => r.dataset.account), ACCOUNTS);
    for (const [i, src] of RAW.run.sources.entries()) {
      const mods = RAW.coverage.modules.filter(m => m.account === src.account_id);
      const notOk = mods.filter(m => m.status !== 'ok').length;
      const want = notOk ? `partial (${notOk} module${notOk === 1 ? '' : 's'} not ok)` : 'complete';
      const row = ui.text(rows[i]);
      assert.ok(row.includes(src.run_id) && row.includes(want) && row.includes(src.graph_sha256.slice(0, 12)), row);
    }
    const partial = RAW.coverage.modules.find(m => m.status !== 'ok');
    const modules = [...ui.panel('coverage').querySelectorAll('table')].find(tb => !tb.dataset.role);
    const cells = [...modules.querySelectorAll('tbody tr')].map(tr => [...tr.querySelectorAll('td')].map(td => ui.text(td)));
    assert.deepEqual(cells.map(c => c.slice(0, 4)), [[partial.account, partial.module, partial.region, partial.status]]);
    ui.assertNoErrors();
  });

  test('[F-126] the findings of both accounts are listed and Discover starts from the merge\'s default sources', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles(P.folder(ui, entries()), { folder: true });
    await P.settled(ui);
    const rows = ui.actions('select-finding', { within: ui.panel('findings') });
    assert.equal(rows.length, RAW.findings.length);
    const findings = P.panelText(ui, 'findings');
    for (const acct of ACCOUNTS) assert.ok(findings.includes(acct), `no finding of ${acct} is listed`);
    const { index } = P.common.pipeline(C, RAW);
    const sources = C.defaultSources(index, [], null);
    const targets = C.defaultTargets(index, {});
    assert.deepEqual(sources, RAW.meta.default_sources);
    const paths = P.common.drain(C.discoverAll(index, { sources, targets })).result.paths;
    await ui.click('discover-all');
    const summary = ui.text(ui.panel('discover').querySelector('[data-role="discover-summary"]'));
    const reached = new Set(paths.map(p => p.source)).size;
    const from = reached > 0 && reached < sources.length ? `${reached} of ${sources.length} sources` : `${sources.length} sources`;
    assert.ok(summary.startsWith(`${paths.length} path${paths.length === 1 ? '' : 's'} from ${from} to ${targets.length} targets`), summary);
    assert.equal(ui.AEUI.state().discovered, paths.length);
    ui.assertNoErrors();
  });
});
