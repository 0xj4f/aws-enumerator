'use strict';
// UI state: loading pipeline, header, reset, session, owned marks, coverage panel (Du, Wave 2).
// dashboard-docs-tests.md A3/A5, dashboard-core-api.md section 5. Findings in test names.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const P = require('./lib/page');

const { fixture, fixtureText, variant, nodeById, EX, HO } = P.common;
/** AEUI.state() as main-realm data (deepStrictEqual compares prototypes across realms). */
const state = (ui) => JSON.parse(JSON.stringify(ui.AEUI.state()));

describe('header and run metadata (F-094, F-122, F-144)', () => {
  test('[F-094] [F-122] the header shows the run metadata and the version written in graph.json, not a constant', async (t) => {
    const raw = variant('example', d => {
      d.generator.version = '9.8.7';
      d.generator.git_sha = 'abcdef0';
      d.run.regions = ['eu-west-2', 'us-east-1'];
    });
    const ui = await P.bootUi(t, { graph: raw });
    const header = P.panelText(ui, 'header');
    for (const s of ['111122223333', raw.run.run_id, 'eu-west-2, us-east-1', '2026-01-01T00:00:00Z', '9.8.7', 'abcdef0',
      raw.generator.engine_version, raw.generator.rules_version, raw.schema_version]) {
      assert.ok(header.includes(s), `header lacks ${s}`);
    }
    assert.doesNotMatch(header, /0\.3\.0|v0\.2/, 'a version constant is shown instead of the report value');
    ui.assertNoErrors();
  });

  test('[F-144] the page is branded with the product name only', async (t) => {
    const ui = await P.bootUi(t, {});
    const brand = ui.text(ui.document.querySelector('.brand'));
    assert.match(brand, /aws-enumerator/);
    assert.doesNotMatch(brand, /j4f/i);
    const title = ui.document.querySelector('title');
    assert.ok(title === null || !/j4f/i.test(title.textContent));
  });

  test('[F-146] the operator is shown with its resolution; merged graphs say "merged view"', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    assert.match(P.panelText(ui, 'header'), /Operator demo-app-role \(assumed-role\)/);
    await ui.load(variant('example', d => {
      d.schema_version = '1.1.0';
      d.run.mode = 'merge';
      d.run.operator = { arn: null, node_id: null, resolution: 'unavailable', redacted: false };
    }));
    const text = ui.text(ui.document.body);
    assert.match(text, /merged view/);
    assert.doesNotMatch(text, /caller not in graph/);
    assert.deepEqual(state(ui).owned, []);
    ui.assertNoErrors();
  });
});

describe('loading pipeline (F-092, F-145, F-093)', () => {
  test('[F-145] a run zip is sniffed by content, whatever its name, and loads', async (t) => {
    const ui = await P.bootUi(t, {});
    const ex = fixture('example');
    await ui.chooseFiles([await P.zipFile(ui, P.runTree('demo-run/', ex), 'report.bin')]);
    const s = await P.settled(ui);
    assert.equal(s.loaded, true, P.messages(ui));
    assert.equal(ui.cy().nodes().length, ex.nodes.length);
    ui.assertNoErrors();
  });

  test('[F-145] a bare graph.json picked under any name loads; anything else is a visible error', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles([ui.file(fixtureText('minimal'), 'export.txt')]);
    assert.equal((await P.settled(ui)).loaded, true);
    for (const [bytes, name] of [['<html>not a report</html>', 'page.html'], [new Uint8Array([0, 1, 2, 3]), 'data.bin'], ['', 'empty.json']]) {
      await ui.chooseFiles([ui.file(bytes, name)]);
      const s = await P.settled(ui, `an error for ${name}`);
      assert.equal(s.overlay, 'error', name);
      assert.match(P.panelText(ui, 'overlay'), /could not load/i, name);
      assert.equal(ui.cores.filter(c => !c.destroyed()).length, 0, 'a graph is still shown after a failed load');
    }
    assert.deepEqual(ui.unhandled, []);
  });

  test('[F-145] the welcome text names every accepted input', async (t) => {
    const ui = await P.bootUi(t, {});
    const text = P.panelText(ui, 'overlay');
    for (const s of ['zip', 'folder', 'graph.json']) assert.ok(text.includes(s), `welcome text lacks ${s}`);
    assert.match(text, /nothing is uploaded/i);
  });

  test('[F-092] a legacy report shows the "run aws-enumerator analyze" banner and renders nothing', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles(P.folder(ui, {
      'old-run/manifest.json': JSON.stringify({ schema_version: '1.0', run_metadata: {} }),
      'old-run/analysis/findings.json': '{"findings": []}',
      'old-run/analysis/s3_relationships.json': '[]',
    }), { folder: true });
    const s = await P.settled(ui);
    assert.equal(s.overlay, 'legacy');
    assert.match(P.panelText(ui, 'overlay'), /aws-enumerator analyze/);
    assert.equal(ui.cores.length, 0);
    ui.assertNoErrors();
  });

  test('[F-092] a v2 run whose analysis has not run says how to analyse it', async (t) => {
    const ui = await P.bootUi(t, {});
    const ex = fixture('example');
    await ui.chooseFiles(P.folder(ui, { 'r/manifest.json': P.manifestFor(ex, { analysis: { status: 'skipped' } }), 'r/global/iam/roles.json': '[]' }), { folder: true });
    await P.settled(ui);
    assert.match(P.messages(ui), /aws-enumerator analyze/);
    ui.assertNoErrors();
  });

  test('[F-092] an unsupported major version and invalid JSON are reported, never a "Loading" hang', async (t) => {
    const ui = await P.bootUi(t, {});
    await ui.chooseFiles([ui.file(JSON.stringify(variant('example', d => { d.schema_version = '7.0.0'; })), 'graph.json')]);
    await P.settled(ui);
    assert.match(P.messages(ui), /unsupported/i);
    await ui.chooseFiles([ui.file('{"schema_version": "1.0.0", "nodes": [', 'graph.json')]);
    await P.settled(ui);
    assert.match(P.messages(ui), /json/i);
    assert.doesNotMatch(P.panelText(ui, 'overlay', { visibleOnly: true }), /Reading the report/);
    assert.deepEqual(ui.unhandled, []);
  });

  test('[F-092] unexpected script errors and rejections are reported in the problems panel', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('minimal') });
    const err = new ui.window.Event('error');
    err.error = new Error('boom from a stale handler');
    ui.window.dispatchEvent(err);
    const rej = new ui.window.Event('unhandledrejection');
    rej.reason = new Error('lost promise');
    ui.window.dispatchEvent(rej);
    const csp = new ui.window.Event('securitypolicyviolation');
    csp.blockedURI = 'inline';
    csp.violatedDirective = 'style-src';
    ui.document.dispatchEvent(csp);
    await ui.settle();
    const text = P.panelText(ui, 'problems');
    for (const s of ['boom from a stale handler', 'lost promise', 'blocked inline (style-src)']) assert.ok(text.includes(s), s);
  });

  test('[F-093] several runs in one input show a run picker; the chosen root is loaded', async (t) => {
    const ui = await P.bootUi(t, {});
    const ex = fixture('example');
    const ho = fixture('hostile');
    await ui.chooseFiles([await P.zipFile(ui, { ...P.runTree('demo/111122223333/run-a/', ex), ...P.runTree('demo/123456789012/run-b/', ho) })]);
    assert.equal((await P.settled(ui)).overlay, 'picker');
    const picks = ui.actions('pick-run');
    assert.deepEqual(picks.map(b => b.dataset.root), ['demo/111122223333/run-a/', 'demo/123456789012/run-b/']);
    assert.match(picks[1].textContent, /123456789012/);
    picks[1].click();
    assert.equal((await P.settled(ui)).loaded, true);
    assert.equal(ui.cy().nodes().length, ho.nodes.length);
    assert.ok(P.panelText(ui, 'header').includes('123456789012'));
    ui.assertNoErrors();
  });

  test('the digest badge says verified or mismatch against manifest.json (F-168 display)', async (t) => {
    const ui = await P.bootUi(t, {});
    const ex = fixture('example');
    const text = fixtureText('example');
    await ui.chooseFiles(P.folder(ui, { 'r/manifest.json': P.manifestWithDigest(ex, text), 'r/analysis/graph.json': text }), { folder: true });
    await P.settled(ui);
    assert.match(P.panelText(ui, 'header'), /digest verified/);
    await ui.chooseFiles(P.folder(ui, { 'r/manifest.json': P.manifestWithDigest(ex, text, 'a'.repeat(64)), 'r/analysis/graph.json': text }), { folder: true });
    await P.settled(ui);
    assert.match(P.panelText(ui, 'header'), /DIGEST MISMATCH/);
    assert.match(P.panelText(ui, 'problems'), /does not match/);
  });

  test('[F-145] a dropped folder (FileSystemEntry tree) loads like a picked one', async (t) => {
    const ui = await P.bootUi(t, {});
    const ho = fixture('hostile');
    const file = (name, text) => ({ isFile: true, isDirectory: false, name, file: (ok) => ok(ui.file(text, name)) });
    const dir = (name, fullPath, children) => ({
      isFile: false, isDirectory: true, name, fullPath,
      createReader() { let done = false; return { readEntries(ok) { ok(done ? [] : children); done = true; } }; },
    });
    const graph = Object.assign(file('graph.json', P.common.fixtureText('hostile')), { fullPath: '/drop/analysis/graph.json' });
    const manifest = Object.assign(file('manifest.json', P.manifestFor(ho)), { fullPath: '/drop/manifest.json' });
    const root = dir('drop', '/drop', [manifest, dir('analysis', '/drop/analysis', [graph])]);
    const ev = new ui.window.Event('drop', { bubbles: true, cancelable: true });
    ev.dataTransfer = { items: [{ kind: 'file', webkitGetAsEntry: () => root }], files: [] };
    ui.document.body.dispatchEvent(ev);
    assert.equal((await P.settled(ui)).loaded, true, P.messages(ui));
    assert.equal(ui.cy().nodes().length, ho.nodes.length);
    ui.assertNoErrors();
  });
});

describe('reset, owned marks and session (F-094, F-098, F-146)', () => {
  test('[F-098] Clear returns to the welcome state and every control stays safe without a graph', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    const cy = ui.cy();
    await ui.click('clear');
    assert.ok(cy.destroyed());
    assert.equal(state(ui).overlay, 'welcome');
    assert.equal(state(ui).loaded, false);
    for (const p of ['owned', 'path', 'discover', 'detail', 'filters', 'legend']) {
      assert.deepEqual(ui.panel(p).querySelectorAll('[data-node-id]').map(e => e.dataset.nodeId), [], p);
    }
    for (const a of ['find-path', 'clear-path', 'discover-all', 'play', 'stop', 'show-more', 'export-findings-csv', 'export-paths-json', 'export-png', 'export-session', 'clear']) {
      const els = ui.actions(a);
      if (els.length) els[0].click();
    }
    await ui.tick(10000);
    assert.equal(ui.clock.intervals().length, 0);
    ui.assertNoErrors();
  });

  test('[F-146] Find path without a chosen source starts at the operator; no operator gives a clear message', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.tap(EX.bucket);
    await ui.click('path-to', { nodeId: EX.bucket });
    await ui.click('find-path');
    assert.deepEqual(state(ui).path[0], EX.appRole);
    await ui.load(variant('example', d => { d.run.operator = { arn: null, node_id: null, resolution: 'unavailable', redacted: false }; }));
    assert.match(ui.text(ui.document.body), /caller not in graph \(unavailable\)/);
    await ui.tap(EX.bucket);
    await ui.click('path-to', { nodeId: EX.bucket });
    await ui.click('find-path');
    assert.match(P.panelText(ui, 'path'), /Choose a source/);
    ui.assertNoErrors();
  });

  test('[F-094] owned marks are not written to web storage unless the user opts in, then survive a reload of the same run', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    assert.deepEqual(ui.storageLog.filter(([op]) => op === 'set'), []);
    const remember = ui.document.querySelectorAll('input[data-option]').find(e => e.dataset.option === 'remember');
    assert.ok(remember && remember.checked === false, 'the remember option must be off by default');
    remember.checked = true;
    remember.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.settle();
    assert.ok(ui.storageLog.some(([op]) => op === 'set'));
    await ui.load(fixture('example'));
    assert.deepEqual(state(ui).owned, [EX.appRole, EX.user]);
    await ui.load(fixture('hostile'));
    assert.ok(!state(ui).owned.includes(EX.user), 'marks leaked into another run');
    ui.assertNoErrors();
  });

  test('[F-094] a saved session restores owned marks and paths for the same run only', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    await ui.click('discover-all');
    const found = state(ui).discovered;
    assert.ok(found > 0);
    await ui.click('export-session');
    const session = await P.downloadText(ui.downloads[ui.downloads.length - 1]);
    const parsed = JSON.parse(session);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.run_id, fixture('example').run.run_id);
    await ui.load(fixture('example'));
    const input = ui.document.querySelector('#session-input');
    input.files = [ui.file(session, 'session.json')];
    input.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.waitFor(() => state(ui).owned.includes(EX.user), { what: 'the session to apply' });
    assert.equal(state(ui).discovered, found);
    // another run's session is refused with a visible problem
    await ui.load(fixture('hostile'));
    input.files = [ui.file(session, 'session.json')];
    input.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.settle();
    assert.ok(!state(ui).owned.includes(EX.user));
    assert.match(P.panelText(ui, 'problems'), /session/i);
    ui.assertNoErrors();
  });

  test('[F-094] a session naming nodes that are not in the report keeps the rest and says so', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('hostile') });
    const runId = fixture('hostile').run.run_id;
    const text = JSON.stringify({ version: 1, run_id: runId, owned: [HO.quoteUser, 'arn:aws:iam::123456789012:user/gone', '__proto__'], paths: [] });
    const input = ui.document.querySelector('#session-input');
    input.files = [ui.file(text, 's.json')];
    input.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.waitFor(() => state(ui).owned.includes(HO.quoteUser), { what: 'session applied' });
    assert.deepEqual(state(ui).owned.filter(id => id !== fixture('hostile').run.operator.node_id), [HO.quoteUser]);
    assert.match(P.panelText(ui, 'problems'), /not nodes of this report/);
    ui.assertNoErrors();
  });
});

describe('findings panel (F-005, F-074, F-006)', () => {
  test('[F-074] severity tiles include LOW and INFO and add up to the total', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const tiles = ui.panel('findings').querySelectorAll('.tile');
    const value = (cls) => Number(tiles.find(x => x.classList.contains(cls)).querySelector('.value').textContent);
    const parts = ['critical', 'high', 'medium', 'low', 'info'].map(value);
    assert.equal(parts.reduce((a, b) => a + b, 0), value('total'));
    assert.equal(value('total'), raw.findings.length);
    assert.ok(value('low') + value('info') > 0, 'the fixture has LOW/INFO findings');
  });

  test('[F-005] severity checkboxes and the text filter narrow the findings table', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const rows = () => ui.actions('select-finding', { within: ui.panel('findings') });
    const boxes = ui.panel('findings').querySelectorAll('input[data-severity]');
    assert.deepEqual(boxes.map(b => b.dataset.severity), ['critical', 'high', 'medium', 'low', 'info']);
    const info = boxes.find(b => b.dataset.severity === 'info');
    info.checked = false;
    info.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.settle();
    assert.equal(rows().length, raw.findings.filter(f => f.severity !== 'INFO').length);
    const search = ui.panel('findings').querySelector('input[type="search"]');
    search.value = 'S3-PUBLIC';
    search.dispatchEvent(new ui.window.Event('input', { bubbles: true }));
    await ui.settle();
    assert.deepEqual(rows().map(r => r.textContent.includes('S3-PUBLIC-001')), [true]);
    ui.assertNoErrors();
  });

  test('[F-005] an unattached finding is listed, counted and opens in the detail panel', async (t) => {
    const raw = variant('example', d => d.findings.push({ ...d.findings[0], id: 'DEMO-UNATTACHED-001', node_id: 'arn:aws:s3:::demo-gone', fingerprint: 'f'.repeat(32) }));
    const ui = await P.bootUi(t, { graph: raw });
    const row = ui.actions('select-finding').find(r => r.textContent.includes('DEMO-UNATTACHED-001'));
    assert.ok(row);
    row.click();
    await ui.settle();
    assert.match(P.panelText(ui, 'detail'), /unattached/);
    assert.match(P.panelText(ui, 'detail'), /demo-gone/);
    ui.assertNoErrors();
  });

  test('[F-006] attachment statuses read as text: unknown (AccessDenied), unknown (legacy report), ok', async (t) => {
    const raw = variant('example', d => {
      Object.assign(nodeById(d, EX.appRole).props, { attached_policies_status: 'denied', attached_policies_error: 'AccessDenied' });
      Object.assign(nodeById(d, EX.deployRole).props, { attached_policies_status: 'legacy-unknown' });
      Object.assign(nodeById(d, EX.adminRole).props, { attached_policies_status: 'ok' });
    });
    const ui = await P.bootUi(t, { graph: raw });
    for (const [id, want] of [[EX.appRole, /Attached policies\s*unknown \(AccessDenied\)/], [EX.deployRole, /unknown \(legacy report\)/], [EX.adminRole, /Attached policies\s*ok/]]) {
      await ui.tap(id);
      assert.match(P.panelText(ui, 'detail'), want, id);
    }
    ui.assertNoErrors();
  });
});

describe('coverage panel (D-28)', () => {
  test('lists every module that is not ok (module vocabulary), the evaluation gaps, denied APIs and analyzers not ok', async (t) => {
    const raw = variant('example', d => {
      d.coverage.modules.push({ module: 'lambda_', region: 'eu-west-2', status: 'denied', error_code: 'AccessDeniedException', detail: 'lambda:ListFunctions denied' });
      d.coverage.modules.push({ module: 'k8s', region: 'eu-west-2', status: 'skipped', error_code: null, detail: 'kubernetes package missing' });
    });
    const ui = await P.bootUi(t, { graph: raw });
    const text = P.panelText(ui, 'coverage');
    for (const m of raw.coverage.modules.filter(x => x.status !== 'ok')) {
      for (const v of [m.module, m.region, m.status, m.detail]) assert.ok(text.includes(v), `${m.module}: ${v}`);
    }
    assert.ok(!text.includes('Modules not ok (0)'));
    for (const g of raw.evaluation_gaps) assert.ok(text.includes(g.code) && text.includes(g.detail), g.code);
    assert.ok(text.includes('s3:GetBucketPolicy'));
    assert.match(text, /posture \(resources\): not_implemented/);
    assert.match(P.panelText(ui, 'header'), /coverage partial \(3 modules not ok\)/);
    ui.assertNoErrors();
  });
});
