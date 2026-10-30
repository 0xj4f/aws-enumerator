'use strict';
// Browser exports (F-165): findings CSV/Markdown for the current view, paths CSV/Markdown/JSON, the
// session, a PNG of the drawn graph. Downloads go through a Blob, <a download> and a revoked object
// URL (dashboard-docs-tests.md A5); the harness records every createObjectURL / revokeObjectURL.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const targets = require('../helpers/targets');
const P = require('./lib/page');

const { fixture, EX } = P.common;
const C = require(path.join(targets.dashboardDir(), 'js', 'graph-core.js'));
const X = require(path.join(targets.dashboardDir(), 'js', 'exports.js'));

function pipeline(raw) {
  const { graph } = C.validateGraph(raw);
  return { graph, index: C.buildIndex(graph) };
}

async function exportOne(ui, action) {
  const before = ui.downloads.length;
  await ui.click(action);
  assert.equal(ui.downloads.length, before + 1, `${action} downloaded nothing`);
  const d = ui.downloads[ui.downloads.length - 1];
  return { d, text: await P.downloadText(d) };
}

describe('browser exports (F-165)', () => {
  test('[F-165] findings CSV and Markdown equal AEExports over the findings view, and follow its filters', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const { graph, index } = pipeline(raw);
    const all = graph.findings.concat(graph.unattachedFindings);
    const csv = await exportOne(ui, 'export-findings-csv');
    assert.equal(csv.d.blob.type, 'text/csv;charset=utf-8');
    assert.deepEqual(csv.text.split('\r\n').slice(1).filter(Boolean).sort(), X.findingsCsv(all, index).split('\r\n').slice(1).filter(Boolean).sort());
    assert.equal(csv.text.split('\r\n')[0], X.findingsCsv(all, index).split('\r\n')[0]);
    const md = await exportOne(ui, 'export-findings-md');
    assert.match(md.text, /111122223333/);
    for (const f of raw.findings) assert.ok(md.text.includes(f.id), f.id);
    // narrow the view: only HIGH findings are exported
    for (const sev of ['critical', 'medium', 'low', 'info']) { // the toolbar is re-rendered after each change
      const box = ui.panel('findings').querySelectorAll('input[data-severity]').find(b => b.dataset.severity === sev);
      box.checked = false;
      box.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
      await ui.settle();
    }
    const high = await exportOne(ui, 'export-findings-csv');
    const rows = high.text.split('\r\n').slice(1).filter(Boolean);
    assert.equal(rows.length, raw.findings.filter(f => f.severity === 'HIGH').length);
    assert.ok(rows.every(r => r.startsWith('"HIGH"')), rows.join('\n'));
    ui.assertNoErrors();
  });

  test('[F-165] formula-looking cells are neutralised in the downloaded CSV', async (t) => {
    const raw = P.common.variant('example', d => { d.findings[0].title = '=HYPERLINK("http://x")'; });
    const ui = await P.bootUi(t, { graph: raw });
    const { text } = await exportOne(ui, 'export-findings-csv');
    assert.ok(!/(^|,)"=/m.test(text), 'a cell starts with =');
    assert.ok(text.includes("'=HYPERLINK"), text);
  });

  test('[F-165] paths export as CSV, Markdown and JSON (the discovered paths, else the found path)', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    await ui.findPath(EX.user, EX.adminRole);
    const one = JSON.parse((await exportOne(ui, 'export-paths-json')).text);
    assert.equal(one.run_id, raw.run.run_id);
    assert.equal(one.paths.length, 1);
    assert.deepEqual(one.paths[0].path, JSON.parse(JSON.stringify(ui.AEUI.state().path)));
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    await ui.click('discover-all');
    const n = ui.AEUI.state().discovered;
    const json = JSON.parse((await exportOne(ui, 'export-paths-json')).text);
    assert.equal(json.paths.length, n);
    for (const p of json.paths) assert.equal(p.edge_types.length, p.edges.length);
    const csv = await exportOne(ui, 'export-paths-csv');
    assert.equal(csv.text.split('\r\n').filter(Boolean).length, n + 1);
    const md = await exportOne(ui, 'export-paths-md');
    assert.match(md.text, / -> /);
    ui.assertNoErrors();
  });

  test('[F-165] object URLs are revoked after the download; nothing is left in the page', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await exportOne(ui, 'export-findings-csv');
    await exportOne(ui, 'export-session');
    assert.equal(ui.document.querySelectorAll('a[download]').length, 0);
    await ui.tick(1500);
    assert.ok(ui.downloads.every(d => d.revoked === true));
    ui.assertNoErrors();
  });

  test('[F-165] download file names carry only a sanitised run id', async (t) => {
    const raw = P.common.variant('example', d => { d.run.run_id = '../../evil "name"'; });
    const ui = await P.bootUi(t, { graph: raw });
    const names = [];
    const realClick = ui.window.HTMLElement.prototype.click;
    ui.window.HTMLElement.prototype.click = function click() {
      if (this.localName === 'a') names.push(this.getAttribute('download'));
      return realClick.call(this);
    };
    try {
      await exportOne(ui, 'export-findings-csv');
      await exportOne(ui, 'export-findings-md');
    } finally {
      ui.window.HTMLElement.prototype.click = realClick;
    }
    assert.deepEqual(names, ['aws-enumerator-.._.._evil__name_-findings.csv', 'aws-enumerator-.._.._evil__name_-findings.md']);
    for (const n of names) assert.ok(!n.includes('/') && !n.includes('"'));
  });

  test('[F-165] PNG export without a drawn graph and exports without a report say why instead of failing', async (t) => {
    const ui = await P.bootUi(t, {});
    for (const a of ['export-findings-csv', 'export-paths-csv', 'export-session', 'export-png']) await ui.click(a);
    assert.equal(ui.downloads.length, 0);
    assert.match(P.panelText(ui, 'problems'), /open a report first/);
    await ui.load(fixture('minimal'));
    await ui.click('export-paths-json');
    assert.match(P.panelText(ui, 'problems'), /find a path or discover paths first/);
    await ui.click('export-png');
    const pngs = ui.downloads.filter(d => d.blob.type === 'image/png');
    assert.ok(pngs.length === 1 || /PNG export needs the drawn graph/.test(P.panelText(ui, 'problems')));
    ui.assertNoErrors();
  });

  test('[F-165] the export panel points to the command line for SARIF, ASFF and OpenGraph', async (t) => {
    const ui = await P.bootUi(t, {});
    const text = ui.text(ui.document.querySelector('#exports-panel'));
    assert.match(text, /aws-enumerator export/);
    assert.match(text, /SARIF/);
  });
});
