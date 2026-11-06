'use strict';
// UI performance budgets (F-038; Du, Wave 2). Skipped unless PERF=1 (dashboard-docs-tests.md C9):
// the timings depend on the machine. The page runs in the regression harness (headless Cytoscape).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const P = require('../ui/lib/page');

const SKIP = process.env.PERF === '1' ? false : 'set PERF=1 to run the UI performance budgets';

describe('UI scale (F-038)', () => {
  test('[F-038] a 40k-edge graph loads in large-graph mode within the budget and Discover stays chunked', { skip: SKIP, timeout: 120000 }, async (t) => {
    const ui = await P.bootUi(t, {});
    const doc = P.G.scaleGraph(40000);
    const t0 = Date.now();
    const { error } = await ui.load(doc);
    const loadMs = Date.now() - t0;
    assert.equal(error, null);
    const s = ui.AEUI.state();
    assert.equal(s.loaded, true);
    assert.equal(s.large, true);
    assert.ok(loadMs < 20000, `load took ${loadMs} ms`);
    const t1 = Date.now();
    await ui.click('discover-all');
    await ui.waitFor(() => !/Discovering/.test(P.panelText(ui, 'discover')), { timeoutMs: 60000, what: 'discover to finish' });
    assert.ok(Date.now() - t1 < 60000);
    assert.ok(ui.AEUI.state().shownPaths <= ui.AEUI.PAGE_SIZE);
    ui.assertNoErrors();
  });

  test('[F-038] doubling the graph size less than triples the load time', { skip: SKIP, timeout: 120000 }, async (t) => {
    const ui = await P.bootUi(t, {});
    const time = async (n) => { const d = P.G.scaleGraph(n); const t0 = Date.now(); await ui.load(d); return Date.now() - t0; };
    await time(2000); // warm-up
    const small = Math.max(await time(10000), 50);
    const large = await time(20000);
    assert.ok(large < small * 3, `10k edges: ${small} ms, 20k edges: ${large} ms`);
  });
});
