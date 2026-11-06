'use strict';
// Generated filters and legend, filter-aware path finding, external/internet nodes (Du, Wave 2).
// dashboard-docs-tests.md A4/A5, dashboard-core-api.md section 5 P7.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const targets = require('../helpers/targets');
const P = require('./lib/page');

const { fixture, variant, nodeById, EX } = P.common;
const K = require(path.join(targets.dashboardDir(), 'js', 'catalog.js'));
const state = (ui) => JSON.parse(JSON.stringify(ui.AEUI.state()));

async function toggle(ui, input, checked) {
  input.checked = checked;
  input.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
  await ui.settle();
}

describe('generated filters and legend (F-090)', () => {
  test('[F-090] one node-type filter and legend entry per type present, with catalogue labels and node counts', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const counts = new Map();
    for (const n of raw.nodes) counts.set(n.type, (counts.get(n.type) || 0) + 1);
    const filters = ui.document.querySelectorAll('input[data-filter-kind]').filter(e => e.dataset.filterKind === 'node-type');
    assert.deepEqual(filters.map(f => f.dataset.filterValue).sort(), [...counts.keys()].sort());
    for (const [type, n] of counts) {
      const label = ui.filter('node-type', type).parentNode;
      assert.ok(label.textContent.includes(K.nodeTypeInfo(type, raw.node_types[type]).label), type);
      assert.ok(label.textContent.endsWith(String(n)), `${type} count`);
      assert.ok(ui.legend('node-type', type), type);
    }
    ui.assertNoErrors();
  });

  test('[F-090] legend icons come from the catalogue allow-list and exist; unknown types fall back to generic', async (t) => {
    const raw = variant('example', d => {
      d.node_types.future_type = { label: 'Future type', icon: '../../etc/x', group: 'posture', order: 99, is_compute_bridge: false, default_source: false, data_asset: false, synthetic: false, description: 'x' };
      d.nodes.push(P.G.node('aws-enumerator:future/111122223333', 'future_type', 'demo-future'));
    });
    const ui = await P.bootUi(t, { graph: raw });
    const icons = ui.panel('legend').querySelectorAll('img').map(i => i.getAttribute('src'));
    assert.ok(icons.length >= new Set(raw.nodes.map(n => n.type)).size);
    for (const src of icons) {
      assert.match(src, /^icons\/[a-z0-9]+\.svg$/);
      assert.ok(fs.existsSync(path.join(targets.dashboardDir(), src)), `${src} is not shipped`);
    }
    const future = ui.legend('node-type', 'future_type');
    assert.equal(future.querySelector('img').getAttribute('src'), 'icons/generic.svg');
    for (const n of ['anonymous', 'external_account', 'idp', 'account', 'account_admin']) {
      const img = ui.legend('node-type', n).querySelector('img').getAttribute('src');
      assert.notEqual(img, 'icons/generic.svg', `${n} should have its own icon`);
    }
    ui.assertNoErrors();
  });

  test('[F-090] context edges (structural) are hidden by default and shown by their traversal filter', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const structural = raw.edges.filter(e => e.traversal === 'structural');
    assert.ok(structural.length > 0);
    const box = ui.filter('traversal', 'structural');
    assert.equal(box.checked, false);
    for (const e of structural) assert.ok(ui.cy().getElementById(e.id).hasClass('filtered-out'), e.type);
    await toggle(ui, box, true);
    for (const e of structural) assert.ok(!ui.cy().getElementById(e.id).hasClass('filtered-out'), e.type);
    for (const tr of ['control', 'access', 'exposure']) assert.equal(ui.filter('traversal', tr).checked, true, tr);
    ui.assertNoErrors();
  });

  test('[F-090] hiding a node type hides its nodes and every edge that touches them', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    await toggle(ui, ui.filter('node-type', 'role'), false);
    const cy = ui.cy();
    for (const n of raw.nodes.filter(x => x.type === 'role')) assert.ok(cy.getElementById(n.id).hasClass('filtered-out'));
    const roles = new Set(raw.nodes.filter(x => x.type === 'role').map(x => x.id));
    for (const e of raw.edges.filter(x => roles.has(x.source) || roles.has(x.target))) assert.ok(cy.getElementById(e.id).hasClass('filtered-out'), e.type);
    await toggle(ui, ui.filter('node-type', 'role'), true);
    for (const n of raw.nodes.filter(x => x.type === 'role')) assert.ok(!cy.getElementById(n.id).hasClass('filtered-out'));
    ui.assertNoErrors();
  });
});

describe('filters restrict path finding (F-096)', () => {
  test('[F-096] a hidden node type blocks paths through it unless "respect filters" is turned off', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.findPath(EX.user, EX.adminRole);
    assert.ok(state(ui).path.includes(EX.group));
    await toggle(ui, ui.filter('node-type', 'group'), false);
    assert.equal(state(ui).path, null);
    assert.match(P.panelText(ui, 'path'), /No path/);
    const respect = ui.document.querySelectorAll('input[data-option]').find(e => e.dataset.option === 'respect-filters');
    await toggle(ui, respect, false);
    assert.ok(state(ui).path && state(ui).path.includes(EX.group), 'with respect-filters off the path is found again');
    ui.assertNoErrors();
  });

  test('[F-096] "include conditional edges" off removes conditional steps from paths', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.findPath(EX.extRoot, EX.appRole);
    assert.deepEqual(state(ui).path, [EX.extRoot, EX.appRole]);
    assert.match(P.panelText(ui, 'path'), /conditional/);
    const cond = ui.document.querySelectorAll('input[data-option]').find(e => e.dataset.option === 'include-conditional');
    await toggle(ui, cond, false);
    assert.equal(state(ui).path, null);
    ui.assertNoErrors();
  });

  test('[F-096] a filter change makes discovered paths stale instead of showing paths through hidden edges', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    await ui.click('discover-all');
    assert.ok(state(ui).discovered > 0);
    await toggle(ui, ui.filter('category', 'privesc'), false);
    assert.equal(state(ui).discovered, 0);
    assert.match(P.panelText(ui, 'discover'), /run Discover again/);
    await ui.click('discover-all');
    for (const p of ui.actions('select-path', { within: ui.panel('discover') })) p.click();
    ui.assertNoErrors();
  });
});

describe('external principals, providers and the internet node (F-036, F-037)', () => {
  test('[F-036] an identity provider and a foreign account are drawn as external sources with traversable assume edges', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const cy = ui.cy();
    assert.ok(cy.getElementById(EX.extRoot).hasClass('external'));
    await ui.findPath(EX.idp, EX.deployRole);
    assert.deepEqual(state(ui).path, [EX.idp, EX.deployRole]);
    await ui.tap(raw.edges.find(e => e.type === 'CAN_ASSUME_WEB_IDENTITY').id);
    const detail = P.panelText(ui, 'detail');
    assert.match(detail, /Traversable\s*yes/);
    assert.match(detail, /Confidence\s*conditional/);
    ui.assertNoErrors();
  });

  test('[F-037] the internet node has its own style and is a Discover source when nothing is owned (data-asset targets)', async (t) => {
    const ui = await P.bootUi(t, { graph: variant('example', d => { d.run.operator = { arn: null, node_id: null, resolution: 'unavailable', redacted: false }; }) });
    assert.ok(ui.cy().getElementById(EX.anonymous).hasClass('internet'));
    assert.deepEqual(state(ui).owned, []);
    // with data assets as targets, the public bucket is reachable from the internet at zero cost
    const assets = ui.document.querySelectorAll('input[data-option]').find(e => e.dataset.option === 'data-assets');
    await toggle(ui, assets, true);
    await ui.click('discover-all');
    assert.ok(ui.actions('select-path', { within: ui.panel('discover') }).length > 0);
    assert.ok(P.panelText(ui, 'discover').includes(nodeById(fixture('example'), EX.anonymous).label));
    ui.assertNoErrors();
  });
});

describe('large graphs (A5)', () => {
  test('[F-038] force-directed layout only for small graphs; a picked layout is kept for the next load', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    const select = ui.document.querySelector('#layout-select');
    assert.equal(select.value, 'cose');
    await ui.load(P.G.scaleGraph(1200));
    assert.equal(select.value, 'concentric');
    assert.match(ui.text(ui.document.querySelector('#graph-info')), /force-directed is slow/);
    select.value = 'breadthfirst';
    select.dispatchEvent(new ui.window.Event('change', { bubbles: true }));
    await ui.settle();
    await ui.load(fixture('example'));
    assert.equal(select.value, 'breadthfirst');
    ui.assertNoErrors();
  });

  test('above the threshold the page switches to large-graph mode (grid layout, notice)', async (t) => {
    const ui = await P.bootUi(t, {});
    const AEUI = ui.AEUI;
    const big = P.G.scaleGraph(AEUI.LARGE_EDGES + 10);
    await ui.load(big);
    const s = state(ui);
    assert.equal(s.loaded, true);
    assert.equal(s.large, true);
    assert.match(P.panelText(ui, 'problems'), /Large graph/);
    assert.equal(ui.document.querySelector('#layout-select').value, 'grid');
    ui.assertNoErrors();
  });
});
