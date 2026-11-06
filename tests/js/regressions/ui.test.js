'use strict';
// Dashboard regression tests: the rendered page (owner of the fix: Du, with Dc's modules).
//
// Written xfail-first in Wave 0 (js/ui.js did not exist); flipped to plain tests by the Du stream in
// Wave 2 when index.html, dom.js and ui.js landed. A failure here now means a regression of the
// finding in the test name. The page runs in a browser-faithful harness (lib/ui-harness.js): the
// strict dom-stub (innerHTML setters, on*= attributes, inline styles and <script> creation all
// throw), the real index.html skeleton, every <script src> of index.html in a page realm, headless
// vendored Cytoscape, fake timers. The UI test protocol (data-panel / data-action / data-filter-*
// hooks) is dashboard-core-api.md section 5 and PROTOCOL in lib/ui-harness.js.
// Findings: F-005, F-006, F-008, F-036, F-037, F-041, F-042, F-043, F-090, F-092, F-094, F-096,
// F-097, F-098, F-145, F-146 (rendering side).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { allAttributes } = require('../helpers/dom-stub');
const { core, fixture, fixtureText, variant, nodeById, edgesOfType, EX, HO, settlesWithin, protoSnapshot } = require('./lib/common');
const { bootUi, includesRendered, stringLeaves } = require('./lib/ui-harness');
const G = require('./lib/graphs');

const CANARY_LABEL = '<img src=x onerror=window.__aeXssCanary=1>';

/** Visible error text: overlay + problems panels. */
const visibleMessage = (ui) => `${ui.text(ui.panel('overlay'))} ${ui.text(ui.panel('problems'))}`;
const nodeIdsIn = (el) => el.querySelectorAll('[data-node-id]').map(e => e.dataset.nodeId);

function assertShows(ui, panel, needle, what) {
  const text = ui.rawText(ui.panel(panel));
  assert.ok(includesRendered(text, needle), `${what || panel} does not show ${JSON.stringify(needle)}`);
}

function assertInert(ui) {
  assert.equal(ui.window.__aeXssCanary, undefined, 'a canary executed');
  for (const a of ui.document.querySelectorAll('a')) {
    const href = a.getAttribute('href');
    if (href === null) continue;
    assert.equal(core().safeHref(href), href, `unsafe link ${href}`);
  }
  for (const { name, value } of allAttributes(ui.document.body)) {
    assert.ok(!/^on/i.test(name), `inline handler attribute ${name}`);
    if (name === 'class') for (const c of value.split(/\s+/).filter(Boolean)) assert.match(c, /^[A-Za-z0-9_-]+$/, `class token ${JSON.stringify(c)} built from data`);
  }
}

describe('UI regressions: findings (F-005)', () => {
  test(`[F-005] the findings panel lists every finding and resource/K8s findings appear in node detail`, async (t) => {
    const raw = fixture('example');
    const ui = await bootUi(t, { graph: raw });
    const panel = ui.panel('findings');
    assert.equal(ui.actions('select-finding', { within: panel }).length, raw.findings.length, 'one row per finding');
    for (const f of raw.findings) {
      assertShows(ui, 'findings', f.id);
      assertShows(ui, 'findings', f.title);
    }
    for (const [id, fid] of [[EX.bucket, 'S3-PUBLIC-001'], [EX.lambda, 'LAMBDA-URL-001'], [EX.instance, 'EC2-IMDS-001'], [EX.account, 'COLLECTION-GAP-001'], [EX.group, 'PRIVESC-014']]) {
      await ui.tap(id);
      assertShows(ui, 'detail', fid, `detail of ${id}`);
    }
    const row = ui.actions('select-finding', { within: panel }).find(el => el.textContent.includes('S3-PUBLIC-001'));
    assert.ok(row, 'no row for S3-PUBLIC-001');
    row.click();
    await ui.settle();
    assertShows(ui, 'detail', 'demo-data-bucket', 'selecting a finding opens its node');
    await ui.load(fixture('hostile'));
    await ui.tap(HO.sa);
    assertShows(ui, 'detail', 'K8S-IRSA-001', 'K8s service account detail');
    await ui.load(variant('example', d => d.findings.push({ ...d.findings[3], node_id: 'arn:aws:s3:::demo-missing-bucket', fingerprint: 'ffffffffffffffffffffffffffffffff' })));
    assert.match(ui.text(ui.panel('findings'), { hidden: true }), /\b1 unattached\b/i, 'unattached findings are counted');
    ui.assertNoErrors();
  });
});

describe('UI regressions: unknown attachments and malformed props (F-006)', () => {
  test(`[F-006] a role whose attachments could not be read shows "unknown (AccessDenied)"; malformed props do not break rendering`, async (t) => {
    const raw = variant('example', d => {
      const app = nodeById(d, EX.appRole);
      app.props.attached_policies_status = 'denied';
      app.props.attached_policies_error = 'AccessDenied';
      nodeById(d, EX.deployRole).props = 'oops';
      nodeById(d, EX.irsaRole).props = ['x'];
      nodeById(d, EX.nodeRole).props = null;
    });
    const ui = await bootUi(t, { graph: raw });
    await ui.tap(EX.appRole);
    assert.match(ui.text(ui.panel('detail')), /unknown \(AccessDenied\)/);
    for (const id of [EX.deployRole, EX.irsaRole, EX.nodeRole]) {
      await ui.tap(id);
      assertShows(ui, 'detail', nodeById(raw, id).label, `detail of ${id}`);
    }
    assert.match(ui.text(ui.panel('problems'), { hidden: true }), /props/i, 'malformed props are reported as problems');
    ui.assertNoErrors();
  });
});

describe('UI regressions: render safety (F-008)', () => {
  test(`[F-008] hostile strings render as inert text in header, node and edge detail, findings, coverage, owned, path steps and discover list`, async (t) => {
    const raw = fixture('hostile');
    const ui = await bootUi(t, { graph: raw });
    assertShows(ui, 'header', raw.run.account_id);
    for (const n of raw.nodes) {
      await ui.tap(n.id);
      assertShows(ui, 'detail', n.label, `detail of ${n.id}`);
      assertShows(ui, 'detail', n.id, `detail of ${n.id}`);
      for (const v of stringLeaves(n.props)) assertShows(ui, 'detail', v, `props of ${n.id}`);
    }
    for (const e of raw.edges) {
      await ui.tap(e.id);
      // A5: the evidence list shows policy/statement provenance, actions, resources and conditions.
      for (const k of ['statements', 'actions', 'resources', 'conditions']) {
        for (const v of stringLeaves(e.evidence[k])) assertShows(ui, 'detail', v, `evidence.${k} of ${e.type}`);
      }
    }
    for (const f of raw.findings) assertShows(ui, 'findings', f.title);
    for (const m of raw.coverage.modules) for (const v of [m.module, m.region, m.detail]) assertShows(ui, 'coverage', v);
    await ui.tap(HO.canaryRole);
    await ui.click('toggle-owned', { nodeId: HO.canaryRole });
    assertShows(ui, 'owned', CANARY_LABEL);
    await ui.findPath(HO.quoteUser, HO.canaryRole);
    for (const id of [HO.quoteUser, HO.protoRole, HO.canaryRole]) assertShows(ui, 'path', nodeById(raw, id).label, 'path steps');
    await ui.click('discover-all');
    assertShows(ui, 'discover', CANARY_LABEL);
    assertInert(ui);
    ui.assertNoErrors();
  });
});

describe('UI regressions: assume edges and the internet node (F-036, F-037)', () => {
  test(`[F-036] external accounts, identity providers and their assume edges are rendered and usable as path sources`, async (t) => {
    const raw = fixture('example');
    const ui = await bootUi(t, { graph: raw });
    const cy = ui.cy();
    for (const id of [EX.extRoot, EX.idp]) assert.ok(cy.getElementById(id).nonempty(), `${id} not rendered`);
    for (const e of [...edgesOfType(raw, 'CAN_ASSUME'), ...edgesOfType(raw, 'CAN_ASSUME_WEB_IDENTITY')]) {
      assert.ok(cy.getElementById(e.id).nonempty(), `${e.type} ${e.source} -> ${e.target} not rendered`);
    }
    await ui.findPath(EX.extRoot, EX.appRole);
    assertShows(ui, 'path', nodeById(raw, EX.extRoot).label);
    assert.doesNotMatch(ui.text(ui.panel('path')), /no path|not connected|unreachable/i);
    ui.assertNoErrors();
  });

  test(`[F-037] the anonymous (internet) node and public grant edges are rendered and the node is a path source`, async (t) => {
    const raw = fixture('example');
    const ui = await bootUi(t, { graph: raw });
    const cy = ui.cy();
    assert.ok(cy.getElementById(EX.anonymous).nonempty(), 'anonymous node not rendered');
    for (const e of [...edgesOfType(raw, 'GRANTS_PUBLIC'), ...edgesOfType(raw, 'SSRF_TO_IMDS')]) assert.ok(cy.getElementById(e.id).nonempty(), `${e.type} not rendered`);
    await ui.tap(EX.anonymous);
    assert.ok(ui.actions('path-from', { nodeId: EX.anonymous }).length, 'anonymous cannot be chosen as a path source');
    await ui.findPath(EX.anonymous, EX.bucket);
    assertShows(ui, 'path', 'demo-data-bucket');
    assert.doesNotMatch(ui.text(ui.panel('path')), /no path|not connected|unreachable/i);
    ui.assertNoErrors();
  });
});

describe('UI regressions: ids round-trip through data attributes (F-041)', () => {
  test(`[F-041] ids with " ' \\ round-trip exactly through data-node-id; actions work; no on* attributes`, async (t) => {
    const raw = fixture('hostile');
    const ui = await bootUi(t, { graph: raw });
    await ui.tap(HO.quoteUser);
    for (const a of ['focus', 'toggle-owned', 'path-from']) assert.ok(ui.actions(a, { nodeId: HO.quoteUser }).length, `no ${a} action for the quoted id`);
    await ui.click('toggle-owned', { nodeId: HO.quoteUser });
    assert.ok(nodeIdsIn(ui.panel('owned')).includes(HO.quoteUser), 'owned list lost the exact id');
    await ui.click('focus', { nodeId: HO.quoteUser, within: ui.panel('owned') });
    const ids = new Set(raw.nodes.map(n => n.id));
    for (const id of nodeIdsIn(ui.document)) assert.ok(ids.has(id), `mangled data-node-id ${JSON.stringify(id)}`);
    assertInert(ui);
    ui.assertNoErrors();
  });
});

describe('UI regressions: prototype-named data (F-042)', () => {
  test(`[F-042] prototype-named nodes work through detail, owned, findings and discover without errors or pollution`, async (t) => {
    const raw = fixture('hostile');
    const before = protoSnapshot();
    const ui = await bootUi(t, { graph: raw });
    const pageBefore = protoSnapshot(ui.realm.Object, ui.realm.Array);
    for (const id of [HO.ctorRole, HO.hasOwnRole, HO.toStringRole, HO.extProto]) {
      await ui.tap(id);
      assertShows(ui, 'detail', nodeById(raw, id).label);
      await ui.click('toggle-owned', { nodeId: id });
    }
    await ui.tap(HO.hasOwnRole);
    assertShows(ui, 'detail', 'TRUST-002', 'finding on the hasOwnProperty role');
    await ui.click('discover-all');
    assertShows(ui, 'discover', CANARY_LABEL);
    assert.deepEqual(protoSnapshot(), before, 'host prototypes changed');
    assert.deepEqual(protoSnapshot(ui.realm.Object, ui.realm.Array), pageBefore, 'page prototypes changed');
    ui.assertNoErrors();
  });
});

describe('UI regressions: discover paging (F-043)', () => {
  test(`[F-043] the discover list shows 50 paths at a time with "Show more" instead of a global top-50`, async (t) => {
    const ui = await bootUi(t, { graph: G.fanInGraph(60) });
    await ui.click('discover-all');
    const panel = ui.panel('discover');
    assert.equal(ui.actions('select-path', { within: panel }).length, 50, 'first page');
    await ui.click('show-more', { within: panel });
    assert.equal(ui.actions('select-path', { within: panel }).length, 100, 'second page');
    ui.assertNoErrors();
  });
});

describe('UI regressions: generated filters and legend (F-090)', () => {
  test(`[F-090] every present node type, edge category and traversal class gets a filter and legend entry (with fallbacks); no 'finding' filter`, async (t) => {
    const raw = variant('example', d => {
      d.node_types.future_type = { label: 'Future type', icon: 'not-an-icon', group: 'posture', order: 99, is_compute_bridge: false, default_source: false, data_asset: false, synthetic: false, description: 'a type this dashboard has never seen' };
      d.nodes.push(G.node('aws-enumerator:future/111122223333', 'future_type', 'demo-future'));
    });
    const ui = await bootUi(t, { graph: raw });
    for (const ty of new Set(raw.nodes.map(n => n.type))) {
      assert.ok(ui.filter('node-type', ty), `no node-type filter for ${ty}`);
      assert.ok(ui.legend('node-type', ty), `no legend entry for ${ty}`);
    }
    for (const c of new Set(raw.edges.map(e => e.category))) assert.ok(ui.filter('category', c), `no category filter for ${c}`);
    for (const c of new Set(raw.edges.map(e => e.traversal))) {
      assert.ok(ui.filter('traversal', c), `no traversal filter for ${c}`);
      assert.ok(ui.legend('traversal', c), `no legend entry for traversal ${c}`);
    }
    assert.equal(ui.filter('category', 'finding'), null, "dead 'finding' filter");
    assert.equal(ui.filter('node-type', 'sqs'), null, 'filters are generated from the loaded graph only');
    ui.assertNoErrors();
  });
});

describe('UI regressions: failures are surfaced (F-092)', () => {
  test(`[F-092] a failing load shows an error and settles: unsupported version, structural error, corrupt zip`, async (t) => {
    const ui = await bootUi(t, {});
    await settlesWithin(ui.load(variant('example', d => { d.schema_version = '2.0.0'; })), 3000, 'loadGraphObject(v2)');
    assert.match(visibleMessage(ui), /unsupported/i, 'unsupported version not shown');
    await settlesWithin(ui.load({ schema_version: '1.0.0', nodes: 'not-a-list', edges: [] }), 3000, 'loadGraphObject(structural error)');
    assert.match(visibleMessage(ui), /error|invalid|could not|cannot/i, 'structural error not shown');
    await ui.chooseFiles([ui.file(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4, 5]), 'report.zip')]);
    await ui.waitFor(() => /error|invalid|could not|cannot|corrupt|unreadable/i.test(visibleMessage(ui)), { what: 'an error for a corrupt zip' });
    assert.doesNotMatch(ui.text(ui.panel('overlay')), /loading/i, 'stuck on "Loading"');
    assert.deepEqual(ui.unhandled, [], 'unhandled promise rejection');
  });
});

describe('UI regressions: reload, session and header (F-094)', () => {
  test(`[F-094] a second load resets owned marks, paths, discover results and timers; the header shows run metadata; nothing is persisted by default`, async (t) => {
    const ex = fixture('example');
    const ui = await bootUi(t, { graph: ex });
    const header = ui.text(ui.panel('header'));
    for (const s of [ex.run.account_id, ex.run.run_id, ex.generator.version, 'eu-west-2']) assert.ok(header.includes(s), `header lacks ${s}`);
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    await ui.findPath(EX.user, EX.adminRole);
    await ui.click('discover-all');
    const first = ui.cy();
    await ui.load(fixture('hostile'));
    assert.ok(first.destroyed(), 'the previous Cytoscape instance was not destroyed');
    const exIds = new Set(ex.nodes.map(n => n.id));
    for (const p of ['owned', 'path', 'discover', 'detail']) {
      const stale = nodeIdsIn(ui.panel(p)).filter(id => exIds.has(id));
      assert.deepEqual(stale, [], `${p} panel kept ids of the previous report`);
      assert.ok(!ui.rawText(ui.panel(p)).includes('demo-user'), `${p} panel kept labels of the previous report`);
    }
    assert.equal(ui.clock.intervals().length, 0, 'a timer of the previous report is still running');
    assert.ok(ui.text(ui.panel('header')).includes('123456789012'), 'header not updated for the new run');
    assert.deepEqual(ui.storageLog.filter(([op]) => op === 'set'), [], 'state was written to web storage without opt-in');
    ui.assertNoErrors();
  });
});

describe('UI regressions: filters apply to path finding (F-096)', () => {
  test(`[F-096] changing a filter clears or re-runs the displayed path`, async (t) => {
    const ui = await bootUi(t, { graph: fixture('example') });
    await ui.findPath(EX.user, EX.adminRole);
    assertShows(ui, 'path', 'demo-devs', 'path via the group');
    await ui.setFilter('category', 'privesc', false);
    assert.ok(!includesRendered(ui.rawText(ui.panel('path')), 'demo-devs'), 'a path through a hidden category is still displayed');
    ui.assertNoErrors();
  });
});

describe('UI regressions: finding links and severity classes (F-097)', () => {
  test(`[F-097] only https references become links (rel/referrerpolicy set); bad severities map to an allow-listed class; titles are text`, async (t) => {
    const refs = new Map([['ADMIN-001', 'javascript:window.__aeXssCanary=1'], ['PRIVESC-014', 'data:text/html,<b>x</b>'], ['S3-PUBLIC-001', 'http://example.invalid/x'], ['TRUST-002', '//example.invalid/x'], ['LAMBDA-URL-001', 'https://example.invalid/docs#lambda']]);
    const raw = variant('example', d => {
      for (const f of d.findings) {
        if (refs.has(f.id)) f.reference = refs.get(f.id);
        if (f.id === 'EC2-IMDS-001') f.severity = 'HIGH" onmouseover="window.__aeXssCanary=1';
        if (f.id === 'IAM-USER-MFA-001') f.severity = '__proto__';
        if (f.id === 'COLLECTION-GAP-001') f.title = '<b>bold</b>';
      }
    });
    const ui = await bootUi(t, { graph: raw });
    const seen = new Set();
    const checkLinks = () => {
      for (const a of ui.document.querySelectorAll('a').filter(x => x.getAttribute('href') !== null)) {
        seen.add(a.getAttribute('href'));
        assert.match(a.getAttribute('rel') || '', /\bnoopener\b/);
        assert.match(a.getAttribute('rel') || '', /\bnoreferrer\b/);
        assert.equal(a.getAttribute('referrerpolicy'), 'no-referrer');
      }
      assertInert(ui); // every href passes safeHref; class tokens are allow-listed
    };
    checkLinks();
    for (const f of raw.findings) {
      await ui.tap(f.node_id); // the detail panel lists the node's findings with their references
      checkLinks();
    }
    assert.ok(seen.has('https://example.invalid/docs#lambda'), 'the https reference is not linked');
    assertShows(ui, 'findings', '<b>bold</b>');
    ui.assertNoErrors();
  });
});

describe('UI regressions: Clear (F-098)', () => {
  test(`[F-098] Clear does not throw, stops playback and leaves no timer that changes the next graph`, async (t) => {
    const ui = await bootUi(t, { graph: fixture('example') });
    // The operator (demo-app-role) reaches no admin target; owning demo-user gives discover paths to play.
    await ui.tap(EX.user);
    await ui.click('toggle-owned', { nodeId: EX.user });
    await ui.click('discover-all');
    assert.ok(ui.actions('select-path', { within: ui.panel('discover') }).length > 0, 'discover found nothing to play');
    await ui.click('play');
    assert.ok(ui.clock.pending().length > 0, 'playback scheduled nothing');
    await ui.tick(5000);
    await ui.click('clear');
    assert.equal(ui.clock.intervals().length, 0, 'playback interval survived Clear');
    await ui.load(fixture('hostile'));
    const cy = ui.cy();
    const snap = () => cy.elements().map(e => `${e.id()}:${e.classes().slice().sort().join(' ')}`).sort().join('|');
    const before = snap();
    await ui.tick(30000);
    assert.equal(snap(), before, 'a stale timer changed the new graph');
    ui.assertNoErrors();
  });
});

describe('UI regressions: input kinds (F-145)', () => {
  test(`[F-145] a non-report file shows an error; a bare graph.json and a report folder load`, async (t) => {
    const ui = await bootUi(t, {});
    await ui.chooseFiles([ui.file('just some notes', 'notes.txt')]);
    await ui.waitFor(() => /unsupported|not a|cannot|could not|error/i.test(visibleMessage(ui)), { what: 'an error for a text file' });
    await ui.chooseFiles([ui.file(fixtureText('example'), 'graph.json')]);
    await ui.waitFor(() => ui.cores.length > 0 && ui.cy().nodes().length === fixture('example').nodes.length, { what: 'graph.json rendered' });
    const hostile = fixture('hostile');
    await ui.chooseFiles([
      ui.file(JSON.stringify({ schema_version: '2.0', run: { run_id: hostile.run.run_id } }), 'manifest.json', { webkitRelativePath: 'demo-run/manifest.json' }),
      ui.file(fixtureText('hostile'), 'graph.json', { webkitRelativePath: 'demo-run/analysis/graph.json' }),
    ], { folder: true });
    await ui.waitFor(() => ui.cy().nodes().length === hostile.nodes.length && !ui.cy().destroyed(), { what: 'folder rendered' });
    assert.deepEqual(ui.unhandled, []);
  });
});

describe('UI regressions: operator principal (F-146)', () => {
  test(`[F-146] the operator node is pre-marked owned and is the default path source; otherwise "caller not in graph (<resolution>)"`, async (t) => {
    const ui = await bootUi(t, { graph: fixture('example') });
    assert.ok(nodeIdsIn(ui.panel('owned')).includes(EX.appRole), 'operator not pre-marked as owned');
    await ui.tap(EX.bucket);
    await ui.click('path-to', { nodeId: EX.bucket });
    if (ui.actions('find-path').length) await ui.click('find-path');
    assertShows(ui, 'path', 'demo-app-role', 'default Find Path source');
    assertShows(ui, 'path', 'demo-data-bucket');
    await ui.load(variant('example', d => {
      d.run.operator = { arn: 'arn:aws:sts::111122223333:federated-user/demo-fed', node_id: null, resolution: 'federated', redacted: false };
      d.meta.default_sources = d.meta.default_sources.filter(x => x !== EX.appRole);
    }));
    assert.match(ui.text(ui.document.body), /caller not in graph \(federated\)/);
    assert.deepEqual(nodeIdsIn(ui.panel('owned')), [], 'nothing is pre-marked without an operator node');
    ui.assertNoErrors();
  });
});
