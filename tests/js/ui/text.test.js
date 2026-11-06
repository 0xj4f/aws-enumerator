'use strict';
// Status texts of the page (security-browser verification, 2026-10-16, observations 3 and 4):
// - the search status said "0 matchs for the search": plural() appended "s" to every word;
// - the Discover summary counted only the sources that produced a path, so an owned source that reaches no
//   target read "0 paths from 0 sources". It now says what was searched (sources, targets) and that none
//   reached a target. Discover sources and targets are dashboard-core-api.md 2.7 / 2.8 (F-043).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');
const P = require('./lib/page');

const { fixture, variant, EX, drain, pipeline } = P.common;
const { C } = H.modules();

/** Words whose plural is not word + "s" (English spelling rules the page's words can hit). */
const IRREGULAR = /(?:s|x|z|ch|sh|[^aeiou]y)$/;

function graphInfo(ui) {
  return ui.text(ui.document.querySelector('#graph-info'));
}

async function search(ui, term) {
  const input = ui.document.querySelector('#search-input');
  input.value = term;
  input.dispatchEvent(new ui.window.Event('input', { bubbles: true }));
  await ui.settle();
  return graphInfo(ui);
}

function summary(ui) {
  const p = ui.panel('discover').querySelector('[data-role="discover-summary"]');
  assert.ok(p, 'no Discover summary line');
  return ui.text(p);
}

/** What the page should search for `raw` with `owned` marked (the core's own defaults). */
function expected(raw, owned, { dataAssets = false } = {}) {
  const { graph, index } = pipeline(C, raw);
  const operator = C.operatorNode(graph).id;
  const sources = C.defaultSources(index, owned, operator);
  const targets = C.defaultTargets(index, { includeDataAssets: dataAssets });
  const { result } = drain(C.discoverAll(index, { sources, targets, owned }));
  return { sources, targets, paths: result.paths, reached: new Set(result.paths.map(p => p.source)).size };
}

describe('plural forms (security-browser observation 3)', () => {
  test('every plural() call of ui.js names the plural of an irregular word explicitly', () => {
    const src = H.moduleSource('ui.js');
    const calls = [...src.matchAll(/\bplural\(([^']*?),\s*'([^']*)'\s*(?:,\s*'([^']*)'\s*)?\)/g)];
    assert.ok(calls.length >= 15, `found only ${calls.length} plural() calls; the scan is broken`);
    for (const [call, , word, many] of calls) {
      const last = word.split(' ').pop();
      if (IRREGULAR.test(last)) assert.ok(many, `${call}: "${word}" needs its plural form (plural(n, word, plural))`);
      if (many !== undefined) assert.notEqual(many, `${word}s`, `${call}: the explicit plural is the default`);
    }
    assert.ok(calls.some(([, , word, many]) => word === 'match' && many === 'matches'), 'the search status call');
  });

  test('the search status reads "0 matches", "1 match", "<n> matches"', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const hits = (term) => raw.nodes.filter(n => n.label.toLowerCase().includes(term) || n.id.toLowerCase().includes(term)).length;
    assert.equal(hits('demo-admin'), 1, 'fixture precondition: one node matches "demo-admin"');
    assert.ok(hits('demo') > 1);
    assert.match(await search(ui, 'no-such-node-anywhere'), / - 0 matches for the search$/);
    assert.match(await search(ui, 'demo-admin'), / - 1 match for the search$/);
    assert.match(await search(ui, 'demo'), new RegExp(` - ${hits('demo')} matches for the search$`));
    assert.doesNotMatch(graphInfo(ui), /matchs/);
    assert.doesNotMatch(await search(ui, '   '), /for the search/);
    ui.assertNoErrors();
  });
});

describe('Discover summary (security-browser observation 4; F-043)', () => {
  test('[F-043] an owned source that reaches no target reads "0 paths from 1 owned source to <n> targets (none reached a target)"', async (t) => {
    // The operator is pre-marked owned (F-146); here it is the secret, a data asset with no way out.
    const raw = variant('example', d => { d.run.operator.node_id = EX.secret; });
    const want = expected(raw, [EX.secret]);
    assert.equal(want.paths.length, 0, 'fixture precondition: the secret reaches no target');
    assert.ok(want.targets.length > 0);
    const ui = await P.bootUi(t, { graph: raw });
    assert.deepEqual(JSON.parse(JSON.stringify(ui.AEUI.state().owned)), [EX.secret]);
    await ui.click('discover-all');
    assert.equal(summary(ui), `0 paths from 1 owned source to ${want.targets.length} targets (none reached a target)`);
    assert.doesNotMatch(P.panelText(ui, 'discover'), /from 0 sources/);
    ui.assertNoErrors();
  });

  test('[F-043] with the operator owned, the summary names the owned sources and the targets searched', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    const owned = JSON.parse(JSON.stringify(ui.AEUI.state().owned));
    assert.deepEqual(owned, [EX.appRole], 'the operator is pre-marked owned (F-146)');
    const want = expected(raw, owned);
    await ui.click('discover-all');
    const n = want.paths.length;
    const head = `${n} path${n === 1 ? '' : 's'} from 1 owned source to ${want.targets.length} targets`;
    assert.equal(summary(ui), n ? `${head}; showing ${n}` : `${head} (none reached a target)`);
    ui.assertNoErrors();
  });

  test('[F-043] with nothing owned, the summary says how many of the default sources reached a target', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    await ui.click('toggle-owned', { nodeId: EX.appRole, within: ui.panel('owned') });
    assert.deepEqual(JSON.parse(JSON.stringify(ui.AEUI.state().owned)), []);
    const want = expected(raw, []);
    assert.ok(want.sources.length > 1 && want.reached >= 1, 'fixture precondition: some default source reaches a target');
    await ui.click('discover-all');
    const n = want.paths.length;
    const from = want.reached < want.sources.length ? `${want.reached} of ${want.sources.length} sources` : `${want.sources.length} sources`;
    assert.equal(summary(ui), `${n} path${n === 1 ? '' : 's'} from ${from} to ${want.targets.length} targets; showing ${n}`);
    assert.equal(ui.AEUI.state().discovered, n);
    ui.assertNoErrors();
  });

  test('[F-043] a report without targets says so instead of counting sources', async (t) => {
    const raw = variant('example', d => {
      d.meta.default_targets = [];
      for (const node of d.nodes) if (node.props) delete node.props.high_value;
    });
    assert.equal(expected(raw, [EX.appRole]).targets.length, 0, 'fixture precondition: no targets');
    const ui = await P.bootUi(t, { graph: raw });
    await ui.click('discover-all');
    assert.equal(summary(ui), '0 paths: no target to reach (the report marks no high-value node; the filters can make data assets targets)');
    ui.assertNoErrors();
  });

  test('a session\'s paths are summarised by their own sources (nothing was searched)', async (t) => {
    const raw = fixture('example');
    const ui = await P.bootUi(t, { graph: raw });
    await ui.click('toggle-owned', { nodeId: EX.appRole, within: ui.panel('owned') });
    await ui.click('discover-all');
    const found = ui.AEUI.state().discovered;
    assert.ok(found > 0);
    await ui.click('export-session');
    const text = await P.downloadText(ui.downloads[ui.downloads.length - 1]);
    const ui2 = await P.bootUi(t, { graph: raw });
    const input = ui2.document.querySelector('#session-input');
    input.files = [ui2.file(text, 'session.json')];
    input.dispatchEvent(new ui2.window.Event('change', { bubbles: true }));
    await ui2.waitFor(() => ui2.AEUI.state().discovered === found, { what: 'the session paths' });
    const sources = new Set(JSON.parse(text).paths.map(p => p.path[0])).size;
    assert.equal(summary(ui2), `${found} path${found === 1 ? '' : 's'} from ${sources} source${sources === 1 ? '' : 's'}; showing ${found}`);
    ui2.assertNoErrors();
  });
});
