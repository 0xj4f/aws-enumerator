'use strict';
// Self-tests for the regression-suite support code in tests/js/regressions/lib/. Plain tests,
// deliberately NOT tagged [F-xxx]: they prove the tooling works, not that a finding is fixed.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const common = require('./lib/common');
const markup = require('./lib/markup');
const scan = require('./lib/scan');
const G = require('./lib/graphs');

describe('regression support: fixtures and matchers', () => {
  test('missingModule() matches node\'s MODULE_NOT_FOUND for exactly that dashboard file', () => {
    let err = null;
    try { require(common.dashboardJsFile('does-not-exist.js')); } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(common.missingModule('does-not-exist.js')(err), true);
    assert.equal(common.missingModule('other.js')(err), false);
    assert.equal(common.missingModule('x.js')(new Error('NotImplemented: dijkstra')), false);
  });

  test('NOT_IMPLEMENTED matches the graph-core stub error only', () => {
    assert.match('NotImplemented: buildIndex', common.NOT_IMPLEMENTED);
    assert.doesNotMatch('Expected values to be strictly equal', common.NOT_IMPLEMENTED);
  });

  test('every finding of this suite has at least one shared path vector or test target', () => {
    const tagged = new Set(common.pathCases().flatMap(c => c.findings || []));
    for (const f of ['F-007', 'F-036', 'F-037', 'F-039', 'F-040', 'F-096']) assert.ok(tagged.has(f), `path_cases.json lost its ${f} vectors`);
    assert.equal(common.FINDINGS.length, 25);
  });

  test('well-known fixture ids exist (example.json, hostile.json)', () => {
    const ex = new Set(common.fixture('example').nodes.map(n => n.id));
    for (const [k, id] of Object.entries(common.EX)) assert.ok(ex.has(id), `EX.${k}`);
    const ho = new Set(common.fixture('hostile').nodes.map(n => n.id));
    for (const [k, id] of Object.entries(common.HO)) assert.ok(ho.has(id), `HO.${k}`);
  });

  test('activeOptionsFor maps path_cases options to activeSubgraph options', () => {
    const index = { categoriesPresent: new Set(['iam', 'lambda']), typesPresent: new Set(['user', 'lambda']) };
    assert.deepEqual(common.activeOptionsFor(index, {}), { respectFilters: true, includeConditional: true, categories: null, nodeTypes: null });
    const o = common.activeOptionsFor(index, { exclude_categories: ['lambda'], exclude_node_types: ['lambda'], definite_only: true });
    assert.deepEqual([...o.categories], ['iam']);
    assert.deepEqual([...o.nodeTypes], ['user']);
    assert.equal(o.includeConditional, false);
  });
});

describe('regression support: synthetic graphs and the reference costs', () => {
  test('edgeId reproduces the contract edge ids of example.json', () => {
    for (const e of common.fixture('example').edges) assert.equal(G.edgeId(e.source, e.type, e.target), e.id);
  });

  test('refCosts agrees with the frozen path vectors', () => {
    for (const c of common.pathCases()) {
      const o = c.options || {};
      const costs = G.refCosts(c.graph, c.source, { excludeCategories: o.exclude_categories, excludeNodeTypes: o.exclude_node_types, definiteOnly: o.definite_only });
      if (c.expect.reachable) assert.equal(costs.get(c.target), c.expect.cost, c.name);
      else assert.equal(costs.has(c.target), false, c.name);
    }
  });

  test('synthetic graphs are well formed (unique ids, endpoints exist, meta derived from props)', () => {
    for (const doc of [G.fanInGraph(5), G.fanOutGraph(5), G.scaleGraph(500)]) {
      const ids = doc.nodes.map(n => n.id);
      assert.equal(new Set(ids).size, ids.length);
      assert.equal(new Set(doc.edges.map(e => e.id)).size, doc.edges.length);
      for (const e of doc.edges) assert.ok(ids.includes(e.source) && ids.includes(e.target));
      assert.ok(doc.meta.default_targets.includes(G.ADMIN));
    }
    assert.equal(G.scaleGraph(2000).edges.length, 2000);
  });
});

describe('regression support: markup loader and static scanners', () => {
  test('tokenize/parseAttributes handle quoting, entities, void and raw-text elements', () => {
    const tags = markup.startTags('<a href="x?a=1&amp;b=2" data-x=\'y\' hidden><br><script>if (a<b) {}</script><input value=v>');
    assert.deepEqual(tags.map(t => t.name), ['a', 'br', 'script', 'input']);
    assert.deepEqual(tags[0].attrs, [['href', 'x?a=1&b=2'], ['data-x', 'y'], ['hidden', '']]);
    assert.deepEqual(markup.scriptTags('<script src="js/a.js"></script><script>var x = "</div>";</script>').map(s => [s.src, s.inline]), [['js/a.js', ''], [null, 'var x = "</div>";']]);
  });

  test('stripJsComments removes comments but keeps strings, templates and regex literals', () => {
    const src = 'var a = "http://x"; // el.innerHTML = 1\nvar r = /\\/\\/[a]/g; /* el.onclick = f */ var t = `//${a}`;\nvar d = a / 2 / 3;';
    const out = markup.stripJsComments(src);
    assert.equal(out.split('\n').length, src.split('\n').length);
    assert.ok(out.includes('"http://x"') && out.includes('/\\/\\/[a]/g') && out.includes('`//${a}`') && out.includes('a / 2 / 3'));
    assert.ok(!out.includes('innerHTML') && !out.includes('onclick'));
  });

  test('scan rules flag the forbidden patterns and pass the allowed ones', () => {
    const run = (code, rules) => scan.scanJs([{ file: 'x.js', text: code, lineOffset: 0 }], rules).length;
    for (const bad of ['el.innerHTML = s;', 'el.outerHTML += s', "el['innerHTML'] = s", 'el.insertAdjacentHTML("beforeend", s)', 'document.write(s)', 'eval(s)', 'new Function(s)',
      "setTimeout('go()', 1)", "el.setAttribute('onclick', s)", "el.setAttribute('style', s)", "cy.$('#' + id)", 'cy.$(`#${id}`)', "cy.nodes('[id = \"' + id)"]) {
      assert.equal(run(bad, scan.SINK_RULES), 1, bad);
    }
    for (const ok of ['el.textContent = s;', 'const h = el.innerHTML;', 'x === el.innerHTML', 'setTimeout(step, 0)', "el.setAttribute('href', u)", 'cy.getElementById(id)', 'evaluate(x)']) {
      assert.equal(run(ok, scan.SINK_RULES), 0, ok);
    }
    for (const bad of ['btn.onclick = f', 'el.onmouseover = f', "el.setAttribute('onload', f)", 'html += `<button class="x" onclick="go()">`']) assert.equal(run(bad, scan.HANDLER_RULES), 1, bad);
    for (const ok of ["cy.on('tap', f)", 'reader.onload = f', "el.addEventListener('click', f)", 'const online = "x";']) assert.equal(run(ok, scan.HANDLER_RULES), 0, ok);
    for (const bad of ["arn.split('/').pop()", "x.split(':').slice(-1)", "id.endsWith('/' + name)"]) assert.equal(run(bad, scan.NAME_MATCH_RULES), 1, bad);
    for (const bad of ['fetch(u)', 'new XMLHttpRequest()', 'import("x")', 'new WebSocket(u)', '"https://cdnjs.cloudflare.com/x.js"']) assert.ok(run(bad, scan.NETWORK_RULES) >= 1, bad);
    assert.deepEqual(scan.remoteLoadsInHtml('<script src="vendor/a.js"></script><img src="data:image/png;base64,AA"><a href="https://example.invalid">doc</a>'), []);
    assert.equal(scan.remoteLoadsInHtml('<script src="https://cdn.example.invalid/a.js"></script><link rel="stylesheet" href="//x/y.css">').length, 2);
    assert.deepEqual(markup.parseCsp("default-src 'none'; img-src 'self' data:;").get('img-src'), ["'self'", 'data:']);
  });
});
