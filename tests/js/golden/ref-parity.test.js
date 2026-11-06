'use strict';
// graph-core.js dijkstra against the Python reference tests/support/ref_paths.py (the executable
// definition of graph-json.md section 11, shared with the engine's traverse.py), through
// tests/fixtures/dc/ref_paths_dump.py. Exact parity: cost, hops, node path and edge ids for every pair.
// Findings: F-007 (directed, traversable only), F-040 (weights), F-096 (filters as vector options).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');

const { C } = H.modules();
const pySkip = H.pythonSkip();

/** Compares every (source, target) answer of one reference response with graph-core. */
function compare(doc, options, results, label) {
  const { index } = H.pipeline(C, doc);
  const active = C.activeSubgraph(index, H.activeOptionsFor(index, options));
  let reachable = 0;
  for (const [s, t, ref] of results) {
    const got = C.dijkstra(index, s, t, { active });
    const want = ref === null ? null : { cost: ref.cost, hops: ref.hops, path: ref.nodes, edges: ref.edges };
    assert.deepEqual(got, want, `${label}: ${s} -> ${t}`);
    if (want) reachable++;
  }
  return reachable;
}

describe('dijkstra == tests/support/ref_paths.py', { skip: pySkip }, () => {
  test('[F-007, F-040] example.json and hostile.json, every pair, with and without filters', () => {
    const variants = [{}, { exclude_categories: ['trust'] }, { exclude_node_types: ['group', 'sa'] }, { definite_only: true }];
    const requests = [];
    for (const name of ['example', 'hostile']) {
      for (const options of variants) requests.push({ graph: H.fixture(name), sources: null, targets: null, options, name });
    }
    const answers = H.refPaths(requests.map(({ name, ...r }) => r));
    let reachable = 0;
    requests.forEach((r, i) => { reachable += compare(r.graph, r.options, answers[i].results, `${r.name} ${JSON.stringify(r.options)}`); });
    assert.ok(reachable > 50, `only ${reachable} reachable pairs compared`);
  });

  test('[F-007, F-096] every path_cases graph, every pair, under the vector options', () => {
    const cases = H.pathCases();
    const answers = H.refPaths(cases.map(c => ({ graph: c.graph, sources: null, targets: null, options: c.options || {} })));
    let reachable = 0;
    cases.forEach((c, i) => { reachable += compare(c.graph, c.options || {}, answers[i].results, c.name); });
    assert.ok(reachable > 50, `only ${reachable} reachable pairs compared`);
  });

  test('[F-007, F-040] generated graphs (gen_large.py): every pair of two seeds', () => {
    const answers = H.refPaths([
      { generate: { scale: 4, seed: 3 }, sources: null, targets: null, options: {} },
      { generate: { scale: 3, seed: 11 }, sources: null, targets: null, options: { definite_only: true } },
    ]);
    let reachable = 0;
    reachable += compare(answers[0].graph, {}, answers[0].results, 'gen 4/3');
    reachable += compare(answers[1].graph, { definite_only: true }, answers[1].results, 'gen 3/11 definite');
    assert.ok(reachable > 50, `only ${reachable} reachable pairs compared`);
  });

  test('[F-007] random tie-heavy graphs: graph-core, the Python reference and brute force agree', () => {
    const docs = [];
    for (let seed = 1000; seed < 1040; seed++) docs.push(H.randomGraph(seed, { n: 7, density: 0.4 }));
    const answers = H.refPaths(docs.map(graph => ({ graph, sources: null, targets: null, options: {} })));
    docs.forEach((doc, i) => {
      compare(doc, {}, answers[i].results, `random ${1000 + i}`);
      for (const [s, t] of answers[i].results) {
        const ref = answers[i].results.find(r => r[0] === s && r[1] === t)[2];
        const brute = H.bruteForcePath(doc, s, t);
        assert.deepEqual(ref && { cost: ref.cost, hops: ref.hops, path: ref.nodes, edges: ref.edges }, brute, `brute ${s} -> ${t}`);
      }
    });
  });
});
