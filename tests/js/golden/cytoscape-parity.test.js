'use strict';
// Distances of graph-core.js dijkstra against the vendored Cytoscape 3.30.4 (headless)
// eles.dijkstra({ root, weight, directed: true }) over the same active subgraph: an independent
// implementation of directed shortest paths. The legacy dashboard used directed:false and `w || 1`;
// this pins that the new core computes what a directed Cytoscape search over traversable edges does.
// Findings: F-007 (directed), F-040 (weight 0 legal), F-096 (filters).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');
const { cytoscapeAvailability, createHeadless } = require('../helpers/cytoscape-headless');

const { C } = H.modules();
const avail = cytoscapeAvailability();

/** All-pairs distance parity on one document under one set of vector options; returns #reachable pairs. */
function parity(doc, options, label) {
  const { graph, index } = H.pipeline(C, doc);
  const active = C.activeSubgraph(index, H.activeOptionsFor(index, options || {}));
  const elements = graph.nodes.map(n => ({ group: 'nodes', data: { id: n.id } }))
    .concat(graph.edges.filter(e => active.edgeAllowed(e))
      .map(e => ({ group: 'edges', data: { id: e.id, source: e.source, target: e.target, weight: e.weight } })));
  const cy = createHeadless(elements);
  let reachable = 0;
  try {
    for (const s of index.nodesById.keys()) {
      const dj = cy.elements().dijkstra({ root: cy.getElementById(s), weight: (e) => e.data('weight'), directed: true });
      for (const t of index.nodesById.keys()) {
        if (s === t) continue;
        const want = dj.distanceTo(cy.getElementById(t));
        const got = C.dijkstra(index, s, t, { active });
        if (want === Infinity) {
          assert.equal(got, null, `${label}: ${s} -> ${t} is unreachable for Cytoscape`);
        } else {
          assert.ok(got, `${label}: ${s} -> ${t} reachable for Cytoscape (distance ${want})`);
          assert.ok(Math.abs(got.cost - want) < 1e-9, `${label}: ${s} -> ${t}: ${got.cost} vs ${want}`);
          reachable++;
        }
      }
    }
  } finally {
    cy.destroy();
  }
  return reachable;
}

describe('dijkstra distances == Cytoscape dijkstra({directed: true})', { skip: avail.skip }, () => {
  test('[F-007, F-040] example.json and hostile.json, every pair', () => {
    let n = 0;
    for (const name of ['example', 'hostile']) n += parity(H.fixture(name), {}, name);
    assert.ok(n > 50, `only ${n} reachable pairs`);
  });

  test('[F-007, F-096] every path_cases graph under its vector options', () => {
    let n = 0;
    for (const c of H.pathCases()) n += parity(c.graph, c.options, c.name);
    assert.ok(n > 50, `only ${n} reachable pairs`);
  });

  test('[F-007, F-040] 60 random tie-heavy graphs with zero weights', () => {
    for (let seed = 2000; seed < 2060; seed++) parity(H.randomGraph(seed, { n: 8, density: 0.3 }), {}, `random ${seed}`);
  });

  test('[F-007] the legacy undirected search would disagree: example.json has pairs only an undirected walk connects', () => {
    const { graph, index } = H.pipeline(C, H.fixture('example'));
    const active = C.activeSubgraph(index, {});
    const elements = graph.nodes.map(n => ({ group: 'nodes', data: { id: n.id } }))
      .concat(graph.edges.filter(e => active.edgeAllowed(e)).map(e => ({ group: 'edges', data: { id: e.id, source: e.source, target: e.target } })));
    const cy = createHeadless(elements);
    let falsePaths = 0;
    for (const s of index.nodesById.keys()) {
      const dj = cy.elements().dijkstra({ root: cy.getElementById(s), directed: false });
      for (const t of index.nodesById.keys()) {
        if (s !== t && dj.distanceTo(cy.getElementById(t)) !== Infinity && C.dijkstra(index, s, t) === null) falsePaths++;
      }
    }
    cy.destroy();
    assert.ok(falsePaths > 0, 'the fixture should exhibit the F-007 false paths of an undirected search');
  });
});
