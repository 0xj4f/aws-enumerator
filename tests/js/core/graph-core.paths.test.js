'use strict';
// graph-core.js activeSubgraph and dijkstra (docs/contracts/dashboard-core-api.md sections 2.4-2.5,
// graph-json.md section 11). The shared vectors tests/fixtures/graph/path_cases.json are consumed here
// through the normative option mapping (DECISIONS.md D-04).
// Findings: F-007 (directed, traversable only), F-040 (weights), F-096 (filters). Assume edges (the engine's
// F-036) are checked here only for their direction.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C } = H.modules();
const { EX } = H;
const G = H.graphs;

/** A raw edge record outside the example.json registry (category/class given explicitly). */
function rawEdge(source, type, target, weight, category, traversal, extra = {}) {
  return {
    id: G.edgeId(source, type, target), source, target, type, category, traversal,
    traversable: extra.traversable === undefined ? true : extra.traversable,
    weight, confidence: extra.confidence || 'definite', evidence: {},
  };
}

function activeFor(index, options) {
  return C.activeSubgraph(index, H.activeOptionsFor(index, options || {}));
}

describe('dijkstra: the shared path vectors (path_cases.json)', () => {
  const cases = H.pathCases();
  test('the vector file is the normative one (31 vectors, every graph valid for the dashboard)', () => {
    assert.ok(cases.length >= 31);
    for (const c of cases) assert.ok(C.validateGraph(c.graph).graph, c.name);
  });

  // Only the dashboard findings of this stream are tagged: a vector's engine findings (F-004, F-016,
  // F-033 ...) are proved by the engine's tests, not by the dashboard reproducing the vector.
  const DC_FINDINGS = new Set(['F-007', 'F-037', 'F-039', 'F-040', 'F-096']);
  for (const c of cases) {
    const mine = (c.findings || []).filter(f => DC_FINDINGS.has(f));
    const tags = mine.length ? `[${mine.join(', ')}] ` : '';
    test(`${tags}path_cases/${c.name}: forward dijkstra and both discoverAll modes give the expected answer`, () => {
      const { index } = H.pipeline(C, c.graph);
      const active = activeFor(index, c.options);
      const r = C.dijkstra(index, c.source, c.target, { active });
      if (!c.expect.reachable) {
        assert.equal(r, null, `${c.name}: expected no path, got ${r && r.path.join(' -> ')}`);
      } else {
        assert.ok(r, `${c.name}: expected a path`);
        assert.equal(r.cost, c.expect.cost);
        assert.equal(r.hops, c.expect.hops);
        assert.deepEqual(r.path, c.expect.path);
        assert.deepEqual(r.edges.map(id => index.edgesById.get(id).type), c.expect.edge_types);
        assert.equal(r.edges.length, r.path.length - 1);
        for (const t of c.expect.must_not_traverse_types || []) {
          assert.ok(!r.edges.some(id => index.edgesById.get(id).type === t), `${c.name} walked ${t}`);
        }
      }
      // discoverAll with one source and one target runs forward; adding a dummy second target forces
      // the reverse mode when it has fewer targets than sources (two extra sources). Same answer both ways.
      const others = [...index.nodesById.keys()].filter(id => id !== c.source && id !== c.target).slice(0, 2);
      const runs = [
        { sources: [c.source], targets: [c.target] },
        { sources: [c.source, ...others], targets: [c.target] },
      ];
      for (const opts of runs) {
        const { result } = H.drain(C.discoverAll(index, { ...opts, active, perSourceCap: Infinity }));
        const got = result.paths.find(p => p.source === c.source && p.target === c.target) || null;
        if (!c.expect.reachable) assert.equal(got, null);
        else assert.deepEqual(got && { cost: got.cost, hops: got.hops, path: got.path, edges: got.edges }, r);
      }
    });
  }
});

describe('dijkstra: directed traversal over traversable edges (F-007)', () => {
  test('[F-007] no path between members of a shared group, holders of a shared policy, readers of a shared bucket or pods of a cluster', () => {
    const doc = G.skeleton();
    const reg = doc.edge_types;
    const alice = 'arn:aws:iam::111122223333:user/demo-alice';
    const bob = 'arn:aws:iam::111122223333:user/demo-bob';
    const group = 'arn:aws:iam::111122223333:group/demo-shared';
    const policy = 'arn:aws:iam::111122223333:policy/demo-shared';
    const bucket = 'arn:aws:s3:::demo-shared';
    const role = 'arn:aws:iam::111122223333:role/demo-role';
    for (const [id, type] of [[alice, 'user'], [bob, 'user'], [group, 'group'], [policy, 'policy'], [bucket, 'bucket'], [role, 'role']]) {
      doc.nodes.push(G.node(id, type, id.split(':').slice(-1)[0], type === 'bucket' ? { data_asset: true } : { attached_policies_status: 'complete' }));
    }
    doc.edges.push(G.edge(reg, alice, 'MEMBER_OF', group, 0), G.edge(reg, bob, 'MEMBER_OF', group, 0));
    doc.edges.push(G.edge(reg, alice, 'HAS_POLICY', policy, 0, { traversable: false }), G.edge(reg, role, 'HAS_POLICY', policy, 0, { traversable: false }));
    doc.edges.push(G.edge(reg, alice, 'CAN_READ', bucket, 1), G.edge(reg, role, 'CAN_READ', bucket, 1));
    doc.edges.push(G.edge(reg, bob, 'CAN_ASSUME', role, 1));
    G.finish(doc);
    const { index } = H.pipeline(C, doc);
    assert.equal(C.dijkstra(index, alice, bob), null, 'shared group');
    assert.equal(C.dijkstra(index, alice, role), null, 'shared policy / shared bucket');
    assert.equal(C.dijkstra(index, role, alice), null, 'reversed grant');
    assert.equal(C.dijkstra(index, role, bob), null, 'reversed CAN_ASSUME');
    assert.equal(C.dijkstra(index, alice, policy), null, 'HAS_POLICY is structural');
    const real = C.dijkstra(index, bob, bucket);
    assert.deepEqual(real.path, [bob, role, bucket], 'the real control path is found');
    assert.equal(real.cost, 2);
  });

  test('[F-007] every pair of example.json and hostile.json matches the reference costs (directed, traversable only)', () => {
    for (const name of ['example', 'hostile']) {
      const doc = H.fixture(name);
      const { index } = H.pipeline(C, doc);
      for (const s of index.nodesById.keys()) {
        const ref = G.refCosts(doc, s);
        for (const t of index.nodesById.keys()) {
          if (s === t) continue;
          const r = C.dijkstra(index, s, t);
          if (ref.has(t)) assert.equal(r && r.cost, ref.get(t), `${name}: ${s} -> ${t}`);
          else assert.equal(r, null, `${name}: ${s} -> ${t} should be unreachable`);
        }
      }
    }
  });

  test('[F-007] a returned path only walks allowed edges forward, and its cost is the sum of their weights', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const active = C.activeSubgraph(index, {});
    for (const s of index.nodesById.keys()) {
      for (const t of index.nodesById.keys()) {
        const r = C.dijkstra(index, s, t, { active });
        if (!r) continue;
        let cost = 0;
        r.edges.forEach((id, i) => {
          const e = index.edgesById.get(id);
          assert.ok(active.edgeAllowed(e));
          assert.equal(e.source, r.path[i]);
          assert.equal(e.target, r.path[i + 1]);
          cost += C.edgeWeight(e);
        });
        assert.equal(r.cost, cost);
        assert.equal(r.hops, r.edges.length);
      }
    }
  });

  test('[F-007] a self query, unknown ids and non-string ids are not paths', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    assert.equal(C.dijkstra(index, EX.user, EX.user), null);
    assert.equal(C.dijkstra(index, EX.user, 'arn:aws:iam::111122223333:role/demo-nope'), null);
    assert.equal(C.dijkstra(index, 'nope', EX.adminRole), null);
    assert.equal(C.dijkstra(index, null, EX.adminRole), null);
    assert.equal(C.dijkstra(index, EX.user, { id: EX.adminRole }), null);
  });

  test('[F-007] ties: equal cost and hops break on the edge-id SEQUENCE, not on node ids (brute force over 300 random graphs)', () => {
    let compared = 0;
    for (let seed = 1; seed <= 300; seed++) {
      const doc = H.randomGraph(seed, { n: 6 });
      const { index } = H.pipeline(C, doc);
      for (const s of index.nodesById.keys()) {
        for (const t of index.nodesById.keys()) {
          const want = H.bruteForcePath(doc, s, t);
          const got = C.dijkstra(index, s, t);
          assert.deepEqual(got, want, `seed ${seed}: ${s} -> ${t}`);
          if (want) compared++;
        }
      }
    }
    assert.ok(compared > 1000, `only ${compared} reachable pairs were compared`);
  });

  test('[F-007] the vector equal_cost_and_hops_breaks_tie_on_edge_ids distinguishes edge ids from node ids', () => {
    const c = H.pathCases().find(x => x.name === 'equal_cost_and_hops_breaks_tie_on_edge_ids');
    const { index } = H.pipeline(C, c.graph);
    const r = C.dijkstra(index, c.source, c.target);
    assert.deepEqual(r.path, c.expect.path);
  });
});

describe('dijkstra: assume edges are walked forward only', () => {
  test('[F-007] cross-account root trust and web-identity trust are walked from the external principal and the IdP', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const fromRoot = C.dijkstra(index, EX.extRoot, EX.appRole);
    assert.ok(fromRoot, 'external root -> role');
    assert.equal(index.edgesById.get(fromRoot.edges[0]).type, 'CAN_ASSUME');
    const fromIdp = C.dijkstra(index, EX.idp, EX.deployRole);
    assert.ok(fromIdp, 'web identity -> role');
    assert.equal(index.edgesById.get(fromIdp.edges[0]).type, 'CAN_ASSUME_WEB_IDENTITY');
    assert.equal(C.dijkstra(index, EX.appRole, EX.extRoot), null, 'trust is not walked backwards');
  });
});

describe('dijkstra: weights (F-040)', () => {
  function weightGraph() {
    const doc = G.skeleton();
    const user = 'arn:aws:iam::111122223333:user/demo-u';
    const bucketA = 'arn:aws:s3:::demo-full';
    const bucketB = 'arn:aws:s3:::demo-admin';
    doc.nodes.push(G.node(user, 'user', 'demo-u', { attached_policies_status: 'complete' }));
    doc.nodes.push(G.node(bucketA, 'bucket', 'demo-full', { data_asset: true }));
    doc.nodes.push(G.node(bucketB, 'bucket', 'demo-admin', { data_asset: true }));
    doc.edges.push(rawEdge(user, 'FULL_ACCESS', bucketA, 0, 's3', 'access'));
    doc.edges.push(rawEdge(user, 'CAN_ADMIN', bucketB, 0.5, 's3', 'access'));
    return { doc: G.finish(doc), user, bucketA, bucketB };
  }

  test('[F-040] FULL_ACCESS (0) is cheaper than CAN_ADMIN (0.5), and a zero-cost path is a real path', () => {
    const { doc, user, bucketA, bucketB } = weightGraph();
    const { index } = H.pipeline(C, doc);
    assert.equal(C.dijkstra(index, user, bucketA).cost, 0);
    assert.equal(C.dijkstra(index, user, bucketB).cost, 0.5);
    const { result } = H.drain(C.discoverAll(index, { sources: [user], targets: [bucketB, bucketA] }));
    assert.deepEqual(result.paths.map(p => [p.target, p.cost]), [[bucketA, 0], [bucketB, 0.5]], 'the 0-cost path is listed first');
  });

  test('[F-040] a missing weight costs 1 and a negative one is a problem plus 1, so neither can undercut a real 0', () => {
    const { doc, user, bucketA, bucketB } = weightGraph();
    doc.edges.find(e => e.target === bucketA).weight = -5;
    delete doc.edges.find(e => e.target === bucketB).weight;
    const { index, problems } = H.pipeline(C, doc);
    assert.equal(C.dijkstra(index, user, bucketA).cost, 1);
    assert.equal(C.dijkstra(index, user, bucketB).cost, 1);
    assert.equal(problems.filter(p => p.code === 'bad-weight').length, 2);
  });

  test('[F-040] edgeWeight reads weights with ??-semantics and never with || 1', () => {
    assert.equal(C.edgeWeight({ weight: 0 }), 0);
    assert.equal(C.edgeWeight({ weight: 2.5 }), 2.5);
    for (const w of [undefined, null, -1, NaN, Infinity, '0', '2', false, true, {}]) assert.equal(C.edgeWeight({ weight: w }), 1, String(w));
    assert.equal(C.edgeWeight(null), 1);
    assert.doesNotMatch(H.moduleSource('graph-core.js'), /weight\s*\|\|\s*1/);
  });

  test('[F-040] lower cost beats fewer hops; equal cost prefers fewer hops', () => {
    const doc = G.skeleton();
    const reg = doc.edge_types;
    const ids = [0, 1, 2, 3].map(G.roleId);
    for (const id of ids) doc.nodes.push(G.node(id, 'role', id.slice(-6), { attached_policies_status: 'complete' }));
    doc.edges.push(G.edge(reg, ids[0], 'CAN_ASSUME', ids[3], 2));
    doc.edges.push(G.edge(reg, ids[0], 'CAN_ASSUME', ids[1], 0), G.edge(reg, ids[1], 'CAN_ASSUME', ids[2], 0.5),
      G.edge(reg, ids[2], 'CAN_ASSUME', ids[3], 1));
    const { index } = H.pipeline(C, G.finish(doc));
    assert.deepEqual(C.dijkstra(index, ids[0], ids[3]).path, [ids[0], ids[1], ids[2], ids[3]], '1.5 beats 2');
    const doc2 = H.clone(doc);
    doc2.edges.find(e => e.target === ids[3] && e.source === ids[2]).weight = 1.5;
    const r = C.dijkstra(H.pipeline(C, doc2).index, ids[0], ids[3]);
    assert.deepEqual(r.path, [ids[0], ids[3]], 'equal cost 2: one hop wins');
  });

  test('maxCost prunes paths that cost more', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const full = C.dijkstra(index, EX.user, EX.adminRole);
    assert.ok(full);
    assert.deepEqual(C.dijkstra(index, EX.user, EX.adminRole, { maxCost: full.cost }), full);
    assert.equal(C.dijkstra(index, EX.user, EX.adminRole, { maxCost: full.cost - 0.25 }), null);
  });
});

describe('activeSubgraph: filters restrict path finding (F-096)', () => {
  test('[F-096] an edge is allowed only when traversable, its category enabled, both endpoint types visible and (optionally) definite', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const edges = [...index.edgesById.values()];
    const all = C.activeSubgraph(index, {});
    for (const e of edges) assert.equal(all.edgeAllowed(e), e.traversable === true, e.type);
    const noTrust = C.activeSubgraph(index, { categories: new Set([...index.categoriesPresent].filter(c => c !== 'trust')) });
    for (const e of edges) if (e.category === 'trust') assert.equal(noTrust.edgeAllowed(e), false);
    const noRoles = C.activeSubgraph(index, { nodeTypes: new Set([...index.typesPresent].filter(t => t !== 'role')) });
    for (const e of edges) {
      const touchesRole = index.nodesById.get(e.source).type === 'role' || index.nodesById.get(e.target).type === 'role';
      if (touchesRole) assert.equal(noRoles.edgeAllowed(e), false, e.type);
    }
    assert.equal(noRoles.nodeAllowed(EX.appRole), false);
    assert.equal(noRoles.nodeAllowed('nope'), false);
    const ignoring = C.activeSubgraph(index, { nodeTypes: new Set(), respectFilters: false });
    for (const e of edges) assert.equal(ignoring.edgeAllowed(e), e.traversable === true, 'respectFilters: false ignores type visibility');
    const definite = C.activeSubgraph(index, { includeConditional: false });
    for (const e of edges) if (e.confidence === 'conditional') assert.equal(definite.edgeAllowed(e), false);
    assert.equal(all.edgeAllowed(null), false);
  });

  test('[F-096] hidden categories and hidden node types change the answer of dijkstra', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const base = C.dijkstra(index, EX.user, EX.adminRole);
    assert.ok(base, 'example.json has a user -> admin role path');
    const usedCats = new Set(base.edges.map(id => index.edgesById.get(id).category));
    for (const cat of usedCats) {
      const active = activeFor(index, { exclude_categories: [cat] });
      const r = C.dijkstra(index, EX.user, EX.adminRole, { active });
      if (r) assert.ok(r.edges.every(id => index.edgesById.get(id).category !== cat), `hidden ${cat} walked`);
    }
    const usedTypes = new Set(base.path.slice(1, -1).map(id => index.nodesById.get(id).type));
    for (const type of usedTypes) {
      const active = activeFor(index, { exclude_node_types: [type] });
      const r = C.dijkstra(index, EX.user, EX.adminRole, { active });
      if (r) assert.ok(r.path.every(id => index.nodesById.get(id).type !== type), `hidden ${type} visited`);
    }
  });

  test('activeSubgraph accepts arrays and Sets, and freezes its options', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const a = C.activeSubgraph(index, { categories: ['trust'], nodeTypes: ['role', 'user'] });
    assert.ok(Object.isFrozen(a) && Object.isFrozen(a.opts));
    assert.ok(a.opts.categories instanceof Set && a.opts.categories.has('trust'));
    assert.equal(a.opts.respectFilters, true);
    assert.equal(a.opts.includeConditional, true);
  });
});
