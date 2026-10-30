'use strict';
// Dashboard regression tests: graph semantics in js/graph-core.js (owner of the fix: Dc).
//
// Written xfail-first in Wave 0 against the NotImplemented stub; flipped to plain tests by the Dc
// stream in Wave 1 when graph-core.js landed (every test XPASSed, none failed for another reason).
// A failure here now means a regression of the finding in the test name.
//
// Contract: docs/contracts/dashboard-core-api.md section 2, graph-json.md section 11, path_cases.json.
// Findings: F-005, F-006, F-007, F-036, F-037, F-038, F-039, F-040, F-042, F-043, F-095, F-096,
// F-146 (core side; the rendering side is in ui.test.js).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const {
  FINDINGS, core, fixture, pathCases, clone, variant, nodeById, edgesOfType,
  EX, HO, pipeline, activeOptionsFor, drain, cmp, protoSnapshot,
} = require('./lib/common');
const G = require('./lib/graphs');

/** Assert a dijkstra result is a well-formed directed path over traversable edges. */
function assertDirectedPath(index, r, source, target, C) {
  assert.ok(r, `expected a path ${source} -> ${target}`);
  assert.equal(r.hops, r.edges.length, 'hops must equal the number of edges');
  assert.equal(r.path.length, r.edges.length + 1, 'path lists one more node than edges');
  assert.equal(r.path[0], source);
  assert.equal(r.path[r.path.length - 1], target);
  let cost = 0;
  r.edges.forEach((eid, i) => {
    const e = index.edgesById.get(eid);
    assert.ok(e, `unknown edge id ${eid}`);
    assert.equal(e.source, r.path[i], `edge ${e.type} walked backwards or out of order`);
    assert.equal(e.target, r.path[i + 1], `edge ${e.type} walked backwards or out of order`);
    assert.equal(e.traversable, true, `non-traversable ${e.type} edge used in a path`);
    cost += C.edgeWeight(e);
  });
  assert.ok(Math.abs(cost - r.cost) < 1e-9, `cost ${r.cost} is not the sum of edge weights ${cost}`);
}

const edgeTypesOf = (index, r) => r.edges.map(id => index.edgesById.get(id).type);

describe('graph-core regressions: findings attach to nodes (F-005)', () => {
  test(`[F-005] every finding attaches to its node, including resource, account and K8s anchors`, () => {
    const C = core();
    for (const name of ['example', 'hostile']) {
      const raw = fixture(name);
      const { graph, problems, index } = pipeline(C, raw);
      assert.equal(graph.findings.length, raw.findings.length, `${name}: findings were dropped`);
      assert.equal(index.unattachedFindings.length, 0, `${name}: valid findings reported as unattached`);
      assert.ok(!problems.some(p => p.code === 'unattached-finding'), `${name}: spurious unattached-finding problem`);
      let attached = 0;
      for (const list of index.findingsByNode.values()) attached += list.length;
      assert.equal(attached, raw.findings.length, `${name}: findingsByNode does not hold every finding exactly once`);
      for (const f of raw.findings) {
        const list = index.findingsByNode.get(f.node_id) || [];
        assert.ok(list.some(x => x.fingerprint === f.fingerprint), `${name}: ${f.id} not attached to ${f.node_id}`);
      }
    }
    const ex = pipeline(C, fixture('example')).index;
    for (const [id, fid] of [[EX.bucket, 'S3-PUBLIC-001'], [EX.lambda, 'LAMBDA-URL-001'], [EX.instance, 'EC2-IMDS-001'], [EX.account, 'COLLECTION-GAP-001'], [EX.group, 'PRIVESC-014']]) {
      assert.ok((ex.findingsByNode.get(id) || []).some(f => f.id === fid), `${fid} missing on ${id}`);
    }
    const ho = pipeline(C, fixture('hostile')).index;
    assert.ok((ho.findingsByNode.get(HO.sa) || []).some(f => f.id === 'K8S-IRSA-001'), 'K8s finding not attached to its service account');
  });

  test(`[F-005] a finding whose node is missing is listed as unattached with a problem, never dropped`, () => {
    const C = core();
    const orphanNode = 'arn:aws:s3:::demo-missing-bucket';
    const raw = variant('example', d => {
      d.findings.push({ ...clone(d.findings[3]), node_id: orphanNode, fingerprint: 'ffffffffffffffffffffffffffffffff' });
    });
    const { graph, problems } = C.validateGraph(clone(raw));
    assert.ok(graph, 'an unattached finding must not be fatal');
    assert.ok(problems.some(p => p.code === 'unattached-finding'), 'no unattached-finding problem recorded');
    assert.ok(problems.filter(p => p.code === 'unattached-finding').every(p => p.level === 'warning' || p.level === 'error'));
    assert.equal(graph.unattachedFindings.length, 1);
    assert.equal(graph.unattachedFindings[0].node_id, orphanNode);
    const fps = new Set([...graph.findings, ...graph.unattachedFindings].map(f => f.fingerprint));
    assert.equal(fps.size, raw.findings.length, 'a finding was dropped');
    const index = C.buildIndex(graph);
    assert.equal(index.unattachedFindings.length, 1);
    let attached = 0;
    for (const list of index.findingsByNode.values()) attached += list.length;
    assert.equal(attached, raw.findings.length - 1);
  });
});

describe('graph-core regressions: tolerant validation (F-006)', () => {
  test(`[F-006] malformed props become {} with a bad-props problem; attached_policies_status survives validation`, () => {
    const C = core();
    const raw = variant('example', d => {
      const app = nodeById(d, EX.appRole);
      app.props.attached_policies_status = 'denied';
      app.props.attached_policies_error = 'AccessDenied';
      nodeById(d, EX.deployRole).props = 'oops';
      nodeById(d, EX.irsaRole).props = ['not', 'an', 'object'];
      nodeById(d, EX.nodeRole).props = null;
    });
    const before = JSON.stringify(raw);
    const { graph, problems } = C.validateGraph(raw);
    assert.equal(JSON.stringify(raw), before, 'validateGraph mutated its input');
    assert.ok(graph, 'malformed props must not be fatal');
    const bad = problems.filter(p => p.code === 'bad-props').map(p => p.ref).sort();
    assert.deepEqual(bad, [EX.deployRole, EX.irsaRole, EX.nodeRole].sort());
    for (const id of [EX.deployRole, EX.irsaRole, EX.nodeRole]) {
      const n = graph.nodes.find(x => x.id === id);
      assert.ok(n, `${id} was dropped`);
      assert.equal(typeof n.props, 'object');
      assert.equal(Object.getPrototypeOf(n.props), null, 'props must be a null-prototype object');
      assert.deepEqual(Object.keys(n.props), []);
    }
    const app = graph.nodes.find(x => x.id === EX.appRole);
    assert.equal(app.props.attached_policies_status, 'denied');
    assert.equal(app.props.attached_policies_error, 'AccessDenied');
    const index = C.buildIndex(graph);
    const r = C.dijkstra(index, EX.user, EX.appRole, {});
    assertDirectedPath(index, r, EX.user, EX.appRole, C);
  });
});

describe('graph-core regressions: shared path vectors (F-007, F-036, F-037, F-039, F-040, F-096)', () => {
  const mine = new Set(FINDINGS);
  for (const c of pathCases()) {
    const tags = (c.findings || []).filter(f => mine.has(f));
    if (!tags.length) continue; // vectors for engine findings (F-004, F-016, ...) belong to Dc's core suite
    const what = c.expect.reachable ? `reaches in ${c.expect.hops} hop(s) at cost ${c.expect.cost}` : 'is unreachable';
    test(`[${tags.join(', ')}] path_cases/${c.name}: ${what}`, () => {
      const C = core();
      const { index } = pipeline(C, clone(c.graph));
      const active = C.activeSubgraph(index, activeOptionsFor(index, c.options || {}));
      const r = C.dijkstra(index, c.source, c.target, { active });
      if (!c.expect.reachable) {
        assert.equal(r, null, `${c.name}: ${c.description}`);
        return;
      }
      assertDirectedPath(index, r, c.source, c.target, C);
      assert.equal(r.cost, c.expect.cost, `${c.name}: cost`);
      assert.equal(r.hops, c.expect.hops, `${c.name}: hops`);
      assert.deepEqual(r.path, c.expect.path, `${c.name}: path`);
      assert.deepEqual(edgeTypesOf(index, r), c.expect.edge_types, `${c.name}: edge types`);
      for (const bad of c.expect.must_not_traverse_types || []) {
        assert.ok(!edgeTypesOf(index, r).includes(bad), `${c.name}: walked ${bad}`);
      }
    });
  }
});

describe('graph-core regressions: directed traversal (F-007)', () => {
  test(`[F-007] dijkstra walks only traversable edges forward and matches the reference costs for every pair of example.json`, () => {
    const C = core();
    const raw = fixture('example');
    const { index } = pipeline(C, clone(raw));
    const ids = raw.nodes.map(n => n.id);
    for (const s of ids) {
      const want = G.refCosts(raw, s);
      for (const t of ids) {
        if (s === t) {
          assert.equal(C.dijkstra(index, s, t, {}), null, 'the self-path is not a path query');
          continue;
        }
        const r = C.dijkstra(index, s, t, {});
        if (!want.has(t)) {
          assert.equal(r, null, `false path ${s} -> ${t}: ${r && edgeTypesOf(index, r).join(' > ')}`);
        } else {
          assertDirectedPath(index, r, s, t, C);
          assert.equal(r.cost, want.get(t), `${s} -> ${t}: cost`);
        }
      }
    }
    // The legacy undirected pivots, explicitly.
    for (const [s, t, why] of [
      [EX.user, EX.policy, 'HAS_POLICY is structural'],
      [EX.group, EX.user, 'MEMBER_OF walked backwards'],
      [EX.appRole, EX.user, 'CAN_ASSUME walked backwards'],
      [EX.bucket, EX.kms, 'ENCRYPTED_BY is structural'],
      [EX.pod, EX.cluster, 'IN_CLUSTER is structural'],
      [EX.secret, EX.appRole, 'access edges end at the data asset'],
      [EX.user, EX.lambda, 'CAN_INVOKE is not traversable'],
    ]) assert.equal(C.dijkstra(index, s, t, {}), null, why);
  });
});

describe('graph-core regressions: assume edges (F-036)', () => {
  test(`[F-036] cross-account root trust and web-identity trust are traversable and their principals are default sources`, () => {
    const C = core();
    const { index } = pipeline(C, fixture('example'));
    const viaRoot = C.dijkstra(index, EX.extRoot, EX.appRole, {});
    assertDirectedPath(index, viaRoot, EX.extRoot, EX.appRole, C);
    assert.deepEqual(edgeTypesOf(index, viaRoot), ['CAN_ASSUME']);
    assert.equal(viaRoot.cost, 2);
    const viaIdp = C.dijkstra(index, EX.idp, EX.deployRole, {});
    assertDirectedPath(index, viaIdp, EX.idp, EX.deployRole, C);
    assert.deepEqual(edgeTypesOf(index, viaIdp), ['CAN_ASSUME_WEB_IDENTITY']);
    const sources = C.defaultSources(index, new Set(), null);
    assert.ok(sources.includes(EX.extRoot) && sources.includes(EX.idp), `default sources ${JSON.stringify(sources)}`);
    const definite = C.activeSubgraph(index, { includeConditional: false });
    assert.equal(C.dijkstra(index, EX.extRoot, EX.appRole, { active: definite }), null, 'conditional trust must be excludable');
  });
});

describe('graph-core regressions: anonymous / internet node (F-037)', () => {
  test(`[F-037] the anonymous node is a default source and reaches the public bucket at zero cost, also in discoverAll`, () => {
    const C = core();
    const { index } = pipeline(C, fixture('example'));
    assert.ok(C.defaultSources(index, new Set(), null).includes(EX.anonymous));
    const pub = C.dijkstra(index, EX.anonymous, EX.bucket, {});
    assertDirectedPath(index, pub, EX.anonymous, EX.bucket, C);
    assert.equal(pub.cost, 0);
    assert.deepEqual(edgeTypesOf(index, pub), ['GRANTS_PUBLIC']);
    const ssrf = C.dijkstra(index, EX.anonymous, EX.appRole, {});
    assertDirectedPath(index, ssrf, EX.anonymous, EX.appRole, C);
    assert.deepEqual(edgeTypesOf(index, ssrf), ['SSRF_TO_IMDS', 'INSTANCE_ROLE'], 'exposure (PUBLIC_INBOUND) is not a control step');
    const targets = C.defaultTargets(index, { includeDataAssets: true });
    assert.ok(targets.includes(EX.bucket), 'data assets are optional targets');
    const { result } = drain(C.discoverAll(index, { sources: [EX.anonymous], targets }));
    const hit = result.paths.find(p => p.source === EX.anonymous && p.target === EX.bucket);
    assert.ok(hit, 'discoverAll lost the anonymous -> public bucket path');
    assert.equal(hit.cost, 0, 'zero-cost paths must be listed (no distance === 0 filter)');
  });
});

describe('graph-core regressions: scale and chunking (F-038)', () => {
  test(`[F-038] discoverAll is a chunked, cancellable generator that reports progress`, () => {
    const C = core();
    const { index } = pipeline(C, fixture('example'));
    const sources = C.defaultSources(index, new Set(), null);
    const targets = C.defaultTargets(index, { includeDataAssets: true });
    const { events, result } = drain(C.discoverAll(index, { sources, targets, chunkSize: 1 }));
    const progress = events.filter(e => e.kind === 'progress');
    assert.ok(events.every(e => e.kind === 'progress' || e.kind === 'path'), 'unknown event kind');
    assert.ok(progress.length >= 2, 'chunkSize 1 must yield progress more than once');
    // One Dijkstra per target when there are fewer targets than sources, else one per source.
    const total = targets.length < sources.length ? targets.length : sources.length;
    progress.forEach((e, i) => {
      assert.equal(e.total, total, 'progress.total is the number of sources (or targets when fewer)');
      if (i) assert.ok(e.done > progress[i - 1].done, 'progress must advance');
    });
    assert.equal(progress[progress.length - 1].done, total);
    const yielded = events.filter(e => e.kind === 'path').map(e => e.result);
    assert.equal(yielded.length, result.paths.length, 'every kept path is yielded once');
    // Cancellation: return() stops the generator for good.
    const gen = C.discoverAll(index, { sources, targets, chunkSize: 1 });
    gen.next();
    gen.return();
    assert.equal(gen.next().done, true);
  });

  test(`[F-038] validate + index + search scale linearly: 4x the edges costs far less than 16x the time`, () => {
    const C = core();
    const small = G.scaleGraph(10000);
    const large = G.scaleGraph(40000);
    const run = (doc) => {
      const t0 = process.hrtime.bigint();
      const { index } = pipeline(C, doc);
      const active = C.activeSubgraph(index, {});
      C.dijkstra(index, doc.nodes[2].id, doc.meta.default_targets[0], { active });
      return Number(process.hrtime.bigint() - t0) / 1e6;
    };
    run(G.scaleGraph(2000)); // warm-up
    const ts = Math.min(run(small), run(small));
    const tl = Math.min(run(large), run(large));
    assert.ok(tl < 3000, `40k edges took ${tl.toFixed(0)} ms (budget 3000 ms)`);
    assert.ok(tl < 8 * Math.max(ts, 50), `quadratic growth: 10k edges ${ts.toFixed(0)} ms, 40k edges ${tl.toFixed(0)} ms`);
  });
});

describe('graph-core regressions: no name-based identity (F-039)', () => {
  test(`[F-039] same-named principals in two accounts stay distinct nodes with their own edges`, () => {
    const C = core();
    const twin = 'arn:aws:iam::999999999999:role/demo-app-role';
    // Registry entries come from the frozen vectors (they equal edge_types.py's table).
    const reg = pathCases().find(c => c.name === 'shared_bucket_grantee_reaches_bucket').graph;
    const raw = variant('example', d => {
      d.edge_types.GRANTS_CROSS_ACCOUNT = reg.edge_types.GRANTS_CROSS_ACCOUNT;
      d.node_types.external_principal = reg.node_types.external_principal;
      d.nodes.push(G.node(twin, 'external_principal', 'demo-app-role', { entry_point: true, external: true }, { account: '999999999999' }));
      d.edges.push(G.edge(d.edge_types, twin, 'GRANTS_CROSS_ACCOUNT', EX.bucket, 2));
    });
    const { graph, problems, index } = pipeline(C, raw);
    assert.ok(!problems.some(p => p.code === 'duplicate-node'), 'distinct ids with the same label are not duplicates');
    assert.equal(graph.nodes.filter(n => n.label === 'demo-app-role').length, 2);
    assert.notEqual(index.nodesById.get(twin), index.nodesById.get(EX.appRole));
    assert.deepEqual(index.out.get(twin).map(e => e.type), ['GRANTS_CROSS_ACCOUNT']);
    assert.equal(C.dijkstra(index, twin, EX.secret, {}), null, 'the external twin inherited the local role\'s grants');
    assert.equal(C.dijkstra(index, EX.user, twin, {}), null, 'the local user\'s CAN_ASSUME was resolved to the external twin');
    const cross = C.dijkstra(index, twin, EX.bucket, {});
    assertDirectedPath(index, cross, twin, EX.bucket, C);
    assert.deepEqual(edgeTypesOf(index, cross), ['GRANTS_CROSS_ACCOUNT']);
  });
});

describe('graph-core regressions: weights (F-040)', () => {
  test(`[F-040] weights use ??-semantics: 0 is free; missing, negative, NaN and string weights become 1 with a bad-weight problem`, () => {
    const C = core();
    const base = pathCases().find(c => c.name === 'zero_weight_edge_preferred');
    assert.ok(base, 'path_cases.json lost zero_weight_edge_preferred');
    const raw = clone(base.graph);
    const alice = base.source;
    const bucket = base.target;
    // Unknown (future) edge types are legal in 1.x readers; only their weights are broken here.
    const bad = [['X_MISSING', undefined], ['X_NEGATIVE', -1], ['X_STRING', 'n/a'], ['X_STRING_ZERO', '0'], ['X_NAN', NaN], ['X_INFINITE', Infinity]];
    const reg = { category: 's3', category_label: 'S3', category_order: 7, traversal: 'access', traversable: true, traversable_rule: null, base_weight: 1, bridge: false, sources: ['user'], targets: ['bucket'], description: 'test-only type', doc_anchor: '#x', legacy_name: null };
    const badIds = [];
    for (const [type, w] of bad) {
      raw.edge_types[type] = { ...reg, doc_anchor: `#${type.toLowerCase()}` };
      const e = G.edge(raw.edge_types, alice, type, bucket, w);
      if (w === undefined) delete e.weight;
      raw.edges.push(e);
      badIds.push(e.id);
    }
    const { graph, problems, index } = pipeline(C, raw);
    assert.deepEqual(problems.filter(p => p.code === 'bad-weight').map(p => p.ref).sort(), badIds.slice().sort());
    for (const id of badIds) assert.equal(graph.edges.find(e => e.id === id).weight, 1, `bad weight on ${id} must read as 1`);
    assert.equal(C.edgeWeight({ weight: 0 }), 0);
    const full = graph.edges.find(e => e.type === 'FULL_ACCESS');
    assert.equal(full.weight, 0, 'a real 0 weight was rewritten');
    const r = C.dijkstra(index, alice, bucket, {});
    assertDirectedPath(index, r, alice, bucket, C);
    assert.equal(r.cost, 0);
    assert.deepEqual(edgeTypesOf(index, r), ['FULL_ACCESS'], 'FULL_ACCESS (0) must beat CAN_ADMIN (0.5)');
    const { result } = drain(C.discoverAll(index, { sources: [alice], targets: [bucket] }));
    assert.ok(result.paths.some(p => p.source === alice && p.target === bucket && p.cost === 0), 'zero-cost path not listed');
  });
});

describe('graph-core regressions: prototype safety (F-042)', () => {
  test(`[F-042] prototype-named ids, labels and tag keys behave like ordinary strings through index, sources, targets, findings and discover`, () => {
    const C = core();
    const raw = fixture('hostile');
    const before = protoSnapshot();
    const text = JSON.stringify(raw);
    const { graph, index } = pipeline(C, raw);
    assert.equal(JSON.stringify(raw), text, 'validateGraph mutated its input');
    for (const k of ['nodesById', 'edgesById', 'out', 'in', 'findingsByNode']) assert.ok(index[k] instanceof Map, `index.${k} must be a Map`);
    for (const k of ['typesPresent', 'categoriesPresent', 'traversalClassesPresent']) assert.ok(index[k] instanceof Set, `index.${k} must be a Set`);
    for (const bare of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
      assert.equal(index.nodesById.get(bare), undefined, `phantom node ${bare}`);
      assert.equal(index.findingsByNode.get(bare), undefined, `phantom findings for ${bare}`);
    }
    assert.equal(index.nodesById.get(HO.protoRole).label, '__proto__');
    assert.ok((index.findingsByNode.get(HO.hasOwnRole) || []).some(f => f.id === 'TRUST-002'));
    for (const n of graph.nodes) {
      assert.equal(Object.getPrototypeOf(n.props), null, `props of ${n.id} must be null-prototype`);
      assert.ok(Array.isArray(n.tags), 'tags stay a list of {key, value}');
    }
    assert.ok(graph.nodes.find(n => n.id === HO.ctorRole).tags.some(t => t.key === '__proto__'), 'a tag keyed __proto__ was lost');
    assert.deepEqual(C.defaultSources(index, new Set([HO.protoRole, HO.ctorRole]), null), [HO.protoRole, HO.ctorRole]);
    const fallback = C.defaultSources(index, new Set(['__proto__', 'constructor']), null);
    assert.ok(!fallback.includes('__proto__') && !fallback.includes('constructor'), 'unknown owned ids must not become sources');
    assert.ok(C.defaultTargets(index, {}).includes(HO.canaryRole));
    const irsa = C.dijkstra(index, HO.pod, HO.ctorRole, {});
    assertDirectedPath(index, irsa, HO.pod, HO.ctorRole, C);
    const { result } = drain(C.discoverAll(index, { owned: new Set([HO.quoteUser]) }));
    assert.ok(result.paths.some(p => p.source === HO.quoteUser && p.target === HO.admin), 'quote user should reach the admin via __proto__');
    assert.deepEqual(protoSnapshot(), before, 'Object/Array prototypes changed');
  });

  test(`[F-042] "__proto__" keys in raw props and evidence cannot pollute prototypes`, () => {
    const C = core();
    let text = JSON.stringify(fixture('example'));
    for (const [from, to] of [
      ['"props":{"imds_v1":true', '"props":{"__proto__":{"polluted":"node"},"imds_v1":true'],
      ['"evidence":{', '"evidence":{"__proto__":{"polluted":"edge"},"constructor":{"prototype":{"polluted":"ctor"}},'],
      ['"run":{', '"run":{"__proto__":{"polluted":"run"},'],
    ]) {
      const next = text.replace(from, to);
      assert.notEqual(next, text, `fixture changed: injection point ${from} not found`);
      text = next;
    }
    const raw = JSON.parse(text); // JSON.parse keeps "__proto__" as an own key, as a browser would
    const before = protoSnapshot();
    const { graph, index } = pipeline(C, raw);
    drain(C.discoverAll(index, {}));
    assert.equal(({}).polluted, undefined, 'Object.prototype polluted');
    assert.equal([].polluted, undefined, 'Array.prototype polluted');
    assert.deepEqual(protoSnapshot(), before);
    const inst = graph.nodes.find(n => n.id === EX.instance);
    assert.equal(Object.getPrototypeOf(inst.props), null);
    assert.equal(inst.props.polluted, undefined);
    assert.equal(inst.props.imds_v1, true);
    assert.equal(graph.run.polluted, undefined, 'run was copied with Object.assign (the __proto__ setter ran)');
    for (const e of graph.edges) assert.equal(e.evidence.polluted, undefined, 'evidence inherited a polluted prototype');
  });
});

describe('graph-core regressions: sources, owned marks and paging (F-043)', () => {
  test(`[F-043] owned nodes of any type are exactly the path sources, in the given order`, () => {
    const C = core();
    const { index } = pipeline(C, fixture('example'));
    assert.deepEqual(C.defaultSources(index, new Set([EX.pod, EX.lambda]), null), [EX.pod, EX.lambda]);
    assert.deepEqual(C.defaultSources(index, [EX.lambda, EX.pod], EX.appRole), [EX.lambda, EX.pod], 'owned wins over the operator');
    const owned = new Set(['arn:aws:iam::111122223333:role/demo-not-collected', EX.group]);
    const withUnknown = C.defaultSources(index, owned, null);
    assert.ok(withUnknown.includes(EX.group) && withUnknown.every(id => owned.has(id)), `owned sources ${JSON.stringify(withUnknown)}`);
    const targets = C.defaultTargets(index, { includeDataAssets: true });
    const { result } = drain(C.discoverAll(index, { owned: new Set([EX.lambda, EX.pod]), targets }));
    assert.ok(result.paths.length > 0, 'owned compute nodes found no path');
    assert.ok(result.paths.every(p => p.source === EX.lambda || p.source === EX.pod), 'a non-owned node was used as a source');
    assert.ok(result.paths.some(p => p.source === EX.lambda && p.target === EX.bucket), 'lambda -> execution role -> bucket missing');
    const grp = drain(C.discoverAll(index, { owned: new Set([EX.group]) })).result;
    assert.ok(grp.paths.some(p => p.source === EX.group && p.target === EX.admin), 'owned group did not reach the admin');
  });

  test(`[F-043] a per-source cap replaces the global top-50; owned-source paths sort first`, () => {
    const C = core();
    const fanIn = pipeline(C, G.fanInGraph(60)).index;
    const all = drain(C.discoverAll(fanIn, { targets: [G.ADMIN] })).result;
    assert.equal(all.paths.length, 60, 'every source keeps its path: no global cap at 50');
    const fanOut = pipeline(C, G.fanOutGraph(60)).index;
    const src = G.userId(0);
    const targets = C.defaultTargets(fanOut, {});
    const capped = drain(C.discoverAll(fanOut, { sources: [src], targets, perSourceCap: 10 })).result;
    assert.equal(capped.paths.length, 10);
    assert.deepEqual(capped.truncatedSources, [src]);
    const costs = capped.paths.map(p => p.cost);
    assert.deepEqual(costs, costs.slice().sort((a, b) => a - b), 'the cheapest paths are kept, cheapest first');
    assert.equal(drain(C.discoverAll(fanOut, { sources: [src], targets })).result.paths.length, 10, 'default perSourceCap is 10');
    const { index } = pipeline(C, fixture('example'));
    const ordered = drain(C.discoverAll(index, { sources: [EX.group, EX.user], owned: new Set([EX.user]) })).result.paths;
    assert.ok(ordered.length >= 2);
    const firstOther = ordered.findIndex(p => p.source !== EX.user);
    const lastOwned = ordered.map(p => p.source).lastIndexOf(EX.user);
    assert.ok(firstOther === -1 || lastOwned < firstOther, 'owned-source paths must come first');
    const rest = ordered.slice(lastOwned + 1);
    for (let i = 1; i < rest.length; i++) {
      const a = rest[i - 1];
      const b = rest[i];
      assert.ok(a.cost < b.cost || (a.cost === b.cost && (a.hops < b.hops || (a.hops === b.hops && (cmp(a.source, b.source) < 0 || (a.source === b.source && cmp(a.target, b.target) <= 0))))), 'paths not sorted by cost, hops, source, target');
    }
  });
});

describe('graph-core regressions: selector order (F-095)', () => {
  test(`[F-095] selectorSort ranks from 1 and reads ranks with ?? (users first, rank 0 is not "missing")`, () => {
    const C = core();
    const { graph } = C.validateGraph(fixture('example'));
    const nodes = graph.nodes;
    const ids = nodes.map(n => n.id);
    const order = new Map([...graph.nodeTypes].map(([k, v]) => [k, v.order]));
    const sorted = C.selectorSort(nodes, order);
    assert.deepEqual(nodes.map(n => n.id), ids, 'selectorSort mutated its input');
    assert.equal(sorted[0].type, 'user', 'users (order 1) must sort first');
    const rank = (n) => (order.get(n.type) ?? Infinity);
    const expected = nodes.slice().sort((a, b) => rank(a) - rank(b) || cmp(a.label, b.label) || cmp(a.id, b.id)).map(n => n.id);
    assert.deepEqual(sorted.map(n => n.id), expected);
    const zero = C.selectorSort(nodes, new Map([['user', 0], ['role', 1]]));
    assert.equal(zero[0].type, 'user', 'rank 0 read with || would put users last');
    assert.ok(zero.findIndex(n => n.type !== 'user' && n.type !== 'role') > zero.map(n => n.type).lastIndexOf('role'), 'unranked types sort last');
    const obj = Object.create(null);
    obj.user = 1; obj.role = 2;
    assert.equal(C.selectorSort(nodes, obj)[0].type, 'user', 'a null-prototype object works as typeOrder');
  });
});

describe('graph-core regressions: filters restrict paths (F-096)', () => {
  test(`[F-096] hidden categories and node types are not walked unless respectFilters is off`, () => {
    const C = core();
    const { index } = pipeline(C, fixture('example'));
    assertDirectedPath(index, C.dijkstra(index, EX.user, EX.adminRole, {}), EX.user, EX.adminRole, C);
    const noPrivesc = C.activeSubgraph(index, { categories: new Set([...index.categoriesPresent].filter(c => c !== 'privesc')) });
    assert.equal(C.dijkstra(index, EX.user, EX.adminRole, { active: noPrivesc }), null, 'hidden category privesc was walked');
    const passRole = edgesOfType(fixture('example'), 'CAN_PASS_ROLE_TO')[0];
    assert.equal(noPrivesc.edgeAllowed(index.edgesById.get(passRole.id)), false);
    const noGroups = new Set([...index.typesPresent].filter(t => t !== 'group'));
    const hidden = C.activeSubgraph(index, { nodeTypes: noGroups });
    assert.equal(C.dijkstra(index, EX.user, EX.adminRole, { active: hidden }), null, 'hidden node type group was walked');
    assert.equal(hidden.nodeAllowed(EX.group), false);
    const ignore = C.activeSubgraph(index, { nodeTypes: noGroups, respectFilters: false });
    assert.ok(C.dijkstra(index, EX.user, EX.adminRole, { active: ignore }), 'respectFilters: false must ignore node-type visibility');
  });
});

describe('graph-core regressions: operator principal (F-146)', () => {
  test(`[F-146] operatorNode returns the engine's operator mapping and the operator is the first default source`, () => {
    const C = core();
    const ex = pipeline(C, fixture('example'));
    assert.deepEqual({ ...C.operatorNode(ex.graph) }, { id: EX.appRole, resolution: 'assumed-role' });
    const op = C.operatorNode(ex.graph).id;
    assert.equal(C.defaultSources(ex.index, new Set(), op)[0], EX.appRole);
    const ho = pipeline(C, fixture('hostile'));
    assert.equal(C.operatorNode(ho.graph).id, HO.protoRole, 'a role named __proto__ is still the operator');
    const notIn = C.validateGraph(variant('example', d => { d.run.operator = { arn: 'arn:aws:iam::111122223333:user/demo-gone', node_id: null, resolution: 'not-in-graph', redacted: false }; })).graph;
    assert.deepEqual({ ...C.operatorNode(notIn) }, { id: null, resolution: 'not-in-graph' });
    const missing = C.validateGraph(variant('example', d => { delete d.run.operator; })).graph;
    assert.deepEqual({ ...C.operatorNode(missing) }, { id: null, resolution: 'missing' });
    const dangling = C.validateGraph(variant('example', d => { d.run.operator.node_id = 'arn:aws:iam::111122223333:role/demo-deleted'; })).graph;
    assert.equal(C.operatorNode(dangling).id, null, 'an operator id that is not a node must not be pre-marked');
  });
});
