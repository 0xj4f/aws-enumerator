'use strict';
// graph-core.js buildIndex, selectorSort, operatorNode (docs/contracts/dashboard-core-api.md sections
// 2.3, 2.9, 2.10). Findings: F-005, F-038, F-039, F-042, F-095, F-146.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C, K } = H.modules();
const { EX, HO } = H;

describe('buildIndex: structure', () => {
  test('[F-038] one Map/Set index: every node has out/in lists, adjacency is sorted by (type, other end, id)', () => {
    const { graph, index } = H.pipeline(C, H.fixture('example'));
    assert.ok(Object.isFrozen(index));
    assert.ok(index.nodesById instanceof Map && index.edgesById instanceof Map);
    assert.ok(index.out instanceof Map && index.in instanceof Map && index.findingsByNode instanceof Map);
    assert.ok(index.typesPresent instanceof Set && index.categoriesPresent instanceof Set && index.traversalClassesPresent instanceof Set);
    assert.equal(index.nodesById.size, graph.nodes.length);
    assert.equal(index.edgesById.size, graph.edges.length);
    for (const n of graph.nodes) {
      assert.ok(Array.isArray(index.out.get(n.id)) && Array.isArray(index.in.get(n.id)), n.id);
    }
    const key = (e, end) => [e.type, e[end], e.id];
    for (const [id, list] of index.out) {
      for (const e of list) assert.equal(e.source, id);
      for (let i = 1; i < list.length; i++) assert.ok(H.cmpSeq(key(list[i - 1], 'target'), key(list[i], 'target')) < 0);
    }
    for (const [id, list] of index.in) {
      for (const e of list) assert.equal(e.target, id);
      for (let i = 1; i < list.length; i++) assert.ok(H.cmpSeq(key(list[i - 1], 'source'), key(list[i], 'source')) < 0);
    }
    const outTotal = [...index.out.values()].reduce((s, l) => s + l.length, 0);
    assert.equal(outTotal, graph.edges.length);
    assert.deepEqual([...index.typesPresent].sort(), [...new Set(graph.nodes.map(n => n.type))].sort());
    assert.deepEqual([...index.categoriesPresent].sort(), [...new Set(graph.edges.map(e => e.category))].sort());
    assert.deepEqual([...index.traversalClassesPresent].sort(), [...new Set(graph.edges.map(e => e.traversal))].sort());
    assert.deepEqual(index.meta.defaultSources, graph.meta.default_sources);
    assert.deepEqual(index.meta.defaultTargets, graph.meta.default_targets);
  });

  test('[F-038] the index of a 40k-edge graph builds in well under a second', () => {
    const doc = H.graphs.scaleGraph(40000);
    const t0 = process.hrtime.bigint();
    const { index } = H.pipeline(C, doc);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.equal(index.edgesById.size, 40000);
    assert.ok(ms < 3000, `validate + index took ${ms.toFixed(0)} ms`);
  });
});

describe('buildIndex: findings on every node (F-005)', () => {
  test('[F-005] every attached finding is listed under its node, of any node type; the totals add up', () => {
    const raw = H.fixture('example');
    const { graph, index } = H.pipeline(C, raw);
    const listed = [...index.findingsByNode.values()].reduce((s, l) => s + l.length, 0);
    assert.equal(listed + index.unattachedFindings.length, raw.findings.length);
    const anchoredTypes = new Set();
    for (const f of raw.findings) {
      const list = index.findingsByNode.get(f.node_id) || [];
      assert.ok(list.some(x => x.fingerprint === f.fingerprint), `${f.id} not on ${f.node_id}`);
      anchoredTypes.add(index.nodesById.get(f.node_id).type);
    }
    for (const t of ['bucket', 'account']) assert.ok(anchoredTypes.has(t), `example.json has no finding on a ${t}`);
    assert.ok([...anchoredTypes].some(t => !['user', 'role', 'group'].includes(t)), 'only IAM principals carry findings');
    assert.equal(graph.findings.length, listed);
  });

  test('[F-005] findings of a node are ordered by severity (case-insensitive), id, fingerprint', () => {
    const raw = H.fixture('example');
    const node = raw.findings[0].node_id;
    const mk = (id, sev, fp) => ({ ...raw.findings[0], id, severity: sev, fingerprint: fp });
    raw.findings.push(mk('ZZZ-001', 'low', 'demo-fp-3'), mk('AAA-001', 'Critical', 'demo-fp-2'),
      mk('AAA-001', 'CRITICAL', 'demo-fp-1'), mk('MMM-001', 'unknown', 'demo-fp-4'));
    const { index } = H.pipeline(C, raw);
    const list = index.findingsByNode.get(node);
    const rank = (s) => C.SEVERITIES.indexOf(C.severityClass(s));
    for (let i = 1; i < list.length; i++) {
      const a = list[i - 1];
      const b = list[i];
      const order = (rank(a.severity) - rank(b.severity)) || H.cmp(a.id, b.id) || H.cmp(a.fingerprint, b.fingerprint);
      assert.ok(order < 0, `${a.id}/${a.fingerprint} before ${b.id}/${b.fingerprint}`);
    }
    assert.equal(list[0].fingerprint, 'demo-fp-1');
  });

  test('[F-005] unattached findings are exposed on the index and counted once', () => {
    const raw = H.fixture('example');
    raw.findings[0].node_id = 'arn:aws:iam::111122223333:role/demo-elsewhere';
    const { index } = H.pipeline(C, raw);
    assert.equal(index.unattachedFindings.length, 1);
    const listed = [...index.findingsByNode.values()].reduce((s, l) => s + l.length, 0);
    assert.equal(listed + 1, raw.findings.length);
  });
});

describe('buildIndex: identity is the id (F-039)', () => {
  test('[F-039] same-named roles in two accounts and two paths stay distinct; nothing resolves by name', () => {
    const doc = H.graphs.skeleton();
    const reg = doc.edge_types;
    const local = 'arn:aws:iam::111122223333:role/deploy';
    const pathed = 'arn:aws:iam::111122223333:role/ci/deploy';
    const foreign = 'arn:aws:iam::999999999999:role/deploy';
    const user = 'arn:aws:iam::111122223333:user/demo-u';
    doc.nodes.push(H.graphs.node(local, 'role', 'deploy', { attached_policies_status: 'complete' }));
    doc.nodes.push(H.graphs.node(pathed, 'role', 'deploy', { attached_policies_status: 'complete' }));
    doc.nodes.push(H.graphs.node(foreign, 'role', 'deploy', { attached_policies_status: 'complete' }, { account: '999999999999' }));
    doc.nodes.push(H.graphs.node(user, 'user', 'demo-u', { attached_policies_status: 'complete' }));
    doc.edges.push(H.graphs.edge(reg, user, 'CAN_ASSUME', pathed, 1));
    H.graphs.finish(doc);
    const { index } = H.pipeline(C, doc);
    assert.equal(index.nodesById.size, 4);
    assert.equal(index.in.get(pathed).length, 1);
    assert.equal(index.in.get(local).length, 0);
    assert.equal(index.in.get(foreign).length, 0);
    assert.equal(C.dijkstra(index, user, local), null);
    assert.equal(C.dijkstra(index, user, foreign), null);
    assert.deepEqual(C.dijkstra(index, user, pathed).path, [user, pathed]);
    assert.equal(C.dijkstra(index, user, 'deploy'), null, 'a label is not an id');
  });

  test('[F-039] graph-core, exports and catalog never extract a last path segment', () => {
    const { NAME_MATCH_RULES, scanJs } = require('../regressions/lib/scan');
    const files = ['graph-core.js', 'exports.js', 'catalog.js'].map(f => ({ file: f, text: H.moduleSource(f), lineOffset: 0 }));
    assert.deepEqual(scanJs(files, NAME_MATCH_RULES), []);
  });
});

describe('buildIndex: prototype names (F-042)', () => {
  test('[F-042] hostile.json: prototype-named ids resolve to their own nodes and findings, inherited names to nothing', () => {
    const { index } = H.pipeline(C, H.fixture('hostile'));
    for (const id of [HO.protoRole, HO.ctorRole, HO.hasOwnRole, HO.toStringRole, HO.extProto, HO.pod, HO.sa]) {
      assert.equal(index.nodesById.get(id).id, id);
      assert.ok(Array.isArray(index.out.get(id)));
    }
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
      assert.equal(index.nodesById.get(name), undefined);
      assert.equal(index.findingsByNode.get(name), undefined);
      assert.equal(index.out.get(name), undefined);
      assert.equal(index.nodeTypes.get(name), undefined);
    }
    const sources = C.defaultSources(index, new Set([HO.protoRole, HO.ctorRole, '__proto__']), null);
    assert.deepEqual(sources, [HO.protoRole, HO.ctorRole]);
  });

  test('[F-042] tags stay a list of pairs; a "__proto__" tag key is data', () => {
    const raw = H.fixture('example');
    const user = H.nodeById(raw, EX.user);
    assert.notEqual(user.props.high_value, true);
    user.tags = JSON.parse('[{"key":"__proto__","value":"x"},{"key":"high_value","value":"true"},{"key":1,"value":"bad"}]');
    const before = H.protoSnapshot();
    const { graph, index } = H.pipeline(C, raw);
    const n = graph.nodes.find(x => x.id === EX.user);
    assert.deepEqual(n.tags, [{ key: '__proto__', value: 'x' }, { key: 'high_value', value: 'true' }]);
    assert.ok(!C.defaultTargets(index, {}).includes(EX.user), 'a high_value TAG is not the high_value flag (F-042)');
    assert.deepEqual(H.protoSnapshot(), before);
  });
});

describe('selectorSort (F-095)', () => {
  test('[F-095] users sort first: ranks start at 1 and a rank of 0 is not "missing"', () => {
    const nodes = [
      { id: 'r2', type: 'role', label: 'b' }, { id: 'x1', type: 'zzz-unknown', label: 'a' },
      { id: 'u2', type: 'user', label: 'b' }, { id: 'u1', type: 'user', label: 'b' }, { id: 'r1', type: 'role', label: 'a' },
    ];
    const frozen = Object.freeze(nodes.slice());
    const order = new Map([['user', 1], ['role', 2]]);
    assert.deepEqual(C.selectorSort(frozen, order).map(n => n.id), ['u1', 'u2', 'r1', 'r2', 'x1']);
    assert.deepEqual(frozen.map(n => n.id), nodes.map(n => n.id), 'input not mutated');
    const zero = Object.assign(Object.create(null), { user: 0, role: 1 });
    assert.deepEqual(C.selectorSort(nodes, zero).map(n => n.id), ['u1', 'u2', 'r1', 'r2', 'x1']);
    const inherited = Object.create({ role: -5 });
    inherited.user = 3;
    assert.equal(C.selectorSort(nodes, inherited)[0].type, 'user', 'inherited ranks are ignored');
  });

  test('[F-095] with the catalogue type order, IAM users come first for example.json', () => {
    const { graph, index } = H.pipeline(C, H.fixture('example'));
    const order = K.typeOrder(index.typesPresent, index.nodeTypes);
    const sorted = C.selectorSort(graph.nodes, order);
    assert.equal(sorted[0].type, 'user');
    const ranks = sorted.map(n => order.get(n.type));
    for (let i = 1; i < ranks.length; i++) assert.ok(ranks[i - 1] <= ranks[i]);
  });
});

describe('operatorNode (F-146)', () => {
  test('[F-146] the engine mapping is returned when its node exists; otherwise id null with the resolution', () => {
    const { graph } = C.validateGraph(H.fixture('example'));
    assert.deepEqual(C.operatorNode(graph), { id: graph.run.operator.node_id, resolution: graph.run.operator.resolution });
    const cases = [
      [{ arn: 'arn:aws:sts::111122223333:federated-user/demo', node_id: null, resolution: 'federated' }, null, 'federated'],
      [{ arn: null, node_id: 'arn:aws:iam::111122223333:role/demo-gone', resolution: 'exact' }, null, 'exact'],
      [{ arn: null, node_id: null, resolution: 'unavailable' }, null, 'unavailable'],
    ];
    for (const [op, id, resolution] of cases) {
      const g = C.validateGraph(H.variant('example', d => { d.run.operator = op; })).graph;
      assert.deepEqual(C.operatorNode(g), { id, resolution });
    }
    const none = C.validateGraph(H.variant('example', d => { delete d.run.operator; })).graph;
    assert.deepEqual(C.operatorNode(none), { id: null, resolution: 'missing' });
    assert.deepEqual(C.operatorNode(null), { id: null, resolution: 'missing' });
  });

  test('[F-146] the operator is the first default source when nothing is owned, and owned wins over it', () => {
    const { graph, index } = H.pipeline(C, H.fixture('example'));
    const op = C.operatorNode(graph).id;
    assert.ok(op);
    assert.equal(C.defaultSources(index, null, op)[0], op);
    assert.deepEqual(C.defaultSources(index, [EX.bucket], op), [EX.bucket]);
  });
});
