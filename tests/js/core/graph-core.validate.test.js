'use strict';
// graph-core.js validateGraph (docs/contracts/dashboard-core-api.md section 2.2, graph-json.md section 12.3).
// Findings: F-005 (unattached findings listed, never dropped), F-040 (weights), F-042 (prototype safety).
// Malformed props are tolerated (the core side of F-006; the UI side is Du's).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const H = require('./lib/helpers');

const { C } = H.modules();
const INVALID_DIR = path.join(H.targets.REPO_ROOT, 'tests', 'fixtures', 'graph-invalid');
const invalid = (file) => JSON.parse(fs.readFileSync(path.join(INVALID_DIR, file), 'utf8'));
const codes = (problems) => problems.map(p => p.code);

describe('validateGraph: fatal input', () => {
  test('non-objects, a missing or foreign schema major and non-list nodes/edges are fatal with one error', () => {
    const cases = [
      [null, 'not-an-object'], [[], 'not-an-object'], ['{}', 'not-an-object'], [42, 'not-an-object'],
      [{ nodes: [], edges: [] }, 'schema-major'],
      [{ schema_version: 1, nodes: [], edges: [] }, 'schema-major'],
      [{ schema_version: '2.0.0', nodes: [], edges: [] }, 'schema-major'],
      [{ schema_version: 'v1', nodes: [], edges: [] }, 'schema-major'],
      [{ schema_version: '1.0.0', nodes: {}, edges: [] }, 'bad-structure'],
      [{ schema_version: '1.0.0', nodes: [] }, 'bad-structure'],
    ];
    for (const [raw, code] of cases) {
      const r = C.validateGraph(raw);
      assert.equal(r.graph, null, JSON.stringify(raw));
      assert.equal(r.problems.length, 1);
      assert.equal(r.problems[0].level, 'error');
      assert.equal(r.problems[0].code, code, JSON.stringify(raw));
      assert.ok(r.problems[0].message.length > 0);
    }
  });

  test('graph-invalid/wrong_schema_major.json is refused; minor versions of 1.x are read', () => {
    assert.equal(C.validateGraph(invalid('wrong_schema_major.json')).graph, null);
    const minor = H.variant('minimal', d => { d.schema_version = '1.7.3'; });
    const r = C.validateGraph(minor);
    assert.ok(r.graph);
    assert.equal(r.graph.schemaVersion, '1.7.3');
  });
});

describe('validateGraph: a valid document', () => {
  test('example.json validates without problems into a fresh normalised copy; raw is not mutated', () => {
    const raw = H.fixture('example');
    const before = JSON.stringify(raw);
    const { graph, problems } = C.validateGraph(raw);
    assert.deepEqual(problems, []);
    assert.equal(JSON.stringify(raw), before, 'validateGraph mutated its input');
    assert.equal(graph.nodes.length, raw.nodes.length);
    assert.equal(graph.edges.length, raw.edges.length);
    assert.equal(graph.findings.length + graph.unattachedFindings.length, raw.findings.length);
    assert.ok(graph.nodeTypes instanceof Map && graph.edgeTypes instanceof Map);
    assert.deepEqual(Object.keys(graph).sort(), ['analyzerStatus', 'coverage', 'edgeTypes', 'edges', 'evaluationGaps',
      'findings', 'generator', 'meta', 'nodeTypes', 'nodes', 'run', 'schemaVersion', 'unattachedFindings']);
    for (const n of graph.nodes) {
      assert.notEqual(n, raw.nodes.find(x => x.id === n.id), 'node records must be copies');
      assert.equal(Object.getPrototypeOf(n.props), null, 'props must be a null-prototype copy');
    }
    for (const e of graph.edges) assert.equal(Object.getPrototypeOf(e.evidence), null);
    assert.deepEqual(graph.meta.default_sources, raw.meta.default_sources);
    assert.deepEqual(graph.meta.default_targets, raw.meta.default_targets);
    assert.equal(graph.run.operator.node_id, raw.run.operator.node_id);
  });

  test('stored severities are kept upper-case (never rewritten)', () => {
    const { graph } = C.validateGraph(H.fixture('example'));
    for (const f of graph.findings) assert.equal(f.severity, f.severity.toUpperCase());
  });

  test('hostile.json is valid and validates without problems', () => {
    const { graph, problems } = C.validateGraph(H.fixture('hostile'));
    assert.ok(graph);
    assert.deepEqual(problems, []);
  });
});

describe('validateGraph: reader tolerance on graph-invalid fixtures', () => {
  const tolerated = [
    ['dangling_edge.json', 'dangling-edge', ''],
    ['duplicate_edge_ids.json', 'duplicate-edge', ''],
    ['duplicate_node_ids.json', 'duplicate-node', ''],
    ['finding_dangling_node_id.json', 'unattached-finding', '[F-005] '],
    ['finding_missing_node_id.json', 'unattached-finding', '[F-005] '],
    ['negative_weight.json', 'bad-weight', '[F-040] '],
    ['non_numeric_weight.json', 'bad-weight', '[F-040] '],
    ['traversable_not_boolean.json', 'bad-traversable', ''],
    ['operator_node_missing.json', 'operator-node-missing', '[F-146] '],
  ];
  for (const [file, code, tag] of tolerated) {
    test(`${tag}${file}: tolerated with a "${code}" problem, the rest of the graph is kept`, () => {
      const raw = invalid(file);
      const { graph, problems } = C.validateGraph(raw);
      assert.ok(graph, `${file} must not be fatal`);
      assert.ok(codes(problems).includes(code), `${file}: ${JSON.stringify(codes(problems))}`);
      assert.ok(graph.nodes.length >= raw.nodes.length - 1);
    });
  }

  test('semantic-only problems the dashboard does not check (bridge invariant, registry mismatch ...) are not fatal', () => {
    const files = JSON.parse(fs.readFileSync(path.join(INVALID_DIR, 'expectations.json'), 'utf8')).map(x => x.file);
    for (const f of files) {
      if (f === 'wrong_schema_major.json') continue;
      assert.ok(C.validateGraph(invalid(f)).graph, `${f} was fatal`);
    }
  });
});

describe('validateGraph: non-fatal problems', () => {
  test('[F-040] weights: 0 is kept, every invalid weight becomes 1 with a bad-weight problem naming the edge', () => {
    const raw = H.fixture('example');
    const bad = [undefined, -1, NaN, Infinity, -Infinity, '0', true, null, { w: 1 }];
    raw.edges[0].weight = 0;
    bad.forEach((w, i) => { if (w === undefined) delete raw.edges[i + 1].weight; else raw.edges[i + 1].weight = w; });
    const { graph, problems } = C.validateGraph(raw);
    const byId = new Map(graph.edges.map(e => [e.id, e]));
    assert.equal(byId.get(raw.edges[0].id).weight, 0);
    const refs = problems.filter(p => p.code === 'bad-weight').map(p => p.ref);
    for (let i = 1; i <= bad.length; i++) {
      assert.equal(byId.get(raw.edges[i].id).weight, 1, `weight ${String(bad[i - 1])}`);
      assert.ok(refs.includes(raw.edges[i].id), `no bad-weight problem for ${String(bad[i - 1])}`);
    }
    assert.ok(!refs.includes(raw.edges[0].id), 'weight 0 is legal');
  });

  test('ids, duplicates and dangling edges: first wins, the problem carries the record id', () => {
    const raw = H.fixture('example');
    const n0 = raw.nodes[0];
    const e0 = raw.edges[0];
    raw.nodes.push({ ...n0, label: 'second copy' });
    raw.nodes.push({ id: 7, type: 'role', label: 'x' });
    raw.nodes.push({ id: 'demo-no-type', label: 'x' });
    raw.edges.push({ ...e0, weight: 99 });
    raw.edges.push({ ...e0, id: 'e:demo-dangling', target: 'arn:aws:iam::111122223333:role/demo-missing' });
    raw.edges.push({ id: 'e:demo-no-type', source: n0.id, target: n0.id });
    const { graph, problems } = C.validateGraph(raw);
    assert.equal(graph.nodes.find(n => n.id === n0.id).label, n0.label, 'first node wins');
    assert.equal(graph.edges.find(e => e.id === e0.id).weight, e0.weight, 'first edge wins');
    const find = (code) => problems.filter(p => p.code === code);
    assert.deepEqual(find('duplicate-node').map(p => p.ref), [n0.id]);
    assert.deepEqual(find('duplicate-edge').map(p => p.ref), [e0.id]);
    assert.deepEqual(find('dangling-edge').map(p => p.ref), ['e:demo-dangling']);
    assert.deepEqual(find('node-invalid').map(p => p.ref), [null, 'demo-no-type']);
    assert.deepEqual(find('edge-invalid').map(p => p.ref), ['e:demo-no-type']);
    for (const p of problems) {
      assert.ok(['error', 'warning'].includes(p.level));
      assert.equal(typeof p.message, 'string');
    }
  });

  test('non-object props become {} with bad-props (ref = node or edge id); traversable is repaired to false', () => {
    const raw = H.fixture('example');
    raw.nodes[0].props = 'not an object';
    raw.nodes[1].props = [1, 2];
    raw.edges[0].props = 5;
    raw.edges[1].traversable = 'yes';
    const { graph, problems } = C.validateGraph(raw);
    const node0 = graph.nodes.find(n => n.id === raw.nodes[0].id);
    assert.equal(Object.keys(node0.props).length, 0);
    assert.equal(Object.getPrototypeOf(node0.props), null);
    const badProps = problems.filter(p => p.code === 'bad-props').map(p => p.ref);
    assert.deepEqual(badProps, [raw.nodes[0].id, raw.nodes[1].id, raw.edges[0].id]);
    assert.equal(graph.edges.find(e => e.id === raw.edges[1].id).traversable, false);
    assert.deepEqual(problems.filter(p => p.code === 'bad-traversable').map(p => p.ref), [raw.edges[1].id]);
  });

  test('[F-005] unattached findings go to unattachedFindings only (ref = fingerprint), invalid findings are dropped', () => {
    const raw = H.fixture('example');
    const total = raw.findings.length;
    raw.findings[0].node_id = 'arn:aws:iam::111122223333:role/demo-not-collected';
    delete raw.findings[1].node_id;
    raw.findings.push({ title: 'no id', fingerprint: 'demo-fp-no-id' });
    const { graph, problems } = C.validateGraph(raw);
    assert.equal(graph.unattachedFindings.length, 2);
    assert.equal(graph.findings.length, total - 2, 'an unattached finding must not also be in graph.findings');
    const refs = problems.filter(p => p.code === 'unattached-finding').map(p => p.ref);
    assert.deepEqual(refs, [raw.findings[0].fingerprint, raw.findings[1].fingerprint]);
    assert.deepEqual(problems.filter(p => p.code === 'finding-invalid').map(p => p.ref), ['demo-fp-no-id']);
    assert.equal(graph.unattachedFindings[1].node_id, null);
  });

  test('problems are capped per code with one summary record, so a hostile document cannot flood the panel', () => {
    const raw = H.fixture('minimal');
    for (let i = 0; i < 450; i++) raw.edges.push({ id: `e:demo-${i}`, source: 'x', target: 'y', type: 'CAN_ASSUME' });
    const { graph, problems } = C.validateGraph(raw);
    assert.ok(graph);
    const dangling = problems.filter(p => p.code === 'dangling-edge');
    assert.equal(dangling.length, 201);
    assert.equal(dangling[200].ref, null);
    assert.match(dangling[200].message, /250 more/);
  });

  test('deeply nested props are cut at a fixed depth with a bad-field problem (no stack overflow)', () => {
    const raw = H.fixture('minimal');
    let deep = { leaf: true };
    for (let i = 0; i < 5000; i++) deep = { d: deep };
    raw.nodes[0].props = deep;
    const { graph, problems } = C.validateGraph(raw);
    assert.ok(graph);
    assert.ok(problems.some(p => p.code === 'bad-field' && p.ref === raw.nodes[0].id));
  });
});

describe('validateGraph: prototype safety (F-042)', () => {
  test('[F-042] graph-invalid/proto_props.json and proto_nested_evidence.json keep "__proto__" as inert data', () => {
    const before = H.protoSnapshot();
    for (const f of ['proto_props.json', 'proto_nested_evidence.json']) {
      const { graph } = C.validateGraph(invalid(f));
      assert.ok(graph, f);
      for (const n of graph.nodes) {
        assert.equal(Object.getPrototypeOf(n.props), null);
        if (Object.prototype.hasOwnProperty.call(n.props, '__proto__')) {
          assert.equal(typeof n.props.__proto__, 'object', 'the key is an own data property of a null-prototype object');
        }
      }
    }
    assert.equal(({}).polluted, undefined);
    assert.equal(({}).isAdmin, undefined);
    assert.deepEqual(H.protoSnapshot(), before);
  });

  test('[F-042] registries keyed by prototype names are Maps; inherited names never resolve', () => {
    const raw = H.fixture('example');
    raw.node_types.constructor = raw.node_types.role;
    Object.defineProperty(raw.edge_types, '__proto__', { value: raw.edge_types.CAN_ASSUME, enumerable: true, writable: true, configurable: true });
    const text = JSON.stringify(raw);
    assert.ok(text.includes('"__proto__":'), 'the document carries an own "__proto__" key');
    const before = H.protoSnapshot();
    const { graph } = C.validateGraph(JSON.parse(text));
    assert.ok(graph.nodeTypes.has('constructor'));
    assert.ok(graph.edgeTypes.has('__proto__'), '"__proto__" is an ordinary registry key');
    assert.equal(graph.edgeTypes.get('__proto__').category, raw.edge_types.CAN_ASSUME.category);
    assert.deepEqual(H.protoSnapshot(), before);
    assert.equal(graph.nodeTypes.get('toString'), undefined);
    assert.equal(graph.edgeTypes.get('hasOwnProperty'), undefined);
  });
});
