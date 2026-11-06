'use strict';
// Synthetic graph.json 1.0 documents and a reference shortest-path cost function for the
// regression tests. Documents follow docs/contracts/graph-json.md (registries copied from the
// frozen fixture example.json, ids built with the contract's edge-id rule) so a correct reader
// treats them like engine output.

const crypto = require('crypto');
const { fixture } = require('./common');

const ACCOUNT = '111122223333';

/** ids.edge_id(): "e:" + sha256(source \x1f type \x1f target)[:20]. */
function edgeId(source, type, target) {
  return 'e:' + crypto.createHash('sha256').update(`${source}\x1f${type}\x1f${target}`, 'utf8').digest('hex').slice(0, 20);
}

function node(id, type, label, props = {}, extra = {}) {
  return {
    id, type, label,
    account: extra.account === undefined ? ACCOUNT : extra.account,
    region: extra.region === undefined ? null : extra.region,
    partition: extra.partition === undefined ? 'aws' : extra.partition,
    props, tags: [], coverage: { status: 'complete', gaps: [] }, findings: [], inherited_findings: [], max_severity: null,
  };
}

/** An edge record whose class/category come from the example.json registry for `type`. */
function edge(registry, source, type, target, weight, extra = {}) {
  const t = registry[type];
  if (!t) throw new Error(`no registry entry for ${type}`);
  return {
    id: edgeId(source, type, target), source, target, type,
    category: t.category, traversal: t.traversal,
    traversable: extra.traversable === undefined ? true : extra.traversable,
    weight, confidence: extra.confidence || 'definite', evidence: extra.evidence || { decision: 'allow' },
  };
}

/** Skeleton document with example.json's generator/run and registries. */
function skeleton() {
  const ex = fixture('example');
  return {
    schema_version: '1.0.0',
    generator: ex.generator,
    run: { ...ex.run, operator: { arn: null, node_id: null, resolution: 'unavailable', redacted: false } },
    meta: { default_sources: [], default_targets: [] },
    node_types: ex.node_types,
    edge_types: ex.edge_types,
    nodes: [], edges: [], findings: [],
    coverage: { source: 'ledger', status: 'complete', modules: [] },
    evaluation_gaps: [], analyzer_status: [],
  };
}

function finish(doc) {
  const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  doc.nodes.sort(byId);
  doc.edges.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : a.type < b.type ? -1 : a.type > b.type ? 1 : a.target < b.target ? -1 : a.target > b.target ? 1 : 0));
  doc.meta.default_sources = doc.nodes.filter(n => n.props.entry_point === true).map(n => n.id).sort();
  doc.meta.default_targets = doc.nodes.filter(n => n.props.high_value === true).map(n => n.id).sort();
  return doc;
}

const userId = (i) => `arn:aws:iam::${ACCOUNT}:user/demo-u${String(i).padStart(5, '0')}`;
const roleId = (i) => `arn:aws:iam::${ACCOUNT}:role/demo-r${String(i).padStart(5, '0')}`;
const ADMIN = `aws-enumerator:account-admin/${ACCOUNT}`;
const ANON = 'aws-enumerator:anonymous';

function baseNodes(doc) {
  doc.nodes.push(node(ADMIN, 'account_admin', 'Account administrator', { high_value: true, high_value_reason: 'account-admin' }));
  doc.nodes.push(node(ANON, 'anonymous', 'Anyone (internet)', { entry_point: true }, { account: null, partition: null }));
}

/**
 * `sources` users, each with CAN_ASSUME to one shared role that is admin-equivalent:
 * exactly `sources` source->admin paths of cost 1 (paging past 50, F-043).
 */
function fanInGraph(sources) {
  const doc = skeleton();
  const reg = doc.edge_types;
  baseNodes(doc);
  const role = roleId(0);
  doc.nodes.push(node(role, 'role', 'demo-r00000', { attached_policies_status: 'complete', high_value: true, high_value_reason: 'admin-equivalent' }));
  doc.edges.push(edge(reg, role, 'IS_ADMIN_EQUIVALENT', ADMIN, 0));
  for (let i = 0; i < sources; i++) {
    const u = userId(i);
    doc.nodes.push(node(u, 'user', `demo-u${String(i).padStart(5, '0')}`, { entry_point: true, attached_policies_status: 'complete' }));
    doc.edges.push(edge(reg, u, 'CAN_ASSUME', role, 1));
  }
  return finish(doc);
}

/** One user with CAN_ASSUME to `targets` admin-equivalent roles (per-source cap, F-043). */
function fanOutGraph(targets) {
  const doc = skeleton();
  const reg = doc.edge_types;
  baseNodes(doc);
  const u = userId(0);
  doc.nodes.push(node(u, 'user', 'demo-u00000', { entry_point: true, attached_policies_status: 'complete' }));
  for (let i = 0; i < targets; i++) {
    const r = roleId(i);
    doc.nodes.push(node(r, 'role', `demo-r${String(i).padStart(5, '0')}`, { attached_policies_status: 'complete', high_value: true, high_value_reason: 'admin-equivalent' }));
    doc.edges.push(edge(reg, u, 'CAN_ASSUME', r, 1 + (i % 3)));
  }
  return finish(doc);
}

/**
 * A large role graph for complexity checks (F-038): `n` roles in a ring plus pseudo-random
 * CAN_ASSUME chords, `nEdges` edges in total. Deterministic.
 */
function scaleGraph(nEdges, { nodesPerEdge = 0.25 } = {}) {
  const doc = skeleton();
  const reg = doc.edge_types;
  baseNodes(doc);
  const n = Math.max(10, Math.floor(nEdges * nodesPerEdge));
  for (let i = 0; i < n; i++) doc.nodes.push(node(roleId(i), 'role', `demo-r${String(i).padStart(5, '0')}`, { attached_policies_status: 'complete' }));
  const seen = new Set();
  let x = 12345;
  const rnd = () => { x = (Math.imul(x, 1103515245) + 12345) >>> 0; return x >>> 8; }; // 32-bit LCG, exact
  const maxEdges = n * (n - 1);
  if (nEdges > maxEdges) throw new Error(`scaleGraph: ${nEdges} edges do not fit ${n} nodes`);
  for (let i = 0; doc.edges.length < nEdges; i++) {
    if (i > nEdges * 20) throw new Error('scaleGraph: generator stalled');
    const a = i < n ? i : rnd() % n;
    const b = i < n ? (i + 1) % n : rnd() % n;
    if (a === b) continue;
    const key = `${a}>${b}`;
    if (seen.has(key)) continue;
    seen.add(key);
    doc.edges.push(edge(reg, roleId(a), 'CAN_ASSUME', roleId(b), 1 + (i % 4)));
  }
  doc.nodes.find(nd => nd.id === roleId(n - 1)).props.high_value = true;
  doc.nodes.find(nd => nd.id === roleId(n - 1)).props.high_value_reason = 'admin-equivalent';
  return finish(doc);
}

/**
 * Reference single-source shortest costs over a raw graph.json document (graph-json.md section 11):
 * directed, traversable === true only, weight read with ??-semantics. Returns Map<target, cost>.
 */
function refCosts(doc, source, { excludeCategories = [], excludeNodeTypes = [], definiteOnly = false } = {}) {
  const types = new Map(doc.nodes.map(n => [n.id, n.type]));
  const hiddenC = new Set(excludeCategories);
  const hiddenT = new Set(excludeNodeTypes);
  const adj = new Map();
  for (const e of doc.edges) {
    if (e.traversable !== true || !types.has(e.source) || !types.has(e.target)) continue;
    if (hiddenC.has(e.category) || hiddenT.has(types.get(e.source)) || hiddenT.has(types.get(e.target))) continue;
    if (definiteOnly && e.confidence === 'conditional') continue;
    const w = (typeof e.weight === 'number' && Number.isFinite(e.weight) && e.weight >= 0) ? e.weight : 1;
    if (!adj.has(e.source)) adj.set(e.source, []);
    adj.get(e.source).push([e.target, w]);
  }
  const dist = new Map([[source, 0]]);
  const done = new Set();
  for (;;) {
    let u = null;
    for (const [k, d] of dist) if (!done.has(k) && (u === null || d < dist.get(u))) u = k;
    if (u === null) break;
    done.add(u);
    for (const [v, w] of adj.get(u) || []) {
      const nd = dist.get(u) + w;
      if (!dist.has(v) || nd < dist.get(v)) dist.set(v, nd);
    }
  }
  dist.delete(source);
  return dist;
}

module.exports = { ACCOUNT, ADMIN, ANON, edgeId, node, edge, skeleton, finish, userId, roleId, fanInGraph, fanOutGraph, scaleGraph, refCosts };
