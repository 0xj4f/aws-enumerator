/*
 * The Principals and Data pages: one row per principal or data asset, with what an operator sorts by.
 */
import { A, C, K } from '../core';
import { ADMIN_EDGE, CONTEXT_NODE_TYPES } from './simplify';
import { cmp, severityRank, shown } from './text';

export const PRINCIPAL_TYPES = new Set(['user', 'role', 'group']);
/** Principals from outside the account: they are listed on the Principals page too. */
export const OUTSIDE_PRINCIPAL_TYPES = new Set(['external_principal', 'external_account', 'idp']);
/** Data assets (node_types data_asset) and the KMS keys that gate them. */
export const DATA_GATE_TYPES = new Set(['kms']);

function findingsOf(index, id) {
  const list = index.findingsByNode.get(id) || [];
  const worst = list.length ? list.map((f) => C.severityClass(f.severity)).sort((a, b) => severityRank(a) - severityRank(b))[0] : null;
  const techniques = [...new Set(list.flatMap((f) => [...A.findingTechniques(f.id)]))].sort();
  return { list, worst, techniques };
}

function typeLabel(index, type) {
  return K.nodeTypeInfo(type, index.nodeTypes.get(type)).label;
}

function isCollapsed(s, e) {
  return s.collapsed.has(e.id);
}

export function principalRows(index, s, reach) {
  const rows = [];
  for (const n of index.graph.nodes) {
    if (!PRINCIPAL_TYPES.has(n.type) && !OUTSIDE_PRINCIPAL_TYPES.has(n.type)) continue;
    const f = findingsOf(index, n.id);
    const into = (index.in.get(n.id) || []).filter((e) => e.traversal === 'control' && !isCollapsed(s, e) && e.source !== n.id);
    const outOf = (index.out.get(n.id) || []).filter((e) => e.traversal === 'control' && !isCollapsed(s, e) && e.type !== ADMIN_EDGE && e.target !== n.id);
    const ra = n.props.reaches_admin;
    rows.push({
      id: n.id, label: shown(n.label), type: n.type, typeLabel: typeLabel(index, n.type),
      findings: f.list, maxSeverity: f.worst, techniques: f.techniques, reachedFrom: reach.get(n.id) || [],
      admin: s.admins.has(n.id), reachesAdmin: ra === 'definite' || ra === 'conditional' ? ra : null,
      external: n.props.external === true || OUTSIDE_PRINCIPAL_TYPES.has(n.type),
      becomeBy: [...new Set(into.map((e) => e.source))], canBecome: [...new Set(outOf.map((e) => e.target))],
    });
  }
  const rank = (r) => (r.admin ? 0 : r.reachesAdmin === 'definite' ? 1 : r.reachesAdmin === 'conditional' ? 2 : 3);
  return rows.sort((a, b) => rank(a) - rank(b) || b.reachedFrom.length - a.reachedFrom.length ||
    (a.maxSeverity ? severityRank(a.maxSeverity) : 9) - (b.maxSeverity ? severityRank(b.maxSeverity) : 9) || cmp(a.label, b.label) || cmp(a.id, b.id));
}

export function isDataNode(index, type, props) {
  return DATA_GATE_TYPES.has(type) || index.nodeTypes.get(type)?.data_asset === true || props.data_asset === true;
}

/**
 * How sensitive an asset usually is (0 most): secrets first, then customer-managed keys, data stores and SecureString
 * parameters, then images and queues; plain String parameters and AWS-managed keys last.
 */
export function sensitivity(type, props) {
  if (type === 'secret' || type === 'k8ssecret') return 0;
  if (type === 'ssmparam') return props.param_type === 'SecureString' ? 1 : 4;
  if (type === 'kms') return props.aws_managed === true ? 4 : 1;
  if (type === 'bucket' || type === 'dynamodb' || type === 'rds' || type === 'rdssnapshot' || type === 'ebssnapshot') return 2;
  return 3;
}

export function dataRows(index, s, reach) {
  const rows = [];
  for (const n of index.graph.nodes) {
    if (!isDataNode(index, n.type, n.props)) continue;
    const f = findingsOf(index, n.id);
    const ins = (index.in.get(n.id) || []).filter((e) => (e.traversal === 'access' || e.traversal === 'exposure') && !isCollapsed(s, e));
    const sourceType = (e) => index.nodesById.get(e.source)?.type || '';
    const readers = [...new Set(ins.filter((e) => PRINCIPAL_TYPES.has(sourceType(e)) && !s.admins.has(e.source)).map((e) => e.source))];
    const keys = (index.out.get(n.id) || []).filter((e) => e.category === 'encryption').map((e) => e.target);
    const techniques = [...new Set([...f.techniques, ...ins.flatMap((e) => [...A.edgeTechniques(e.type)])])].sort();
    rows.push({
      id: n.id, label: shown(n.label), type: n.type, typeLabel: typeLabel(index, n.type),
      findings: f.list, maxSeverity: f.worst, techniques, reachedFrom: reach.get(n.id) || [],
      public: ins.some((e) => sourceType(e) === 'anonymous'),
      crossAccount: ins.some((e) => sourceType(e) === 'external_account' || sourceType(e) === 'external_principal'),
      readers, keys: [...new Set(keys)], sensitivity: sensitivity(n.type, n.props),
    });
  }
  const rank = (r) => (r.public ? 0 : r.crossAccount ? 1 : 2);
  return rows.sort((a, b) => rank(a) - rank(b) || a.sensitivity - b.sensitivity || b.reachedFrom.length - a.reachedFrom.length || b.readers.length - a.readers.length ||
    cmp(a.typeLabel, b.typeLabel) || cmp(a.label, b.label) || cmp(a.id, b.id));
}

/** A node's edges of the given traversal classes, for the drawer (admin fan-out and context nodes left out). */
export function relatedEdges(index, s, id, direction, classes) {
  const list = direction === 'in' ? index.in.get(id) || [] : index.out.get(id) || [];
  return list.filter((e) => {
    if (!classes.includes(e.traversal) || isCollapsed(s, e) || e.source === e.target) return false;
    const other = index.nodesById.get(direction === 'in' ? e.source : e.target);
    return !!other && !CONTEXT_NODE_TYPES.has(other.type);
  });
}
