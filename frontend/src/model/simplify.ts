/*
 * The operator lens: what the canvases and path finding leave out by default (plan "noise defaults").
 *
 * - Admin fan-out: an admin-equivalent principal can do anything, so its hundreds of out-edges
 *   (CAN_MODIFY_PERMISSIONS_OF, CAN_TAKEOVER ... to every role) say nothing an operator does not already know.
 *   Only its IS_ADMIN_EQUIVALENT edge to the account administrator is kept. Paths to the administrator are
 *   unchanged: they end at the first admin-equivalent node anyway.
 * - Context nodes: managed policies and AWS service principals are never attack steps; the drawer lists them
 *   as "Attached policies" and "Trusted services" instead.
 * - Context edges: structural and info edges (traversal classes the catalogue hides by default).
 */
import { C, K } from '../core';
import type { Active, GEdge, GNode, Index } from '../core';

export interface Lens {
  collapseAdmin: boolean;
  hideContextNodes: boolean;
  hideContextEdges: boolean;
}

export const OPERATOR_LENS: Readonly<Lens> = Object.freeze({ collapseAdmin: true, hideContextNodes: true, hideContextEdges: true });

export const CONTEXT_NODE_TYPES: ReadonlySet<string> = new Set(['policy', 'service_principal']);
export const ADMIN_EDGE = 'IS_ADMIN_EQUIVALENT';
/** Node types an attacker starts from without a credential in the account. */
export const ENTRY_TYPES: ReadonlySet<string> = new Set(['anonymous', 'external_account', 'external_principal', 'idp']);

export function isAdminEquivalent(n: GNode | undefined): boolean {
  return !!n && n.props.high_value_reason === 'admin-equivalent';
}

export function isAccountAdmin(n: GNode | undefined): boolean {
  return !!n && n.type === 'account_admin';
}

export function isEntryPoint(n: GNode | undefined): boolean {
  return !!n && (ENTRY_TYPES.has(n.type) || n.props.entry_point === true);
}

export interface Simplified {
  /** Ids of admin-equivalent nodes. */
  admins: Set<string>;
  /** Ids of the out-edges the admin fan-out collapse removes. */
  collapsed: Set<string>;
}

export function simplify(index: Index): Simplified {
  const admins = new Set<string>();
  const collapsed = new Set<string>();
  for (const n of index.graph.nodes) {
    if (!isAdminEquivalent(n)) continue;
    admins.add(n.id);
    for (const e of index.out.get(n.id) || []) if (e.type !== ADMIN_EDGE) collapsed.add(e.id);
  }
  return { admins, collapsed };
}

/** Whether an edge is drawn under `lens` (endpoint visibility included). */
export function edgeVisible(e: GEdge, index: Index, s: Simplified, lens: Lens): boolean {
  if (lens.collapseAdmin && s.collapsed.has(e.id)) return false;
  if (lens.hideContextEdges && K.traversalInfo(e.traversal).hiddenByDefault) return false;
  if (lens.hideContextNodes) {
    const a = index.nodesById.get(e.source);
    const b = index.nodesById.get(e.target);
    if (!a || !b || CONTEXT_NODE_TYPES.has(a.type) || CONTEXT_NODE_TYPES.has(b.type)) return false;
  }
  return true;
}

export function nodeVisible(n: GNode, lens: Lens): boolean {
  return !(lens.hideContextNodes && CONTEXT_NODE_TYPES.has(n.type));
}

/** Path finding over the operator lens: the core's active subgraph minus the collapsed admin fan-out. */
export function operatorActive(index: Index, s: Simplified, opts: { includeConditional?: boolean } = {}): Active {
  const base = C.activeSubgraph(index, { includeConditional: opts.includeConditional !== false });
  return Object.freeze({
    opts: base.opts,
    index: base.index,
    nodeAllowed: base.nodeAllowed,
    edgeAllowed: (edge: GEdge) => base.edgeAllowed(edge) && !s.collapsed.has(edge.id),
  });
}

export interface DrawerContext {
  policies: { id: string; label: string; edge: string }[];
  services: { id: string; label: string }[];
}

/** The context nodes around one node, for the drawer: attached policies and the services that can assume it. */
export function drawerContext(index: Index, id: string): DrawerContext {
  const policies: DrawerContext['policies'] = [];
  const services: DrawerContext['services'] = [];
  for (const e of index.out.get(id) || []) {
    const t = index.nodesById.get(e.target);
    if (t && t.type === 'policy') policies.push({ id: t.id, label: t.label, edge: e.type });
  }
  for (const e of index.in.get(id) || []) {
    const s = index.nodesById.get(e.source);
    if (s && s.type === 'service_principal') services.push({ id: s.id, label: s.label });
  }
  return { policies, services };
}
