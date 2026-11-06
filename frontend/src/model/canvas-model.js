/*
 * What a canvas draws, independent of the canvas library: cards (a node, or a group of hidden neighbours)
 * in columns, and edges with every parallel edge of a pair merged into one.
 */
import { K } from '../core';
import { ADMIN_EDGE, edgeVisible, isAccountAdmin, isAdminEquivalent, isEntryPoint, nodeVisible } from './simplify';
import { cmp, shown } from './text';

const STYLE_RANK = { admin: 0, control: 1, exposure: 2, access: 3, context: 4 };

export function edgeStyle(e) {
  if (e.type === ADMIN_EDGE) return 'admin';
  if (e.traversal === 'control' || e.traversal === 'access' || e.traversal === 'exposure') return e.traversal;
  return 'context';
}

export function nodeCard(index, s, id, column, ctx) {
  const n = index.nodesById.get(id);
  const info = K.nodeTypeInfo(n ? n.type : '', n ? index.nodeTypes.get(n.type) : undefined);
  const badges = [];
  if (n && id === ctx.operator) badges.push('operator');
  if (n && ctx.owned.has(id) && id !== ctx.operator) badges.push('owned');
  if (n && (isAdminEquivalent(n) || s.admins.has(id))) badges.push('admin-equivalent');
  if (n && isAccountAdmin(n)) badges.push('account admin');
  if (n && n.props.external === true) badges.push('external');
  if (n && isEntryPoint(n) && !n.props.external) badges.push('entry point');
  return {
    id, column, kind: 'node', nodeId: id, type: n ? n.type : '',
    label: shown(n ? n.label : id), sub: info.label, iconUrl: info.iconUrl,
    severity: n && n.max_severity ? n.max_severity : null, badges, count: 1, groupKey: null,
  };
}

/** Merge parallel edges (same source and target) into one link, in first-seen order. */
export function mergeLinks(edges, idOf) {
  const byPair = new Map();
  for (const e of edges) {
    const source = idOf(e.source);
    const target = idOf(e.target);
    const key = source + '\u0000' + target;
    const style = edgeStyle(e);
    const link = byPair.get(key);
    if (!link) {
      byPair.set(key, { id: 'l:' + key, source, target, types: [e.type], style, conditional: e.confidence === 'conditional', edgeIds: [e.id] });
      continue;
    }
    if (!link.types.includes(e.type)) link.types.push(e.type);
    link.edgeIds.push(e.id);
    if (STYLE_RANK[style] < STYLE_RANK[link.style]) link.style = style;
    link.conditional = link.conditional && e.confidence === 'conditional';
  }
  const out = [...byPair.values()];
  out.forEach((l) => l.types.sort(cmp));
  return out; // first-seen order: path order for a path, adjacency order (sorted by the core) otherwise
}

/** The kill-chain canvas of one path: one card per step, in order. */
export function pathCanvas(index, s, path, edgeIds, ctx, firstLabel, columnTactics = []) {
  const cards = path.map((id, i) => nodeCard(index, s, id, i, ctx));
  const edges = edgeIds.map((id) => index.edgesById.get(id)).filter((e) => !!e);
  const columns = path.map((id, i) => {
    const n = index.nodesById.get(id);
    let label = 'Pivot';
    if (i === 0) label = firstLabel;
    else if (isAccountAdmin(n)) label = 'Impact';
    else if (s.admins.has(id)) label = 'Admin-equivalent';
    else if (i === path.length - 1) label = 'Target';
    // The ATT&CK tactic of this column (how the attacker is in, then the step that gets here), when known.
    const tactic = columnTactics[i] || null;
    return { column: i, label: `${i + 1}. ${label}` + (tactic ? ` \u00b7 ${tactic}` : '') };
  });
  return { cards, links: mergeLinks(edges, (x) => x), columns, truncated: 0 };
}

export const GROUP_LIMIT = 12;
export const MAX_CARDS = 150;

/**
 * The neighbourhood of one node under a lens: who reaches it (left), the node (middle), what it reaches
 * (right). More than GROUP_LIMIT neighbours of one type on one side collapse into a group card unless the
 * group was expanded. At most MAX_CARDS cards.
 */
export function neighbourhood(index, s, lens, focus, expanded, ctx) {
  const outEdges = (index.out.get(focus) || []).filter((e) => e.target !== focus && edgeVisible(e, index, s, lens));
  const inEdges = (index.in.get(focus) || []).filter((e) => e.source !== focus && edgeVisible(e, index, s, lens));
  const outIds = new Set(outEdges.map((e) => e.target));
  const inIds = new Set([...inEdges.map((e) => e.source)].filter((id) => !outIds.has(id)));
  const cards = [nodeCard(index, s, focus, 1, ctx)];
  const idOf = new Map([[focus, focus]]);
  let truncated = 0;

  const place = (ids, column, side) => {
    const byType = new Map();
    for (const id of ids) {
      const n = index.nodesById.get(id);
      if (!n || !nodeVisible(n, lens)) continue;
      (byType.get(n.type) || byType.set(n.type, []).get(n.type)).push(id);
    }
    const types = [...byType.keys()].sort(cmp);
    for (const t of types) {
      const list = byType.get(t).sort((a, b) => cmp(index.nodesById.get(a).label, index.nodesById.get(b).label) || cmp(a, b));
      const key = side + ':' + t;
      if (list.length > GROUP_LIMIT && !expanded.has(key)) {
        const info = K.nodeTypeInfo(t, index.nodeTypes.get(t));
        const gid = 'group:' + key;
        cards.push({ id: gid, column, kind: 'group', nodeId: null, type: t, label: `${list.length} × ${info.label}`,
          sub: 'Click to expand', iconUrl: info.iconUrl, severity: null, badges: [], count: list.length, groupKey: key });
        list.forEach((id) => idOf.set(id, gid));
        continue;
      }
      for (const id of list) {
        if (cards.length >= MAX_CARDS) {
          truncated++;
          continue;
        }
        cards.push(nodeCard(index, s, id, column, ctx));
        idOf.set(id, id);
      }
    }
  };
  place(inIds, 0, 'in');
  place(outIds, 2, 'out');
  const edges = [...inEdges, ...outEdges].filter((e) => idOf.has(e.source) && idOf.has(e.target));
  return {
    cards,
    links: mergeLinks(edges, (id) => idOf.get(id)),
    columns: [{ column: 0, label: 'Who reaches it' }, { column: 1, label: 'Focus' }, { column: 2, label: 'What it reaches' }],
    truncated,
  };
}
