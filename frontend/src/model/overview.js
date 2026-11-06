/*
 * The kill-chain map (D-59): every attack route on one canvas, in kill-chain order. Ways in on the left, then
 * footholds, escalation, the admin-equivalent principals, the account administrator, and the data the ways in
 * reach. A node takes the lowest column any route gives it. More than GROUP_LIMIT cards of one type in a column
 * collapse into a group card (click to expand); data is grouped by asset type. At most MAX_CARDS cards.
 *
 * Pivots rank the nodes the routes run through: the principal or resource worth compromising first.
 */
import { A, K } from '../core';
import { GROUP_LIMIT, MAX_CARDS, mergeLinks, nodeCard } from './canvas-model';
import { isAccountAdmin } from './simplify';
import { cmp, shown } from './text';

export const MAP_COLUMNS = Object.freeze(['Ways in', 'Footholds', 'Escalation', 'Admin-equivalent', 'Account admin', 'Data reached']);
const DATA_COLUMN = 5;

/** Every route the map draws: each route and its alternatives, in scope, expected ones only when asked. */
export function mapRoutes(routes, { scope = 'all', includeExpected = false, expected = new Set(), ctx }) {
  const mine = (id) => id === ctx.operator || ctx.owned.has(id);
  return routes
    .flatMap((h) => [h, ...h.alternatives])
    .filter((h) => (scope !== 'foothold' || mine(h.source)) &&
      (includeExpected || !(expected.has('route:' + h.id) || expected.has('entry:' + h.source))));
}

/** Which column a route's i-th node goes in. */
function columnOf(index, s, id, i) {
  if (i === 0) return 0;
  if (isAccountAdmin(index.nodesById.get(id))) return 4;
  if (s.admins.has(id)) return 3;
  return i === 1 ? 1 : 2;
}

/** The tactic most steps into a column stand for (ties: the first seen). */
function topTactic(counts) {
  let best = null;
  for (const [name, n] of counts) if (!best || n > best[1]) best = [name, n];
  return best ? best[0] : null;
}

/**
 * The map's canvas model (the shape of model/canvas-model.js, plus `cardOf`: node id -> card id).
 * `paths` come from mapRoutes; `dataRows` from model/inventory.js dataRows (their reachedFrom lists the ways in).
 */
export function killChainMap(index, s, paths, dataRows, { expanded = new Set(), scope = 'all', includeExpected = false, expected = new Set(), ctx }) {
  const col = new Map();
  const tactics = MAP_COLUMNS.map(() => new Map());
  const place = (id, c) => {
    if (!col.has(id) || c < col.get(id)) col.set(id, c);
  };
  // As on a route's canvas: the way in is labelled with how the attacker is in, every other column with the
  // tactic of the step that reaches it.
  for (const h of paths) {
    h.path.forEach((id, i) => {
      const c = columnOf(index, s, id, i);
      place(id, c);
      const t = i === 0 ? h.steps[0]?.entry : h.steps[i - 1]?.tactic;
      if (t) tactics[c].set(t.name, (tactics[c].get(t.name) || 0) + 1);
    });
  }

  // Data the ways in reach (over attack steps, admin fan-out collapsed). Its sources are ways in too, even when
  // they have no route to admin: anyone on the internet reading a bucket is a way in.
  const mine = (id) => id === ctx.operator || ctx.owned.has(id);
  const sourceOk = (id) => (scope === 'foothold' ? mine(id) : includeExpected || !expected.has('entry:' + id));
  const data = [];
  for (const r of dataRows) {
    const from = r.reachedFrom.filter(sourceOk);
    if (!from.length) continue;
    data.push({ row: r, from });
    from.forEach((id) => place(id, 0));
  }
  if (data.length) tactics[DATA_COLUMN].set(A.TACTICS.find((t) => t.shortname === 'collection')?.name || 'Collection', 1);

  const cards = [];
  const cardOf = new Map();
  let truncated = 0;
  const add = (card, members) => {
    if (cards.length >= MAX_CARDS) {
      truncated += members.length;
      return;
    }
    cards.push(card);
    members.forEach((id) => cardOf.set(id, card.id));
  };
  const group = (key, column, type, members, label) => {
    const info = K.nodeTypeInfo(type, index.nodeTypes.get(type));
    add({ id: 'group:' + key, column, kind: 'group', nodeId: null, type, label: label || `${members.length} × ${info.label}`,
      sub: 'Click to expand', iconUrl: info.iconUrl, severity: null, badges: [], count: members.length, groupKey: key }, members);
  };
  const byLabel = (a, b) => cmp(index.nodesById.get(a)?.label || a, index.nodesById.get(b)?.label || b) || cmp(a, b);

  for (let c = 0; c < DATA_COLUMN; c++) {
    const byType = new Map();
    for (const [id, cc] of col) {
      if (cc !== c) continue;
      const t = index.nodesById.get(id)?.type || '';
      (byType.get(t) || byType.set(t, []).get(t)).push(id);
    }
    for (const t of [...byType.keys()].sort(cmp)) {
      const list = byType.get(t).sort(byLabel);
      const key = 'c' + c + ':' + t;
      if (list.length > GROUP_LIMIT && !expanded.has(key)) group(key, c, t, list);
      else list.forEach((id) => add(nodeCard(index, s, id, c, ctx), [id]));
    }
  }

  // Data: one group card per asset type, the most sensitive types first; a single asset or an expanded group
  // shows its assets.
  const dataByType = new Map();
  for (const d of data) (dataByType.get(d.row.type) || dataByType.set(d.row.type, []).get(d.row.type)).push(d);
  const dataTypes = [...dataByType.keys()].sort((a, b) =>
    Math.min(...dataByType.get(a).map((d) => d.row.sensitivity)) - Math.min(...dataByType.get(b).map((d) => d.row.sensitivity)) || cmp(a, b));
  for (const t of dataTypes) {
    const list = dataByType.get(t);
    const key = 'data:' + t;
    const ids = list.map((d) => d.row.id).sort(byLabel);
    if (list.length > 1 && !expanded.has(key)) group(key, DATA_COLUMN, t, ids, `${list.length} × ${list[0].row.typeLabel}`);
    else ids.forEach((id) => add(nodeCard(index, s, id, DATA_COLUMN, ctx), [id]));
  }

  // Links: the routes' steps (parallel edges merged), then one "reaches" link from each way in to each data card.
  const seen = new Set();
  const edges = [];
  for (const h of paths) {
    for (const id of h.edges) {
      const e = index.edgesById.get(id);
      if (!e || seen.has(id) || !cardOf.has(e.source) || !cardOf.has(e.target)) continue;
      seen.add(id);
      edges.push(e);
    }
  }
  const links = mergeLinks(edges, (id) => cardOf.get(id)).filter((l) => l.source !== l.target);
  const reachLinks = new Map();
  for (const d of data) {
    const target = cardOf.get(d.row.id);
    if (!target) continue;
    for (const src of d.from) {
      const source = cardOf.get(src);
      if (!source || source === target) continue;
      const id = 'l:' + source + '\u0000' + target;
      if (!reachLinks.has(id)) reachLinks.set(id, { id, source, target, types: ['reaches'], style: 'access', conditional: false, edgeIds: [] });
    }
  }
  const linkIds = new Set(links.map((l) => l.id));
  for (const l of reachLinks.values()) if (!linkIds.has(l.id)) links.push(l);

  // Only the columns that have cards, numbered in reading order.
  const present = new Set(cards.map((c) => c.column));
  const columns = MAP_COLUMNS.map((label, c) => ({ column: c, label, tactic: topTactic(tactics[c]) }))
    .filter((c) => present.has(c.column))
    .map((c, i) => ({ column: c.column, label: `${i + 1}. ${c.label}` + (c.tactic ? ` · ${c.tactic}` : '') }));
  return { cards, links, columns, truncated, cardOf, waysIn: cards.filter((c) => c.column === 0).reduce((n, c) => n + c.count, 0), data: data.length };
}

/** The cards and links of some routes on a map (for the highlight): through group cards where grouped. */
export function routeHighlight(model, paths) {
  const cards = new Set();
  const links = new Set();
  for (const h of paths) {
    const ids = h.path.map((id) => model.cardOf.get(id));
    ids.forEach((c) => c && cards.add(c));
    for (let i = 0; i + 1 < ids.length; i++) {
      if (ids[i] && ids[i + 1] && ids[i] !== ids[i + 1]) links.add('l:' + ids[i] + '\u0000' + ids[i + 1]);
    }
  }
  return { cards, links };
}

/**
 * Key pivots: the nodes the routes run through (not their ways in, not the account administrator), ranked by
 * the routes through them, then by how many ways in reach them; admin-equivalent principals last (they are the
 * goal, not the pivot).
 */
export function pivots(index, s, paths, limit = 8) {
  const by = new Map();
  for (const h of paths) {
    h.path.forEach((id, i) => {
      const n = index.nodesById.get(id);
      if (i === 0 || !n || isAccountAdmin(n)) return;
      let p = by.get(id);
      if (!p) by.set(id, (p = { id, routes: new Set(), sources: new Set() }));
      p.routes.add(h.id);
      p.sources.add(h.source);
    });
  }
  return [...by.values()]
    .map((p) => {
      const n = index.nodesById.get(p.id);
      return {
        id: p.id, label: shown(n.label), type: n.type, typeLabel: K.nodeTypeInfo(n.type, index.nodeTypes.get(n.type)).label,
        admin: s.admins.has(p.id), routes: p.routes.size, waysIn: p.sources.size, routeIds: [...p.routes],
      };
    })
    .sort((a, b) => Number(a.admin) - Number(b.admin) || b.routes - a.routes || b.waysIn - a.waysIn || cmp(a.label, b.label) || cmp(a.id, b.id))
    .slice(0, limit);
}

/** The routes (and alternatives) a node is on, and its place on each: the way in, a step, or the end. */
export function routesThrough(routes, id) {
  const out = [];
  for (const h of routes.flatMap((r) => [r, ...r.alternatives])) {
    const i = h.path.indexOf(id);
    if (i < 0) continue;
    out.push({ route: h, role: i === 0 ? 'way in' : i === h.path.length - 1 ? 'end' : 'step ' + i });
  }
  return out;
}
