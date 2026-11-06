/*
 * Breach hypotheses: who can get in (or already is in) and become account administrator, and how.
 *
 * Sources are the entry points (anyone, external accounts and principals, identity providers, nodes marked
 * entry_point) plus the owned nodes and the operator. Targets are the account administrator node(s) and
 * the admin-equivalent principals. The search is graph-core's discoverAll (cheapest path per source and
 * target, chunked) over the operator lens (admin fan-out collapsed), so a path never runs through one admin
 * to reach another. Each path is cut at the first admin-equivalent node it reaches and, when that node has
 * an IS_ADMIN_EQUIVALENT edge, extended to the account administrator, so every hypothesis reads
 * "entry -> ... -> admin-equivalent X -> account administrator".
 */
import { C } from '../core';
import { ADMIN_EDGE, ENTRY_TYPES, isAccountAdmin, isAdminEquivalent, operatorActive } from './simplify';
import { routeSteps, routeTactics } from './tactics';
import { cmp, severityRank, shown } from './text';

export const ENTRY_KIND_LABELS = Object.freeze({
  internet: 'Internet',
  'cross-account': 'Cross-account',
  federation: 'Federation',
  entry: 'Entry point',
  foothold: 'Your foothold',
  session: 'From session',
  custom: 'Custom route',
});

/** Order of the kinds in the table filter and in the ranking (outside-in first). */
export const ENTRY_KIND_ORDER = ['internet', 'cross-account', 'federation', 'entry', 'foothold', 'session', 'custom'];

const VERBS = Object.freeze({
  CAN_ASSUME: 'can assume',
  CAN_ASSUME_SAML: 'can sign in through SAML as',
  CAN_ASSUME_WEB_IDENTITY: 'can federate into',
  SERVICE_CAN_ASSUME: 'can be assumed by',
  CAN_ESCALATE: 'can escalate to',
  CAN_PASS_ROLE_TO: 'can pass a role to',
  CAN_TAKEOVER: 'can take over',
  CAN_MODIFY_PERMISSIONS_OF: 'can rewrite the permissions of',
  CAN_MODIFY: 'can modify',
  CAN_UPDATE_CODE: 'can replace the code of',
  CAN_HIJACK: 'can hijack',
  CAN_INVOKE: 'can invoke',
  USES_ROLE: 'runs as',
  PUBLIC_INBOUND: 'can reach',
  FULL_ACCESS: 'has full access to',
  CAN_ADMIN: 'can administer',
  CAN_READ: 'can read',
  CAN_WRITE: 'can write',
  CAN_DECRYPT: 'can decrypt with',
  CAN_READ_PARAM: 'can read',
});

export function verbOf(edgeType) {
  return VERBS[edgeType] || edgeType.toLowerCase().replace(/_/g, ' ');
}

export function entryKind(n, firstEdge, owned, operator) {
  if (n.id === operator || owned.has(n.id)) return 'foothold';
  if (n.type === 'anonymous') return 'internet';
  if (n.type === 'idp' || (firstEdge && (firstEdge.type === 'CAN_ASSUME_SAML' || firstEdge.type === 'CAN_ASSUME_WEB_IDENTITY'))) return 'federation';
  if (n.type === 'external_account' || n.type === 'external_principal' || n.props.external === true) return 'cross-account';
  return 'entry';
}

/** Entry points of the graph (not the owned set): the outside-in sources. */
export function entryPoints(index) {
  return index.graph.nodes
    .filter((n) => ENTRY_TYPES.has(n.type) || n.props.entry_point === true)
    .map((n) => n.id)
    .sort(cmp);
}

/** Account administrator nodes and admin-equivalent principals; the default targets when there are none. */
export function breachTargets(index, s) {
  const admin = index.graph.nodes.filter((n) => isAccountAdmin(n)).map((n) => n.id);
  const targets = [...admin, ...[...s.admins].sort(cmp)];
  return targets.length ? targets : C.defaultTargets(index, {});
}

/** discoverAll over the operator lens, from entries and footholds to the admin targets (yields progress). */
export function* breachSearch(index, s, opts) {
  const owned = opts.owned.filter((id) => index.nodesById.has(id));
  const sources = [];
  const seen = new Set();
  const add = (id) => {
    if (!id || seen.has(id) || !index.nodesById.has(id) || s.admins.has(id) || isAccountAdmin(index.nodesById.get(id))) return;
    seen.add(id);
    sources.push(id);
  };
  owned.forEach(add);
  add(opts.operator);
  entryPoints(index).forEach(add);
  const targets = breachTargets(index, s);
  if (!sources.length || !targets.length) return [];
  const gen = C.discoverAll(index, {
    sources, targets, owned, operator: opts.operator,
    active: operatorActive(index, s, { includeConditional: opts.includeConditional }),
    perSourceCap: targets.length,
  });
  let step = gen.next();
  while (!step.done) {
    if (step.value.kind === 'progress') yield step.value;
    step = gen.next();
  }
  return toHypotheses(index, s, step.value.paths, new Set(owned), opts.operator);
}

/** Runs breachSearch to the end (tests, small graphs). */
export function findBreaches(index, s, opts) {
  const gen = breachSearch(index, s, opts);
  let step = gen.next();
  while (!step.done) step = gen.next();
  return step.value;
}

function adminExtension(index, id) {
  return (index.out.get(id) || []).find((e) => e.type === ADMIN_EDGE && isAccountAdmin(index.nodesById.get(e.target)));
}

/** Cut a path at its first admin-equivalent or administrator node and append the IS_ADMIN_EQUIVALENT step. */
export function normalisePath(index, s, p) {
  let path = p.path.slice();
  let edges = p.edges.slice();
  for (let i = 1; i < path.length; i++) {
    const n = index.nodesById.get(path[i]);
    if (s.admins.has(path[i]) || isAccountAdmin(n)) {
      path = path.slice(0, i + 1);
      edges = edges.slice(0, i);
      break;
    }
  }
  const last = path[path.length - 1];
  if (s.admins.has(last)) {
    const ext = adminExtension(index, last);
    if (ext) {
      path.push(ext.target);
      edges.push(ext.id);
    }
  }
  const cost = edges.reduce((sum, id) => sum + C.edgeWeight(index.edgesById.get(id)), 0);
  return { source: path[0], target: path[path.length - 1], cost, hops: edges.length, path, edges };
}

function pathFindings(index, path) {
  const out = [];
  const seen = new Set();
  for (const id of path) {
    for (const f of index.findingsByNode.get(id) || []) {
      const key = f.fingerprint || f.id + '@' + id;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  return out.sort((a, b) => severityRank(C.severityClass(a.severity)) - severityRank(C.severityClass(b.severity)) || cmp(a.id, b.id));
}

function label(index, id) {
  const n = index.nodesById.get(id);
  return shown(n ? n.label : id);
}

/** A hypothesis from one (already normalised) path. */
export function toHypothesis(index, s, p, kind) {
  const edges = p.edges.map((id) => index.edgesById.get(id));
  const pivotId = p.path.find((id, i) => i > 0 && s.admins.has(id)) || null;
  const targetNode = index.nodesById.get(p.target);
  const reachesAdmin = !!pivotId || isAccountAdmin(targetNode) || isAdminEquivalent(targetNode);
  const findings = pathFindings(index, p.path);
  const worst = findings.length ? C.severityClass(findings[0].severity) : null;
  const conditional = edges.some((e) => e && e.confidence === 'conditional');
  const steps = routeSteps(kind, edges.filter((e) => !!e));
  const parts = [];
  edges.forEach((e, i) => {
    if (!e) return;
    if (e.type === ADMIN_EDGE) parts.push('which is admin-equivalent');
    else parts.push((i === 0 ? '' : 'then ') + verbOf(e.type) + ' ' + label(index, p.path[i + 1]));
  });
  // The route itself, up to the admin-equivalent pivot: "entry -> foothold -> pivot -> admin".
  const shownIds = p.path.filter((id) => !isAccountAdmin(index.nodesById.get(id)));
  const title = shownIds.map((id) => label(index, id)).join(' → ') + (reachesAdmin ? ' → admin' : '');
  return {
    id: p.source + '|' + p.edges.join(','),
    kind,
    source: p.source,
    target: p.target,
    pivot: pivotId,
    path: p.path,
    edges: p.edges,
    hops: p.hops,
    cost: p.cost,
    confidence: conditional ? 'conditional' : 'definite',
    title,
    statement: label(index, p.source) + ' ' + parts.join(', ') + '.',
    findings,
    maxSeverity: worst,
    reachesAdmin,
    steps,
    tactics: routeTactics(steps),
    alternatives: [],
  };
}

/** Source plus the path before its first admin-equivalent or administrator node: one table row per foothold. */
function routeKey(index, s, h) {
  const cut = h.path.findIndex((id, i) => i > 0 && (s.admins.has(id) || isAccountAdmin(index.nodesById.get(id))));
  return (cut < 0 ? h.path : h.path.slice(0, cut)).join('\u0000');
}

export function compareHypotheses(a, b) {
  return (
    Number(b.reachesAdmin) - Number(a.reachesAdmin) ||
    (a.confidence === b.confidence ? 0 : a.confidence === 'definite' ? -1 : 1) ||
    a.hops - b.hops ||
    a.cost - b.cost ||
    ENTRY_KIND_ORDER.indexOf(a.kind) - ENTRY_KIND_ORDER.indexOf(b.kind) ||
    cmp(a.title, b.title) ||
    cmp(a.id, b.id)
  );
}

function toHypotheses(index, s, paths, owned, operator) {
  const byId = new Map();
  for (const raw of paths) {
    const p = normalisePath(index, s, raw);
    const src = index.nodesById.get(p.source);
    if (!src || p.edges.length === 0) continue;
    const h = toHypothesis(index, s, p, entryKind(src, index.edgesById.get(p.edges[0]), owned, operator));
    const prev = byId.get(h.id);
    if (!prev || compareHypotheses(h, prev) < 0) byId.set(h.id, h);
  }
  const groups = new Map();
  for (const h of [...byId.values()].sort(compareHypotheses)) {
    const key = routeKey(index, s, h);
    (groups.get(key) || groups.set(key, []).get(key)).push(h);
  }
  return [...groups.values()].map(([best, ...rest]) => ({ ...best, alternatives: rest })).sort(compareHypotheses);
}

/** A hypothesis for an arbitrary route (custom Find path, a session path). */
export function routeHypothesis(index, s, p, kind) {
  return toHypothesis(index, s, p, kind);
}
