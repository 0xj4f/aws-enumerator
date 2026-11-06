import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { C } from '../core';
import type { Index } from '../core';
import { findBreaches, normalisePath } from './breaches';
import { buildBrief } from './brief';
import { GROUP_LIMIT, MAX_CARDS, neighbourhood, pathCanvas } from './canvas-model';
import { DEFAULT_GRID, layeredLayout, noOverlap, snapAndResolve } from './grid-layout';
import { OPERATOR_LENS, drawerContext, edgeVisible, simplify } from './simplify';

const FIXTURES = join(__dirname, '..', '..', '..', 'tests', 'fixtures');

function indexOf(raw: unknown): Index {
  const { graph, problems } = C.validateGraph(raw);
  if (!graph) throw new Error('invalid graph: ' + JSON.stringify(problems.slice(0, 3)));
  return C.buildIndex(graph);
}

function fixture(rel: string): Index {
  return indexOf(JSON.parse(readFileSync(join(FIXTURES, rel), 'utf8')));
}

type RawNode = { id: string; type: string; label?: string; props?: Record<string, unknown> };
type RawEdge = [string, string, string, string?];

/** A small valid graph.json: nodes and [source, type, target, traversal] edges. */
function synthetic(nodes: RawNode[], edges: RawEdge[], extra: Record<string, unknown> = {}): Index {
  return indexOf({
    schema_version: '1.0.0',
    generator: { tool: 'aws-enumerator', version: 'test' },
    run: { run_id: 'run-t', account_id: '111122223333', mode: 'run', regions: [], operator: null },
    meta: { default_sources: [], default_targets: [] },
    node_types: {},
    edge_types: {},
    nodes: nodes.map((n) => ({ label: n.id, props: {}, tags: [], findings: [], inherited_findings: [], ...n })),
    edges: edges.map(([source, type, target, traversal], i) => ({
      id: `e${i}`, source, target, type, category: 'privesc', traversal: traversal || 'control',
      traversable: traversal !== 'info' && traversal !== 'structural', weight: 1, confidence: 'definite', evidence: {},
    })),
    findings: [],
    coverage: { status: 'complete', modules: [] },
    evaluation_gaps: [],
    analyzer_status: [],
    ...extra,
  });
}

/** An external account that can assume an admin role whose fan-out reaches 40 other roles. */
function fanOut(): Index {
  const roles: RawNode[] = Array.from({ length: 40 }, (_, i) => ({ id: `role-${String(i).padStart(2, '0')}`, type: 'role' }));
  return synthetic(
    [
      { id: 'ext', type: 'external_account', label: 'External account 999', props: { external: true } },
      { id: 'admin-role', type: 'role', props: { high_value: true, high_value_reason: 'admin-equivalent' } },
      { id: 'acct-admin', type: 'account_admin', label: 'Administrator', props: { high_value: true, high_value_reason: 'account-admin' } },
      { id: 'pol', type: 'policy' },
      ...roles,
    ],
    [
      ['ext', 'CAN_ASSUME', 'admin-role'],
      ['admin-role', 'IS_ADMIN_EQUIVALENT', 'acct-admin'],
      ['admin-role', 'HAS_POLICY', 'pol', 'structural'],
      ...roles.map((r): RawEdge => ['admin-role', 'CAN_TAKEOVER', r.id]),
      ...roles.map((r): RawEdge => ['admin-role', 'CAN_MODIFY_PERMISSIONS_OF', r.id]),
    ],
  );
}

describe('operator lens (simplify)', () => {
  it('collapses the out-edges of admin-equivalent nodes except IS_ADMIN_EQUIVALENT', () => {
    const index = fanOut();
    const s = simplify(index);
    expect([...s.admins]).toEqual(['admin-role']);
    expect(s.collapsed.size).toBe(81); // 40 + 40 fan-out edges and HAS_POLICY
    const visible = index.graph.edges.filter((e) => edgeVisible(e, index, s, OPERATOR_LENS)).map((e) => e.type);
    expect(visible.sort()).toEqual(['CAN_ASSUME', 'IS_ADMIN_EQUIVALENT']);
  });

  it('lists attached policies and trusted services for the drawer', () => {
    const ctx = drawerContext(fanOut(), 'admin-role');
    expect(ctx.policies.map((p) => p.id)).toEqual(['pol']);
  });
});

describe('breach hypotheses', () => {
  it('turns an external trust of an admin role into one 2-step breach to the account administrator', () => {
    const index = fanOut();
    const s = simplify(index);
    const hyps = findBreaches(index, s, { owned: [], operator: null });
    expect(hyps).toHaveLength(1);
    const h = hyps[0];
    expect(h.kind).toBe('cross-account');
    expect(h.path).toEqual(['ext', 'admin-role', 'acct-admin']);
    expect(h.hops).toBe(2);
    expect(h.pivot).toBe('admin-role');
    expect(h.reachesAdmin).toBe(true);
    expect(h.title).toBe('External account 999 → admin-role → admin');
    expect(h.statement).toBe('External account 999 can assume admin-role, which is admin-equivalent.');
  });

  it('cuts paths at the first admin-equivalent node', () => {
    const index = fanOut();
    const s = simplify(index);
    const p = normalisePath(index, s, { source: 'ext', target: 'admin-role', cost: 1, hops: 1, path: ['ext', 'admin-role'], edges: ['e0'] });
    expect(p.path).toEqual(['ext', 'admin-role', 'acct-admin']);
  });

  it('never passes through one admin to reach another, and ranks definite and short paths first (example fixture)', () => {
    const index = fixture('graph/example.json');
    const s = simplify(index);
    const hyps = findBreaches(index, s, { owned: [], operator: null });
    expect(hyps.length).toBeGreaterThan(0);
    for (const h of hyps) {
      const inner = h.path.slice(1, -1).filter((id) => s.admins.has(id));
      expect(inner.length).toBeLessThanOrEqual(1);
      if (h.reachesAdmin) expect(index.nodesById.get(h.target)!.type).toBe('account_admin');
    }
    expect(new Set(hyps.map((h) => h.id)).size).toBe(hyps.length);
  });

  it('finds the administrator of each account of a merged graph', () => {
    const index = fixture('dashboard-merge/merged/20260101T000000Z-0e0e0e/analysis/graph.json');
    const s = simplify(index);
    const owned = index.graph.nodes.filter((n) => n.type === 'user' && !s.admins.has(n.id)).map((n) => n.id);
    const hyps = findBreaches(index, s, { owned, operator: null });
    for (const h of hyps) expect(h.kind).toBe('foothold');
  });

  it('keeps hostile labels as plain strings in titles (rendered as text)', () => {
    const index = fixture('graph/hostile.json');
    const hyps = findBreaches(index, simplify(index), { owned: [], operator: null });
    expect(hyps.some((h) => h.title.includes('<img src=x onerror=window.__aeXssCanary=1>'))).toBe(true);
  });
});

describe('brief', () => {
  it('states the verdict, the shortest breach and the entry points that reach admin', () => {
    const index = fanOut();
    const s = simplify(index);
    const brief = buildBrief(index, s, findBreaches(index, s, { owned: [], operator: null }), null);
    expect(brief.verdict).toBe('Account administrator is reachable from 1 of 1 entry point, the shortest in 2 steps.');
    expect(brief.tiles.find((t) => t.key === 'entries')!.value).toBe('1 of 1');
    expect(brief.tone).toBe('bad');
    expect(brief.coverage.tone).toBe('ok');
  });
});

describe('grid layout', () => {
  it('puts every card on the 20px grid without overlaps', () => {
    const nodes = Array.from({ length: 30 }, (_, i) => ({ id: `n${i}`, column: i % 4 }));
    const edges = nodes.slice(1).map((n, i) => ({ source: nodes[i].id, target: n.id }));
    const pos = layeredLayout(nodes, edges);
    expect(pos.size).toBe(30);
    for (const p of pos.values()) {
      expect(p.x % DEFAULT_GRID.grid).toBe(0);
      expect(p.y % DEFAULT_GRID.grid).toBe(0);
    }
    expect(noOverlap(pos)).toBe(true);
    expect(layeredLayout(nodes, edges)).toEqual(pos);
  });

  it('moves a card dropped on another one to the nearest free cell', () => {
    const pos = new Map([['a', { x: 0, y: 40 }], ['b', { x: 0, y: 120 }]]);
    const landed = snapAndResolve('b', { x: 7, y: 43 }, pos);
    pos.set('b', landed);
    expect(noOverlap(pos)).toBe(true);
    expect(Math.abs(landed.x % 20)).toBe(0);
    expect(Math.abs(landed.y % 20)).toBe(0);
    expect(landed.y).toBeGreaterThan(40);
  });
});

describe('canvas models', () => {
  it('groups more than GROUP_LIMIT neighbours of one type, and expands a group on request', () => {
    const index = fanOut();
    const s = simplify(index);
    const lens = { ...OPERATOR_LENS, collapseAdmin: false };
    const ctx = { owned: new Set<string>(), operator: null };
    const grouped = neighbourhood(index, s, lens, 'admin-role', new Set(), ctx);
    const group = grouped.cards.find((c) => c.kind === 'group');
    expect(group!.count).toBe(40);
    expect(grouped.cards.length).toBeLessThan(GROUP_LIMIT);
    expect(grouped.links.find((l) => l.target === group!.id)!.types).toEqual(['CAN_MODIFY_PERMISSIONS_OF', 'CAN_TAKEOVER']);
    const open = neighbourhood(index, s, lens, 'admin-role', new Set(['out:role']), ctx);
    expect(open.cards.filter((c) => c.type === 'role' && c.id !== 'admin-role')).toHaveLength(40);
    expect(open.cards.length).toBeLessThanOrEqual(MAX_CARDS);
  });

  it('draws a path as one column per step with stage labels', () => {
    const index = fanOut();
    const s = simplify(index);
    const m = pathCanvas(index, s, ['ext', 'admin-role', 'acct-admin'], ['e0', 'e1'], { owned: new Set(), operator: null }, 'Cross-account');
    expect(m.columns.map((c) => c.label)).toEqual(['1. Cross-account', '2. Admin-equivalent', '3. Impact']);
    expect(m.links.map((l) => l.style)).toEqual(['control', 'admin']);
  });
});
