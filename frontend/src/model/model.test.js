import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { C } from '../core';
import { findBreaches, normalisePath } from './breaches';
import { buildBrief } from './brief';
import { GROUP_LIMIT, MAX_CARDS, neighbourhood, pathCanvas } from './canvas-model';
import { DEFAULT_GRID, layeredLayout, noOverlap, snapAndResolve } from './grid-layout';
import { OPERATOR_LENS, drawerContext, edgeVisible, simplify } from './simplify';

const FIXTURES = join(__dirname, '..', '..', '..', 'tests', 'fixtures');

function indexOf(raw) {
  const { graph, problems } = C.validateGraph(raw);
  if (!graph) throw new Error('invalid graph: ' + JSON.stringify(problems.slice(0, 3)));
  return C.buildIndex(graph);
}

function fixture(rel) {
  return indexOf(JSON.parse(readFileSync(join(FIXTURES, rel), 'utf8')));
}

/** A small valid graph.json: nodes and [source, type, target, traversal] edges. */
function synthetic(nodes, edges, extra = {}) {
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
function fanOut() {
  const roles = Array.from({ length: 40 }, (_, i) => ({ id: `role-${String(i).padStart(2, '0')}`, type: 'role' }));
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
      ...roles.map((r) => ['admin-role', 'CAN_TAKEOVER', r.id]),
      ...roles.map((r) => ['admin-role', 'CAN_MODIFY_PERMISSIONS_OF', r.id]),
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
      if (h.reachesAdmin) expect(index.nodesById.get(h.target).type).toBe('account_admin');
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
    expect(brief.tiles.find((t) => t.key === 'entries').value).toBe('1 of 1');
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
    const ctx = { owned: new Set(), operator: null };
    const grouped = neighbourhood(index, s, lens, 'admin-role', new Set(), ctx);
    const group = grouped.cards.find((c) => c.kind === 'group');
    expect(group.count).toBe(40);
    expect(grouped.cards.length).toBeLessThan(GROUP_LIMIT);
    expect(grouped.links.find((l) => l.target === group.id).types).toEqual(['CAN_MODIFY_PERMISSIONS_OF', 'CAN_TAKEOVER']);
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

describe('ATT&CK on routes (D-58)', () => {
  it('tags the entry step with how the attacker gets in and each step with its edge technique', async () => {
    const { columnTactics } = await import('./tactics');
    const index = fanOut();
    const s = simplify(index);
    const [h] = findBreaches(index, s, { owned: [], operator: null });
    expect(h.steps[0].techniques).toEqual(['T1199', 'T1548.005']);
    expect(h.steps[1].techniques).toEqual([]);
    expect(h.tactics.map((t) => t.name)).toEqual(['Initial Access', 'Privilege Escalation']);
    const edges = h.edges.map((id) => index.edgesById.get(id));
    expect(columnTactics(h.kind, edges)).toEqual(['Initial Access', 'Privilege Escalation', null]);
  });
});

describe('plumbing hints', () => {
  it('recognises AWS-managed roles by their whole ARN, never by a bare name', async () => {
    const { plumbingHint, plumbingOf } = await import('./plumbing');
    expect(plumbingOf('arn:aws:iam::111122223333:role/AWSControlTowerExecution')).toBe('AWS Control Tower');
    expect(plumbingOf('arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_x_1')).toBe('IAM Identity Center permission set');
    expect(plumbingOf('arn:aws:iam::999999999999:role/AWSAFTAdmin')).toBe('Account Factory for Terraform');
    expect(plumbingOf('arn:aws:iam::111122223333:role/my-AWSControlTowerExecution-copy')).toBeNull();
    expect(plumbingOf('AWSControlTowerExecution')).toBeNull();
    expect(plumbingHint(['arn:aws:iam::1:role/AWSAFTAdmin', 'arn:aws:iam::2:role/AWSAFTExecution'])).toEqual(['Account Factory for Terraform']);
  });
});

describe('reach, principals, data, finding groups', () => {
  it('reaches over attack steps only, with the admin fan-out collapsed', async () => {
    const { reachFrom } = await import('./reach');
    const index = fanOut();
    const reach = reachFrom(index, simplify(index), ['ext'], true);
    expect(reach.get('admin-role')).toEqual(['ext']);
    expect(reach.get('acct-admin')).toEqual(['ext']);
    expect(reach.has('role-00')).toBe(false);
  });

  it('ranks admin-equivalent principals first and counts who can become them', async () => {
    const { reachFrom } = await import('./reach');
    const { principalRows } = await import('./inventory');
    const index = fanOut();
    const s = simplify(index);
    const rows = principalRows(index, s, reachFrom(index, s, ['ext'], true));
    expect(rows[0].id).toBe('admin-role');
    expect(rows[0].admin).toBe(true);
    expect(rows[0].becomeBy).toEqual(['ext']);
    expect(rows[0].canBecome).toEqual([]);
    expect(rows.find((r) => r.id === 'role-00').becomeBy).toEqual([]);
  });

  it('lists data assets with their exposure, readers and keys (example fixture)', async () => {
    const { dataRows } = await import('./inventory');
    const index = fixture('graph/example.json');
    const rows = dataRows(index, simplify(index), new Map());
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.type === 'kms' || index.nodeTypes.get(r.type)?.data_asset === true)).toBe(true);
    const pub = rows.filter((r) => r.public);
    expect(pub.length).toBeGreaterThan(0);
    expect(rows.indexOf(pub[0])).toBe(0);
  });

  it('groups findings by rule, worst severity first', async () => {
    const { groupFindings } = await import('./findings');
    const index = fixture('graph/example.json');
    const all = index.graph.findings;
    const groups = groupFindings(all);
    expect(groups.length).toBe(new Set(all.map((f) => f.id)).size);
    expect(groups.reduce((n, g) => n + g.findings.length, 0)).toBe(all.length);
    const ranks = groups.map((g) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(g.severity));
    expect([...ranks].sort((a, b) => a - b)).toEqual(ranks);
  });
});

/**
 * Two ways in to one foothold: an external account and your own user both assume role-a, which escalates to
 * role-b, which assumes the admin role. role-a reads three secrets.
 */
function chain() {
  return synthetic(
    [
      { id: 'ext', type: 'external_account', label: 'External account 999', props: { external: true } },
      { id: 'me', type: 'user', label: 'operator' },
      { id: 'role-a', type: 'role' },
      { id: 'role-b', type: 'role' },
      { id: 'admin-role', type: 'role', props: { high_value: true, high_value_reason: 'admin-equivalent' } },
      { id: 'acct-admin', type: 'account_admin', label: 'Administrator', props: { high_value: true, high_value_reason: 'account-admin' } },
      ...[1, 2, 3].map((i) => ({ id: `secret-${i}`, type: 'secret', props: { data_asset: true } })),
    ],
    [
      ['ext', 'CAN_ASSUME', 'role-a'],
      ['me', 'CAN_ASSUME', 'role-a'],
      ['role-a', 'CAN_PASS_ROLE_TO', 'role-b'],
      ['role-b', 'CAN_ASSUME', 'admin-role'],
      ['admin-role', 'IS_ADMIN_EQUIVALENT', 'acct-admin'],
      ...[1, 2, 3].map((i) => ['role-a', 'CAN_READ', `secret-${i}`, 'access']),
    ],
  );
}

describe('kill-chain map (D-59)', () => {
  const ctxOf = (operator, owned = []) => ({ operator, owned: new Set(owned) });

  it('puts the way in, the admin-equivalent and the account administrator in columns 0, 3 and 4', async () => {
    const { killChainMap, mapRoutes } = await import('./overview');
    const index = fanOut();
    const s = simplify(index);
    const ctx = ctxOf(null);
    const paths = mapRoutes(findBreaches(index, s, { owned: [], operator: null }), { ctx });
    const map = killChainMap(index, s, paths, [], { ctx });
    const col = (id) => map.cards.find((c) => c.nodeId === id)?.column;
    expect([col('ext'), col('admin-role'), col('acct-admin')]).toEqual([0, 3, 4]);
    expect(map.cards.some((c) => c.nodeId === 'role-00')).toBe(false);
    expect(map.columns[0].label).toBe('1. Ways in · Initial Access');
    expect(map.links.map((l) => l.types.join('+'))).toEqual(['CAN_ASSUME', 'IS_ADMIN_EQUIVALENT']);
  });

  it('places footholds, escalation and grouped data, and keeps only your routes in the foothold scope', async () => {
    const { reachFrom } = await import('./reach');
    const { dataRows } = await import('./inventory');
    const { killChainMap, mapRoutes } = await import('./overview');
    const index = chain();
    const s = simplify(index);
    const ctx = ctxOf('me', ['me']);
    const hyps = findBreaches(index, s, { owned: ['me'], operator: 'me' });
    const data = dataRows(index, s, reachFrom(index, s, ['ext', 'me'], true));
    const map = killChainMap(index, s, mapRoutes(hyps, { ctx }), data, { ctx });
    const col = (id) => map.cards.find((c) => c.nodeId === id)?.column;
    expect([col('ext'), col('me'), col('role-a'), col('role-b'), col('admin-role'), col('acct-admin')]).toEqual([0, 0, 1, 2, 3, 4]);
    const secrets = map.cards.find((c) => c.column === 5);
    expect(secrets).toMatchObject({ kind: 'group', count: 3, groupKey: 'data:secret' });
    expect(map.links.filter((l) => l.target === secrets.id).map((l) => l.source).sort()).toEqual(['ext', 'me']);
    const open = killChainMap(index, s, mapRoutes(hyps, { ctx }), data, { ctx, expanded: new Set(['data:secret']) });
    expect(open.cards.filter((c) => c.column === 5).map((c) => c.nodeId)).toEqual(['secret-1', 'secret-2', 'secret-3']);

    const mine = mapRoutes(hyps, { ctx, scope: 'foothold' });
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((h) => h.source === 'me')).toBe(true);
    const footMap = killChainMap(index, s, mine, data, { ctx, scope: 'foothold' });
    expect(footMap.cards.some((c) => c.nodeId === 'ext')).toBe(false);
  });

  it('leaves expected routes out unless asked', async () => {
    const { mapRoutes } = await import('./overview');
    const index = chain();
    const s = simplify(index);
    const ctx = ctxOf('me', ['me']);
    const hyps = findBreaches(index, s, { owned: ['me'], operator: 'me' });
    const expected = new Set(['entry:ext']);
    expect(mapRoutes(hyps, { ctx, expected }).some((h) => h.source === 'ext')).toBe(false);
    expect(mapRoutes(hyps, { ctx, expected, includeExpected: true }).some((h) => h.source === 'ext')).toBe(true);
  });

  it('ranks pivots by the routes and ways in through them, admin-equivalents last, and highlights their routes', async () => {
    const { killChainMap, mapRoutes, pivots, routeHighlight, routesThrough } = await import('./overview');
    const index = chain();
    const s = simplify(index);
    const ctx = ctxOf('me', ['me']);
    const hyps = findBreaches(index, s, { owned: ['me'], operator: 'me' });
    const paths = mapRoutes(hyps, { ctx });
    const list = pivots(index, s, paths);
    expect(list.map((p) => p.id)).toEqual(['role-a', 'role-b', 'admin-role']);
    expect(list[0]).toMatchObject({ routes: 2, waysIn: 2, admin: false });
    expect(list[2].admin).toBe(true);
    const map = killChainMap(index, s, paths, [], { ctx });
    const hl = routeHighlight(map, paths.filter((h) => h.source === 'ext'));
    expect([...hl.cards].sort()).toEqual(['acct-admin', 'admin-role', 'ext', 'role-a', 'role-b']);
    expect(hl.links.has('l:ext\u0000role-a')).toBe(true);
    expect(hl.links.has('l:me\u0000role-a')).toBe(false);
    expect(routesThrough(hyps, 'role-b').map((r) => r.role)).toEqual(['step 2', 'step 2']);
  });

  it('stays within MAX_CARDS and lays out without overlap on the example fixture', async () => {
    const { dataRows } = await import('./inventory');
    const { reachFrom } = await import('./reach');
    const { entryPoints } = await import('./breaches');
    const { killChainMap, mapRoutes } = await import('./overview');
    const index = fixture('graph/example.json');
    const s = simplify(index);
    const ctx = ctxOf(null);
    const paths = mapRoutes(findBreaches(index, s, { owned: [], operator: null }), { ctx });
    const map = killChainMap(index, s, paths, dataRows(index, s, reachFrom(index, s, entryPoints(index), true)), { ctx });
    expect(map.cards.length).toBeGreaterThan(0);
    expect(map.cards.length).toBeLessThanOrEqual(MAX_CARDS);
    expect(new Set(map.cards.map((c) => c.id)).size).toBe(map.cards.length);
    for (const l of map.links) expect(map.cards.some((c) => c.id === l.source) && map.cards.some((c) => c.id === l.target)).toBe(true);
    const pos = layeredLayout(map.cards.map((c) => ({ id: c.id, column: c.column })), map.links, { ...DEFAULT_GRID, gapX: 160 });
    expect(noOverlap(pos, { ...DEFAULT_GRID, gapX: 160 })).toBe(true);
  });
});

describe("the operator's audit (D-59)", () => {
  const REGION = 'aws-enumerator:region/111122223333/eu-west-2';
  const finding = (id, severity, category, node) => ({
    id, severity, category, title: id + ' title', node_id: node, fingerprint: id + '@' + node, confidence: 'definite', status: 'open',
  });
  function posture(findings, modules) {
    return synthetic(
      [{ id: REGION, type: 'region', label: 'eu-west-2', region: 'eu-west-2' }, { id: 'dist', type: 'role', region: null }],
      [],
      { findings, coverage: { status: 'partial', modules: modules.map(([module, region, status]) => ({ module, region, status })) } },
    );
  }

  it('reads each detection control as watching, blind or unknown, per region', async () => {
    const { detectionMap } = await import('./audit');
    const index = posture(
      [finding('CLOUDTRAIL-001', 'HIGH', 'posture_logging', REGION), finding('WAF-001', 'MEDIUM', 'posture_waf', 'dist'), finding('WAF-001', 'MEDIUM', 'posture_waf', 'dist')],
      [['cloudtrail', 'eu-west-2', 'ok'], ['guardduty', 'eu-west-2', 'ok'], ['securityhub', 'eu-west-2', 'failed'], ['waf_cloudfront', 'global', 'failed']],
    );
    const m = detectionMap(index);
    const cell = (region, control) => m.rows.find((r) => r.region === region).cells.find((c) => c.control === control);
    expect(cell('eu-west-2', 'cloudtrail')).toMatchObject({ state: 'blind', worst: 'high' });
    expect(cell('eu-west-2', 'guardduty').state).toBe('watching');
    expect(cell('eu-west-2', 'securityhub')).toMatchObject({ state: 'unknown', note: 'collection failed' });
    expect(cell('eu-west-2', 'config')).toMatchObject({ state: 'unknown', note: 'not collected' });
    expect(cell('global', 'waf')).toMatchObject({ state: 'blind', note: '2 findings: unfiltered internet endpoints' });
    expect(cell('global', 'cloudtrail').state).toBe('n/a');
    expect(m.quietest.region).toBe('eu-west-2');
  });

  it('counts findings per category and severity, worst categories first, in the operator\'s words', async () => {
    const { surfaceByCategory } = await import('./audit');
    const rows = surfaceByCategory([
      finding('TRUST-001', 'MEDIUM', 'trust_policy', 'x'), finding('PRIVESC-001', 'CRITICAL', 'privilege_escalation', 'x'),
      finding('PRIVESC-002', 'INFO', 'privilege_escalation', 'y'), finding('ROUTE53-001', 'INFO', 'route53_dangling', 'z'),
    ]);
    expect(rows.map((r) => r.label)).toEqual(['Escalation', 'Trust policies', 'Dangling DNS (takeover candidates)']);
    expect(rows[0].counts).toMatchObject({ critical: 1, info: 1 });
    expect(rows[0].total).toBe(2);
  });
});
