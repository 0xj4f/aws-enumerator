/*
 * Optional check against a real report (never committed): AE_REAL_GRAPH=/path/to/analysis/graph.json.
 * Prints the brief and the hypotheses; asserts only the invariants every report must satisfy.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { C } from '../core';
import { detectionMap, surfaceByCategory } from './audit';
import { entryPoints, findBreaches } from './breaches';
import { buildBrief } from './brief';
import { DEFAULT_GRID, layeredLayout, noOverlap } from './grid-layout';
import { dataRows } from './inventory';
import { killChainMap, mapRoutes, pivots } from './overview';
import { reachFrom } from './reach';
import { OPERATOR_LENS, edgeVisible, simplify } from './simplify';

const file = process.env.AE_REAL_GRAPH;

describe.skipIf(!file)('real report', () => {
  it('builds the brief and the breach hypotheses', () => {
    const { graph } = C.validateGraph(JSON.parse(readFileSync(file, 'utf8')));
    const index = C.buildIndex(graph);
    const s = simplify(index);
    const op = C.operatorNode(graph).id;
    const t0 = Date.now();
    const hyps = findBreaches(index, s, { owned: op ? [op] : [], operator: op });
    const ms = Date.now() - t0;
    const brief = buildBrief(index, s, hyps, op);
    const visible = graph.edges.filter((e) => edgeVisible(e, index, s, OPERATOR_LENS)).length;
    console.log(JSON.stringify({ ms, edges: graph.edges.length, visible, collapsed: s.collapsed.size, verdict: brief.verdict,
      tiles: brief.tiles.map((t) => `${t.label}: ${t.value}`), operatorIsAdmin: brief.operatorIsAdmin,
      exposure: brief.exposure.map((x) => `${x.type} ${x.label}`), posture: brief.posture.map((f) => f.id),
      hyps: hyps.map((h) => `[${h.kind}] ${h.title} (${h.hops}, ${h.confidence})`) }, null, 1));
    for (const h of hyps) expect(h.edges.length).toBe(h.path.length - 1);

    // The kill-chain map: bounded, laid out without overlap, and its pivots.
    const ctx = { operator: op, owned: new Set(op ? [op] : []) };
    const reach = reachFrom(index, s, [...new Set([...entryPoints(index), ...(op ? [op] : [])])], true);
    const paths = mapRoutes(hyps, { ctx });
    const map = killChainMap(index, s, paths, dataRows(index, s, reach), { ctx });
    const pos = layeredLayout(map.cards.map((c) => ({ id: c.id, column: c.column })), map.links, { ...DEFAULT_GRID, gapX: 160 });
    console.log(JSON.stringify({ map: { routes: paths.length, cards: map.cards.length, links: map.links.length, truncated: map.truncated,
      waysIn: map.waysIn, data: map.data, columns: map.columns.map((c) => c.label),
      groups: map.cards.filter((c) => c.kind === 'group').map((c) => c.label) },
    pivots: pivots(index, s, paths).map((p) => `${p.label} (${p.typeLabel}): ${p.routes} routes, ${p.waysIn} ways in`) }, null, 1));
    expect(map.cards.length).toBeLessThanOrEqual(150);
    expect(noOverlap(pos, { ...DEFAULT_GRID, gapX: 160 })).toBe(true);

    // The operator's audit: every cell has a state; the quietest region (if any) has a blind control.
    const det = detectionMap(index);
    console.log(JSON.stringify({ quietest: det.quietest?.label || null,
      detection: det.rows.map((r) => r.label + ': ' + r.cells.map((c) => `${c.control}=${c.state}${c.findings.length ? '(' + c.findings.length + ')' : ''}`).join(' ')),
      surface: surfaceByCategory(graph.findings.concat(graph.unattachedFindings)).map((r) => `${r.label}: ${r.total}`) }, null, 1));
    for (const r of det.rows) for (const c of r.cells) expect(['watching', 'blind', 'unknown', 'n/a']).toContain(c.state);
    if (det.quietest) expect(det.quietest.cells.some((c) => c.state === 'blind')).toBe(true);
  });
});
