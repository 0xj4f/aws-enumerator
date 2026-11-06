/*
 * Optional check against a real report (never committed): AE_REAL_GRAPH=/path/to/analysis/graph.json.
 * Prints the brief and the hypotheses; asserts only the invariants every report must satisfy.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { C } from '../core';
import { findBreaches } from './breaches';
import { buildBrief } from './brief';
import { OPERATOR_LENS, edgeVisible, simplify } from './simplify';

const file = process.env.AE_REAL_GRAPH;

describe.skipIf(!file)('real report', () => {
  it('builds the brief and the breach hypotheses', () => {
    const { graph } = C.validateGraph(JSON.parse(readFileSync(file as string, 'utf8')));
    const index = C.buildIndex(graph!);
    const s = simplify(index);
    const op = C.operatorNode(graph!).id;
    const t0 = Date.now();
    const hyps = findBreaches(index, s, { owned: op ? [op] : [], operator: op });
    const ms = Date.now() - t0;
    const brief = buildBrief(index, s, hyps, op);
    const visible = graph!.edges.filter((e) => edgeVisible(e, index, s, OPERATOR_LENS)).length;
    console.log(JSON.stringify({ ms, edges: graph!.edges.length, visible, collapsed: s.collapsed.size, verdict: brief.verdict,
      tiles: brief.tiles.map((t) => `${t.label}: ${t.value}`), operatorIsAdmin: brief.operatorIsAdmin,
      exposure: brief.exposure.map((x) => `${x.type} ${x.label}`), posture: brief.posture.map((f) => f.id),
      hyps: hyps.map((h) => `[${h.kind}] ${h.title} (${h.hops}, ${h.confidence})`) }, null, 1));
    for (const h of hyps) expect(h.edges.length).toBe(h.path.length - 1);
  });
});
