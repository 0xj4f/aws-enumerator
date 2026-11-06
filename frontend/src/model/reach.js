/*
 * Who reaches what: from every entry point and foothold, the nodes reachable over the operator lens's attack
 * steps (traversable edges, admin fan-out collapsed). One breadth-first search per source.
 */
import { operatorActive } from './simplify';

/** node id -> the sources (entry points and footholds) that reach it, in source order. */
export function reachFrom(index, s, sources, includeConditional) {
  const active = operatorActive(index, s, { includeConditional });
  const out = new Map();
  for (const src of sources) {
    if (!index.nodesById.has(src)) continue;
    const seen = new Set([src]);
    const queue = [src];
    while (queue.length) {
      const id = queue.shift();
      for (const e of index.out.get(id) || []) {
        if (seen.has(e.target) || !active.edgeAllowed(e)) continue;
        seen.add(e.target);
        queue.push(e.target);
        (out.get(e.target) || out.set(e.target, []).get(e.target)).push(src);
      }
    }
  }
  return out;
}
