/*
 * Layered grid layout, the canvas's "Obsidian" feel: nodes sit in columns (kill-chain steps, or
 * in-neighbours | focus | out-neighbours), every position is on a 20px grid, and cards never overlap.
 * Row order inside a column comes from barycenter sweeps (fewer edge crossings). Deterministic: the same
 * input always gives the same positions.
 */

export const DEFAULT_GRID = Object.freeze({ cellW: 220, cellH: 60, gapX: 100, gapY: 20, grid: 20, top: 40 });

export function snap(v, grid) {
  return Math.round(v / grid) * grid;
}

export function layeredLayout(nodes, edges, opts = DEFAULT_GRID) {
  const columns = new Map();
  for (const n of nodes) {
    if (!columns.has(n.column)) columns.set(n.column, []);
    columns.get(n.column).push(n.id);
  }
  const keys = [...columns.keys()].sort((a, b) => a - b);
  const colOf = new Map();
  nodes.forEach((n) => colOf.set(n.id, n.column));
  const neighbours = new Map();
  for (const e of edges) {
    if (!colOf.has(e.source) || !colOf.has(e.target)) continue;
    (neighbours.get(e.source) || neighbours.set(e.source, []).get(e.source)).push(e.target);
    (neighbours.get(e.target) || neighbours.set(e.target, []).get(e.target)).push(e.source);
  }
  const rank = new Map();
  for (const k of keys) columns.get(k).forEach((id, i) => rank.set(id, i));

  const sweep = (from, adjacentOffset) => {
    for (const k of from) {
      const adj = keys[keys.indexOf(k) + adjacentOffset];
      if (adj === undefined) continue;
      const list = columns.get(k);
      const bary = new Map();
      for (const id of list) {
        const ns = (neighbours.get(id) || []).filter((o) => colOf.get(o) === adj);
        bary.set(id, ns.length ? ns.reduce((sum, o) => sum + (rank.get(o)), 0) / ns.length : (rank.get(id)));
      }
      list.sort((a, b) => (bary.get(a)) - (bary.get(b)) || (rank.get(a)) - (rank.get(b)));
      list.forEach((id, i) => rank.set(id, i));
    }
  };
  for (let i = 0; i < 2; i++) {
    sweep(keys.slice(1), -1);
    sweep(keys.slice(0, -1).reverse(), 1);
  }

  const stepX = snap(opts.cellW + opts.gapX, opts.grid);
  const stepY = snap(opts.cellH + opts.gapY, opts.grid);
  const tallest = Math.max(0, ...keys.map((k) => columns.get(k).length));
  const out = new Map();
  keys.forEach((k, ci) => {
    const list = columns.get(k);
    const offset = snap(((tallest - list.length) * stepY) / 2, opts.grid);
    list.forEach((id, ri) => out.set(id, { x: ci * stepX, y: opts.top + offset + ri * stepY }));
  });
  return out;
}

function overlaps(a, b, opts) {
  return Math.abs(a.x - b.x) < opts.cellW + opts.grid && Math.abs(a.y - b.y) < opts.cellH + opts.grid / 2;
}

/**
 * Where a dragged card lands: its position snapped to the grid, or the nearest grid cell where it does not
 * overlap another card (searched in growing rings, nearest first).
 */
export function snapAndResolve(id, pos, positions, opts = DEFAULT_GRID) {
  const start = { x: snap(pos.x, opts.grid), y: snap(pos.y, opts.grid) };
  const others = [...positions.entries()].filter(([k]) => k !== id).map(([, p]) => p);
  const free = (p) => others.every((o) => !overlaps(p, o, opts));
  if (free(start)) return start;
  for (let r = 1; r <= 60; r++) {
    const ring = [];
    for (let dx = -r; dx <= r; dx++) {
      for (let dy = -r; dy <= r; dy++) {
        if (Math.max(Math.abs(dx), Math.abs(dy)) !== r) continue;
        ring.push({ x: start.x + dx * opts.grid, y: start.y + dy * opts.grid });
      }
    }
    // nearest first; ties go down, then right (where a dropped card is expected to settle)
    ring.sort((a, b) => Math.hypot(a.x - start.x, a.y - start.y) - Math.hypot(b.x - start.x, b.y - start.y) || b.y - a.y || b.x - a.x);
    const hit = ring.find(free);
    if (hit) return hit;
  }
  return start;
}

/** True when no two cards overlap (used by tests and the e2e check). */
export function noOverlap(positions, opts = DEFAULT_GRID) {
  const list = [...positions.values()];
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      if (Math.abs(list[i].x - list[j].x) < opts.cellW && Math.abs(list[i].y - list[j].y) < opts.cellH) return false;
    }
  }
  return true;
}
