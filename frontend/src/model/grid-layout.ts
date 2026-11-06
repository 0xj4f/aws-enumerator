/*
 * Layered grid layout, the canvas's "Obsidian" feel: nodes sit in columns (kill-chain steps, or
 * in-neighbours | focus | out-neighbours), every position is on a 20px grid, and cards never overlap.
 * Row order inside a column comes from barycenter sweeps (fewer edge crossings). Deterministic: the same
 * input always gives the same positions.
 */
export interface LayoutNode {
  id: string;
  column: number;
}

export interface LayoutEdge {
  source: string;
  target: string;
}

export interface GridOptions {
  cellW: number;
  cellH: number;
  gapX: number;
  gapY: number;
  grid: number;
  top: number;
}

export interface Point {
  x: number;
  y: number;
}

export const DEFAULT_GRID: Readonly<GridOptions> = Object.freeze({ cellW: 220, cellH: 60, gapX: 100, gapY: 20, grid: 20, top: 40 });

export function snap(v: number, grid: number): number {
  return Math.round(v / grid) * grid;
}

export function layeredLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], opts: GridOptions = DEFAULT_GRID): Map<string, Point> {
  const columns = new Map<number, string[]>();
  for (const n of nodes) {
    if (!columns.has(n.column)) columns.set(n.column, []);
    columns.get(n.column)!.push(n.id);
  }
  const keys = [...columns.keys()].sort((a, b) => a - b);
  const colOf = new Map<string, number>();
  nodes.forEach((n) => colOf.set(n.id, n.column));
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    if (!colOf.has(e.source) || !colOf.has(e.target)) continue;
    (neighbours.get(e.source) || neighbours.set(e.source, []).get(e.source)!).push(e.target);
    (neighbours.get(e.target) || neighbours.set(e.target, []).get(e.target)!).push(e.source);
  }
  const rank = new Map<string, number>();
  for (const k of keys) columns.get(k)!.forEach((id, i) => rank.set(id, i));

  const sweep = (from: number[], adjacentOffset: number) => {
    for (const k of from) {
      const adj = keys[keys.indexOf(k) + adjacentOffset];
      if (adj === undefined) continue;
      const list = columns.get(k)!;
      const bary = new Map<string, number>();
      for (const id of list) {
        const ns = (neighbours.get(id) || []).filter((o) => colOf.get(o) === adj);
        bary.set(id, ns.length ? ns.reduce((sum, o) => sum + (rank.get(o) as number), 0) / ns.length : (rank.get(id) as number));
      }
      list.sort((a, b) => (bary.get(a) as number) - (bary.get(b) as number) || (rank.get(a) as number) - (rank.get(b) as number));
      list.forEach((id, i) => rank.set(id, i));
    }
  };
  for (let i = 0; i < 2; i++) {
    sweep(keys.slice(1), -1);
    sweep(keys.slice(0, -1).reverse(), 1);
  }

  const stepX = snap(opts.cellW + opts.gapX, opts.grid);
  const stepY = snap(opts.cellH + opts.gapY, opts.grid);
  const tallest = Math.max(0, ...keys.map((k) => columns.get(k)!.length));
  const out = new Map<string, Point>();
  keys.forEach((k, ci) => {
    const list = columns.get(k)!;
    const offset = snap(((tallest - list.length) * stepY) / 2, opts.grid);
    list.forEach((id, ri) => out.set(id, { x: ci * stepX, y: opts.top + offset + ri * stepY }));
  });
  return out;
}

function overlaps(a: Point, b: Point, opts: GridOptions): boolean {
  return Math.abs(a.x - b.x) < opts.cellW + opts.grid && Math.abs(a.y - b.y) < opts.cellH + opts.grid / 2;
}

/**
 * Where a dragged card lands: its position snapped to the grid, or the nearest grid cell where it does not
 * overlap another card (searched in growing rings, nearest first).
 */
export function snapAndResolve(id: string, pos: Point, positions: ReadonlyMap<string, Point>, opts: GridOptions = DEFAULT_GRID): Point {
  const start = { x: snap(pos.x, opts.grid), y: snap(pos.y, opts.grid) };
  const others = [...positions.entries()].filter(([k]) => k !== id).map(([, p]) => p);
  const free = (p: Point) => others.every((o) => !overlaps(p, o, opts));
  if (free(start)) return start;
  for (let r = 1; r <= 60; r++) {
    const ring: Point[] = [];
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
export function noOverlap(positions: ReadonlyMap<string, Point>, opts: GridOptions = DEFAULT_GRID): boolean {
  const list = [...positions.values()];
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      if (Math.abs(list[i].x - list[j].x) < opts.cellW && Math.abs(list[i].y - list[j].y) < opts.cellH) return false;
    }
  }
  return true;
}
