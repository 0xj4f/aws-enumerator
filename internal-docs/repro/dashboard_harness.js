// dashboard-a-2 verification harness. Synthetic data only; no network, no browser.
// Runs the dashboard's real inline <script> in a Node vm with a DOM stub and a
// Cytoscape stub whose dijkstra() mirrors cytoscape 3.x semantics
// (neighborhood() + edgesTo/edgesWith, min-weight parallel edge, duplicate ids skipped).
'use strict';
const fs = require('fs');
const vm = require('vm');
const INDEX = require('path').resolve(process.cwd(), 'app/dashboard/index.html'); // run from the repository root

function load() {
  const html = fs.readFileSync(INDEX, 'utf8');
  const m = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  const src = m[m.length - 1][1];
  const els = {};
  const mk = id => ({ id, textContent: '', innerHTML: '', value: '', style: {}, dataset: {}, options: [],
    classList: (() => { const s = new Set(); return { add: (...c) => c.forEach(x => s.add(x)), remove: (...c) => c.forEach(x => s.delete(x)), contains: c => s.has(c), toggle() {}, _s: s }; })(),
    addEventListener() {}, querySelector() { return dropText; }, querySelectorAll() { return []; }, add(o) { this.options.push(o); }, click() {}, scrollIntoView() {} });
  const dropText = mk('drop-text');
  const document = { getElementById: id => (els[id] = els[id] || mk(id)), body: mk('body'),
    querySelectorAll: () => [], querySelector: () => null, addEventListener() {} };

  class C extends Array {
    static from2(a) { const c = new C(); a.forEach(x => c.push(x)); return c; }
    nodes() { return C.from2([...this].filter(e => e.group === 'nodes')); }
    edges() { return C.from2([...this].filter(e => e.group === 'edges')); }
    filter(f) { return C.from2([...this].filter(f)); }
    sort(f) { return C.from2([...this].sort(f)); }
    addClass(c) { c.split(' ').forEach(x => this.forEach(e => e.cls.add(x))); return this; }
    removeClass(c) { c.split(' ').forEach(x => this.forEach(e => e.cls.delete(x))); return this; }
    data(k) { return this[0] && this[0].data(k); }
    id() { return this[0] && this[0].id(); }
    hasClass(c) { return !!this[0] && this[0].cls.has(c); }
    closedNeighborhood() { const s = new Set(this); this.forEach(n => n.adj && n.adj().forEach(e => { s.add(e); s.add(e.src()); s.add(e.tgt()); })); return C.from2([...s]); }
    dijkstra({ root, weight, directed }) {
      const src = root[0] || root;
      const nodes = [...this].filter(e => e.group === 'nodes');
      const edges = new Set([...this].filter(e => e.group === 'edges' && e.data('source') !== e.data('target')));
      const dist = new Map(), prev = new Map(), known = new Map();
      nodes.forEach(n => dist.set(n, n === src ? 0 : Infinity));
      const Q = new Set(nodes);
      while (Q.size) {
        let u = null; for (const n of Q) if (u === null || dist.get(n) < dist.get(u)) u = n;
        Q.delete(u); const du = dist.get(u); known.set(u, du);
        if (du === Infinity) continue;
        const nbrs = new Set(); for (const e of u.adj()) if (edges.has(e)) nbrs.add(e.src() === u ? e.tgt() : e.src());
        for (const v of nbrs) {
          const uvs = u.adj().filter(e => edges.has(e) && (directed ? (e.src() === u && e.tgt() === v) : ((e.src() === u && e.tgt() === v) || (e.src() === v && e.tgt() === u))));
          let best = Infinity, be = null; for (const e of uvs) { const w = weight(e); if (w < best || !be) { best = w; be = e; } }
          const alt = du + best;
          if (alt < dist.get(v)) { dist.set(v, alt); prev.set(v, [u, be]); }
        }
      }
      return {
        distanceTo: n => known.get(n[0] || n),
        pathTo: n => { n = n[0] || n; const S = [n]; let u = n; while (prev.has(u)) { const [p, e] = prev.get(u); S.unshift(e); S.unshift(p); u = p; } return C.from2(S); },
      };
    }
  }
  class E {
    constructor(cy, j) { this.cy = cy; this.group = j.group; this._d = j.data; this.cls = new Set(); }
    data(k) { return k === undefined ? this._d : this._d[k]; }
    id() { return this._d.id; }
    src() { return this.cy._n.get(this._d.source); }
    tgt() { return this.cy._n.get(this._d.target); }
    adj() { return this.cy._adj.get(this.id()) || []; }
    hasClass(c) { return this.cls.has(c); }
  }
  let lastCore = null;
  const cytoscape = o => {
    const core = { _n: new Map(), _e: new Map(), _adj: new Map(), dupIds: [], destroyed: false };
    for (const j of o.elements) if (j.group === 'nodes') { if (core._n.has(j.data.id)) { core.dupIds.push(j.data.id); continue; } core._n.set(j.data.id, new E(core, j)); }
    for (const j of o.elements) if (j.group === 'edges') {
      if (core._e.has(j.data.id)) { core.dupIds.push(j.data.id); continue; }
      if (!core._n.has(j.data.source) || !core._n.has(j.data.target)) throw new Error('missing endpoint ' + j.data.id);
      const e = new E(core, j); core._e.set(j.data.id, e);
      for (const end of [j.data.source, j.data.target]) { if (!core._adj.has(end)) core._adj.set(end, []); core._adj.get(end).push(e); }
    }
    Object.assign(core, { on() {}, destroy() { core.destroyed = true; }, fit() {}, resize() {}, layout: () => ({ run() {} }),
      nodes: () => C.from2([...core._n.values()]), edges: () => C.from2([...core._e.values()]),
      elements: () => C.from2([...core._n.values(), ...core._e.values()]),
      getElementById: id => C.from2([core._n.get(id) || core._e.get(id)].filter(Boolean)) });
    lastCore = core; return core;
  };
  const JSZip = { loadAsync: async f => ({ forEach(cb) { for (const [p, c] of Object.entries(f)) cb(p, { dir: false, async: async () => c }); } }) };
  class Option { constructor(t, v) { this.textContent = t; this.value = v; this.style = {}; } }
  const ctx = { document, Option, cytoscape, JSZip, console, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1 };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  return { ctx, els, get: n => vm.runInContext(n, ctx), core: () => lastCore };
}

// Build a report "zip" (map path->string) from a partial spec, single-region layout with manifest.
function report(spec) {
  const f = { 'r/manifest.json': '{}' };
  const put = (p, v) => { f['r/' + p] = JSON.stringify(v); };
  put('iam/users.json', spec.users || []);
  put('iam/roles.json', spec.roles || []);
  put('iam/groups.json', spec.groups || []);
  put('iam/policies.json', spec.policies || []);
  put('iam/user_group_memberships.json', spec.ugm || {});
  put('iam/user_attached_policies.json', spec.uap || {});
  put('iam/role_attached_policies.json', spec.rap || {});
  put('iam/group_attached_policies.json', spec.gap || {});
  put('analysis/findings.json', { findings: spec.findings || [] });
  put('analysis/trust_relationships.json', spec.trust || []);
  put('s3/buckets.json', spec.buckets || []);
  for (const k of ['s3', 'ec2', 'k8s', 'secrets', 'lambda', 'kms', 'compute', 'messaging', 'newsurface', 'extra'])
    if (spec[k]) put(`analysis/${k}_relationships.json`, { edges: spec[k], findings: [] });
  return f;
}

async function run(spec) {
  const d = load();
  await d.get('processLoadedFiles')(report(spec));
  return d;
}

function fmtPath(p) {
  const out = [];
  for (const e of p) out.push(e.group === 'nodes' ? `[${e.data('type')}]${e.data('label')}` : `-${e.data('type')}(w=${e.data('weight')})-`);
  return out.join(' ');
}

module.exports = { load, report, run, fmtPath };
