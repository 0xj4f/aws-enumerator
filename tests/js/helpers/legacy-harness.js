'use strict';
// Characterisation harness for the LEGACY dashboard (baseline d13c215).
//
// Ported from internal-docs/repro/dashboard_harness.js (untracked, so not imported).
// It runs the dashboard's real inline <script>, read from git history with
// `git show d13c215:app/dashboard/index.html` (read-only), inside a Node `vm`
// context with:
//   - a permissive DOM stub that records textContent / innerHTML / style / classList
//     (the legacy code writes markup with innerHTML, so the strict dom-stub.js used
//     for the new UI cannot host it);
//   - a Cytoscape-semantics stub whose dijkstra() mirrors cytoscape 3.x (min-weight
//     parallel edge, self-loops ignored, duplicate ids skipped first-wins, missing
//     endpoint throws, Infinity when unreachable), with a linear-scan queue, so
//     equal-cost routes may differ from the browser: assert distances, reachability
//     or edge-type sets, never one specific equal-cost route.
//   Or, with {cytoscape: 'real'}, the vendored Cytoscape 3.30.4 running headless.
//
// Nothing here touches app/ on disk: the legacy source comes from the git object
// store, so the harness keeps working after the rename/split.
// Synthetic data only; no network, no browser.

const vm = require('vm');
const { execFileSync } = require('child_process');
const targets = require('./targets');

let _legacy = null;

/**
 * {ok, src, skip, reason}: the inline <script> of the legacy dashboard.
 * Skips (never throws) when git or the baseline commit is unavailable, e.g. in an
 * sdist/tarball, a shallow clone without d13c215, or a machine without git.
 */
function legacySource() {
  if (_legacy) return _legacy;
  const { commit, dashboardIndexGitPath } = targets.legacyBaseline();
  let html;
  try {
    html = execFileSync('git', ['show', `${commit}:${dashboardIndexGitPath}`], {
      cwd: targets.REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GIT_PAGER: 'cat', GIT_TERMINAL_PROMPT: '0' },
    });
  } catch (err) {
    const why = (err.stderr && String(err.stderr).trim()) || err.message;
    _legacy = { ok: false, src: null, skip: `legacy dashboard unavailable: needs a git checkout containing ${commit} (${why.split('\n')[0]})`, reason: why };
    return _legacy;
  }
  // The LAST attribute-free <script> is the inline app; the two CDN <script src> tags are skipped.
  const m = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  if (!m.length) {
    _legacy = { ok: false, src: null, skip: `no inline <script> in ${commit}:${dashboardIndexGitPath}`, reason: 'no inline script' };
    return _legacy;
  }
  _legacy = { ok: true, src: m[m.length - 1][1], skip: false, reason: null, commit, path: dashboardIndexGitPath, htmlBytes: Buffer.byteLength(html) };
  return _legacy;
}

// ── Cytoscape-semantics stub (verbatim semantics of the repro, plus call recording) ──
function makeStubCytoscape(record) {
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
      record.dijkstraCalls.push({ directed, weight });
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
    record.cores.push(core);
    return core;
  };
  return cytoscape;
}

// Real vendored Cytoscape, headless, evaluated INSIDE the legacy vm context.
// Cytoscape recognises option objects with `obj.constructor === Object`; objects made
// by the legacy script belong to the vm realm, so a main-realm Cytoscape would
// silently ignore e.g. dijkstra({root, weight}) and report every distance as Infinity.
// It is evaluated before `window` exists in the context, so it initialises as a
// non-browser (headless) library.
function makeRealCytoscape(record, ctx) {
  const fs = require('fs');
  const { cytoscapeAvailability } = require('./cytoscape-headless');
  const avail = cytoscapeAvailability();
  if (!avail.ok) throw new Error(avail.reason);
  vm.runInContext(fs.readFileSync(avail.path, 'utf8'), ctx, { filename: avail.path });
  ctx.__aeRealCytoscape = ctx.cytoscape;
  delete ctx.cytoscape;
  vm.runInContext(
    'var __aeHeadless = function (o) { return __aeRealCytoscape({ headless: true, styleEnabled: false,' +
    " layout: { name: 'null' }, elements: JSON.parse(JSON.stringify(o.elements)) }); };", ctx);
  return o => {
    const cy = ctx.__aeHeadless(o);
    record.cores.push(cy);
    return cy;
  };
}

/**
 * Run the legacy inline script in a fresh vm context.
 * @param {{cytoscape?: 'stub'|'real'}} opts
 * @returns {{ctx, els, get, core, record, impl}}
 */
function load(opts = {}) {
  const legacy = legacySource();
  if (!legacy.ok) throw new Error(legacy.skip);
  const impl = opts.cytoscape || 'stub';
  const record = { cores: [], dijkstraCalls: [], elements: [] };

  const els = {};
  const mk = id => ({ id, textContent: '', innerHTML: '', value: '', style: {}, dataset: {}, options: [],
    classList: (() => { const s = new Set(); return { add: (...c) => c.forEach(x => s.add(x)), remove: (...c) => c.forEach(x => s.delete(x)), contains: c => s.has(c), toggle() {}, _s: s }; })(),
    addEventListener() {}, querySelector() { return dropText; }, querySelectorAll() { return []; }, add(o) { this.options.push(o); }, click() {}, scrollIntoView() {} });
  const dropText = mk('drop-text');
  const document = { getElementById: id => (els[id] = els[id] || mk(id)), body: mk('body'),
    querySelectorAll: () => [], querySelector: () => null, addEventListener() {} };

  const JSZip = { loadAsync: async f => ({ forEach(cb) { for (const [p, c] of Object.entries(f)) cb(p, { dir: false, async: async () => c }); } }) };
  class Option { constructor(t, v) { this.textContent = t; this.value = v; this.style = {}; } }
  const ctx = { document, Option, JSZip, console, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1 };
  vm.createContext(ctx);
  const base = impl === 'real' ? makeRealCytoscape(record, ctx) : makeStubCytoscape(record);
  ctx.cytoscape = o => { record.elements = JSON.parse(JSON.stringify(o.elements)); return base(o); };
  ctx.window = ctx;
  vm.runInContext(legacy.src, ctx, { filename: `${legacy.commit}:${legacy.path}#inline-script` });
  return { ctx, els, get: n => vm.runInContext(n, ctx), core: () => record.cores[record.cores.length - 1], record, impl };
}

/** Build a report "zip" (map path->string) from a partial spec: single-region layout with manifest. */
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

/** load() + processLoadedFiles(report(spec)). */
async function run(spec, opts = {}) {
  const d = load(opts);
  await d.get('processLoadedFiles')(report(spec));
  return d;
}

function fmtPath(p) {
  const out = [];
  for (const e of p) out.push(e.group === 'nodes' || (typeof e.isNode === 'function' && e.isNode())
    ? `[${e.data('type')}]${e.data('label')}`
    : `-${e.data('type')}(w=${e.data('weight')})-`);
  return out.join(' ');
}

// Works for both stub elements and real cytoscape elements.
function isNodeEl(e) { return typeof e.isNode === 'function' ? e.isNode() : e.group === 'nodes'; }
function endpoints(e) {
  return typeof e.source === 'function' ? [e.source().id(), e.target().id()] : [e.data('source'), e.data('target')];
}

/** Plain-data view of one dashboard path (a cytoscape collection, node-edge-node...). */
function describePath(path) {
  const seq = [...path];
  const nodes = seq.filter(isNodeEl).map(n => n.id());
  const edges = [];
  for (let i = 1; i < seq.length; i += 2) {
    const e = seq[i];
    const [source, target] = endpoints(e);
    const from = seq[i - 1].id(), to = seq[i + 1] ? seq[i + 1].id() : null;
    edges.push({ id: e.id(), type: e.data('type'), category: e.data('category'), weight: e.data('weight'),
      source, target, walked: source === from && target === to ? 'forward' : 'reversed' });
  }
  return { nodes, edges };
}

/** Run the real "Discover All Paths" (incl. its playback wrapper) and return plain data. */
function discoverAll(d) {
  d.get('findAllAttackPaths')();
  const status = d.els['attack-paths-status'] ? d.els['attack-paths-status'].textContent : '';
  const paths = Array.from(d.get('window._discoveredPaths') || [], p => ({
    source: p.source.id(), target: p.target.id(), distance: p.distance, hops: p.hops,
    route: fmtPath(p.path), ...describePath(p.path),
  }));
  // JSON round trip: plain main-realm data (vm-realm arrays fail deepStrictEqual).
  return JSON.parse(JSON.stringify({ status, paths }));
}

/** Run the real "Find Attack Path" panel for (fromId, toId) and return what it rendered. */
function findPath(d, fromId, toId) {
  d.get('document').getElementById('path-from').value = fromId;
  d.get('document').getElementById('path-to').value = toId;
  d.get('findPath')();
  return {
    cost: d.els['path-cost'] ? d.els['path-cost'].textContent : '',
    hops: d.els['path-hops'] ? d.els['path-hops'].textContent : '',
    stepsHtml: d.els['path-steps'] ? d.els['path-steps'].innerHTML : '',
  };
}

/** A standalone Cytoscape-semantics stub core over `elements` (for Dijkstra parity checks). */
function stubCore(elements) {
  const record = { cores: [], dijkstraCalls: [], elements: [] };
  return makeStubCytoscape(record)({ elements: JSON.parse(JSON.stringify(elements)) });
}

module.exports = { legacySource, load, report, run, fmtPath, describePath, discoverAll, findPath, stubCore };
