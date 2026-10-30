'use strict';
// Shared support for the Dc unit tests (tests/js/core/*.test.js) and parity tests (tests/js/golden/*).
//
// Not a test file (node --test only runs *.test.js). Production files are reached only through
// tests/js/helpers/targets.js; fixtures and synthetic graphs are shared with the regression suite
// (tests/js/regressions/lib/{common,graphs}.js, also owned by Dc).

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const targets = require('../../helpers/targets');
const { loadVendored } = require('../../helpers/vendor-libs');
const common = require('../../regressions/lib/common');
const graphs = require('../../regressions/lib/graphs');

/** The four Dc modules, loaded the way node:test sees them (module.exports of the UMD wrappers). */
function modules() {
  return {
    C: require(targets.dashboardJsFile('graph-core.js')),
    L: require(targets.dashboardJsFile('loader.js')),
    X: require(targets.dashboardJsFile('exports.js')),
    K: require(targets.dashboardJsFile('catalog.js')),
  };
}

/** Absolute path of a dashboard JS module (for source scans). */
function moduleSource(name) {
  return fs.readFileSync(targets.dashboardJsFile(name), 'utf8');
}

// -- deterministic randomness ---------------------------------------------------------------------

/** mulberry32: a small seeded PRNG, so randomised tests are reproducible from their seed. */
function prng(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Lexicographic comparison of two id sequences (code units), shorter-is-smaller on a common prefix. */
function cmpSeq(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const c = cmp(a[i], b[i]);
    if (c !== 0) return c;
  }
  return a.length - b.length;
}

/**
 * A random contract-shaped graph of `n` roles with random CAN_ASSUME edges and weights drawn from
 * `weights` (many ties on purpose). Some edges are non-traversable, some conditional. Deterministic.
 */
function randomGraph(seed, { n = 7, density = 0.35, weights = [0, 0.5, 1, 1, 2] } = {}) {
  const rnd = prng(seed);
  const doc = graphs.skeleton();
  const reg = doc.edge_types;
  for (let i = 0; i < n; i++) {
    doc.nodes.push(graphs.node(graphs.roleId(i), 'role', `demo-r${i}`, { attached_policies_status: 'complete' }));
  }
  for (let a = 0; a < n; a++) {
    for (let b = 0; b < n; b++) {
      if (a === b || rnd() >= density) continue;
      const w = weights[Math.floor(rnd() * weights.length)];
      const r = rnd();
      const extra = { traversable: r >= 0.1, confidence: r < 0.25 ? 'conditional' : 'definite' };
      doc.edges.push(graphs.edge(reg, graphs.roleId(a), 'CAN_ASSUME', graphs.roleId(b), w, extra));
    }
  }
  return graphs.finish(doc);
}

/**
 * Brute force over every simple path (graph-json.md section 11): the minimum of (cost, hops, edge-id
 * sequence). Simple paths suffice: a cycle never lowers cost (weights >= 0) and always adds hops.
 * `allowed(edge)` filters the raw edges. Returns {cost, hops, path, edges} or null.
 */
function bruteForcePath(doc, source, target, allowed = (e) => e.traversable === true) {
  if (source === target) return null;
  const weight = (e) => ((typeof e.weight === 'number' && Number.isFinite(e.weight) && e.weight >= 0) ? e.weight : 1);
  const out = new Map();
  for (const e of doc.edges) {
    if (e.source === e.target || !allowed(e)) continue;
    if (!out.has(e.source)) out.set(e.source, []);
    out.get(e.source).push(e);
  }
  let best = null;
  const onPath = new Set([source]);
  const nodes = [source];
  const edges = [];
  const visit = (u, cost) => {
    if (u === target) {
      const cand = { cost, hops: edges.length, path: nodes.slice(), edges: edges.map(e => e.id) };
      if (best === null || cand.cost < best.cost || (cand.cost === best.cost &&
          (cand.hops < best.hops || (cand.hops === best.hops && cmpSeq(cand.edges, best.edges) < 0)))) best = cand;
      return;
    }
    for (const e of out.get(u) || []) {
      if (onPath.has(e.target)) continue;
      onPath.add(e.target); nodes.push(e.target); edges.push(e);
      visit(e.target, cost + weight(e));
      onPath.delete(e.target); nodes.pop(); edges.pop();
    }
  };
  visit(source, 0);
  return best;
}

// -- zips and folders ---------------------------------------------------------------------------

function jszip() {
  const r = loadVendored('jszip');
  if (!r.ok) throw new Error(r.reason);
  return r.lib;
}

/** Skip reason for tests that need the vendored JSZip (false when available). */
function jszipSkip() {
  const r = loadVendored('jszip');
  return r.ok ? false : r.reason;
}

/** Zip a {path: text | Uint8Array} map; returns a Uint8Array. */
async function zipBytes(entries, { compression = 'DEFLATE' } = {}) {
  const JSZip = jszip();
  const z = new JSZip();
  for (const [p, c] of Object.entries(entries)) z.file(p, c);
  return z.generateAsync({ type: 'uint8array', compression });
}

/** The same as zipBytes, as an ArrayBuffer (what File.arrayBuffer() gives). */
async function zipBuffer(entries, opts) {
  const u8 = await zipBytes(entries, opts);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/** Records every ZipObject inflation (async / nodeStream / internalStream) while `fn` runs. */
async function inflations(fn) {
  const JSZip = jszip();
  const probe = await JSZip.loadAsync(await zipBytes({ 'probe.txt': 'x' }));
  const proto = Object.getPrototypeOf(probe.files['probe.txt']);
  const names = [];
  const saved = {};
  for (const m of ['async', 'nodeStream', 'internalStream']) {
    saved[m] = proto[m];
    proto[m] = function (...args) { names.push(this.name); return saved[m].apply(this, args); };
  }
  try {
    await fn();
  } finally {
    for (const m of Object.keys(saved)) proto[m] = saved[m];
  }
  return names;
}

/** A browser-like File of a picked folder (webkitRelativePath) that logs every read. */
class FakeFile extends Blob {
  constructor(content, relPath, log = [], { size } = {}) {
    super([content]);
    this.name = relPath.split('/').slice(-1)[0];
    this.webkitRelativePath = relPath;
    this.lastModified = 0;
    this._log = log;
    this._size = size;
  }
  get size() { return this._size === undefined ? super.size : this._size; }
  arrayBuffer() { this._log.push(this.webkitRelativePath); return super.arrayBuffer(); }
  text() { this._log.push(this.webkitRelativePath); return super.text(); }
}

/** FakeFiles for a {relPath: content} map. */
function folderFiles(entries, log = []) {
  return Object.entries(entries).map(([p, c]) => new FakeFile(c, p, log));
}

function manifestFor(doc, extra = {}) {
  return JSON.stringify({
    schema_version: '2.0',
    run: { run_id: doc.run.run_id, started_at: '2026-01-01T00:00:00Z' },
    target: { account_id: doc.run.account_id, regions: doc.run.regions },
    ...extra,
  });
}

/** A run tree under `root` (with trailing '/'), with the collector files a loader must never touch. */
function runTree(root, doc, manifestExtra) {
  return {
    [`${root}manifest.json`]: manifestFor(doc, manifestExtra),
    [`${root}analysis/graph.json`]: JSON.stringify(doc),
    [`${root}analysis/permission_map.json`]: JSON.stringify({ secret: 'never inflate me' }),
    [`${root}analysis/findings.json`]: JSON.stringify({ findings: [] }),
    [`${root}global/iam/policy_documents/demo-policy.json`]: JSON.stringify({ Statement: [] }),
    [`${root}eu-west-2/ec2/instances.json`]: '[]',
  };
}

/** Expect `fn` (sync throw or rejection) to fail with a LoaderError whose code is `code`. */
async function loaderRejects(L, fn, code, what) {
  let err = null;
  try {
    await common.settlesWithin(Promise.resolve().then(fn), 5000, what);
  } catch (e) {
    err = e;
  }
  if (!err) throw new Error(`${what}: expected LoaderError ${code}, got success`);
  if (!(err instanceof L.LoaderError)) throw new Error(`${what}: expected a LoaderError, got ${err.name}: ${err.message}`);
  if (err.code !== code) throw new Error(`${what}: code ${err.code} (${err.message}), expected ${code}`);
  if (typeof err.message !== 'string' || err.message.length === 0) throw new Error(`${what}: empty message`);
  return err;
}

// -- Python (reference implementations; offline, read-only) --------------------------------------

/** Skip reason when the repo's .venv Python is missing (false when available). */
function pythonSkip() {
  return fs.existsSync(targets.pythonBin()) ? false : `no Python at ${path.relative(targets.REPO_ROOT, targets.pythonBin())}`;
}

/**
 * Runs `.venv/bin/python -I -B` with `args` from the repo root, feeding `input` on stdin; returns stdout.
 * -I keeps the environment out; -B keeps __pycache__ out of the tree.
 */
function runPython(args, input = '') {
  return execFileSync(targets.pythonBin(), ['-I', '-B', ...args], {
    cwd: targets.REPO_ROOT, input, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
    env: { PATH: process.env.PATH || '', PYTHONDONTWRITEBYTECODE: '1', PYTHONHASHSEED: '0' },
  });
}

/** Python code run with the repo root on sys.path (for `import aws_enumerator...` / `tests.support`). */
function runPythonCode(code, input = '') {
  const prelude = `import sys; sys.path.insert(0, ${JSON.stringify(targets.REPO_ROOT)})\n`;
  return runPython(['-c', prelude + code], input);
}

const REF_PATHS_DUMP = path.join(targets.REPO_ROOT, 'tests', 'fixtures', 'dc', 'ref_paths_dump.py');

/** Merges example.json (111122223333) and hostile.json (123456789012) with the engine (graph 1.1). */
const MERGE_CODE = [
  'import json, os, pathlib, tempfile',
  'os.environ["SOURCE_DATE_EPOCH"] = "1767225600"',
  'from aws_enumerator.engine import merge',
  'fixtures = pathlib.Path("tests/fixtures/graph")',
  'with tempfile.TemporaryDirectory() as tmp:',
  '    roots = []',
  '    for name in ("example", "hostile"):',
  '        root = pathlib.Path(tmp) / name',
  '        (root / "analysis").mkdir(parents=True)',
  '        (root / "analysis" / "graph.json").write_bytes((fixtures / (name + ".json")).read_bytes())',
  '        roots.append(root)',
  '    doc = merge.merge_graphs(merge.plan_merge(roots), run_id="demo-merge")',
  'print(json.dumps(doc))',
].join('\n');
let mergedCache = null;

/**
 * A merged graph.json 1.1 document (graph-json.md section 4.2) built by the real `engine.merge` from the two
 * fixture graphs (deterministic: SOURCE_DATE_EPOCH). Returns a fresh copy on every call.
 */
function mergedGraph() {
  if (mergedCache === null) mergedCache = runPythonCode(MERGE_CODE);
  return JSON.parse(mergedCache);
}

/** tests/support/ref_paths.shortest_path answers for the given requests (see ref_paths_dump.py). */
function refPaths(requests) {
  return JSON.parse(runPython([REF_PATHS_DUMP], JSON.stringify(requests)));
}

module.exports = {
  ...common,
  graphs,
  targets,
  modules,
  moduleSource,
  prng,
  cmpSeq,
  randomGraph,
  bruteForcePath,
  jszip,
  jszipSkip,
  zipBytes,
  zipBuffer,
  inflations,
  FakeFile,
  folderFiles,
  manifestFor,
  runTree,
  loaderRejects,
  pythonSkip,
  runPython,
  runPythonCode,
  refPaths,
  mergedGraph,
};
