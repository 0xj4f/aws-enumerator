'use strict';
// Dashboard regression tests: report loading in js/loader.js (owner of the fix: Dc).
//
// Written xfail-first in Wave 0 (js/loader.js did not exist); flipped to plain tests by the Dc stream
// in Wave 1 when loader.js landed. Contract: docs/contracts/dashboard-core-api.md section 3,
// report-layout.md section 9. Zips are built with the vendored JSZip 3.10.1 (the one the page ships).
// Findings: F-091, F-092, F-093, F-145.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('crypto');
const { loadVendored } = require('../helpers/vendor-libs');
const { requireDashboard, fixture, fixtureText, variant, settlesWithin } = require('./lib/common');

const subtle = webcrypto.subtle;
const enc = new TextEncoder();

function loader() { return requireDashboard('loader.js'); }

function jszip() {
  const r = loadVendored('jszip');
  if (!r.ok) throw new Error(r.reason);
  return r.lib;
}

/** Zip the {path: text|Uint8Array} map; returns an ArrayBuffer (what File.arrayBuffer() gives). */
async function zipOf(entries) {
  const JSZip = jszip();
  const z = new JSZip();
  for (const [p, c] of Object.entries(entries)) z.file(p, c);
  const u8 = await z.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

function manifestFor(doc) {
  return JSON.stringify({ schema_version: '2.0', run: { run_id: doc.run.run_id, started_at: '2026-01-01T00:00:00Z' }, target: { account_id: doc.run.account_id, regions: doc.run.regions } });
}

/** A run tree under `root` with a manifest and analysis/graph.json, plus the collector files a loader must never touch. */
function runTree(root, doc) {
  return {
    [`${root}manifest.json`]: manifestFor(doc),
    [`${root}analysis/graph.json`]: JSON.stringify(doc),
    [`${root}analysis/permission_map.json`]: JSON.stringify({ secret: 'never inflate me' }),
    [`${root}analysis/findings.json`]: JSON.stringify({ findings: [] }),
    [`${root}global/iam/policy_documents/demo-policy.json`]: JSON.stringify({ Statement: [] }),
    [`${root}eu-west-2/ec2/instances.json`]: '[]',
  };
}

/** Record every ZipObject inflation (async/nodeStream/internalStream) while `fn` runs. */
async function inflations(fn) {
  const JSZip = jszip();
  const probe = await JSZip.loadAsync(await zipOf({ 'probe.txt': 'x' }));
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
    Object.assign(proto, saved);
  }
  return names;
}

/** A browser-like File for folder input (webkitRelativePath) that logs every read. */
class FakeFile extends Blob {
  constructor(content, relPath, log) {
    super([content]);
    this.name = relPath.split('/').pop();
    this.webkitRelativePath = relPath;
    this.lastModified = 0;
    this._log = log;
  }
  arrayBuffer() { this._log.push(this.webkitRelativePath); return super.arrayBuffer(); }
  text() { this._log.push(this.webkitRelativePath); return super.text(); }
  stream() { this._log.push(this.webkitRelativePath); return super.stream(); }
  slice(...a) { this._log.push(this.webkitRelativePath); return super.slice(...a); }
}

function folder(entries, log = []) {
  return Object.entries(entries).map(([p, c]) => new FakeFile(c, p, log));
}

/** Expect `fn` (sync throw or async rejection) to fail with a LoaderError whose code is in `codes`. */
async function rejectsWith(L, fn, codes, what) {
  let err = null;
  try {
    await settlesWithin(Promise.resolve().then(fn), 3000, what);
  } catch (e) {
    err = e;
  }
  assert.ok(err, `${what}: expected a LoaderError (${codes.join('|')}), got success`);
  assert.ok(err instanceof L.LoaderError, `${what}: expected a LoaderError, got ${err && err.name}: ${err && err.message}`);
  if (codes.length) assert.ok(codes.includes(err.code), `${what}: code ${err.code}, expected ${codes.join('|')}`);
  assert.ok(typeof err.message === 'string' && err.message.length > 0, `${what}: the error needs a message the UI can show`);
  return err;
}

async function openZip(L, buf, limits) {
  const fileSet = await L.fromZip(buf, { JSZip: jszip(), limits: limits || L.LIMITS });
  const roots = L.findRoots(fileSet);
  return { fileSet, roots };
}

describe('loader regressions: input kinds (F-145)', () => {
  test(`[F-145] sniff detects a zip by its magic bytes and JSON by its first non-space "{" (not by file name)`, async () => {
    const L = loader();
    const zip = new Uint8Array(await zipOf({ 'a.json': '{}' }));
    assert.equal(L.sniff(zip), 'zip');
    assert.equal(L.sniff(enc.encode('  \n\t{"schema_version":"1.0.0"}')), 'json');
    for (const other of ['<html></html>', 'PK', '', 'schema_version', '[1,2]', '\u00ef\u00bb\u00bfhello']) {
      assert.equal(L.sniff(enc.encode(other)), 'unknown', JSON.stringify(other));
    }
  });

  test(`[F-145] a bare graph.json, a report folder and a zip all reach the same validated document`, async () => {
    const L = loader();
    const doc = fixture('example');
    const single = L.fromGraphText(fixtureText('example'));
    assert.equal(single.kind, 'single');
    const sRoots = L.findRoots(single);
    assert.equal(sRoots.length, 1);
    assert.equal(sRoots[0].hasGraph, true);
    assert.deepEqual({ ...(await L.classify(single, sRoots[0].root)) }, { kind: 'ok', schemaMajor: 1 });
    const fromSingle = await L.load(single, sRoots[0].root, { subtle });
    assert.equal(fromSingle.raw.run.run_id, doc.run.run_id);

    const log = [];
    const dir = L.fromFolder(folder(runTree('demo-report/run-1/', doc), log));
    assert.equal(dir.kind, 'folder');
    assert.deepEqual(dir.paths, dir.paths.slice().sort(), 'FileSet.paths must be sorted');
    const dRoots = L.findRoots(dir);
    assert.equal(dRoots.length, 1);
    assert.equal(dRoots[0].hasGraph, true);
    assert.equal(dRoots[0].hasManifest, true);
    assert.equal((await L.classify(dir, dRoots[0].root)).kind, 'ok');
    assert.equal((await L.load(dir, dRoots[0].root, { subtle })).raw.run.account_id, doc.run.account_id);
    assert.ok(log.every(p => /(^|\/)(manifest\.json|analysis\/graph\.json)$/.test(p)), `folder load read ${JSON.stringify(log)}`);

    const z = await openZip(L, await zipOf(runTree('run-1/', doc)));
    assert.equal(z.fileSet.kind, 'zip');
    assert.equal((await L.load(z.fileSet, z.roots[0].root, { subtle })).raw.run.run_id, doc.run.run_id);
  });

  test(`[F-145] input that is neither a zip nor graph.json is rejected with a visible LoaderError`, async () => {
    const L = loader();
    await rejectsWith(L, () => L.fromZip(enc.encode('just some notes').buffer, { JSZip: jszip(), limits: L.LIMITS }), ['unsupported-input'], 'text passed as a zip');
    const notJson = L.fromGraphText('this is not json');
    const roots = L.findRoots(notJson);
    assert.equal(roots.length, 1, 'a bare graph.json is one root');
    await rejectsWith(L, () => L.load(notJson, roots[0].root, { subtle }), ['bad-json'], 'text passed as graph.json');
  });
});

describe('loader regressions: zip limits (F-091)', () => {
  test(`[F-091] LIMITS is a frozen set of positive, consistent limits that admit a normal report`, async () => {
    const L = loader();
    assert.ok(Object.isFrozen(L.LIMITS));
    for (const k of ['maxArchiveBytes', 'maxEntries', 'maxEntryBytes', 'maxTotalInflatedBytes']) {
      assert.ok(Number.isFinite(L.LIMITS[k]) && L.LIMITS[k] > 0, `LIMITS.${k}`);
    }
    assert.ok(L.LIMITS.maxEntryBytes <= L.LIMITS.maxTotalInflatedBytes);
    const z = await openZip(L, await zipOf(runTree('run-1/', fixture('example'))));
    assert.equal((await L.classify(z.fileSet, z.roots[0].root)).kind, 'ok');
  });

  test(`[F-091] archives over a limit are rejected with an explicit code before the oversized entry is inflated`, async () => {
    const L = loader();
    const doc = fixture('example');
    const run = runTree('run-1/', doc);
    const full = async (buf, limits) => {
      const { fileSet, roots } = await openZip(L, buf, limits);
      await L.classify(fileSet, roots[0].root);
      return L.load(fileSet, roots[0].root, { subtle });
    };
    const buf = await zipOf(run);
    await rejectsWith(L, () => full(buf, { ...L.LIMITS, maxArchiveBytes: 512 }), ['too-large'], 'archive over maxArchiveBytes');
    await rejectsWith(L, () => full(buf, { ...L.LIMITS, maxEntries: 3 }), ['too-many-entries'], 'archive over maxEntries');
    const graphBytes = Buffer.byteLength(run['run-1/analysis/graph.json']);
    const inflated = await inflations(async () => {
      await rejectsWith(L, () => full(buf, { ...L.LIMITS, maxEntryBytes: graphBytes - 1 }), ['entry-too-large'], 'graph.json over maxEntryBytes');
    });
    assert.ok(!inflated.includes('run-1/analysis/graph.json'), 'the oversized entry was inflated before the size check');
    const manifestBytes = Buffer.byteLength(run['run-1/manifest.json']);
    await rejectsWith(L, () => full(buf, { ...L.LIMITS, maxTotalInflatedBytes: graphBytes + manifestBytes - 1 }), ['too-large', 'entry-too-large'], 'archive over maxTotalInflatedBytes');
  });

  test(`[F-091] only <root>/manifest.json and <root>/analysis/graph.json are ever inflated (never permission_map.json or policy dumps)`, async () => {
    const L = loader();
    const inflated = await inflations(async () => {
      const { fileSet, roots } = await openZip(L, await zipOf(runTree('run-1/', fixture('example'))));
      assert.equal(roots.length, 1);
      await L.classify(fileSet, roots[0].root);
      await L.load(fileSet, roots[0].root, { subtle });
    });
    assert.ok(inflated.length > 0, 'nothing was inflated: graph.json must be read');
    const allowed = new Set(['run-1/manifest.json', 'run-1/analysis/graph.json']);
    const extra = inflated.filter(n => !allowed.has(n));
    assert.deepEqual(extra, [], `inflated outside the allow-list: ${extra.join(', ')}`);
  });
});

describe('loader regressions: exact roots (F-093)', () => {
  test(`[F-093] two runs in one archive: findRoots lists both and load reads only the chosen root`, async () => {
    const L = loader();
    const a = fixture('example');
    const b = variant('example', d => { d.run.run_id = '20260202T000000Z-b2c3d4'; d.run.account_id = '123456789012'; });
    const buf = await zipOf({ ...runTree('demo-runs/111122223333/run-a/', a), ...runTree('demo-runs/123456789012/run-b/', b) });
    const { fileSet, roots } = await openZip(L, buf);
    assert.equal(roots.length, 2, `roots ${JSON.stringify(roots)}`);
    const rootNames = roots.map(r => r.root);
    assert.deepEqual(rootNames, rootNames.slice().sort(), 'findRoots is sorted by root');
    assert.ok(roots.every(r => r.hasGraph && r.hasManifest));
    const rootB = roots.find(r => r.root.includes('run-b')).root;
    let result;
    const inflated = await inflations(async () => {
      assert.equal((await L.classify(fileSet, rootB)).kind, 'ok');
      result = await L.load(fileSet, rootB, { subtle });
    });
    assert.equal(result.raw.run.run_id, '20260202T000000Z-b2c3d4');
    assert.equal(result.raw.run.account_id, '123456789012');
    assert.ok(inflated.every(n => n.includes('/run-b/')), `read files of another run: ${inflated.join(', ')}`);
  });

  test(`[F-093] reads are exact: a run without its own graph.json never borrows another run's file by suffix match`, async () => {
    const L = loader();
    const log = [];
    const files = folder({
      'runs/run-a/manifest.json': manifestFor(fixture('example')),
      'runs/run-a/analysis/graph.json': fixtureText('example'),
      'runs/run-b/manifest.json': manifestFor(fixture('hostile')),
      'runs/run-b/analysis/findings.json': '{"findings": []}',
    }, log);
    const fileSet = L.fromFolder(files);
    const roots = L.findRoots(fileSet);
    const rootB = roots.find(r => r.root.includes('run-b'));
    assert.ok(rootB, `run-b not offered: ${JSON.stringify(roots)}`);
    assert.equal(rootB.hasGraph, false);
    const kind = (await L.classify(fileSet, rootB.root)).kind;
    assert.equal(kind, 'legacy', 'a run with analysis/findings.json but no graph.json is a legacy report');
    await rejectsWith(L, () => L.load(fileSet, rootB.root, { subtle }), [], 'load of a root without graph.json');
    assert.ok(!log.includes('runs/run-a/analysis/graph.json'), 'run-a\'s graph.json was read for run-b');
  });
});

describe('loader regressions: failures surface (F-092)', () => {
  test(`[F-092] every loader failure settles as a LoaderError with a message (no silent hang)`, async () => {
    const L = loader();
    const real = new Uint8Array(await zipOf(runTree('run-1/', fixture('example'))));
    const truncated = real.slice(0, 40).buffer;
    await rejectsWith(L, () => L.fromZip(truncated, { JSZip: jszip(), limits: L.LIMITS }), [], 'truncated zip');
    await rejectsWith(L, () => L.fromZip(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4, 5, 6, 7, 8]).buffer, { JSZip: jszip(), limits: L.LIMITS }), [], 'zip magic followed by garbage');
    const broken = L.fromGraphText('{"schema_version": "1.0.0", "nodes": [');
    const roots = L.findRoots(broken);
    assert.equal(roots.length, 1);
    await rejectsWith(L, () => L.load(broken, roots[0].root, { subtle }), ['bad-json'], 'truncated graph.json');
    const ok = L.fromGraphText(fixtureText('example'));
    await rejectsWith(L, () => L.load(ok, 'no-such-root/', { subtle }), ['no-report'], 'unknown root');
    const empty = L.fromFolder([]);
    assert.deepEqual(L.findRoots(empty), []);
    assert.equal((await settlesWithin(L.classify(empty, ''), 3000, 'classify(empty)')).kind, 'missing');
    const future = L.fromGraphText(JSON.stringify({ ...fixture('minimal'), schema_version: '2.0.0' }));
    const fr = L.findRoots(future)[0].root;
    assert.deepEqual({ ...(await L.classify(future, fr)) }, { kind: 'unsupported-version', schemaMajor: 2 });
  });
});
