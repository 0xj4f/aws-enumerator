'use strict';
// loader.js (docs/contracts/dashboard-core-api.md section 3, report-layout.md section 9).
// Findings: F-091 (zip limits, allow-listed inflation), F-093 (exact roots, run picker),
// F-145 (zip / folder / bare graph.json by sniffing; anything else is a visible error),
// Every failure is a LoaderError (core side of F-092); the digest badge is display-only (F-168 is R's).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto, createHash } = require('crypto');
const H = require('./lib/helpers');

const { L, C } = H.modules();
const subtle = webcrypto.subtle;
const enc = new TextEncoder();
const skip = H.jszipSkip();

/** A JSZip stand-in that records whether loadAsync ran (it must not for archives refused up front). */
function spyJSZip() {
  const real = H.jszip();
  const spy = { calls: 0, loadAsync(...args) { spy.calls++; return real.loadAsync(...args); } };
  return spy;
}

/** Offsets of the central directory headers of a zip, by entry name. */
function centralHeaders(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = bytes.length - 22;
  while (eocd >= 0 && dv.getUint32(eocd, true) !== 0x06054b50) eocd--;
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const out = new Map();
  for (let i = 0; i < count; i++) {
    const nameLen = dv.getUint16(p + 28, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    out.set(name, p);
    p += 46 + nameLen + dv.getUint16(p + 30, true) + dv.getUint16(p + 32, true);
  }
  return { out, eocd, dv };
}

describe('sniff and fromBytes (F-145)', () => {
  test('[F-145] content decides, never the file name: zip magic, JSON after BOM/whitespace, anything else unknown', () => {
    assert.equal(L.sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0])), 'zip');
    assert.equal(L.sniff(enc.encode('  \r\n\t{"a":1}')), 'json');
    assert.equal(L.sniff(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), 'json');
    assert.equal(L.sniff(enc.encode('[1,2]')), 'unknown', 'graph.json is an object');
    assert.equal(L.sniff(enc.encode('PK')), 'unknown');
    assert.equal(L.sniff(new Uint8Array(0)), 'unknown');
    assert.equal(L.sniff('{"a":1}'), 'unknown', 'a string is not bytes');
    assert.equal(L.sniff(enc.encode('{').buffer), 'json', 'an ArrayBuffer is accepted');
  });

  test('[F-145] fromBytes builds a zip or single-file FileSet and rejects other content with a visible message', { skip }, async () => {
    const doc = H.fixture('example');
    const zip = await L.fromBytes(await H.zipBytes(H.runTree('run-1/', doc)), { JSZip: H.jszip() });
    assert.equal(zip.kind, 'zip');
    const single = await L.fromBytes(enc.encode(JSON.stringify(doc)), { name: 'graph (1).json' });
    assert.equal(single.kind, 'single');
    assert.deepEqual(L.findRoots(single), [{ root: '', hasGraph: true, hasManifest: false }]);
    assert.equal((await L.load(single, '', { subtle })).raw.run.run_id, doc.run.run_id);
    for (const bytes of [enc.encode('just some notes'), new Uint8Array([0x89, 0x50, 0x4e, 0x47]), enc.encode('')]) {
      const err = await H.loaderRejects(L, () => L.fromBytes(bytes, { JSZip: H.jszip() }), 'unsupported-input', 'non-report bytes');
      assert.match(err.message, /zip|graph\.json/);
    }
    await H.loaderRejects(L, () => L.fromBytes(enc.encode('{"x":1}'), { limits: { maxEntryBytes: 3 } }), 'entry-too-large', 'oversized json');
  });

  test('[F-145] a bare graph.json is one root at the top level whatever it contains; bad JSON surfaces at classify/load', async () => {
    const fs = L.fromGraphText('not json at all', 'upload.json');
    assert.deepEqual(fs.paths, ['analysis/graph.json']);
    assert.equal(fs.name, 'upload.json');
    await H.loaderRejects(L, () => L.classify(fs, ''), 'bad-json', 'classify');
    await H.loaderRejects(L, () => L.load(fs, '', { subtle }), 'bad-json', 'load');
    assert.throws(() => L.fromGraphText(42), (e) => e instanceof L.LoaderError && e.code === 'unsupported-input');
  });
});

describe('fromFolder (F-145, F-093)', () => {
  test('[F-145] a picked folder (webkitRelativePath) loads; only the two allow-listed files are read', async () => {
    const doc = H.fixture('example');
    const log = [];
    const files = H.folderFiles(H.runTree('demo-run/', doc), log);
    const fileSet = L.fromFolder(files);
    assert.equal(fileSet.kind, 'folder');
    assert.deepEqual(L.findRoots(fileSet), [{ root: 'demo-run/', hasGraph: true, hasManifest: true }]);
    assert.equal((await L.classify(fileSet, 'demo-run/')).kind, 'ok');
    const loaded = await L.load(fileSet, 'demo-run/', { subtle });
    assert.equal(loaded.raw.run.run_id, doc.run.run_id);
    assert.deepEqual(log.slice().sort(), ['demo-run/analysis/graph.json', 'demo-run/manifest.json']);
  });

  test('[F-145] a dropped folder as {path, file} pairs loads the same way; ".." paths are ignored', async () => {
    const doc = H.fixture('example');
    const tree = H.runTree('dropped/', doc);
    const pairs = Object.entries(tree).map(([p, c]) => ({ path: `/${p}`, file: new Blob([c]) }));
    pairs.push({ path: '../outside/manifest.json', file: new Blob(['{}']) });
    const fileSet = L.fromFolder(pairs);
    assert.ok(!fileSet.paths.some(p => p.includes('..')));
    assert.deepEqual(L.findRoots(fileSet).map(r => r.root), ['dropped/']);
    assert.equal((await L.load(fileSet, 'dropped/', { subtle })).raw.run.run_id, doc.run.run_id);
  });

  test('[F-091] a folder file whose size is over the limit is refused before it is read', async () => {
    const doc = H.fixture('example');
    const log = [];
    const files = H.folderFiles({ 'r/analysis/graph.json': JSON.stringify(doc) }, log);
    const fileSet = L.fromFolder(files, { limits: { maxEntryBytes: 100 } });
    await H.loaderRejects(L, () => L.load(fileSet, 'r/', { subtle }), 'entry-too-large', 'oversized folder file');
    assert.deepEqual(log, [], 'the oversized file was read');
    const lying = [new H.FakeFile(JSON.stringify(doc), 'r/analysis/graph.json', log, { size: 10 })];
    await H.loaderRejects(L, () => L.load(L.fromFolder(lying, { limits: { maxEntryBytes: 100 } }), 'r/', { subtle }),
      'entry-too-large', 'a file larger than its declared size');
  });
});

describe('fromZip limits (F-091)', { skip }, () => {
  test('[F-091] JSZip 3.10.1 exposes _data.uncompressedSize from the central directory (pinned)', async () => {
    const JSZip = H.jszip();
    const z = await JSZip.loadAsync(await H.zipBytes({ 'a/analysis/graph.json': 'x'.repeat(1234) }));
    assert.equal(JSZip.version, '3.10.1');
    assert.equal(z.files['a/analysis/graph.json']._data.uncompressedSize, 1234);
  });

  test('[F-091] the archive size is checked before anything is parsed', async () => {
    const bytes = await H.zipBytes(H.runTree('run-1/', H.fixture('example')));
    const spy = spyJSZip();
    await H.loaderRejects(L, () => L.fromZip(bytes, { JSZip: spy, limits: { maxArchiveBytes: bytes.length - 1 } }), 'too-large', 'archive size');
    assert.equal(spy.calls, 0);
  });

  test('[F-091] the entry count comes from the central directory, before JSZip builds any object, even when the end record lies', async () => {
    const entries = {};
    for (let i = 0; i < 40; i++) entries[`run-1/eu-west-2/demo/${i}.json`] = '[]';
    const bytes = await H.zipBytes(entries);
    const spy = spyJSZip();
    await H.loaderRejects(L, () => L.fromZip(bytes, { JSZip: spy, limits: { maxEntries: 10 } }), 'too-many-entries', 'entry count');
    assert.equal(spy.calls, 0, 'JSZip parsed the archive before the entry-count check');
    const { eocd, dv } = centralHeaders(bytes);
    const lying = bytes.slice();
    const ldv = new DataView(lying.buffer);
    ldv.setUint16(eocd + 8, 1, true);
    ldv.setUint16(eocd + 10, 1, true);
    assert.ok(dv.getUint16(eocd + 10, true) >= 40, 'the real directory holds 40 files (plus the folder entries JSZip adds)');
    await H.loaderRejects(L, () => L.fromZip(lying, { JSZip: spy, limits: { maxEntries: 10 } }), 'too-many-entries', 'lying end record');
    assert.equal(spy.calls, 0);
  });

  test('[F-091] an entry that inflates past its declared size is cut off while streaming (zip bomb with a lying header)', async () => {
    const doc = H.fixture('example');
    const bytes = await H.zipBytes(H.runTree('run-1/', doc));
    const { out } = centralHeaders(bytes);
    const at = out.get('run-1/analysis/graph.json');
    const lying = bytes.slice();
    new DataView(lying.buffer).setUint32(at + 24, 64, true);
    const manifestBytes = Buffer.byteLength(H.manifestFor(doc));
    // The total budget fits the manifest plus the declared 64 bytes, not the manifest plus the real size.
    const fileSet = await L.fromZip(lying, { JSZip: H.jszip(), limits: { maxTotalInflatedBytes: manifestBytes + 32 } });
    const err = await H.loaderRejects(L, () => L.load(fileSet, 'run-1/', { subtle }), 'unsupported-input', 'lying size');
    assert.match(err.message, /declares/);
    const info = await L.describeRoot(fileSet, 'run-1/');
    assert.equal(info.problem, null, 'the failed read released its 64-byte reservation, so the manifest still fits');
    assert.equal(info.runId, doc.run.run_id);
  });

  test('[F-091] the total inflated budget covers manifest + graph together', async () => {
    const doc = H.fixture('example');
    const run = H.runTree('run-1/', doc);
    const graphBytes = Buffer.byteLength(run['run-1/analysis/graph.json']);
    const manifestBytes = Buffer.byteLength(run['run-1/manifest.json']);
    const bytes = await H.zipBytes(run);
    const tight = { maxEntryBytes: graphBytes, maxTotalInflatedBytes: graphBytes + manifestBytes };
    const ok = await L.fromZip(bytes, { JSZip: H.jszip(), limits: tight });
    assert.equal((await L.load(ok, 'run-1/', { subtle })).raw.run.run_id, doc.run.run_id);
    const over = await L.fromZip(bytes, { JSZip: H.jszip(), limits: { ...tight, maxTotalInflatedBytes: graphBytes + manifestBytes - 1 } });
    await H.loaderRejects(L, () => L.load(over, 'run-1/', { subtle }), 'too-large', 'total budget');
  });

  test('[F-091] only <root>manifest.json and <root>analysis/graph.json are inflated; read() refuses every other path', async () => {
    const doc = H.fixture('example');
    let fileSet;
    const names = await H.inflations(async () => {
      fileSet = await L.fromZip(await H.zipBuffer(H.runTree('run-1/', doc)), { JSZip: H.jszip() });
      await L.classify(fileSet, 'run-1/');
      await L.load(fileSet, 'run-1/', { subtle });
      await L.describeRoot(fileSet, 'run-1/');
    });
    assert.deepEqual([...new Set(names)].sort(), ['run-1/analysis/graph.json', 'run-1/manifest.json']);
    for (const p of ['run-1/analysis/permission_map.json', 'run-1/global/iam/policy_documents/demo-policy.json', '../x', 42]) {
      await H.loaderRejects(L, () => fileSet.read(p), 'unsupported-input', `read(${p})`);
    }
    assert.equal(await fileSet.read('run-2/analysis/graph.json'), null, 'an allow-listed path that is absent reads as null');
  });

  test('[F-091] truncated or corrupt archives and a missing JSZip are LoaderErrors, not exceptions of the library', async () => {
    const bytes = await H.zipBytes(H.runTree('run-1/', H.fixture('example')));
    await H.loaderRejects(L, () => L.fromZip(bytes.slice(0, Math.floor(bytes.length / 2)), { JSZip: H.jszip() }), 'unsupported-input', 'truncated');
    await H.loaderRejects(L, () => L.fromZip(bytes, {}), 'unsupported-input', 'no JSZip');
    await H.loaderRejects(L, () => L.fromZip('PK\u0003\u0004', { JSZip: H.jszip() }), 'unsupported-input', 'a string');
    await H.loaderRejects(L, () => L.fromZip(enc.encode('{"schema_version":"1.0.0"}'), { JSZip: H.jszip() }), 'unsupported-input', 'json as zip');
  });

  test('LIMITS is frozen and limits are overridden key by key (invalid overrides are ignored)', async () => {
    assert.ok(Object.isFrozen(L.LIMITS));
    assert.ok(L.LIMITS.maxEntryBytes <= L.LIMITS.maxTotalInflatedBytes);
    const bytes = await H.zipBytes(H.runTree('run-1/', H.fixture('example')));
    const fileSet = await L.fromZip(bytes, { JSZip: H.jszip(), limits: { maxEntries: -1, maxArchiveBytes: 'big', maxEntryBytes: NaN } });
    assert.equal((await L.classify(fileSet, 'run-1/')).kind, 'ok');
  });
});

describe('roots and classification (F-093, report-layout.md section 9)', () => {
  test('[F-093] several runs: every root is listed (sorted, trailing "/"), load needs a choice and reads only that root', { skip }, async () => {
    const a = H.fixture('example');
    const b = H.variant('example', d => { d.run.run_id = '20260202T000000Z-b2c3d4'; });
    const bytes = await H.zipBytes({ ...H.runTree('runs/b/', b), ...H.runTree('runs/a/', a) });
    const fileSet = await L.fromZip(bytes, { JSZip: H.jszip() });
    const roots = L.findRoots(fileSet);
    assert.deepEqual(roots.map(r => r.root), ['runs/a/', 'runs/b/']);
    await H.loaderRejects(L, () => L.load(fileSet, undefined, { subtle }), 'ambiguous', 'no root chosen');
    await H.loaderRejects(L, () => L.load(fileSet, 'runs/', { subtle }), 'no-report', 'not a root');
    const names = await H.inflations(async () => {
      assert.equal((await L.load(fileSet, 'runs/b/', { subtle })).raw.run.run_id, b.run.run_id);
    });
    assert.ok(names.every(n => n.startsWith('runs/b/')), names.join(', '));
  });

  test('[F-093] describeRoot gives run-picker labels from the manifest only, and never rejects on bad data', async () => {
    const doc = H.fixture('example');
    const fileSet = L.fromFolder(H.folderFiles({
      ...H.runTree('ok/', doc),
      'broken/manifest.json': '{not json',
      'bare/analysis/graph.json': JSON.stringify(doc),
    }));
    const ok = await L.describeRoot(fileSet, 'ok/');
    assert.equal(ok.runId, doc.run.run_id);
    assert.equal(ok.accountId, doc.run.account_id);
    assert.equal(ok.label, `${doc.run.run_id} (${doc.run.account_id}, 2026-01-01T00:00:00Z)`);
    const broken = await L.describeRoot(fileSet, 'broken/');
    assert.equal(broken.runId, null);
    assert.match(broken.problem, /not valid JSON/);
    const bare = await L.describeRoot(fileSet, 'bare/');
    assert.equal(bare.label, 'bare/');
    assert.equal(bare.hasGraph, true);
  });

  test('[F-093] classify: graph.json decides ok / unsupported-version; legacy markers; v2 run without analysis is missing', async () => {
    const doc = H.fixture('example');
    const v2 = H.variant('example', d => { d.schema_version = '2.0.0'; });
    const fileSet = L.fromFolder(H.folderFiles({
      'ok/analysis/graph.json': JSON.stringify(doc),
      'v2/analysis/graph.json': JSON.stringify(v2),
      'legacy-findings/manifest.json': JSON.stringify({ schema_version: '2.0' }),
      'legacy-findings/analysis/findings.json': '[]',
      'legacy-rel/manifest.json': JSON.stringify({ schema_version: '2.0' }),
      'legacy-rel/analysis/s3_relationships.json': '[]',
      'legacy-global/manifest.json': JSON.stringify({ schema_version: '2.0' }),
      'legacy-global/global/analysis/findings.json': '[]',
      'legacy-manifest/manifest.json': JSON.stringify({ run_metadata: { caller_arn: null } }),
      'pending/manifest.json': JSON.stringify({ schema_version: '2.1', analysis: { status: 'skipped' } }),
      'nested/deeper/analysis/s3_relationships.json': '[]',
    }));
    const kinds = {};
    for (const r of L.findRoots(fileSet)) kinds[r.root] = (await L.classify(fileSet, r.root)).kind;
    assert.deepEqual(kinds, {
      'legacy-findings/': 'legacy', 'legacy-global/': 'legacy', 'legacy-manifest/': 'legacy', 'legacy-rel/': 'legacy',
      'ok/': 'ok', 'pending/': 'missing', 'v2/': 'unsupported-version',
    });
    assert.equal((await L.classify(fileSet, 'v2/')).schemaMajor, 2);
    const pending = await L.classify(fileSet, 'pending/');
    assert.match(pending.message, /skipped/);
    assert.match(pending.message, /aws-enumerator analyze/);
    const legacy = await L.classify(fileSet, 'legacy-rel/');
    assert.match(legacy.message, /predates graph\.json/);
    const err = await H.loaderRejects(L, () => L.load(fileSet, 'legacy-rel/', { subtle }), 'no-report', 'legacy load');
    assert.match(err.message, /aws-enumerator analyze/);
    await H.loaderRejects(L, () => L.load(L.fromFolder([]), undefined, { subtle }), 'no-report', 'empty input');
  });

  test('[F-093] a run nested next to another never borrows its files (no suffix matching)', async () => {
    const doc = H.fixture('example');
    const log = [];
    const fileSet = L.fromFolder(H.folderFiles({
      'x/run/analysis/graph.json': JSON.stringify(doc),
      'run/manifest.json': H.manifestFor(doc),
    }, log));
    const roots = L.findRoots(fileSet);
    assert.deepEqual(roots.map(r => [r.root, r.hasGraph, r.hasManifest]), [['run/', false, true], ['x/run/', true, false]]);
    await H.loaderRejects(L, () => L.load(fileSet, 'run/', { subtle }), 'no-report', 'run/ has no graph');
    assert.ok(!log.includes('x/run/analysis/graph.json'));
  });
});

describe('integrity badge (display only)', () => {
  test('integrity badge: verified when manifest.files has the graph digest, mismatch (with an error problem) when not, n/a otherwise', async () => {
    const doc = H.fixture('example');
    const graphText = JSON.stringify(doc);
    const sha = createHash('sha256').update(graphText).digest('hex');
    const tree = (files) => H.folderFiles({
      'r/analysis/graph.json': graphText,
      'r/manifest.json': H.manifestFor(doc, files === undefined ? {} : { files }),
    });
    const run = async (files, opts = { subtle }) => L.load(L.fromFolder(tree(files)), 'r/', opts);
    assert.equal((await run([{ path: 'analysis/graph.json', sha256: sha.toUpperCase(), bytes: 1 }])).integrity, 'verified');
    const bad = await run([{ path: 'analysis/graph.json', sha256: '0'.repeat(64) }]);
    assert.equal(bad.integrity, 'mismatch');
    assert.deepEqual(bad.problems.map(p => [p.level, p.code]), [['error', 'digest-mismatch']]);
    assert.equal((await run(undefined)).integrity, 'n/a');
    assert.equal((await run([{ path: 'global/s3/buckets.json', sha256: sha }])).integrity, 'n/a');
    const malformed = await run([{ path: 'analysis/graph.json', sha256: 'abc' }]);
    assert.equal(malformed.integrity, 'n/a');
    assert.equal(malformed.problems[0].code, 'manifest-files');
    const noSubtle = await run([{ path: 'analysis/graph.json', sha256: sha }], {});
    assert.equal(noSubtle.integrity, 'n/a');
    assert.equal(noSubtle.problems[0].code, 'digest-unavailable');
    assert.equal(await L.sha256Hex(enc.encode('abc'), subtle), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('the loaded document feeds validateGraph unchanged', () => {
  test('load returns the parsed raw document; validateGraph accepts it; LoaderError has the contract shape', async () => {
    const doc = H.fixture('hostile');
    const fileSet = L.fromGraphText(JSON.stringify(doc));
    const { raw, manifest, integrity, problems } = await L.load(fileSet, '', { subtle });
    assert.deepEqual(raw, doc);
    assert.equal(manifest, null);
    assert.equal(integrity, 'n/a');
    assert.deepEqual(problems, []);
    assert.ok(C.validateGraph(raw).graph);
    const e = new L.LoaderError('bad-json', 'x');
    assert.equal(e.name, 'LoaderError');
    assert.equal(e.code, 'bad-json');
    assert.ok(e instanceof Error);
    assert.ok(new L.LoaderError('no-report').message.length > 0, 'a default message the UI can show');
    for (const code of ['unsupported-input', 'too-large', 'too-many-entries', 'entry-too-large', 'bad-json', 'no-report', 'ambiguous']) {
      assert.ok(L.ERROR_CODES.includes(code), code);
    }
  });
});
