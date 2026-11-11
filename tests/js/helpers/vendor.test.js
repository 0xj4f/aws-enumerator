'use strict';
// Pins the vendored libraries (F-089 groundwork) and the path indirection.
// - Every row of vendor/VENDOR.md's Files table matches the bytes on disk.
// - scripts/vendor_dashboard_libs.py --verify agrees (skipped without .venv).
// - Behavioural facts of the vendored JSZip that the loader tests rely on.
// (Cytoscape.js was vendored here until DECISIONS.md D-57; the dashboard no longer uses it.)

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const targets = require('./targets');
const { loadVendored } = require('./vendor-libs');

const VENDOR_SKIP = fs.existsSync(targets.vendorDir()) ? false : `no vendor dir at ${path.relative(targets.REPO_ROOT, targets.vendorDir())}`;

function manifestRows() {
  const text = fs.readFileSync(targets.vendorManifestPath(), 'utf8');
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('| `')) continue;
    const cells = line.split('|').slice(1, -1).map(c => c.trim().replace(/^`|`$/g, ''));
    if (cells.length === 6 && /\.(js|txt)$/.test(cells[0])) {
      rows.push({ file: cells[0], library: cells[1], version: cells[2], bytes: Number(cells[3]), sha256: cells[4], sri: cells[5] });
    }
  }
  return rows;
}

describe('path indirection (tests/js/helpers/targets.js)', () => {
  test('dashboard dir is derived from tests/support/targets.py and exists', () => {
    const src = targets.dashboardDirSource();
    if (fs.existsSync(path.join(targets.REPO_ROOT, 'tests', 'support', 'targets.py'))) {
      assert.equal(src, 'tests/support/targets.py', 'targets.py exists but its DASHBOARD_DIR line was not understood');
    }
    assert.ok(fs.statSync(targets.dashboardDir()).isDirectory(), `missing ${targets.dashboardDirRel()}`);
    assert.ok(fs.existsSync(targets.dashboardIndexPath()), 'index.html missing (run npm run build in frontend/)');
    assert.ok(fs.statSync(targets.frontendDir()).isDirectory(), 'frontend/ (the dashboard source) missing');
  });

  test('parser understands REPO_ROOT and chained NAME / "seg" assignments', () => {
    const env = targets.parsePyPathAssignments([
      'REPO_ROOT = Path(__file__).resolve().parents[2]',
      'PACKAGE_DIR = REPO_ROOT / "aws_enumerator"',
      'DASHBOARD_DIR = PACKAGE_DIR / "dashboard"  # moved',
      'OTHER = SOMETHING_UNKNOWN / "x"',
      'NOT_A_PATH = "app.main"',
    ].join('\n'));
    assert.deepEqual(env.get('DASHBOARD_DIR'), ['aws_enumerator', 'dashboard']);
    assert.equal(env.has('OTHER'), false);
    assert.equal(env.has('NOT_A_PATH'), false);
  });
});

describe('vendored files match VENDOR.md', () => {
  test('Files table covers exactly the vendored files and every hash matches', { skip: VENDOR_SKIP }, () => {
    const rows = manifestRows();
    const onDisk = fs.readdirSync(targets.vendorDir()).filter(f => f !== 'VENDOR.md').sort();
    assert.deepEqual(rows.map(r => r.file).sort(), onDisk);
    for (const r of rows) {
      const data = fs.readFileSync(targets.vendorFile(r.file));
      assert.equal(data.length, r.bytes, `${r.file} size`);
      assert.equal(crypto.createHash('sha256').update(data).digest('hex'), r.sha256, `${r.file} sha256`);
      assert.equal('sha384-' + crypto.createHash('sha384').update(data).digest('base64'), r.sri, `${r.file} SRI`);
    }
  });

  test('library versions in VENDOR.md match the files and the loaders', { skip: VENDOR_SKIP }, () => {
    const rows = Object.fromEntries(manifestRows().map(r => [r.file, r]));
    for (const [name, file] of [['jszip', 'jszip.min.js']]) {
      const lib = loadVendored(name);
      assert.ok(lib.ok, lib.reason);
      assert.equal(lib.version, rows[file].version, `${name} version`);
    }
  });

  const py = targets.pythonBin();
  test('scripts/vendor_dashboard_libs.py --verify agrees (offline)', { skip: VENDOR_SKIP || (fs.existsSync(py) ? false : 'no .venv/bin/python') }, () => {
    const outText = execFileSync(py, ['-I', '-B', targets.vendorScriptPath(), '--verify', '--vendor-dir', targets.vendorDir()], {
      cwd: targets.REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    });
    assert.match(outText, /^verify: ok$/m);
  });
});

describe('vendored JSZip 3.10.1 facts (Node)', () => {
  const jz = loadVendored('jszip');
  test('round-trips a zip in Node and exposes _data.uncompressedSize (loader limits rely on it)', { skip: jz.ok ? false : jz.reason }, async () => {
    const JSZip = jz.lib;
    const zip = new JSZip();
    zip.file('run/manifest.json', '{}');
    zip.file('run/analysis/graph.json', '{"schema_version":"1.0"}');
    const buf = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
    assert.deepEqual([...buf.subarray(0, 4)], [0x50, 0x4b, 0x03, 0x04], 'PK\\x03\\x04 magic');
    const back = await JSZip.loadAsync(buf);
    const entry = back.file('run/analysis/graph.json');
    assert.equal(entry._data.uncompressedSize, 24);
    assert.equal(await entry.async('string'), '{"schema_version":"1.0"}');
    const names = [];
    back.forEach((p, e) => { if (!e.dir) names.push(p); });
    assert.deepEqual(names, ['run/manifest.json', 'run/analysis/graph.json']);
  });
});
