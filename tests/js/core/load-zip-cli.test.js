'use strict';
// tests/js/helpers/load-zip-cli.js: the command-line loader the Python end-to-end test drives
// (tests/python/orchestration/test_e2e_fake_account.py). Checked here on synthetic zips so the helper
// itself is covered by `node --test tests/js`. Findings: F-145 (a zip loads through the dashboard core),
// F-168 (digest badge).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const H = require('./lib/helpers');
const { loadZip, main } = require('../helpers/load-zip-cli');

const jsSkip = H.jszipSkip();

async function zipFile(t, entries) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ae-load-zip-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'report.zip');
  fs.writeFileSync(file, await H.zipBytes(entries));
  return file;
}

function digestTree(root, doc) {
  const text = JSON.stringify(doc);
  const sha256 = crypto.createHash('sha256').update(text).digest('hex');
  const tree = H.runTree(root, doc, { files: [{ path: 'analysis/graph.json', sha256, bytes: Buffer.byteLength(text) }] });
  tree[`${root}analysis/graph.json`] = text;
  return tree;
}

describe('load-zip-cli (end-to-end helper)', () => {
  test('[F-145] [F-168] a run zip loads: one root, verified digest, counts and no structural problem', { skip: jsSkip }, async (t) => {
    const doc = H.fixture('example');
    const result = await loadZip(await zipFile(t, digestTree('demo-run/', doc)));
    assert.equal(result.root, 'demo-run/');
    assert.equal(result.kind, 'ok');
    assert.equal(result.integrity, 'verified');
    assert.equal(result.structural, 0);
    assert.equal(result.nodes, doc.nodes.length);
    assert.equal(result.edges, doc.edges.length);
    assert.equal(result.findings + result.unattached, doc.findings.length);
    assert.equal(result.run_id, doc.run.run_id);
  });

  test('[F-168] a digest that does not match makes the helper fail', { skip: jsSkip }, async (t) => {
    const doc = H.fixture('example');
    const tree = digestTree('demo-run/', doc);
    tree['demo-run/manifest.json'] = H.manifestFor(doc, { files: [{ path: 'analysis/graph.json', sha256: '0'.repeat(64), bytes: 1 }] });
    const file = await zipFile(t, tree);
    assert.equal((await loadZip(file)).integrity, 'mismatch');
    const out = [];
    const write = process.stdout.write;
    process.stdout.write = (s) => { out.push(String(s)); return true; };
    try {
      assert.equal(await main([file]), 1);
    } finally {
      process.stdout.write = write;
    }
    assert.equal(JSON.parse(out.join('')).integrity, 'mismatch');
  });

  test('structural problems are counted (the operator outside the graph is not one)', { skip: jsSkip }, async (t) => {
    const doc = H.variant('example', d => {
      d.edges.push({ ...d.edges[0], id: 'e-dangling', target: 'arn:aws:iam::111122223333:role/not-in-graph' });
      d.run.operator = { arn: 'arn:aws:iam::111122223333:role/demo-elsewhere', node_id: 'arn:aws:iam::111122223333:role/demo-elsewhere', resolution: 'assumed-role' };
    });
    const result = await loadZip(await zipFile(t, H.runTree('demo-run/', doc)));
    assert.equal(result.problems['dangling-edge'], 1);
    assert.equal(result.structural, 1);
  });

  test('usage errors exit 64 and a missing file exits 1', async () => {
    const errs = [];
    const write = process.stderr.write;
    process.stderr.write = (s) => { errs.push(String(s)); return true; };
    try {
      assert.equal(await main([]), 64);
      assert.equal(await main(['--help']), 64);
      assert.equal(await main([path.join(os.tmpdir(), 'ae-no-such-report.zip')]), 1);
    } finally {
      process.stderr.write = write;
    }
    assert.match(errs.join(''), /usage: node .*load-zip-cli\.js <report\.zip>/);
  });
});
