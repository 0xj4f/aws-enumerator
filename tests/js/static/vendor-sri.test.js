'use strict';
// Vendored libraries, SRI and their licences (F-089; Du, Wave 2). The regression suite
// (tests/js/regressions/static.test.js) pins integrity == sha384(file) == VENDOR.md for the two
// scripts; this file adds the licence side and the hash formats.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const crypto = require('crypto');
const targets = require('../helpers/targets');
const { scriptTags } = require('../regressions/lib/markup');

const vendorText = (name) => fs.readFileSync(targets.vendorFile(name), 'utf8');

describe('vendored libraries (F-089)', () => {
  test('[F-089] both vendored scripts load with a sha384 integrity of their exact bytes', () => {
    const scripts = scriptTags(fs.readFileSync(targets.dashboardIndexPath(), 'utf8')).filter(s => s.src.startsWith('vendor/'));
    assert.deepEqual(scripts.map(s => s.src), ['vendor/jszip.min.js', 'vendor/cytoscape.min.js']);
    for (const s of scripts) {
      const bytes = fs.readFileSync(targets.vendorFile(s.src.slice('vendor/'.length)));
      assert.equal(s.attrs.get('integrity'), 'sha384-' + crypto.createHash('sha384').update(bytes).digest('base64'), s.src);
    }
  });

  test('[F-089] every library inside the vendored files has its licence text next to it', () => {
    const manifest = vendorText('VENDOR.md');
    for (const lib of ['jszip', 'cytoscape', 'pako', 'lie', 'immediate', 'setimmediate', 'readable-stream']) {
      const file = `LICENSE-${lib}.txt`;
      assert.ok(fs.existsSync(targets.vendorFile(file)), `${file} missing`);
      assert.ok(manifest.includes(`| \`${file}\` |`), `${file} has no VENDOR.md row`);
      assert.match(vendorText(file), /Permission is hereby granted, free of charge/, `${file} is not an MIT text`);
    }
    // the bundle's own header names pako; the dependency tables name the registry integrity of each tarball
    assert.match(vendorText('jszip.min.js').slice(0, 600), /pako released under the MIT license/);
    for (const lib of ['pako', 'lie', 'immediate', 'setimmediate', 'readable-stream']) {
      assert.match(manifest, new RegExp(`\\| ${lib} \\| [0-9.]+ \\| .*\\| \`sha512-[A-Za-z0-9+/=]+\` \\|`), lib);
    }
  });

  test('[F-089] VENDOR.md records sha512 for both libraries and says how to verify offline', () => {
    const manifest = vendorText('VENDOR.md');
    for (const lib of ['jszip.min.js', 'cytoscape.min.js']) {
      const sha512 = 'sha512-' + crypto.createHash('sha512').update(fs.readFileSync(targets.vendorFile(lib))).digest('base64');
      assert.ok(manifest.includes(sha512), lib);
    }
    assert.match(manifest, /vendor_dashboard_libs\.py --verify/);
  });
});
