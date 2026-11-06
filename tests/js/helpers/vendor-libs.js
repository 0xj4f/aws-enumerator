'use strict';
// Loads the vendored (owner-approved, integrity-verified) UMD libraries into Node.
// Both files are pinned by scripts/vendor_dashboard_libs.py and VENDOR.md; the
// helpers self-test checks the pins before anything relies on them.
//
// Every loader returns {ok, lib, reason}; callers turn `reason` into a node:test
// skip so a checkout without vendor/ skips cleanly instead of crashing.

const fs = require('fs');
const path = require('path');
const targets = require('./targets');

const LIBS = Object.freeze({
  cytoscape: { file: 'cytoscape.min.js', version: '3.30.4', versionOf: (lib) => lib && lib.version },
  jszip: { file: 'jszip.min.js', version: '3.10.1', versionOf: (lib) => lib && lib.version },
});

const _cache = new Map();

function loadVendored(name) {
  if (_cache.has(name)) return _cache.get(name);
  const spec = LIBS[name];
  if (!spec) throw new Error(`vendor-libs: unknown library ${name}`);
  const abs = targets.vendorFile(spec.file);
  const rel = path.relative(targets.REPO_ROOT, abs);
  let result;
  if (!fs.existsSync(abs)) {
    result = { ok: false, lib: null, path: abs, reason: `vendored ${name} missing at ${rel} (run scripts/vendor_dashboard_libs.py --verify)` };
  } else {
    try {
      const lib = require(abs);
      const got = spec.versionOf(lib);
      result = got === spec.version
        ? { ok: true, lib, path: abs, version: got, reason: null }
        : { ok: false, lib: null, path: abs, reason: `vendored ${name} at ${rel} reports version ${got}, expected ${spec.version}` };
    } catch (err) {
      result = { ok: false, lib: null, path: abs, reason: `vendored ${name} at ${rel} failed to load: ${err.message}` };
    }
  }
  _cache.set(name, result);
  return result;
}

module.exports = { LIBS, loadVendored };
