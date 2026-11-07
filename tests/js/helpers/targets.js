'use strict';
// The single indirection point between the node:test suite and production files.
//
// JS mirror of tests/support/targets.py (owner: harness-engine). JS tests never
// hard-code `app/...` or `aws_enumerator/...`; they ask this module.
//
// Rename readiness: the dashboard directory is DERIVED from the
// `DASHBOARD_DIR = ...` assignment in tests/support/targets.py, so the rename
// agent (app/ -> aws_enumerator/) edits only targets.py. The parser understands
// assignments of the form  NAME = BASE / "seg" / "seg"  where BASE is REPO_ROOT
// or a NAME assigned earlier in that file (e.g. PACKAGE_DIR). If targets.py is
// missing or uses another form, FALLBACK_DASHBOARD_DIR is used and
// `dashboardDirSource()` reports 'fallback' (the helpers self-test then checks
// that the directory really exists, so a stale fallback fails loudly).
//
// The legacy baseline (commit d13c215) is history: its paths never change.

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
// Since DECISIONS.md D-57 the dashboard is built from frontend/ (Vite + Vue) into the dashboard directory.
// Its pure core modules and the vendored JSZip are source files under frontend/, shared with these tests.
const FRONTEND_DIR = path.join(REPO_ROOT, 'frontend');
const PY_TARGETS = path.join(REPO_ROOT, 'tests', 'support', 'targets.py');
const FALLBACK_DASHBOARD_DIR = 'aws_enumerator/dashboard'; // was app/dashboard before the Wave 0b rename

const LEGACY_BASELINE = Object.freeze({
  commit: 'd13c215',
  dashboardIndexGitPath: 'app/dashboard/index.html',
});

// Parse `NAME = BASE / "a" / "b"` assignments from targets.py (no Python needed).
function parsePyPathAssignments(src) {
  const env = new Map([['REPO_ROOT', []]]);
  const re = /^([A-Z][A-Z0-9_]*)\s*=\s*([A-Z][A-Z0-9_]*)((?:\s*\/\s*"[^"\\]*")+)\s*(?:#.*)?$/;
  for (const line of src.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (!m || !env.has(m[2])) continue;
    const segs = [...m[3].matchAll(/"([^"\\]*)"/g)].map(x => x[1]);
    env.set(m[1], [...env.get(m[2]), ...segs]);
  }
  return env;
}

let _dash = null;
function resolveDashboard() {
  if (_dash) return _dash;
  let rel = FALLBACK_DASHBOARD_DIR;
  let source = 'fallback';
  try {
    const env = parsePyPathAssignments(fs.readFileSync(PY_TARGETS, 'utf8'));
    if (env.has('DASHBOARD_DIR') && env.get('DASHBOARD_DIR').length) {
      rel = env.get('DASHBOARD_DIR').join('/');
      source = 'tests/support/targets.py';
    }
  } catch (_) { /* targets.py absent: keep fallback */ }
  _dash = { rel, abs: path.join(REPO_ROOT, ...rel.split('/')), source };
  return _dash;
}

/** Absolute path of the dashboard directory (aws_enumerator/dashboard since the Wave 0b rename). */
function dashboardDir() { return resolveDashboard().abs; }
/** Repo-relative POSIX path of the dashboard directory. */
function dashboardDirRel() { return resolveDashboard().rel; }
/** Where the dashboard path came from: 'tests/support/targets.py' or 'fallback'. */
function dashboardDirSource() { return resolveDashboard().source; }
/** The built page (npm run build writes it next to server.py). */
function dashboardIndexPath() { return path.join(dashboardDir(), 'index.html'); }
/** The dashboard source tree (frontend/, D-57). */
function frontendDir() { return FRONTEND_DIR; }
/** A pure core module of the dashboard (graph-core.js, loader.js, exports.js, catalog.js): frontend/src/core/. */
function dashboardJsFile(name) { return path.join(FRONTEND_DIR, 'src', 'core', name); }
/** The built bundle (js/app.js) and stylesheet (css/app.css) of the page. */
function dashboardBuiltFile(rel) { return path.join(dashboardDir(), ...rel.split('/')); }
/** The node-type icons (source: frontend/public/icons, copied to <dashboard>/icons by the build). */
function iconsDir() { return path.join(FRONTEND_DIR, 'public', 'icons'); }
/** The vendored, hash-pinned third-party files (JSZip and its licences): frontend/vendor/. */
function vendorDir() { return path.join(FRONTEND_DIR, 'vendor'); }
function vendorFile(name) { return path.join(vendorDir(), name); }
function vendorManifestPath() { return vendorFile('VENDOR.md'); }
function vendorScriptPath() { return path.join(REPO_ROOT, 'scripts', 'vendor_dashboard_libs.py'); }
function pythonBin() { return path.join(REPO_ROOT, '.venv', 'bin', 'python'); }
function goldenDir(name) { return path.join(REPO_ROOT, 'tests', 'golden', name); }
function legacyBaseline() { return LEGACY_BASELINE; }

module.exports = {
  REPO_ROOT,
  FALLBACK_DASHBOARD_DIR,
  parsePyPathAssignments,
  dashboardDir,
  dashboardDirRel,
  dashboardDirSource,
  dashboardIndexPath,
  frontendDir,
  dashboardJsFile,
  dashboardBuiltFile,
  iconsDir,
  vendorDir,
  vendorFile,
  vendorManifestPath,
  vendorScriptPath,
  pythonBin,
  goldenDir,
  legacyBaseline,
};
