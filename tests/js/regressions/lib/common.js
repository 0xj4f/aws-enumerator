'use strict';
// Shared support for the dashboard regression tests (tests/js/regressions/*.test.js).
//
// Every regression test was written xfail-first against the CONTRACT APIs:
//   - js/graph-core.js  docs/contracts/dashboard-core-api.md section 2 (landed in Wave 1, Dc: tests flipped)
//   - js/loader.js      dashboard-core-api.md section 3 (landed in Wave 1, Dc: tests flipped)
//   - js/exports.js     dashboard-core-api.md section 4 (landed in Wave 1, Dc: tests flipped)
//   - js/ui.js, dom.js  dashboard-docs-tests.md A1/A2/A5 + the UI test protocol in ./ui-harness.js
//                       (Du, Wave 2: still xfail)
// The `raises` matcher of every xfail pins WHY it fails today (NotImplemented, a missing module,
// or an assertion about the current index.html), so a test never passes "for the wrong reason":
// when the module lands and the behaviour is still wrong, the xfail turns into a failure
// (XFailWrongReasonError) instead of silently staying green.
//
// Nothing here is a test file (node --test only runs *.test.js), and nothing here hard-codes a
// production path: everything goes through tests/js/helpers/targets.js.

const fs = require('fs');
const path = require('path');
const targets = require('../../helpers/targets');

const FIXTURE_GRAPH_DIR = path.join(targets.REPO_ROOT, 'tests', 'fixtures', 'graph');
const OWN_FIXTURE_DIR = path.join(targets.REPO_ROOT, 'tests', 'fixtures', 'js-regressions');

/** The dashboard findings this suite covers (assignment of the regressions-js stream). */
const FINDINGS = Object.freeze([
  'F-005', 'F-006', 'F-007', 'F-008', 'F-036', 'F-037', 'F-038', 'F-039', 'F-040', 'F-041', 'F-042', 'F-043',
  'F-089', 'F-090', 'F-091', 'F-092', 'F-093', 'F-094', 'F-095', 'F-096', 'F-097', 'F-098', 'F-145', 'F-146',
  'F-165',
]);

// -- xfail reasons -----------------------------------------------------------
// Appended to test names so the reason is visible in every reporter (the assignment asks for it).
// `core`, `loader` and `exports` are no longer used by the flipped core-*.test.js files; they stay
// for the support self-tests and for any future xfail against those modules.
const PENDING = Object.freeze({
  core: '(xfail: graph-core.js is still a NotImplemented stub)',
  loader: '(xfail: js/loader.js does not exist yet)',
  exports: '(xfail: js/exports.js does not exist yet)',
  ui: '(xfail: js/ui.js does not exist yet)',
  index: '(xfail: current index.html)',
});

/** `raises` matcher: a graph-core stub function that still throws NotImplemented. */
const NOT_IMPLEMENTED = /^NotImplemented: [A-Za-z]+$/;

/**
 * The dashboard directory under test. Normally targets.dashboardDir(); the environment variable
 * AE_REGRESSIONS_DASHBOARD_DIR points the suite at another tree (used once to check that these
 * tests pass against a reference implementation of the contracts; never set in normal runs).
 */
function dashboardDir() {
  return process.env.AE_REGRESSIONS_DASHBOARD_DIR ? path.resolve(process.env.AE_REGRESSIONS_DASHBOARD_DIR) : targets.dashboardDir();
}
const dashboardJsFile = (file) => path.join(dashboardDir(), 'js', file);

/**
 * `raises` matcher: requiring `js/<file>` failed because the module does not exist.
 * Matches node's own MODULE_NOT_FOUND for that exact file (and the UI harness's equivalent error).
 */
function missingModule(file) {
  const abs = dashboardJsFile(file);
  const pred = (err) => !!err && err.code === 'MODULE_NOT_FOUND' && typeof err.message === 'string' && err.message.includes(abs);
  Object.defineProperty(pred, 'name', { value: `missingModule(${file})` });
  return pred;
}

/** require() a dashboard module (js/<file>) through the targets indirection. */
function requireDashboard(file) {
  return require(dashboardJsFile(file));
}

/** AEGraphCore (js/graph-core.js). */
function core() { return requireDashboard('graph-core.js'); }

// -- fixtures ----------------------------------------------------------------
/** A fresh deep copy of tests/fixtures/graph/<name>.json (example, hostile, minimal). */
function fixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_GRAPH_DIR, `${name}.json`), 'utf8'));
}

/** Raw text of a graph fixture (for loader tests). */
function fixtureText(name) {
  return fs.readFileSync(path.join(FIXTURE_GRAPH_DIR, `${name}.json`), 'utf8');
}

/** The shared path vectors (graph-json.md section 11). Each vector embeds a full valid document. */
function pathCases() {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_GRAPH_DIR, 'path_cases.json'), 'utf8'));
}

/** Deep copy through JSON (also turns vm-realm values into main-realm ones). */
function clone(v) { return v === undefined ? undefined : JSON.parse(JSON.stringify(v)); }

/** fixture(name) mutated by fn(doc); returns the doc. */
function variant(name, fn) {
  const doc = fixture(name);
  fn(doc);
  return doc;
}

const nodeById = (doc, id) => doc.nodes.find(n => n.id === id);
const edgeById = (doc, id) => doc.edges.find(e => e.id === id);
const edgesOfType = (doc, type) => doc.edges.filter(e => e.type === type);

// Well-known ids in tests/fixtures/graph/example.json (account 111122223333).
const EX = Object.freeze({
  user: 'arn:aws:iam::111122223333:user/demo-user',
  group: 'arn:aws:iam::111122223333:group/demo-devs',
  appRole: 'arn:aws:iam::111122223333:role/demo-app-role',
  adminRole: 'arn:aws:iam::111122223333:role/admin/demo-admin-role',
  deployRole: 'arn:aws:iam::111122223333:role/demo-deploy-role',
  irsaRole: 'arn:aws:iam::111122223333:role/demo-irsa-web',
  nodeRole: 'arn:aws:iam::111122223333:role/demo-node-role',
  policy: 'arn:aws:iam::111122223333:policy/demo-deploy-policy',
  idp: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com',
  extRoot: 'arn:aws:iam::999999999999:root',
  bucket: 'arn:aws:s3:::demo-data-bucket',
  secret: 'arn:aws:secretsmanager:eu-west-2:111122223333:secret:demo/db-AbCdEf',
  kms: 'arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  lambda: 'arn:aws:lambda:eu-west-2:111122223333:function:demo-fn',
  instance: 'arn:aws:ec2:eu-west-2:111122223333:instance/i-0123456789abcdef0',
  cluster: 'arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster',
  nodegroup: 'arn:aws:eks:eu-west-2:111122223333:nodegroup/demo-cluster/demo-ng/0a1b2c3d-1111-2222-3333-444455556666',
  pod: 'k8s://arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster/Pod/default/Deployment:demo-web',
  sa: 'k8s://arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster/ServiceAccount/default/demo-web',
  admin: 'aws-enumerator:account-admin/111122223333',
  account: 'aws-enumerator:account/111122223333',
  anonymous: 'aws-enumerator:anonymous',
});

// Well-known ids in tests/fixtures/graph/hostile.json (account 123456789012).
const HO = Object.freeze({
  canaryRole: 'arn:aws:iam::123456789012:role/<img/src=x/onerror=window.__aeXssCanary=1>/demo-canary',
  protoRole: 'arn:aws:iam::123456789012:role/__proto__',
  ctorRole: 'arn:aws:iam::123456789012:role/constructor',
  hasOwnRole: 'arn:aws:iam::123456789012:role/hasOwnProperty',
  toStringRole: 'arn:aws:iam::123456789012:role/toString',
  quoteUser: 'arn:aws:iam::123456789012:user/"\'\\/demo-quote',
  extProto: 'arn:aws:iam::999999999999:role/__proto__',
  bucket: 'arn:aws:s3:::demo-hostile-bucket',
  cluster: 'arn:aws:eks:eu-west-2:123456789012:cluster/demo-hostile',
  pod: 'k8s://arn:aws:eks:eu-west-2:123456789012:cluster/demo-hostile/Pod/constructor/Deployment:toString',
  sa: 'k8s://arn:aws:eks:eu-west-2:123456789012:cluster/demo-hostile/ServiceAccount/constructor/hasownproperty',
  admin: 'aws-enumerator:account-admin/123456789012',
  anonymous: 'aws-enumerator:anonymous',
});

// -- graph-core pipeline -----------------------------------------------------
/** validateGraph + buildIndex in one call. */
function pipeline(C, raw) {
  const { graph, problems } = C.validateGraph(raw);
  if (!graph) throw new Error(`validateGraph rejected the document: ${JSON.stringify(problems)}`);
  const index = C.buildIndex(graph);
  return { graph, problems, index };
}

/**
 * Map path_cases.json `options` to activeSubgraph options (requests/contracts-engine-3.md section 2):
 * exclude_categories -> categories (all others enabled), exclude_node_types -> nodeTypes
 * (respectFilters: true), definite_only -> includeConditional: false.
 */
function activeOptionsFor(index, options = {}) {
  const opts = { respectFilters: true, includeConditional: !options.definite_only };
  const hiddenCats = new Set(options.exclude_categories || []);
  const hiddenTypes = new Set(options.exclude_node_types || []);
  opts.categories = hiddenCats.size ? new Set([...index.categoriesPresent].filter(c => !hiddenCats.has(c))) : null;
  opts.nodeTypes = hiddenTypes.size ? new Set([...index.typesPresent].filter(t => !hiddenTypes.has(t))) : null;
  return opts;
}

/** Drain a discoverAll generator: { events, result } (result = the generator's return value). */
function drain(gen, { max = 1e6 } = {}) {
  const events = [];
  for (let i = 0; i < max; i++) {
    const step = gen.next();
    if (step.done) return { events, result: step.value };
    events.push(step.value);
  }
  throw new Error('discoverAll did not finish within the step budget');
}

/** Code-unit string comparison (the contract's tie-break order; never localeCompare). */
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// -- misc --------------------------------------------------------------------
/** Reject if `promise` does not settle within `ms` (proves "never hangs"). */
function settlesWithin(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
  });
  return Promise.race([Promise.resolve(promise), timeout]).finally(() => clearTimeout(timer));
}

/** Own property names of Object.prototype and Array.prototype (for prototype-pollution checks). */
function protoSnapshot(realmObject = Object, realmArray = Array) {
  return {
    object: Object.getOwnPropertyNames(realmObject.prototype).sort(),
    array: Object.getOwnPropertyNames(realmArray.prototype).sort(),
  };
}

module.exports = {
  FINDINGS,
  PENDING,
  NOT_IMPLEMENTED,
  FIXTURE_GRAPH_DIR,
  OWN_FIXTURE_DIR,
  dashboardDir,
  dashboardJsFile,
  missingModule,
  requireDashboard,
  core,
  fixture,
  fixtureText,
  pathCases,
  clone,
  variant,
  nodeById,
  edgeById,
  edgesOfType,
  EX,
  HO,
  pipeline,
  activeOptionsFor,
  drain,
  cmp,
  settlesWithin,
  protoSnapshot,
};
