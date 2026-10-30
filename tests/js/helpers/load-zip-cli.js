#!/usr/bin/env node
'use strict';
// Loads a run zip (`aws-enumerator collect --zip` / `aws-enumerator package`) exactly as the dashboard does and
// prints what it found, so a Python end-to-end test can check the CLI -> zip -> dashboard core chain offline
// (tests/python/orchestration/test_e2e_fake_account.py; PLAN.md Wave 3 I1).
//
//   node tests/js/helpers/load-zip-cli.js <report.zip>
//
// Chain: AELoader.fromZip (vendored JSZip, default limits) -> findRoots -> classify -> load (digest badge
// against manifest.files) -> AEGraphCore.validateGraph -> buildIndex. stdout is one JSON object:
//   {root, kind, integrity, schema_version, run_id, account_id, mode, nodes, edges, findings, unattached,
//    problems: {<code>: count}, structural}
// `structural` counts every validateGraph problem except `operator-node-missing` (a caller that is not in the
// graph is a fact of the account, not a structural defect). Exit 0 when the graph loaded, `structural` is 0
// and the digest is `verified` or `n/a`; 1 otherwise; 64 for a usage error. Nothing is written anywhere.

const fs = require('fs');
const path = require('path');
const targets = require('./targets');
const { loadVendored } = require('./vendor-libs');

const EXIT_OK = 0;
const EXIT_FAIL = 1;
const EXIT_USAGE = 64;
const NOT_STRUCTURAL = new Set(['operator-node-missing']);

function core() {
  return {
    C: require(targets.dashboardJsFile('graph-core.js')),
    L: require(targets.dashboardJsFile('loader.js')),
  };
}

function countByCode(problems) {
  const out = {};
  for (const p of problems) out[p.code] = (out[p.code] || 0) + 1;
  return out;
}

async function loadZip(file) {
  const jszip = loadVendored('jszip');
  if (!jszip.ok) throw new Error(jszip.reason);
  const { C, L } = core();
  const bytes = fs.readFileSync(file);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const fileSet = await L.fromZip(buffer, { JSZip: jszip.lib });
  const roots = L.findRoots(fileSet);
  if (roots.length !== 1) throw new Error(`expected one run root in the zip, found ${roots.length}`);
  const root = roots[0].root;
  const kind = (await L.classify(fileSet, root)).kind;
  if (kind !== 'ok') return { root, kind };
  const loaded = await L.load(fileSet, root, { subtle: globalThis.crypto.subtle });
  const { graph, problems } = C.validateGraph(loaded.raw);
  if (!graph) return { root, kind: 'invalid', problems: countByCode(problems), structural: problems.length };
  const index = C.buildIndex(graph);
  const all = problems.concat(loaded.problems || []);
  return {
    root, kind, integrity: loaded.integrity, schema_version: graph.schemaVersion, run_id: graph.run.run_id,
    account_id: graph.run.account_id, mode: graph.run.mode, nodes: index.nodesById.size, edges: graph.edges.length,
    findings: graph.findings.length, unattached: graph.unattachedFindings.length, problems: countByCode(all),
    structural: all.filter(p => !NOT_STRUCTURAL.has(p.code)).length,
  };
}

async function main(argv) {
  if (argv.length !== 1 || argv[0].startsWith('-')) {
    process.stderr.write(`usage: node ${path.relative(process.cwd(), __filename)} <report.zip>\n`);
    return EXIT_USAGE;
  }
  let result;
  try {
    result = await loadZip(argv[0]);
  } catch (err) {
    process.stderr.write(`load-zip-cli: ${err && err.code ? err.code + ': ' : ''}${err && err.message}\n`);
    return EXIT_FAIL;
  }
  process.stdout.write(JSON.stringify(result) + '\n');
  const good = result.kind === 'ok' && result.structural === 0 && ['verified', 'n/a'].includes(result.integrity);
  return good ? EXIT_OK : EXIT_FAIL;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}

module.exports = { loadZip, main };
