'use strict';
// attack.js (the dashboard's ATT&CK tables) against aws_enumerator/engine/attack.py, the source of truth
// (DECISIONS.md D-58), read through the repo's Python, offline.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');
const targets = require('../helpers/targets');

const A = require(targets.dashboardJsFile('attack.js'));
const pySkip = H.pythonSkip();

const DUMP = `
import json
from aws_enumerator.engine import attack as a
print(json.dumps({
    "version": a.ATTACK_VERSION,
    "tactics": [[t.id, t.shortname, t.name] for t in a.TACTICS],
    "techniques": [[k, t.name, list(t.tactics)] for k, t in sorted(a.TECHNIQUES.items())],
    "edges": [[k, list(v)] for k, v in sorted(a.EDGE_TECHNIQUES.items())],
    "findings": [[k, list(v)] for k, v in sorted(a.FINDING_TECHNIQUES.items())],
}))
`;

describe('attack.js == engine/attack.py', { skip: pySkip }, () => {
  const engine = pySkip ? null : JSON.parse(H.runPythonCode(DUMP));

  test('the same ATT&CK version, tactics in matrix order and techniques', () => {
    assert.equal(A.VERSION, engine.version);
    assert.deepEqual(A.TACTICS.map((t) => [t.id, t.shortname, t.name]), engine.tactics);
    assert.deepEqual(A.TECHNIQUE_IDS.map((id) => { const t = A.technique(id); return [t.id, t.name, [...t.tactics]]; }), engine.techniques);
  });

  test('the same techniques for every edge type and finding id', () => {
    assert.deepEqual(A.EDGE_TYPES.map((k) => [k, [...A.edgeTechniques(k)]]), engine.edges);
    assert.deepEqual(A.FINDING_IDS.map((k) => [k, [...A.findingTechniques(k)]]), engine.findings);
  });
});

describe('attack.js lookups', () => {
  test('unknown keys, including prototype names, give nothing', () => {
    for (const k of ['__proto__', 'constructor', 'toString', '', null, 42]) {
      assert.deepEqual([...A.edgeTechniques(k)], []);
      assert.deepEqual([...A.findingTechniques(k)], []);
      assert.equal(A.technique(k), null);
    }
  });

  test('tacticsOf dedups and follows the matrix order; url points at attack.mitre.org', () => {
    assert.deepEqual(A.tacticsOf(['T1530', 'T1078.004', 'T1548.005']).map((t) => t.id), ['TA0001', 'TA0003', 'TA0004', 'TA0005', 'TA0009']);
    assert.equal(A.url('T1548.005'), 'https://attack.mitre.org/techniques/T1548/005/');
    assert.equal(A.url('T0000'), null);
    assert.equal(A.tactic('TA0112').name, 'Defense Impairment');
  });
});
