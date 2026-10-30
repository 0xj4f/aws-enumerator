'use strict';
// graph-core.js reading graph.json 1.1 merged graphs (graph-json.md sections 4.2 and 10; dashboard-core-api.md
// section 2.2): the normalisers keep run.sources and the per-account keys (account / accounts) instead of
// dropping them, and a 1.0 graph reads with empty / null defaults. The merged document is built by the real
// engine (`aws-enumerator merge` logic) from example.json + hostile.json. Finding: F-126.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C } = H.modules();
const pySkip = H.pythonSkip();

describe('graph 1.1: merged graphs keep their sources and per-account coverage (F-126)', () => {
  test('[F-126] run.sources is normalised: one record per source run with operator, generator and digest', { skip: pySkip }, () => {
    const raw = H.mergedGraph();
    const { graph, problems } = C.validateGraph(raw);
    assert.ok(graph, 'the merged graph is refused');
    assert.deepEqual(problems.filter(p => p.level === 'error'), []);
    assert.equal(graph.schemaVersion, '1.1.0');
    assert.equal(graph.run.mode, 'merge');
    assert.deepEqual(graph.run.sources.map(s => s.account_id), ['111122223333', '123456789012']);
    for (const [i, s] of graph.run.sources.entries()) {
      const r = raw.run.sources[i];
      assert.equal(s.run_id, r.run_id);
      assert.deepEqual(s.regions, r.regions);
      assert.equal(s.graph_sha256, r.graph_sha256);
      assert.match(s.graph_sha256, /^[0-9a-f]{64}$/);
      assert.equal(s.mode, r.mode);
      assert.equal(s.generated_at, r.generated_at);
      assert.equal(s.operator.resolution, r.operator.resolution);
      assert.equal(s.operator.node_id, r.operator.node_id);
      assert.equal(s.generator.version, r.generator.version);
    }
  });

  test('[F-126] coverage modules, denied APIs, facets, gaps and analyzer status keep their account(s)', { skip: pySkip }, () => {
    const raw = H.mergedGraph();
    const { graph } = C.validateGraph(raw);
    assert.equal(graph.coverage.modules.length, raw.coverage.modules.length);
    for (const [i, m] of graph.coverage.modules.entries()) assert.equal(m.account, raw.coverage.modules[i].account);
    assert.deepEqual(new Set(graph.coverage.modules.map(m => m.account)), new Set(['111122223333', '123456789012']));
    for (const [i, d] of graph.coverage.denied_apis.entries()) assert.equal(d.account, raw.coverage.denied_apis[i].account);
    for (const [i, g] of graph.evaluationGaps.entries()) assert.deepEqual(g.accounts, raw.evaluation_gaps[i].accounts);
    assert.ok(graph.evaluationGaps.some(g => g.accounts.length === 2), 'a gap reported by both accounts');
    for (const [i, a] of graph.analyzerStatus.entries()) assert.equal(a.account, raw.analyzer_status[i].account);
  });

  test('[F-126] no single operator; every source operator present in the graph is a default source', { skip: pySkip }, () => {
    const { graph } = C.validateGraph(H.mergedGraph());
    assert.deepEqual(C.operatorNode(graph), { id: null, resolution: 'unavailable' });
    const index = C.buildIndex(graph);
    const sources = C.defaultSources(index, null, null);
    for (const s of graph.run.sources) {
      if (s.operator && s.operator.node_id && index.nodesById.has(s.operator.node_id)) {
        assert.ok(sources.includes(s.operator.node_id), `${s.operator.node_id} is not a default source`);
      }
    }
  });

  test('a 1.0 graph reads with no sources and null / empty per-account keys', () => {
    const { graph } = C.validateGraph(H.fixture('example'));
    assert.deepEqual(graph.run.sources, []);
    assert.ok(graph.coverage.modules.length > 0);
    assert.ok(graph.coverage.modules.every(m => m.account === null));
    assert.ok(graph.evaluationGaps.every(g => Array.isArray(g.accounts) && g.accounts.length === 0));
    assert.ok(graph.analyzerStatus.every(a => a.account === null));
  });

  test('[F-042] malformed or prototype-named source records are inert', { skip: pySkip }, () => {
    const raw = H.mergedGraph();
    raw.run.sources.push('not-an-object', null, 42, JSON.parse('{"__proto__": {"polluted": true}, "account_id": 7}'));
    raw.coverage.modules.push({ module: 'iam', region: 'global', status: 'ok', account: { nested: 'object' } });
    const { graph } = C.validateGraph(raw);
    assert.equal(graph.run.sources.length, 3);
    const odd = graph.run.sources[2];
    assert.equal(odd.account_id, null, 'a non-string account id is not shown');
    assert.equal(odd.polluted, undefined);
    assert.equal({}.polluted, undefined, 'Object.prototype was polluted');
    assert.deepEqual(odd.regions, []);
    assert.equal(graph.coverage.modules[graph.coverage.modules.length - 1].account, null);
  });
});
