'use strict';
// graph-core.js discoverAll, defaultSources, defaultTargets (docs/contracts/dashboard-core-api.md
// sections 2.6-2.8). Findings: F-037 (anonymous source), F-038 (chunked, cancellable discovery),
// F-043 (owned sources, per-source cap, no global top-N), F-146 (operator source).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C } = H.modules();
const { EX } = H;
const G = H.graphs;

const key = (p) => `${p.source}\u0000${p.target}`;

/** Checks the event protocol of section 2.6 and returns {progress, paths, result}. */
function checkedRun(index, opts) {
  const { events, result } = H.drain(C.discoverAll(index, opts));
  const progress = events.filter(e => e.kind === 'progress');
  const paths = events.filter(e => e.kind === 'path').map(e => e.result);
  assert.equal(progress.length + paths.length, events.length, 'only progress and path events');
  assert.ok(progress.length >= 1, 'at least one progress event');
  for (let i = 1; i < progress.length; i++) assert.ok(progress[i].done > progress[i - 1].done, 'done strictly increases');
  const last = progress[progress.length - 1];
  assert.equal(last.done, last.total, 'the last progress event has done === total');
  assert.deepEqual(paths.map(key).sort(), result.paths.map(key).sort(), 'yielded paths == returned paths (multiset)');
  return { progress, paths, result };
}

describe('discoverAll: event protocol and chunking (F-038)', () => {
  test('[F-038] forward mode: one progress event per chunk of sources, total = sources', () => {
    const { index } = H.pipeline(C, G.fanInGraph(60));
    const sources = [...index.nodesById.values()].filter(n => n.type === 'user').map(n => n.id);
    const targets = [...index.nodesById.keys()];
    assert.ok(targets.length >= sources.length, 'forward mode needs at least as many targets as sources');
    const { progress, result } = checkedRun(index, { sources, targets, chunkSize: 25 });
    assert.deepEqual(progress.map(p => [p.done, p.total]), [[25, 60], [50, 60], [60, 60]]);
    assert.equal(result.paths.length, 120, 'every user reaches the shared role and the admin');
  });

  test('[F-038] reverse mode (fewer targets than sources): total = targets, results identical to forward mode', () => {
    const { index } = H.pipeline(C, G.fanInGraph(30));
    const sources = [...index.nodesById.values()].filter(n => n.type === 'user').map(n => n.id);
    const reverse = checkedRun(index, { sources, targets: [G.ADMIN], chunkSize: 1 });
    assert.deepEqual(reverse.progress.map(p => [p.done, p.total]), [[1, 1]]);
    const forward = sources.map(s => C.dijkstra(index, s, G.ADMIN));
    assert.deepEqual(reverse.result.paths.map(p => ({ cost: p.cost, hops: p.hops, path: p.path, edges: p.edges })),
      forward.slice().sort((a, b) => H.cmp(a.path[0], b.path[0])));
  });

  test('[F-038] cancelling with generator.return() stops the work: no further events', () => {
    const { index } = H.pipeline(C, G.fanInGraph(100));
    const gen = C.discoverAll(index, { targets: [...index.nodesById.keys()], chunkSize: 10 });
    let progressSeen = 0;
    for (let step = gen.next(); !step.done; step = gen.next()) {
      if (step.value.kind === 'progress' && ++progressSeen === 2) break;
    }
    const ended = gen.return(undefined);
    assert.equal(ended.done, true);
    assert.equal(gen.next().done, true);
    assert.equal(progressSeen, 2);
  });

  test('[F-038] empty sources or targets give one progress event {0, 0} and no paths', () => {
    const { index } = H.pipeline(C, H.fixture('minimal'));
    for (const opts of [{ sources: [], targets: [] }, { sources: [], targets: [G.ADMIN] }]) {
      const { events, result } = H.drain(C.discoverAll(index, opts));
      assert.deepEqual(events, [{ kind: 'progress', done: 0, total: 0 }]);
      assert.deepEqual(result, { paths: [], truncatedSources: [] });
    }
  });

  test('[F-038] forward and reverse discovery agree on 150 random graphs (paths, order, caps)', () => {
    for (let seed = 1; seed <= 150; seed++) {
      const doc = H.randomGraph(seed, { n: 8, density: 0.3 });
      const { index } = H.pipeline(C, doc);
      const ids = [...index.nodesById.keys()].filter(id => id.includes(':role/'));
      const many = ids.slice(0, 6);
      const few = ids.slice(5, 7);
      const cap = 1 + (seed % 2);
      // Reverse: |targets| < |sources|. Forward over the same pairs: one run per source.
      const rev = checkedRun(index, { sources: many, targets: few, perSourceCap: cap }).result;
      const fwdPaths = [];
      const fwdTrunc = [];
      for (const s of many) {
        const r = checkedRun(index, { sources: [s], targets: few, perSourceCap: cap }).result;
        fwdPaths.push(...r.paths);
        fwdTrunc.push(...r.truncatedSources);
      }
      const sort = (list) => list.slice().sort((a, b) => (a.cost - b.cost) || (a.hops - b.hops) || H.cmp(a.source, b.source) || H.cmp(a.target, b.target));
      assert.deepEqual(rev.paths, sort(fwdPaths), `seed ${seed}`);
      assert.deepEqual(rev.truncatedSources.slice().sort(), fwdTrunc.slice().sort(), `seed ${seed}: truncated`);
      for (const p of rev.paths) assert.deepEqual(C.dijkstra(index, p.source, p.target), { cost: p.cost, hops: p.hops, path: p.path, edges: p.edges });
    }
  });
});

describe('discoverAll: sources, caps and paging (F-043)', () => {
  test('[F-043] owned nodes of any type (pod, lambda) are exactly the sources; owned paths sort first', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const owned = new Set([EX.pod, EX.lambda]);
    const everything = [...index.nodesById.keys()];
    const { result } = checkedRun(index, { owned, targets: everything, perSourceCap: Infinity });
    assert.deepEqual([...new Set(result.paths.map(p => p.source))].sort(), [EX.lambda, EX.pod].sort(),
      'both owned compute nodes are sources, and nothing else is');
    assert.ok(result.paths.some(p => p.source === EX.pod && p.target === EX.irsaRole), 'pod -> IRSA role');
    const mixed = checkedRun(index, { owned, sources: [EX.user, EX.pod], targets: everything, perSourceCap: Infinity }).result;
    const firstNonOwned = mixed.paths.findIndex(p => !owned.has(p.source));
    const lastOwned = mixed.paths.map(p => owned.has(p.source)).lastIndexOf(true);
    if (firstNonOwned >= 0 && lastOwned >= 0) assert.ok(lastOwned < firstNonOwned, 'owned-source paths come first');
  });

  test('[F-043] no global top-50: 120 sources give 120 paths; the per-source cap applies and is reported', () => {
    const { index } = H.pipeline(C, G.fanInGraph(120));
    const all = checkedRun(index, {}).result;
    assert.equal(all.paths.filter(p => p.target === G.ADMIN).length, 120);
    const fan = H.pipeline(C, G.fanOutGraph(15)).index;
    const capped = checkedRun(fan, { sources: [G.userId(0)], perSourceCap: 4 }).result;
    assert.equal(capped.paths.length, 4);
    assert.deepEqual(capped.truncatedSources, [G.userId(0)]);
    const costs = capped.paths.map(p => p.cost);
    assert.deepEqual(costs, costs.slice().sort((a, b) => a - b), 'the cheapest paths are kept');
    assert.equal(Math.max(...costs), 1, 'the kept paths are the cost-1 ones');
    const uncapped = checkedRun(fan, { sources: [G.userId(0)], perSourceCap: Infinity }).result;
    assert.equal(uncapped.paths.length, 15);
    assert.deepEqual(uncapped.truncatedSources, []);
    assert.equal(checkedRun(fan, { sources: [G.userId(0)] }).result.paths.length, 10, 'default cap is 10');
  });

  test('[F-043] results are sorted by owned first, then cost, hops, source id, target id', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const { result } = checkedRun(index, { includeDataAssets: true, perSourceCap: Infinity });
    for (let i = 1; i < result.paths.length; i++) {
      const a = result.paths[i - 1];
      const b = result.paths[i];
      const order = (a.cost - b.cost) || (a.hops - b.hops) || H.cmp(a.source, b.source) || H.cmp(a.target, b.target);
      assert.ok(order < 0, `${key(a)} before ${key(b)}`);
    }
  });
});

describe('defaultSources and defaultTargets (F-037, F-043, F-146)', () => {
  test('[F-043] owned ids present in the index win, in the given order and of any type; absent ones are dropped', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    assert.deepEqual(C.defaultSources(index, [EX.bucket, 'arn:aws:iam::111122223333:role/demo-gone', EX.pod, EX.bucket], EX.appRole), [EX.bucket, EX.pod]);
    assert.deepEqual(C.defaultSources(index, new Set([EX.sa]), null), [EX.sa]);
    const fallback = C.defaultSources(index, ['arn:aws:iam::111122223333:role/demo-gone'], null);
    assert.deepEqual(fallback, index.meta.defaultSources, 'only absent owned ids: fall back to the defaults');
  });

  test('[F-037, F-146] without owned nodes: operator first, then meta.default_sources, entry points and the anonymous node', () => {
    const raw = H.fixture('example');
    raw.meta.default_sources = [];
    const { index } = H.pipeline(C, raw);
    const sources = C.defaultSources(index, null, EX.appRole);
    assert.equal(sources[0], EX.appRole);
    assert.ok(sources.includes(EX.anonymous), 'the anonymous node is a source even when meta is incomplete');
    const rest = sources.slice(1);
    assert.deepEqual(rest, rest.slice().sort(H.cmp), 'entry points are sorted by id');
    assert.equal(new Set(sources).size, sources.length);
    const full = H.pipeline(C, H.fixture('example')).index;
    assert.deepEqual(new Set(C.defaultSources(full, null, null)), new Set(full.meta.defaultSources),
      'for a valid graph the set equals meta.default_sources');
  });

  test('[F-037] the anonymous node reaches the public bucket at zero cost in a default discovery with data assets', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    assert.ok(!C.defaultTargets(index, {}).includes(EX.bucket), 'data assets are not default targets');
    const targets = C.defaultTargets(index, { includeDataAssets: true });
    assert.ok(targets.includes(EX.bucket));
    const { result } = checkedRun(index, { includeDataAssets: true, perSourceCap: Infinity });
    const pub = result.paths.find(p => p.source === EX.anonymous && p.target === EX.bucket);
    assert.ok(pub, 'anonymous -> public bucket');
    assert.equal(pub.cost, 0);
    assert.equal(index.edgesById.get(pub.edges[0]).type, 'GRANTS_PUBLIC');
  });

  test('[F-043] targets: meta.default_targets, then props.high_value nodes sorted, then (toggle) data assets; no duplicates', () => {
    const raw = H.fixture('example');
    raw.meta.default_targets = [EX.admin];
    H.nodeById(raw, EX.secret).props.high_value = true;
    const { index } = H.pipeline(C, raw);
    const targets = C.defaultTargets(index, {});
    assert.equal(targets[0], EX.admin);
    const highValue = raw.nodes.filter(n => n.props.high_value === true && n.id !== EX.admin).map(n => n.id).sort(H.cmp);
    assert.deepEqual(targets.slice(1), highValue);
    const withData = C.defaultTargets(index, { includeDataAssets: true });
    assert.equal(new Set(withData).size, withData.length);
    for (const n of raw.nodes) {
      const isData = raw.node_types[n.type].data_asset === true || n.props.data_asset === true;
      if (isData) assert.ok(withData.includes(n.id), `${n.type} ${n.id}`);
    }
    assert.ok(!withData.includes(EX.kms) || raw.node_types.kms.data_asset === true, 'a KMS key is a data gate, not a data asset');
  });
});
