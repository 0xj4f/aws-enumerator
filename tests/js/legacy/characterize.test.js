'use strict';
// Characterisation of the LEGACY dashboard (baseline d13c215), captured before the
// dashboard rewrite. INFORMATIONAL ONLY: the recorded paths are known to be wrong
// (undirected traversal F-007, `weight || 1` F-040, grant edges as pivots). These
// tests pin what the old code does so later waves can show what changed; they are
// deliberately NOT tagged [F-xxx], because a passing characterisation test is not
// evidence that a finding is fixed.
//
// Goldens: tests/golden/legacy-dashboard/<scenario>.json. Rewrite with
//   UPDATE_GOLDEN=1 node --test tests/js/legacy
// (the legacy source is read from git history, so a diff here means the harness
// or the scenarios changed, never the product).
//
// Skips cleanly outside a git checkout that contains d13c215; the parity block also
// skips when the vendored Cytoscape is missing.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const H = require('../helpers/legacy-harness');
const targets = require('../helpers/targets');
const { cytoscapeAvailability, createHeadless } = require('../helpers/cytoscape-headless');
const { SCENARIOS, GRANT_EDGE_TYPES } = require('./scenarios');

const legacy = H.legacySource();
const SKIP = legacy.ok ? false : legacy.skip;
const cyAvail = cytoscapeAvailability();
const PARITY_SKIP = SKIP || cyAvail.skip;
const UPDATE = process.env.UPDATE_GOLDEN === '1';
const GOLDEN_DIR = targets.goldenDir('legacy-dashboard');
const NAMES = Object.keys(SCENARIOS);

const dist = d => (d === Infinity || d === undefined || d === null ? 'unreachable' : d);

// The dashboard's own weight function (captured below) vs the fixed rule from the design (A4).
const LEGACY_WEIGHT = e => e.data('weight') || 1;
const NULLISH_WEIGHT = e => { const w = e.data('weight'); return typeof w === 'number' && Number.isFinite(w) && w >= 0 ? w : 1; };

function canonical(v) {
  if (Array.isArray(v)) return Array.from(v, canonical); // Array.from: main-realm arrays even for vm-realm input
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = canonical(v[k]);
    return out;
  }
  return v;
}

const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/** Run one scenario through the real legacy script and reduce it to plain, canonical data. */
async function characterize(name) {
  const { spec, description } = SCENARIOS[name];
  const d = await H.run(spec);
  const core = d.core();
  const els = d.record.elements;

  const nodes = els.filter(e => e.group === 'nodes').map(e => ({
    id: e.data.id, type: e.data.type, label: e.data.label,
    isHighValue: e.data.isHighValue === undefined ? null : e.data.isHighValue,
    maxSeverity: e.data.maxSeverity === undefined ? null : e.data.maxSeverity,
  })).sort(byId);
  const edges = els.filter(e => e.group === 'edges').map(e => ({
    id: e.data.id, source: e.data.source, target: e.data.target, type: e.data.type,
    category: e.data.category, weight: e.data.weight,
  })).sort(byId);

  // Discover All Paths, with every dijkstra() call it makes recorded by the stub.
  const before = d.record.dijkstraCalls.length;
  const da = H.discoverAll(d);
  const calls = d.record.dijkstraCalls.slice(before);
  const weightFn = calls.length ? calls[0].weight : null;
  const directedFlags = [...new Set(calls.map(c => c.directed))];

  const effective = new Map();
  if (weightFn) {
    for (const e of core.edges()) {
      const key = `${e.data('type')}|${e.data('weight')}`;
      if (!effective.has(key)) effective.set(key, { type: e.data('type'), authored: e.data('weight'), effective: weightFn(e) });
    }
  }
  const effectiveWeights = [...effective.values()].sort((a, b) => (a.type + a.authored < b.type + b.authored ? -1 : 1));

  const paths = da.paths.map(p => {
    const reversedEdgeTypes = p.edges.filter(e => e.walked === 'reversed').map(e => e.type);
    return {
      source: p.source, target: p.target, distance: p.distance, hops: p.hops,
      authoredCost: p.edges.reduce((s, e) => s + e.weight, 0),
      route: p.route,
      edges: p.edges.map(e => ({ type: e.type, weight: e.weight, walked: e.walked })),
      reversedEdgeTypes,
      directedValid: reversedEdgeTypes.length === 0,
      traversesGrantEdge: p.edges.some(e => GRANT_EDGE_TYPES.has(e.type)),
    };
  });

  const pairs = [];
  for (const p of paths) if (!pairs.some(([s, t]) => s === p.source && t === p.target)) pairs.push([p.source, p.target]);
  const directedComparison = pairs.map(([s, t]) => {
    const S = core.getElementById(s), T = core.getElementById(t);
    const und = core.elements().dijkstra({ root: S, weight: weightFn, directed: false }).distanceTo(T);
    const dir = core.elements().dijkstra({ root: S, weight: weightFn, directed: true }).distanceTo(T);
    return { from: s, to: t, undirected: dist(und), directed: dist(dir) };
  });
  const findPath = pairs.map(([s, t]) => { const r = H.findPath(d, s, t); return { from: s, to: t, cost: r.cost, hops: r.hops }; });

  const golden = canonical({
    scenario: name,
    description,
    note: 'Informational characterisation of the legacy dashboard; the paths below are known to be wrong (F-007, F-040). Not a specification.',
    legacy: { commit: legacy.commit, path: legacy.path },
    harness: 'tests/js/helpers/legacy-harness.js (DOM stub + Cytoscape-semantics stub; equal-cost routes may differ from a browser)',
    graph: {
      elementsPassedToCytoscape: els.length,
      nodeCount: core.nodes().length,
      edgeCount: core.edges().length,
      duplicateIds: core.dupIds.slice(),
      graphInfoText: d.els['graph-info'] ? d.els['graph-info'].textContent : null,
      nodes,
      edges,
    },
    pathFinding: { dijkstraCallsByDiscoverAll: calls.length, directedFlags, effectiveWeights },
    discoverAll: {
      status: da.status,
      pathCount: paths.length,
      falsePathCount: paths.filter(p => !p.directedValid || p.traversesGrantEdge).length,
      paths,
    },
    directedComparison,
    findPath,
  });
  return { golden, d, core, weightFn, directedFlags, paths };
}

function checkGolden(name, obj) {
  const file = path.join(GOLDEN_DIR, `${name}.json`);
  const rel = path.relative(targets.REPO_ROOT, file);
  const text = JSON.stringify(obj, null, 2) + '\n';
  if (UPDATE) {
    fs.mkdirSync(GOLDEN_DIR, { recursive: true });
    fs.writeFileSync(file, text);
    return 'written';
  }
  assert.ok(fs.existsSync(file), `golden missing: ${rel} (run UPDATE_GOLDEN=1 node --test tests/js/legacy)`);
  const expected = fs.readFileSync(file, 'utf8');
  if (expected !== text) {
    assert.deepStrictEqual(JSON.parse(text), JSON.parse(expected), `legacy golden drift in ${rel}; rewrite with UPDATE_GOLDEN=1 and explain it in tests/golden/CHANGES.d/`);
    assert.equal(text, expected, `formatting drift in ${rel}`);
  }
  return 'matched';
}

describe('legacy dashboard (d13c215) characterisation goldens — informational', () => {
  for (const name of NAMES) {
    test(`${name}: matches tests/golden/legacy-dashboard/${name}.json`, { skip: SKIP }, async (t) => {
      const { golden } = await characterize(name);
      t.diagnostic(`golden ${checkGolden(name, golden)}`);
    });
  }

  test('two fresh runs of every scenario are identical (determinism)', { skip: SKIP }, async () => {
    for (const name of NAMES) {
      const a = JSON.stringify((await characterize(name)).golden);
      const b = JSON.stringify((await characterize(name)).golden);
      assert.equal(a, b, `${name} is not deterministic`);
    }
  });

  test('no stale golden files', { skip: SKIP || (UPDATE ? 'UPDATE_GOLDEN=1' : false) }, () => {
    const files = fs.existsSync(GOLDEN_DIR) ? fs.readdirSync(GOLDEN_DIR).filter(f => f.endsWith('.json')).sort() : [];
    assert.deepEqual(files, NAMES.map(n => `${n}.json`).sort());
  });
});

describe('legacy dashboard behaviour, asserted explicitly — informational', () => {
  test('Discover All Paths runs dijkstra undirected with `weight || 1` (characterises F-007, F-040)', { skip: SKIP }, async () => {
    for (const name of NAMES) {
      const { directedFlags, weightFn } = await characterize(name);
      assert.deepEqual(directedFlags, [false], `${name}: directed flags`);
      const fake = w => ({ data: k => (k === 'weight' ? w : undefined) });
      assert.equal(weightFn(fake(0)), 1, 'weight 0 becomes 1');
      assert.equal(weightFn(fake(0.5)), 0.5);
      assert.equal(weightFn(fake(2)), 2);
      assert.equal(weightFn(fake(undefined)), 1);
    }
  });

  test('shared-group and shared-policy: the only path walks an edge backwards; directed search finds none', { skip: SKIP }, async () => {
    for (const [name, viaType] of [['shared-group', 'MEMBER_OF'], ['shared-policy', 'HAS_POLICY']]) {
      const { golden } = await characterize(name);
      assert.equal(golden.discoverAll.pathCount, 1, name);
      const [p] = golden.discoverAll.paths;
      assert.deepEqual(p.edges.map(e => [e.type, e.walked]), [[viaType, 'forward'], [viaType, 'reversed']], name);
      assert.equal(p.distance, 2, `${name}: two weight-0 edges cost 2`);
      assert.equal(p.authoredCost, 0, name);
      assert.deepEqual(golden.directedComparison.map(c => [c.undirected, c.directed]), [[2, 'unreachable']], name);
    }
  });

  test('shared-bucket: directed-valid path that pivots through a GRANTS_ACCESS (resource -> principal) edge', { skip: SKIP }, async () => {
    const { golden } = await characterize('shared-bucket');
    assert.equal(golden.discoverAll.pathCount, 1);
    const [p] = golden.discoverAll.paths;
    assert.deepEqual(p.edges.map(e => [e.type, e.walked]), [['CAN_READ', 'forward'], ['GRANTS_ACCESS', 'forward']]);
    assert.equal(p.directedValid, true);
    assert.equal(p.traversesGrantEdge, true);
    assert.deepEqual(golden.directedComparison.map(c => [c.undirected, c.directed]), [[2, 2]]);
  });

  test('k8s-cross-workload: pod -> cluster -> pod hop; five weight-0 edges cost 1 each', { skip: SKIP }, async () => {
    const { golden } = await characterize('k8s-cross-workload');
    assert.equal(golden.discoverAll.status, '1 paths found (2 sources -> 1 targets)');
    const [p] = golden.discoverAll.paths;
    assert.deepEqual(p.edges.map(e => e.type), ['IRSA_BRIDGE', 'RUNS_AS', 'IN_CLUSTER', 'IN_CLUSTER', 'RUNS_AS', 'IRSA_BRIDGE']);
    assert.equal(p.distance, 6);
    assert.equal(p.authoredCost, 2);
    assert.equal(p.directedValid, false);
    for (const t of ['IN_CLUSTER', 'RUNS_AS']) {
      assert.deepEqual(golden.pathFinding.effectiveWeights.find(w => w.type === t), { type: t, authored: 0, effective: 1 });
    }
  });

  test('f007-combined reproduces the repro numbers: 6 paths, all false', { skip: SKIP }, async () => {
    const { golden } = await characterize('f007-combined');
    assert.equal(golden.graph.nodeCount, 7);
    assert.equal(golden.graph.edgeCount, 6);
    assert.equal(golden.discoverAll.status, '6 paths found (4 sources -> 2 targets)');
    assert.equal(golden.discoverAll.falsePathCount, 6);
    assert.deepEqual(golden.discoverAll.paths.map(p => p.distance), [2, 2, 2, 4, 4, 6]);
    assert.equal(golden.findPath.find(f => f.from.endsWith(':user/demo-dev-user') && f.to.endsWith(':role/demo-admin-role')).cost, '2.0');
  });
});

describe('Dijkstra parity: harness stub vs vendored Cytoscape 3.30.4 headless (distances only)', () => {
  for (const name of NAMES) {
    test(`${name}: all-pairs distances agree (undirected/directed, legacy and nullish weights)`, { skip: PARITY_SKIP }, async () => {
      const d = await H.run(SCENARIOS[name].spec);
      const els = d.record.elements;
      const stub = H.stubCore(els);
      const real = createHeadless(JSON.parse(JSON.stringify(els)));
      assert.equal(real.nodes().length, stub.nodes().length, 'node count (duplicate handling)');
      assert.equal(real.edges().length, stub.edges().length, 'edge count (duplicate handling)');
      const ids = [...stub.nodes()].map(n => n.id());
      let compared = 0;
      for (const [wName, weight] of [['legacy', LEGACY_WEIGHT], ['nullish', NULLISH_WEIGHT]]) {
        for (const directed of [false, true]) {
          for (const s of ids) {
            const sd = stub.elements().dijkstra({ root: stub.getElementById(s), weight, directed });
            const rd = real.elements().dijkstra({ root: real.getElementById(s), weight, directed });
            for (const t of ids) {
              const ds = dist(sd.distanceTo(stub.getElementById(t)));
              const dr = dist(rd.distanceTo(real.getElementById(t)));
              assert.equal(ds, dr, `${wName} directed=${directed} ${s} -> ${t}`);
              if (dr !== 'unreachable' && s !== t) {
                // Each implementation's own route must cost exactly its distance.
                const rCost = rd.pathTo(real.getElementById(t)).edges().map(weight).reduce((a, b) => a + b, 0);
                const sCost = [...sd.pathTo(stub.getElementById(t))].filter(e => e.group === 'edges').map(weight).reduce((a, b) => a + b, 0);
                assert.equal(rCost, dr, `real route cost ${s} -> ${t}`);
                assert.equal(sCost, ds, `stub route cost ${s} -> ${t}`);
              }
              compared++;
            }
          }
        }
      }
      assert.ok(compared > 0);
    });

    test(`${name}: Discover All Paths gives the same (source, target, distance) list on real Cytoscape`, { skip: PARITY_SKIP }, async () => {
      const viaStub = H.discoverAll(await H.run(SCENARIOS[name].spec));
      const viaReal = H.discoverAll(await H.run(SCENARIOS[name].spec, { cytoscape: 'real' }));
      assert.equal(viaReal.status, viaStub.status);
      const key = r => r.paths.map(p => [p.source, p.target, p.distance]);
      assert.deepEqual(key(viaReal), key(viaStub));
    });
  }
});
