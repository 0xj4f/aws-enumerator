'use strict';
const { run, fmtPath } = require('./dashboard_harness');
const A = '111122223333', X = '999999999999';
const u = n => ({ UserName: n, Arn: `arn:aws:iam::${A}:user/${n}` });
const r = n => ({ RoleName: n, Arn: `arn:aws:iam::${A}:role/${n}` });
const crit = (entity) => ({ entity, severity: 'CRITICAL', id: 'X', title: 't' });

(async () => {
  // ── Scenario A: undirected traversal through shared group / shared policy / shared bucket / shared secret
  const spec = {
    users: [u('dev-user'), u('admin-user')],
    roles: [r('app-role'), r('admin-role')],
    groups: [{ GroupName: 'devs', Arn: `arn:aws:iam::${A}:group/devs` }],
    policies: [{ PolicyName: 'shared-policy', Arn: `arn:aws:iam::${A}:policy/shared-policy` }],
    ugm: { 'dev-user': [{ GroupName: 'devs' }], 'admin-user': [{ GroupName: 'devs' }] },
    uap: { 'dev-user': [{ PolicyName: 'shared-policy' }] },
    rap: { 'admin-role': [{ PolicyName: 'shared-policy' }, { PolicyName: 'AdministratorAccess' }] },
    findings: [crit('user/admin-user')],
    buckets: [{ Name: 'logs' }],
    s3: [
      { source: `arn:aws:iam::${A}:role/app-role`, target: 'bucket:logs', type: 'CAN_READ', weight: 1, category: 's3_access' },
      { source: 'bucket:logs', target: `arn:aws:iam::${A}:role/admin-role`, type: 'GRANTS_ACCESS', weight: 1, category: 's3_grant' },
    ],
  };
  const d = await run(spec);
  const cy = d.get('cy');
  console.log('nodes', cy.nodes().length, 'edges', cy.edges().length);
  // Discover All Paths (real function, incl. wrapper)
  d.get('findAllAttackPaths')();
  console.log('DiscoverAll status:', d.els['attack-paths-status'].textContent);
  for (const p of d.get('window._discoveredPaths') || []) console.log('  ', p.distance.toFixed(1), fmtPath(p.path));

  // Same graph, directed:true for comparison (same weight fn)
  console.log('-- directed:true comparison (same weight fn) --');
  for (const [s, t] of [['dev-user', 'admin-user'], ['dev-user', 'admin-role'], ['app-role', 'admin-role']]) {
    const S = cy.nodes().filter(n => n.data('label') === s), T = cy.nodes().filter(n => n.data('label') === t);
    for (const directed of [false, true]) {
      const dj = cy.elements().dijkstra({ root: S, weight: e => e.data('weight') || 1, directed });
      const dist = dj.distanceTo(T);
      console.log(`  ${s} -> ${t} directed=${directed}: ${dist === Infinity ? 'no path' : dist.toFixed(1) + '  ' + fmtPath(dj.pathTo(T))}`);
    }
  }

  // ── Scenario B: K8s cross-workload path (IRSA role A -> sa -> pod -> cluster -> pod2 -> sa2 -> IRSA role B)
  const C = 'c1';
  const spec2 = {
    roles: [r('irsa-a'), r('irsa-b')],
    rap: { 'irsa-b': [{ PolicyName: 'AdministratorAccess' }] },
    k8s: [
      { source: `sa:${C}/ns/a`, target: `arn:aws:iam::${A}:role/irsa-a`, type: 'IRSA_BRIDGE', weight: 1, category: 'k8s_irsa' },
      { source: `sa:${C}/ns/b`, target: `arn:aws:iam::${A}:role/irsa-b`, type: 'IRSA_BRIDGE', weight: 1, category: 'k8s_irsa' },
      { source: `pod:${C}/ns/p1`, target: `cluster:${C}`, type: 'IN_CLUSTER', weight: 0, category: 'k8s_structural' },
      { source: `pod:${C}/ns/p2`, target: `cluster:${C}`, type: 'IN_CLUSTER', weight: 0, category: 'k8s_structural' },
      { source: `pod:${C}/ns/p1`, target: `sa:${C}/ns/a`, type: 'RUNS_AS', weight: 0, category: 'k8s_workload' },
      { source: `pod:${C}/ns/p2`, target: `sa:${C}/ns/b`, type: 'RUNS_AS', weight: 0, category: 'k8s_workload' },
    ],
  };
  const d2 = await run(spec2);
  d2.get('findAllAttackPaths')();
  console.log('K8s DiscoverAll:', d2.els['attack-paths-status'].textContent);
  for (const p of d2.get('window._discoveredPaths') || []) console.log('  ', p.distance.toFixed(1), fmtPath(p.path));
})();
