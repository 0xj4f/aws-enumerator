'use strict';
// Synthetic report specs for the legacy-dashboard characterisation (F-007 family).
// Derived from internal-docs/repro/f007_dashboard_paths.js, renamed to demo-* and
// split so each false-path mechanism has its own golden. Placeholder account only.

const A = '111122223333';
const u = n => ({ UserName: n, Arn: `arn:aws:iam::${A}:user/${n}` });
const r = n => ({ RoleName: n, Arn: `arn:aws:iam::${A}:role/${n}` });
const crit = entity => ({ entity, severity: 'CRITICAL', id: 'DEMO-CRIT-001', title: 'demo critical finding' });
const roleArn = n => `arn:aws:iam::${A}:role/${n}`;

const SCENARIOS = {
  // Two users in one group; the CRITICAL user is the target. Undirected walk:
  // user -MEMBER_OF-> group <-MEMBER_OF- user (second hop walked backwards).
  'shared-group': {
    description: 'Two users share a group; Discover All Paths reaches the CRITICAL user through the group (undirected).',
    spec: {
      users: [u('demo-dev-user'), u('demo-admin-user')],
      groups: [{ GroupName: 'demo-devs', Arn: `arn:aws:iam::${A}:group/demo-devs` }],
      ugm: { 'demo-dev-user': [{ GroupName: 'demo-devs' }], 'demo-admin-user': [{ GroupName: 'demo-devs' }] },
      findings: [crit('user/demo-admin-user')],
    },
  },

  // A user and an admin role attach the same customer-managed policy.
  'shared-policy': {
    description: 'A user and an admin role attach the same customer-managed policy; the path runs through the policy node (undirected).',
    spec: {
      users: [u('demo-dev-user')],
      roles: [r('demo-admin-role')],
      policies: [{ PolicyName: 'demo-shared-policy', Arn: `arn:aws:iam::${A}:policy/demo-shared-policy` }],
      uap: { 'demo-dev-user': [{ PolicyName: 'demo-shared-policy' }] },
      rap: { 'demo-admin-role': [{ PolicyName: 'demo-shared-policy' }, { PolicyName: 'AdministratorAccess' }] },
    },
  },

  // Principal->resource CAN_READ plus resource->principal GRANTS_ACCESS: the walk is
  // "directed-valid" but treats a bucket-policy grant as an attacker pivot.
  'shared-bucket': {
    description: 'A role reads a bucket whose policy grants an admin role; the path pivots through the GRANTS_ACCESS edge.',
    spec: {
      roles: [r('demo-app-role'), r('demo-admin-role')],
      rap: { 'demo-admin-role': [{ PolicyName: 'AdministratorAccess' }] },
      buckets: [{ Name: 'demo-logs' }],
      s3: [
        { source: roleArn('demo-app-role'), target: 'bucket:demo-logs', type: 'CAN_READ', weight: 1, category: 's3_access' },
        { source: 'bucket:demo-logs', target: roleArn('demo-admin-role'), type: 'GRANTS_ACCESS', weight: 1, category: 's3_grant' },
      ],
    },
  },

  // IRSA role A -> sa -> pod -> cluster <- pod2 <- sa2 <- IRSA role B (admin).
  'k8s-cross-workload': {
    description: 'Two workloads in one cluster; the path hops pod -> cluster -> other pod via IN_CLUSTER (undirected), weight-0 edges cost 1.',
    spec: {
      roles: [r('demo-irsa-a'), r('demo-irsa-b')],
      rap: { 'demo-irsa-b': [{ PolicyName: 'AdministratorAccess' }] },
      k8s: [
        { source: 'sa:demo-cluster/demo-ns/demo-sa-a', target: roleArn('demo-irsa-a'), type: 'IRSA_BRIDGE', weight: 1, category: 'k8s_irsa' },
        { source: 'sa:demo-cluster/demo-ns/demo-sa-b', target: roleArn('demo-irsa-b'), type: 'IRSA_BRIDGE', weight: 1, category: 'k8s_irsa' },
        { source: 'pod:demo-cluster/demo-ns/demo-pod-1', target: 'cluster:demo-cluster', type: 'IN_CLUSTER', weight: 0, category: 'k8s_structural' },
        { source: 'pod:demo-cluster/demo-ns/demo-pod-2', target: 'cluster:demo-cluster', type: 'IN_CLUSTER', weight: 0, category: 'k8s_structural' },
        { source: 'pod:demo-cluster/demo-ns/demo-pod-1', target: 'sa:demo-cluster/demo-ns/demo-sa-a', type: 'RUNS_AS', weight: 0, category: 'k8s_workload' },
        { source: 'pod:demo-cluster/demo-ns/demo-pod-2', target: 'sa:demo-cluster/demo-ns/demo-sa-b', type: 'RUNS_AS', weight: 0, category: 'k8s_workload' },
      ],
    },
  },
};

// The original repro's Scenario A, all three mechanisms at once (README: "6 paths").
SCENARIOS['f007-combined'] = {
  description: 'Shared group + shared policy + shared bucket together, as in the F-007 repro (6 discovered paths).',
  spec: {
    users: [u('demo-dev-user'), u('demo-admin-user')],
    roles: [r('demo-app-role'), r('demo-admin-role')],
    groups: SCENARIOS['shared-group'].spec.groups,
    policies: SCENARIOS['shared-policy'].spec.policies,
    ugm: SCENARIOS['shared-group'].spec.ugm,
    uap: SCENARIOS['shared-policy'].spec.uap,
    rap: SCENARIOS['shared-policy'].spec.rap,
    findings: [crit('user/demo-admin-user')],
    buckets: SCENARIOS['shared-bucket'].spec.buckets,
    s3: SCENARIOS['shared-bucket'].spec.s3,
  },
};

// Edge types whose direction is resource -> principal ("X grants Y"): walking one
// as an attacker pivot is wrong even when it is walked forwards (roadmap R-11).
const GRANT_EDGE_TYPES = new Set([
  'GRANTS_ACCESS', 'GRANTS_CROSS_ACCOUNT', 'GRANTS_PUBLIC',
  'SECRET_GRANTS_ACCESS', 'SECRET_GRANTS_CROSS_ACCOUNT', 'LAMBDA_GRANTS_INVOKE', 'LAMBDA_GRANTS_CROSS_ACCOUNT',
  'KMS_GRANTS_DECRYPT', 'KMS_GRANTS_CROSS_ACCOUNT', 'MSG_GRANTS_CROSS_ACCOUNT', 'ECR_GRANTS_CROSS_ACCOUNT',
  'DDB_GRANTS_CROSS_ACCOUNT', 'EBS_SHARED_CROSS_ACCOUNT',
]);

module.exports = { SCENARIOS, GRANT_EDGE_TYPES, ACCOUNT: A };
