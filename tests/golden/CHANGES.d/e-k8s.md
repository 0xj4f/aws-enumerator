# Golden ledger: E-k8s (Wave 2, Kubernetes / EKS analyzers, `io/loaders/k8s.py`)

E-k8s replaced the d13c215 `_analyze_k8s_relationships` (one 456-line function) by the native `k8s` analyzer
(`aws_enumerator/engine/analyzers/k8s/{util,cluster,workloads,rbac,eks_identity,irsa,network}.py`) on the
policy evaluator and the GraphBuilder. The d13c215 function moved unchanged to `analyzers/k8s/legacy.py`
(re-exported for `legacy_api` and used as the pipeline's standby fallback). No golden was regenerated
(ownership.md §3.5); I1 regenerates in Wave 3 against these entries.

## No change: `legacy/<scenario>/**` (the d13c215 `analyze()` characterisation)
- Findings: —
- Goldens: `legacy/{eks_irsa,all_mode,hostile_strings,malformed,malformed_stubs,...}/analysis/k8s_relationships.json`
- Change: none. `test_legacy_analyze_golden[*]` runs `legacy_api.analyze()`, which still calls the d13c215
  function (moved verbatim to `analyzers/k8s/legacy.py`; only two unused locals, `role_by_name` and
  `sec_ctx`, were dropped). Any diff in these files is not from E-k8s.
- Expected diff: none from this stream.

## Run-root analyses: `k8s_relationships.json` rendered from the graph by the native analyzer
- Findings: F-025, F-033, F-034, F-035, F-050, F-083, F-084, F-085, F-086, F-087, F-150, F-152
- Goldens: `collectors-v0/{single,all}/**/analysis/k8s_relationships.json`, `collectors-v0/{single,all}/**/analysis/
  findings.json`, `.../analysis/summary.json` (counts), and `legacy/all_mode_main/**/analysis/{k8s_relationships,
  findings,summary}.json` (the `--all` run analyses at the run root since E-core's F-010 entry)
- Change: in every analysis made by `analyze_run` / `analyze_report` (the product paths) the k8s legacy file is
  no longer the d13c215 analyzer's output passed through E-core's adapter; E-core's legacy writer renders it
  from `graph.json` (`writers/legacy.render_from_graph`). Record shape: `{source, target, type, weight,
  category, edge_id}` (+ `has_conditions` for conditional edges); the d13c215 extra keys (`cluster`,
  `namespace`, `iam_role_known`, `access_types` …) are gone. Ids keep the d13c215 prefixes (`pod:`, `sa:`,
  `k8srole:`, `cluster:`, `nodegroup:`), but pods are aggregated by owner (`pod:<cluster>/<ns>/Deployment:web`)
  and a RoleBinding to a ClusterRole targets the namespaced instance `k8srole:<cluster>/<ns>/ClusterRole:<name>`.
  Edge-level changes:
  - `BOUND_TO` also for `User` and `Group` subjects (F-035), plus the implicit `system:masters` →
    `cluster-admin` binding;
  - `IRSA_BRIDGE` is kept for every annotated service account (non-traversable ones included, see graph.json
    `traversable`), plus one from every service account a provider-trusting role admits (F-034);
  - `EXPOSES` (ingress → service) unchanged in name.
  New graph-only edges (no legacy rendering): `CAN_RUN_AS_SA`, `MEMBER_OF_K8S_GROUP`, `CAN_REACH_NODE_IMDS`,
  `EKS_ACCESS_ENTRY`, `AWS_AUTH_MAPPING`, `POD_IDENTITY`, `PUBLIC_INBOUND` to clusters and LoadBalancer
  services.
  Finding changes:
  - `K8S-IRSA-ADMIN` only when the role's trust admits the service account and the role is admin-equivalent by
    exact ARN (F-034, F-085); otherwise `K8S-IRSA-002` (LOW, trust does not admit) or `K8S-IRSA-003` (INFO,
    trust not evaluable);
  - `K8S-RBAC-002` no longer for built-in roles (`cluster-admin`, `system:*`, `eks:*`, `rbac-defaults`; F-086);
  - `K8S-DEFAULT-SA` once per workload (pods aggregated by owner) and only when the default service account's
    token is mounted; LOW unless that account holds bindings or an IRSA role (MEDIUM) (F-086);
  - `K8S-NET-001` not for internal load balancers (annotations, LB Controller default, `internal-` hostname),
    LOW with restrictive `loadBalancerSourceRanges` (F-083); `K8S-NET-002` only for internet-facing ALB ingresses
    (definite) or non-ALB classes (conditional), never for an ALB ingress on the controller's internal default;
  - `K8S-PRIV-001` also for init and ephemeral containers (F-035);
  - new ids: `EKS-ENDPOINT-001`, `K8S-AUTH-001`, `K8S-CALLER-001` (F-033, F-152), `K8S-HOSTIPC-001`,
    `K8S-HOSTPATH-001`, `K8S-CAP-001`, `K8S-ESCALATION-001`, `K8S-RBAC-003` (F-035), `EKS-ADMIN-001`,
    `EKS-AUTH-MAP-001` (F-050);
  - every finding carries `fingerprint` and `node_id` (anchored at the cluster, workload, service account,
    role, service or ingress node).
- Expected diff (measured on the acme world, `collect --region eu-west-2`, against
  `collectors-v0/single/.../eu-west-2/analysis/k8s_relationships.json`): edges `BOUND_TO` 2 → 3 (the
  `system:masters` group binding), other edge counts equal (`CLUSTER_ROLE` 1, `EXPOSES` 1, `IN_CLUSTER` 3,
  `IRSA_BRIDGE` 2, `MOUNTS_SECRET` 1, `NODE_ROLE` 1, `RUNS_AS` 3, `SELECTS` 1); findings `K8S-RBAC-002` 1 → 0,
  new `EKS-ADMIN-001` 1, `EKS-ENDPOINT-001` 1, `K8S-CALLER-001` 1, `K8S-HOSTPATH-001` 1, `K8S-IRSA-002` 2
  (the `aws-node` annotation names the EC2 node role; the `demo-worker` Pod Identity association names a role
  that does not trust `pods.eks.amazonaws.com`); `K8S-HOSTNET-001` 2, `K8S-HOSTPID-001` 1, `K8S-NET-001` 1,
  `K8S-NET-002` 1 (`internet-facing` scheme), `K8S-PRIV-001` 1, `K8S-RBAC-001` 1 unchanged. For the
  `all_mode` scenario (two regions): `CAN_REACH_NODE_IMDS` 2 and `EKS-ENDPOINT-001` 2 are added,
  `IRSA_BRIDGE` 1 → 2 (`apps/default` → `demo-irsa-west1`: the role's trust admits that service account too,
  conditional because no pod holds an `sts.amazonaws.com` token for it), `K8S-IRSA-ADMIN` stays 1.
