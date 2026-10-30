# Golden ledger: C-K8s (Wave 1, eks and k8s collectors, `aws_enumerator/k8s/`)

C-K8s migrated `collectors/eks.py` and `collectors/k8s.py` to `collect(ctx)` (collector-context.md) and
replaced the Kubernetes client code by `aws_enumerator/k8s/{options,auth,transport,reader,projections,rbac}.py`.
No golden was regenerated (ownership.md §3.5). The entries below describe every intended difference in
`tests/golden/collectors-v0/**`; I1 regenerates them in Wave 3. At the time of writing the collectors-v0 golden
tests could not run at all (R's `cli.py`/`runner.py` were mid-refactor), so the diffs are described from the
code and from the collector tests in `tests/python/collectors/test_{eks,k8s,k8s_projections}.py`, not from a
regenerated tree.

## eks: stable shapes, pagination, access entries, Pod Identity, no add-on configuration values
- Findings: F-050, F-107, F-033 (data), F-053/F-103 (coverage contract)
- Goldens: `collectors-v0/{single,all}/111122223333/{eu-west-1,eu-west-2}/eks/*.json` (and
  `eu-west-1`/`eu-west-2` regions of `all`), `collectors-v0/calls-{single,all}.json`,
  `collectors-v0/console-{single,all}.json`
- Change:
  - every list call is paginated (`maxResults=100` + `nextToken`), so `calls-*.json` gain `maxResults` /
    `nextToken` parameter names for `ListClusters`, `ListNodegroups`, `ListFargateProfiles`, `ListAddons`;
  - new calls per cluster: `ListAccessEntries` (only for `API`/`API_AND_CONFIG_MAP` clusters),
    `DescribeAccessEntry`, `ListAssociatedAccessPolicies`, `ListPodIdentityAssociations`,
    `DescribePodIdentityAssociation`;
  - new files `access_entries.json` and `pod_identity_associations.json` (`{cluster: [...]}`) and
    `_coverage.json`;
  - every file is always written with its stable shape, also in a region without clusters (before: only
    `clusters.json: []`);
  - `{"Error": ...}` objects are gone: a failed per-cluster listing omits the cluster key; a failed describe
    keeps `{nodegroupName|fargateProfileName|addonName, clusterName, CollectionErrors}` (before
    `{"name", "Error"}`); a failed `DescribeCluster` keeps `{name, arn, CollectionErrors}` (before
    `{"name", "Error"}`) and the cluster's listings are still attempted (before: skipped with `continue`), so in
    eu-west-1 `demo-denied-cluster` may now appear as a key in the per-cluster files;
  - `addons.json`: `configurationValues` replaced by `configurationValuesPresent: bool` (the
    `eks_addon_config` canary disappears);
  - clusters and per-cluster lists are sorted by name;
  - console: the `[+] EKS Enumeration ...` / `[!] EKS list_clusters failed` print lines are gone (logging).
- Expected diff: the per-region `eks/` directories gain 3 files; error strings are replaced by
  `CollectionErrors`; `addons.json` loses `configurationValues`.

## k8s: projections, no Secret listing by default, nodes, rules review, aws-auth
- Findings: F-009, F-054, F-035 (data), F-033 (data), F-050, F-062, F-120, F-149, F-150, F-152, F-136
- Goldens: `collectors-v0/{single,all}/111122223333/{eu-west-1,eu-west-2}/k8s/**`,
  `collectors-v0/console-{single,all}.json`, and through the legacy engine
  `collectors-v0/single/111122223333/eu-west-2/analysis/{k8s_relationships,findings}.json` and
  `collectors-v0/all/111122223333/global/analysis/{k8s_relationships,findings}.json`
- Change:
  - list files hold **projections** (snake_case keys, only the fields of collectors-cli.md §5.16) instead of
    the full `to_dict()`: no `managed_fields`, no `kubectl.kubernetes.io/last-applied-configuration`,
    annotation values `null` except the allow-list, container `env` reduced to
    `{name, value_from, value_present}`, no `command`/`args`, no `status` beyond `phase`; Role/ClusterRole
    items carry `kind`;
  - `secrets.json` is no longer written by default (no `/secrets` request); with `--k8s-secrets` it is a
    metadata-only list `{name, namespace, type, labels, annotations}`;
  - new files per reachable cluster: `nodes.json`, `self_rules.json`, `aws_auth.json`; new
    `<region>/k8s/_coverage.json`;
  - `cluster_info.json` has the new field set (`auth_mode`, `auth_status`, `error_code`, `error`, `version`
    as `{major, minor, git_version, platform}`, endpoint access fields, `endpoint_hint`, rules-review fields,
    `secrets_listed`, `resources{...}`); a cluster without endpoint (eu-west-1 `demo-denied-cluster`) now gets
    a `cluster_info.json` with `auth_status: "skipped"` (before: no directory); `demo-west-cluster` (401) is
    `auth_status: "failed"`, `error_code: "Unauthorized"`;
  - console: the `[+] K8s Enumeration ...` / `[!] Cluster ...` print lines are gone (logging);
  - the canaries `k8s_secret_last_applied`, `k8s_pod_env`, `k8s_init_container_env` (and `eks_addon_config`,
    above) disappear from every report file.
- Expected diff (analysis, legacy engine): `K8S-RBAC-002` for the ClusterRole `cluster-admin` now reads
  `ClusterRole cluster/cluster-admin has * on * ...` (title and description) instead of `Role ...`, because the
  legacy engine takes the kind from the item and `to_dict()` list items had `kind: null`. Edges and every other
  finding are unchanged: the engine-field parity test
  (`tests/python/collectors/test_k8s_projections.py::test_every_field_the_engine_reads_survives_the_projection`)
  shows every field path the legacy analyzer reads keeps its value.

## Not a golden file, but frozen test data to update with the regeneration
- `tests/python/collectors/test_collectors_v0_golden.py::LEGACY_V0_LEAKED_CANARIES` must drop
  `eks_addon_config`, `k8s_init_container_env`, `k8s_pod_env` and `k8s_secret_last_applied`
  (`test_canary_leak_inventory` fails until then). Change request `requests/c-k8s-1.md`.
