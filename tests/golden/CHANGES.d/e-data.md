# Golden change ledger: E-data (Wave 2)

E-data replaced the d13c215 KMS, Secrets Manager / SSM and data-store (ECR, DynamoDB, RDS, API Gateway) analyzers
with native analyzers on the policy evaluator (`analyzers/{kms,secrets,data_stores}.py`) and rewrote their loaders
(`io/loaders/{kms,secrets,data_stores}.py`). Unlike E-net and E-compute, the d13c215 entry points of these three
modules (`_analyze_kms_relationships`, `_analyze_secrets_relationships`, `_analyze_newsurface_relationships`) are
**thin adapters over the native code** (R-13: no raw `stmt['actions']` walker is left in the module; the private
`_resource_policy_grants` walker is deleted, D-39, and its name is a thin alias over
`Evaluator.resource_policy_grants`). So `legacy_api.analyze()` — what `tests/python/golden/test_legacy_goldens.py`
runs — now writes the three files from the native graph, and the legacy goldens of every scenario that has KMS,
Secrets Manager, SSM, ECR, DynamoDB, RDS or API Gateway data change as listed below. Counts were measured with
`legacy_api.analyze()` on the scenario trees and with the acme `collect` runs of the collectors-v0 harness.

## Record shape of the three files (every scenario)
- Findings: F-022, F-037, F-039, F-088, F-164
- Goldens: `legacy/<scenario>/analysis/{kms,secrets,newsurface}_relationships.json`,
  `collectors-v0/{single,all}/…/analysis/{kms,secrets,newsurface}_relationships.json`
- Change: the files are rendered from `graph.json` by `writers.legacy.render_from_graph` (`EdgeType.legacy_*`):
  edge records are `{source, target, type, weight, category, edge_id, matched_actions?, has_conditions?,
  is_cross_account?}` (no `access_types`, `source_policy`, `source_type`, `granted_actions`,
  `is_wildcard_resource`, `kms_key_arn`, `api_name`, `param_type`); one record per (source, type, target) instead
  of one per policy statement (F-022); grant edges keep the d13c215 direction (`kms:<arn>` / `secret:<arn>` /
  `ecr:<arn>` / `dynamodb:<arn>` → grantee, `principal:*` for public); findings carry `fingerprint`, `node_id`,
  `reference` and the catalogue `category`/`remediation`.
- Expected diff: field-level differences in every edge and finding record of the three files; record counts as
  in the sections below.

## Key-policy-first KMS edges (F-028, F-029, F-031)
- Findings: F-001, F-014, F-015, F-028, F-029, F-031, F-081
- Goldens: `legacy/{all_mode,cross_account,data_services,poweruser_notaction}/analysis/kms_relationships.json`,
  `findings.json`, `summary.json`; `collectors-v0/single/…/analysis/kms_relationships.json`
- Change: IAM permissions count only when the key policy delegates to the account; principals named in the key
  policy get `KMS_GRANTS_DECRYPT` (decrypt) / `CAN_ADMIN_KEY`; `GenerateDataKey*` is `CAN_ENCRYPT` (rendered only
  when no decrypt/admin edge exists); decrypt and admin are separate edges (d13c215 emitted one type per pair);
  `kms:CallerAccount`-guarded `*` statements are not public; every decrypt-capable grant gives `KMS_GRANT`
  (service grantees included); NotAction grants (PowerUser) reach keys.
- Expected diff: `all_mode` CAN_DECRYPT 2 → 6; `cross_account` +3 CAN_DECRYPT; `data_services` CAN_DECRYPT
  1 → 10 (the key policy grants `kms:Decrypt` to every principal of the account through
  `"*" + kms:CallerAccount`), KMS_GRANT 1 → 2 (the `rds.eu-west-2.amazonaws.com` service grant),
  KMS_GRANTS_PUBLIC 1 → 0 (CallerAccount-guarded, F-031); `poweruser_notaction` CAN_ADMIN_KEY 4 → 7 and
  CAN_DECRYPT 0 → 7 (NotAction, F-001); acme single-region run: CAN_ADMIN_KEY 12 → 16, CAN_DECRYPT 1 → 16,
  KMS_GRANT 1, KMS_GRANTS_DECRYPT 0 → 1. KMS-XACCT-001 counts unchanged.

## Secrets Manager / SSM edges and findings (F-026, F-027, F-079, F-086, F-088, F-114, F-116)
- Findings: F-001, F-026, F-027, F-031, F-079, F-086, F-088, F-114, F-116
- Goldens: `legacy/{all_mode,cross_account,data_services,hostile_strings,poweruser_notaction}/analysis/
  secrets_relationships.json`, `findings.json`, `summary.json`; `collectors-v0/single/…/analysis/
  secrets_relationships.json`, `findings.json`, `summary.json`
- Change: `CAN_READ_SECRET` needs GetSecretValue (metadata actions no longer read, F-026) but read and write are now
  separate edges (d13c215 kept only the write edge when both were granted); `SECRET_GRANTS_ACCESS` is folded into
  the effective-access edges; `SECRET_ENCRYPTED_BY` is also drawn for secrets without `KmsKeyId` (default
  `aws/secretsmanager`, resolved to the collected key or a region-qualified placeholder, F-027);
  `SECRET-XAUTH-001` is reported as `SECRET-XACCT-001` (old id in `legacy_ids`, remediation without ExternalId,
  F-088); new findings `SSMDOC-PUB-001` / `SSMDOC-XACCT-001` / `PARAM-XACCT-001` from the new collector files.
- Expected diff: `all_mode` CAN_READ_SECRET 2 → 6; `cross_account` +3 CAN_READ_SECRET, +1 SECRET_ENCRYPTED_BY,
  finding id `SECRET-XAUTH-001` → `SECRET-XACCT-001`; `data_services` SECRET_GRANTS_ACCESS 1 → 0,
  SECRET_ENCRYPTED_BY 1 → 2, `SECRET-XAUTH-001` → `SECRET-XACCT-001`; `hostile_strings` CAN_READ_SECRET 12 → 15,
  SECRET_ENCRYPTED_BY 0 → 3 (defaults); `poweruser_notaction` CAN_WRITE_SECRET 4 → 7, CAN_READ_SECRET 0 → 7,
  `PARAM-PLAIN-001` counts unchanged in these scenarios (their names are whole-token matches); acme single-region
  run: CAN_READ_SECRET 6 → 28, CAN_WRITE_SECRET 16 → 20, CAN_READ_PARAM 15 → 19, SECRET_ENCRYPTED_BY 1 → 5,
  SECRET_GRANTS_CROSS_ACCOUNT 0 → 1 (+ `SECRET-XACCT-001`), `SSMDOC-PUB-001` 1, `SSMDOC-XACCT-001` 1.

## Data stores (F-031, F-044, F-056, F-082, F-099, F-116)
- Findings: F-031, F-044, F-056, F-082, F-099, F-116
- Goldens: `legacy/data_services/analysis/newsurface_relationships.json`, `findings.json`, `summary.json`;
  `collectors-v0/single/…/analysis/newsurface_relationships.json`, `findings.json`, `summary.json`
- Change: DynamoDB read and write are separate edges (PartiQL and export actions added); public/cross-account
  grants graded by the shared resource-policy walker; `APIGW-AUTH-001` only for routes whose effective
  authorisation is NONE (one finding per API, routes in evidence); RDS sharing (`RDS-XACCT-001` per target
  account, cluster snapshots), ECR registry policy (`ECR-REGISTRY-001`) and replication (`ECR-REPLICATION-001`).
- Expected diff: `data_services` CAN_READ_TABLE 2 → 4 (write-capable principals also get the read edge), finding
  counts unchanged; acme single-region run: CAN_WRITE_TABLE 8 → 12, CAN_READ_TABLE 0 → 12, RDS_ENCRYPTED_BY
  2 → 4 (the `demo-aurora` cluster and its `demo-aurora-snap-shared` cluster snapshot, collected since C-B's
  F-056 change), APIGW-AUTH-001 1 → 2 (`demo-http-api` has an authorizer object but one Lambda route with
  effective authorisation NONE: the F-044 false negative; the `demo-rest-api` finding is now per route),
  RDS-SNAP-001 1 → 2 (public Aurora cluster snapshot), new `RDS-XACCT-001` ×2, `ECR-REGISTRY-001` 1,
  `ECR-REPLICATION-001` 1.

## `--all` runs and graph.json of collector runs
- Findings: F-010 (engine side, E-core), F-027, F-059
- Goldens: `collectors-v0/all/…/analysis/{kms,secrets,newsurface}_relationships.json` (empty in the golden because
  d13c215 analysed before collection), `collectors-v0/{single,all}/…/analysis/graph.json` (E-core's new file)
- Change: both regions' data now (acme two-region run: CAN_ADMIN_KEY 20, CAN_DECRYPT 20, CAN_READ_PARAM 23, the
  rest as the single-region run); KMS/secret/data-store nodes with node coverage and the evaluation gaps
  `kms:key-policy-unknown`, `kms:grants-unknown`, `kms:aliases-unknown`, `secrets:resource-policy-unknown`,
  `data-stores:resource-policy-unknown`, `rds:snapshot-sharing-unknown` where acme denies the reads.
- Expected diff: as described; no `legacy:unknown-lists-as-empty` gap from these three domains any more (they read
  `null` as unknown natively, `requests/c-b-1.md`).
