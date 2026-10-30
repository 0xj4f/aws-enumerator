# Golden ledger: i1-reconcile (Wave 3a integration: golden regeneration and reconciliation)

i1-reconcile is the stream that regenerated the goldens (ownership.md §3.5, D-36). Every difference between the
retired goldens and the new output was reviewed against the other ledgers in this directory; the full review, with
the ledger entry or finding behind each changed area, is `$RUN/handoffs/golden-reconciliation.md`. This file
records (1) the golden sets that changed shape, (2) the one bug the review found, and (3) the differences that no
earlier ledger entry described (each explained by a contract page, a stream handoff or a finding; none is a
defect).

## Golden sets: `legacy/**` and `collectors-v0/**` retired, `v1/**` and `collectors-v2/**` captured
- Findings: F-084, F-137 (the d13c215 engine and `main()` they characterised are gone, D-53), F-010, F-063
- Goldens removed: `legacy/<13 scenarios>/**`, `legacy/all_mode_main/**`, `collectors-v0/**`
  (copies kept outside the repository in `$RUN/scratch/i1-reconcile/goldens-before/`)
- Goldens added:
  - `v1/<scenario>/{graph,findings,summary,outcome}.json`: `engine.analyze_report` (= `aws-enumerator analyze`) on
    every `tests/fixtures/scenarios` tree from its old-layout root (the account directory for `all_mode`, the region
    directory otherwise); engine order kept, keys sorted, `generated_at` / `duration_seconds` masked
    (`tests/python/golden/test_v1_goldens.py`);
  - `collectors-v2/{single,all}/<account>/<run_id>/**`, `collectors-v2/calls-{single,all}.json`,
    `collectors-v2/console-{single,all}.json`: the v2 `collect` run of the acme world
    (`tests/python/collectors/test_collectors_v2_golden.py`);
  - `d13c215-relationship-edge-types.json`: the 62 (file, edge type) pairs the retired legacy goldens held, read by
    `engine/core/test_contracts_engine.py::test_legacy_goldens_edge_types_are_in_inventory`.
- Change against `collectors-v0` normalisation: the fixed run ids (`golden-single`, `golden-all`) are restored in
  paths and texts (no `<RUN_ID>` file names); `$AWS_ENUMERATOR_GIT_SHA=000000000000` pins `tool.git_sha` and
  `generator.git_sha` (they followed the checkout's HEAD); the manifest `tool.{python,boto3,botocore,kubernetes}`
  versions are masked (they describe the test interpreter).
- `legacy/all_mode_main` (d13c215 `main() --all` with copied scenario data) is superseded by `collectors-v2/all`
  (the v2 `collect --all` run: one `analyze_run` at the run root after both regions, `calls-all.json`
  `analyze_calls`) and `test_all_mode_analyses_once_after_every_region` (F-010, F-025, F-063).

## Bug fixed: legacy node-group names carried the ARN's uuid
- Findings: none (contract: the legacy files keep the d13c215 node-id strings, D-22, `writers/legacy.py` docstring)
- Goldens: `collectors-v2/{single,all}/**/analysis/k8s_relationships.json` (the v1 goldens hold no legacy file;
  `graph.json` is unaffected)
- Change: `engine/writers/legacy.py::legacy_ref` rendered a node group as `nodegroup:<cluster>/<name>/<uuid>`;
  d13c215 wrote `nodegroup:<cluster>/<name>`. It now keeps the first two segments of the ARN resource.
- Expected diff vs the retired goldens: none (the `NODE_ROLE` records name the node group as d13c215 did);
  test `test_v1_goldens.py::test_legacy_relationship_files_keep_the_d13c215_node_names`.

## Not described by an earlier ledger entry (explained, no defect)
- Findings / sources as listed per item.
- `trust_relationships.json` rows keep every d13c215 key and value and add `account`, `actions`, `admits`,
  `category`, `condition_strength`, `denied`, `guard`, `normalised_principal`, `provider`, `sid`,
  `statement_index` (E-core trust rewrite, `engine/iam/trust.py`; F-020, F-021, F-036, F-073). One value changes:
  a bare account-id principal (`cross_account` scenario, role `bare-account`) is `is_cross_account: true` (F-072).
- `permission_map.json` entries gain `attached_policy_arns` (E-core `restore_policy_names`; F-013: policies resolved
  by ARN, names restored for the legacy view). Every d13c215 key keeps its value (list order aside).
- A per-domain legacy file whose analyzer did not finish carries `"status"` (`skipped` for `ec2`/`s3` in scenarios
  without that data) so an empty file is not read as "nothing found" (E-core `writers/legacy.py`; F-002, F-061).
- Rule findings (PRIVESC-*, DANGER-*, ADMIN-001) of the native pipeline carry no `entity`, `entity_arn`,
  `resource`, `source_policy`, `source_type`: they are optional legacy keys (finding-identity.md §1); the anchor
  is `node_id` (F-005) and the provenance is in `evidence` (F-071).
- New finding ids in the scenario analyses beyond the domain ledgers' acme lists: `TRUST-OIDC-001`,
  `TRUST-SAML-001` and the TRUST-001 / TRUST-002 regrading (E-core; F-020, F-036, F-072, F-073);
  `IAM-USER-MFA-001` (E-compute hygiene; F-148, F-110); `K8S-AUTH-001` (E-k8s; F-033, F-152).
- Identity edges to KMS keys and secrets in `poweruser_notaction` are 6 per type, not the 7 the E-data ledger
  measured: a user whose access comes only from a traversable group reaches the resource through `MEMBER_OF` and
  the group's edge (E-data handoff, F-022); the E-data figure was measured through the d13c215 `legacy_api` path.
- `all_mode` has 8 rule findings, not the 6 of the E-rules table: E-rules analysed the scenario's `global/` directory
  (`legacy-single`, no region, D-19); the v1 golden analyses the account directory (`legacy-all`, both regions), so
  `PRIVESC-021` (existing Lambda functions) and `PRIVESC-051` (existing instances) fire on regional resources
  (F-010, F-025, F-011).
- `PUBLIC_INBOUND` to EKS clusters and Kubernetes LoadBalancer services is rendered in `ec2_relationships.json`
  (`eks_irsa`, acme): the legacy rendering is per edge type (`edge_types.py`: `PUBLIC_INBOUND` → ec2 file), so the
  E-k8s ledger's "graph-only, no legacy rendering" is inaccurate for this one type (F-037).
- `LAMBDA-PUB-001` disappears where the only public grant is `lambda:InvokeFunctionUrl` (`public_exposure`): the
  exposure is reported once, by `LAMBDA-URL-001` (E-compute; F-080).
- acme `users.json`: `+MFAActive`, `-LoginProfileCreateDate` (credential-report fields instead of per-user
  `GetLoginProfile`; C-A, F-148, F-167); `instance_profiles.json` roles in the GAAD shape and
  `policies.json` `PermissionsBoundaryUsageCount` from GAAD (C-A IAM entry, F-013, F-052).
