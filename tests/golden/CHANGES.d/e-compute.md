# Golden change ledger: E-compute (Wave 2)

E-compute replaced the d13c215 Lambda, compute and messaging analyzers with native analyzers on the policy
evaluator, added `analyzers/cognito.py`, `analyzers/coverage_gaps.py` and `iam/hygiene.py`, and rewrote the
`lambda_` / `compute` / `messaging` loaders. Every intended golden diff caused by that is listed here. The
d13c215 functions (`_analyze_lambda_relationships`, `_analyze_compute_relationships`,
`_analyze_messaging_relationships` and their helpers) are kept **verbatim** for `legacy_api` (one release) and as
the pipeline's standby fallback (only an unused loop variable was renamed and `a; b; break` lines were split for
ruff, behaviour unchanged).

## No diff in `tests/golden/legacy/**`
- Findings: —
- Goldens: `legacy/<every scenario>/analysis/*`, `legacy/all_mode_main/**`
- Change: none from E-compute. `test_legacy_goldens.py` runs `legacy_api.analyze()`, i.e. the d13c215 orchestration
  over the verbatim d13c215 functions above. (These goldens already fail because of other streams' ledgered
  changes; nothing in `lambda_relationships.json`, `compute_relationships.json` or `messaging_relationships.json` of
  those scenarios changes because of E-compute.)

## Lambda relationship file and findings of collector runs
- Findings: F-001, F-004, F-014, F-015, F-055, F-059, F-080, F-116
- Goldens: `collectors-v0/{single,all}/<account>/<run_id>/analysis/lambda_relationships.json`, `findings.json`,
  `summary.json`, `graph.json` (new file, E-core's entry)
- Change: the native `lambda` analyzer (identity edges from the evaluator, function policies of the function **and
  every alias** attached to the unqualified node, URL findings that need a public grant, layers, event source
  mappings); `lambda_relationships.json` is rendered from graph.json through `EdgeType.legacy_*`.
- Expected diff (acme, measured on the single-region run): `CAN_UPDATE_CODE` 15 (unchanged), `USES_ROLE` 3
  (unchanged), `LAMBDA_GRANTS_PUBLIC` 1 → 2 (the alias `live` URL grant of `demo-internal`, F-055),
  `LAMBDA_GRANTS_CROSS_ACCOUNT` 1 (unchanged), `LAMBDA_GRANTS_INVOKE` 0 → 1 (a same-account/service grant
  d13c215 skipped); `CAN_EXPOSE` edges render under the old name `CAN_MODIFY_CONFIG`; every record gains `edge_id`
  and the canonical `category`; grant records keep the d13c215 direction (`lambda:<arn>` → grantee). Findings:
  `LAMBDA-URL-001` 1 → 2 (alias URL of `demo-internal`), new `LAMBDA-LAYER-PUB-001` (MEDIUM, public layer
  `demo-deps:3`), `LAMBDA-XACCT-001` unchanged; a NONE-auth URL without a public grant would now be
  `LAMBDA-URL-002` (INFO) instead of `LAMBDA-URL-001` (none in acme). In `--all` mode the file was empty in the
  golden (F-010) and now holds both regions' edges (20 `CAN_UPDATE_CODE`, 4 `USES_ROLE`, …).

## Compute relationship file of collector runs
- Findings: F-004, F-049, F-051, F-113
- Goldens: `collectors-v0/{single,all}/<account>/<run_id>/analysis/compute_relationships.json`, `findings.json`,
  `summary.json`
- Change: one ECS node per (family, role set) with the revisions as props; the execution role is `EXECUTION_ROLE`
  (rendered as `USES_ROLE` in the legacy file, as `edge_types.py` says); control edges come from the per-action
  table (`CAN_HIJACK` / `CAN_EXEC` / `CAN_MODIFY`, all three rendered as `CAN_MODIFY`); new surfaces (SageMaker
  Studio domains and user profiles, CloudFormation StackSets, ECS services with ECS Exec, Glue dev endpoints).
- Expected diff (single-region acme): `CAN_MODIFY` 40 → 69 and `USES_ROLE` 8 → 12 (new SageMaker domain/profile,
  StackSet and ECS service nodes; the ECS execution-role edges; d13c215 had one node per task-definition
  revision, now one per role set); targets are full ARNs (`ecstask:arn:…:task-definition/<family>` without the
  revision, Glue `job/<name>` ARNs instead of bare names). New finding `CODEBUILD-WEBHOOK-001` only for projects
  with a webhook (none in acme). `--all`: the empty file now holds both regions' edges (73 / 13).

## Messaging relationship file of collector runs
- Findings: F-001, F-014, F-015, F-030, F-031, F-116
- Goldens: `collectors-v0/{single,all}/<account>/<run_id>/analysis/messaging_relationships.json`, `findings.json`
- Change: identity edges from the evaluator: `CAN_ADMIN_MSG` when the principal can rewrite the policy (it implies
  the rest), else `CAN_RECEIVE` and `CAN_SEND` separately (d13c215 emitted one edge per statement with the
  strongest class); same-account grants in a queue/topic policy count (same-account union); `SUBSCRIBES` and
  `MSG_ENCRYPTED_BY` edges are new graph edges without a legacy rendering (they do not appear in the file).
- Expected diff (single-region acme): `CAN_ADMIN_MSG` 16 → 20 and `CAN_RECEIVE` 2 → 3, all five new edges target
  `demo-denied-queue` (C-B now keeps a queue whose attributes were denied, F-102, and its unknown policy no longer
  hides identity grants); `CAN_SEND` 1 and `MSG_GRANTS_CROSS_ACCOUNT` 1 unchanged, `MSG-XACCT-001` unchanged; no
  edge disappears. `--all`: the empty file now holds both regions' edges.

## New findings in every collector run's findings.json / summary.json
- Findings: F-148, F-110 (hygiene), F-058/F-059 (collection gaps), F-032/F-048 (Cognito)
- Goldens: `collectors-v0/{single,all}/<account>/<run_id>/analysis/findings.json`, `summary.json`, `graph.json`
- Change: `iam-hygiene` (phase IDENTITY), `coverage-gaps` (phase POSTPROCESS), `cognito` (phase RESOURCES).
- Expected diff (single-region acme): `IAM-KEY-AGE-001` ×3 (keys of `demo-alice`, `demo-bob`, `demo-ci` older than
  365 days at the run's reference time: MEDIUM), `IAM-ALTCRED-001` ×3 (SSH key, signing certificate,
  service-specific credential), `IAM-PWPOL-001` ×1 (no password policy, a console user: MEDIUM),
  `COLLECTION-GAP-001` ×24 (`--all`: ×45; one per failing API and unit of acme's denied calls),
  `COGNITO-CLASSIC-001` ×2 (pools with `AllowClassicFlow`; MEDIUM when a role trusts the pool, else LOW),
  `COGNITO-UNAUTH-001` ×1 unchanged (pool `…5a` has guest access on). The finding-count fields of `summary.json`
  (`total_findings`, `by_severity`, `info_count`, `by_category` …) change accordingly. In graph.json the Cognito
  pools also get `COGNITO_PUBLIC_IDENTITY` / `POOL_*` edges with the guest-access and auth-path gates, user pools
  are `cognitouserpool` nodes, and failing items carry `coverage.status = partial`.

## Not a golden change (for the record)
- `tests/golden/v1/**` is captured by I1 in Wave 3 (D-36); E-compute's tests validate every emitted graph with the
  schema and `validate_graph(strict_order=True)` (`tests/fixtures/e-compute/kit.py::problems`).
- `collectors-v0/calls-*.json`, `console-*.json`: no E-compute change (analysis issues no AWS call).
