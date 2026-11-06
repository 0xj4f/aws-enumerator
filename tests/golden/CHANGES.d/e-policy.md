# Golden ledger: E-policy (Wave 1, 2026-10-16)

E-policy replaced the Allow-only, action-set rule engine with the policy evaluator (`engine/policy/**`), the
principal models (`engine/iam/principals.py`) and the data-driven rules (`engine/rules/**`). The legacy entry
points (`_build_permission_map`, `_detect_privesc_paths`, `_detect_dangerous_permissions`, the ARN/glob helpers)
keep their names and signatures, so every legacy golden that contains `permission_map.json`, `findings.json`,
`summary.json` or a relationship file built with the shared ARN helpers moves. Other Wave 1 streams (E-core:
pipeline, references, summary counts; collectors) change the same files; the entries below cover only the
E-policy part. Goldens were **not** regenerated (ownership.md §3.5).

Measured with a scratch comparison (not shipped): pristine d13c215 `policy_parser` vs the new legacy entry points on the
same permission-map inputs, rule findings only:

| Scenario | rule findings before → after | severity before → after |
|---|---|---|
| all_mode (global) | 63 → 64 (+1 DANGER-009) | C22 H32 M9 → C10 H26 M14 I14 |
| cross_account | 91 → 91 | C33 H46 M12 → C15 H37 M18 I21 |
| data_services | 6 → 4 (−PRIVESC-014, −PRIVESC-019) | C2 H3 M1 → M4 |
| eks_irsa, single_region_minimal | 30 → 30 | C11 H15 M4 → C4 H12 M7 I7 |
| hostile_strings | 42 → 42 | C15 H15 M12 → C4 H10 M21 I7 |
| ir_leaked_key, ir_leaked_key_quarantine | 120 → 120 | C44 H60 M16 → C31 H43 M18 I28 |
| microbench | 108 → 83 | C41 H54 M13 → C8 H31 M12 L15 I17 |
| poweruser_notaction | 155 → 130 | C60 H76 M19 → C5 H47 M19 L22 I37 |
| malformed, malformed_stubs, public_exposure | unchanged | unchanged |

## permission_map.json: the legacy view records what d13c215 dropped
- Findings: F-001, F-014, F-015, F-052, F-006 (legacy view of attachment errors)
- Goldens: `legacy/*/analysis/permission_map.json`, `legacy/all_mode_main/**/permission_map.json`,
  `collectors-v0/*/**/analysis/permission_map.json`
- Change: entity entries keep the d13c215 keys and order; new keys appear **only when used**: on effective
  (Allow) statements `not_actions`, `not_resources`, `conditions`, `sid`, `statement_index`, `policy_arn`
  (managed policies whose document carries a `PolicyArn`); per entity `deny_statements` (Deny statements, same
  shape, group-inherited ones with `via_group`), `permissions_boundary` (`{arn, status: collected|missing,
  effective_statements, deny_statements}`), `attached_policies_error`, `inline_policy_errors`; per role
  `trust_policy` (the parsed `AssumeRolePolicyDocument`, always) and `path` (only when not `/`). Groups that
  have inline policies but no `group_attached_policies.json` entry now get an entry (and their members inherit
  it). Allow-statement `actions`/`resources` are unchanged, so an Allow NotAction statement still shows
  `actions: []` there.
- Expected diff: every role entry gains `trust_policy`; managed-policy statements gain `policy_arn`; scenarios
  with Deny / NotAction / NotResource / Condition / boundaries (poweruser_notaction, microbench,
  ir_leaked_key_quarantine, cross_account) gain the corresponding keys. No key is removed.

## findings.json / summary.json: PRIVESC-* and DANGER-* through the evaluator
- Findings: F-001, F-012, F-014, F-015, F-017, F-019, F-052, F-069, F-071
- Goldens: `legacy/*/analysis/findings.json`, `legacy/*/analysis/summary.json`,
  `legacy/all_mode_main/**/{findings,summary}.json`, `collectors-v0/*/**/analysis/{findings,summary}.json`
- Change:
  - Deny (F-014), NotAction/NotResource (F-001), conditions (F-015), permissions boundaries (F-052) and
    resource scope (F-017) decide whether a rule fires; e.g. poweruser_notaction's PowerUser role/group member
    now get DANGER-003/004/005/007/008/009/010, the Deny-iam and quarantined roles lose their PRIVESC rows, the
    boundary-capped principals' rows become conditional and drop two levels (missing boundary document).
  - PassRole rules (PRIVESC-014..020) select passable, service-trusting, more-privileged roles; without one
    the finding is INFO with `no_candidate: true` (F-012); chains must be complete (F-069), so
    `RegisterTaskDefinition`-only and `CreateFunction`-without-invoke shapes no longer fire (data_services −2).
  - Takeover / modification rules evaluate concrete targets; self-scoped `${aws:username}` grants never fire; a
    `probe` target stands for "any principal of the kind" when none is collected (F-017).
  - DANGER rules are capability probes over service resource templates (F-019): `arn:aws:iam::*:role/*`,
    `arn:aws:secretsmanager:*:*:secret:*` etc. count as unrestricted; DANGER-009 tests the concrete SSM read
    actions (all_mode +1 DANGER-009); an overlapping Deny breaks "unrestricted".
  - Severity follows `rules/severity.py`: self-modification CRITICAL, modification of others HIGH, derived
    classes from the target tier (CRITICAL admin, HIGH crown jewels the caller lacks or a probe target, MEDIUM
    otherwise), conditional decisions lowered by strength (WEAK −1, STRONG −2). Hence the CRITICAL → HIGH /
    MEDIUM / INFO shifts in the table above and the new LOW and INFO counts in `summary.json`.
  - Finding records keep every d13c215 key and add `base_severity`, `confidence`, `targets`
    (`{node_id, arn, tier (severity), tier_class, decision, probe?, role?}`), `evidence.steps` (per rule action:
    decision, granting statements wildcard-first, denies considered), and when relevant `no_candidate`,
    `via_group`, `gaps`. `matched_actions` lists the rule actions on the path that fired, including the `any`
    alternative (F-071); `source_policy` / `resource` come from the first (wildcard-first) granting statement.
  - DANGER-005's title is reworded ("May call sts:AssumeRole on any role (each role's trust policy decides)").
- Expected diff: the per-id and per-severity changes of the table above; finding count per scenario as listed.

## Relationship files: shared ARN / glob helpers are partition-agnostic and one-directional
- Findings: F-072, F-079, F-119
- Goldens: `legacy/*/analysis/{s3,secrets,lambda,kms,messaging,newsurface,extra}_relationships.json`,
  `collectors-v0/*/**/analysis/*_relationships.json` (only where the inputs exercise these cases)
- Change: `_extract_account_from_arn` returns a bare 12-digit account id (bare-id principals become
  cross-account, F-072); `_extract_bucket_from_arn` / `_arn_matches_*` accept every partition (F-119);
  secret / parameter / Lambda / KMS / simple matchers are one-directional with a case-sensitive resource part
  and never use a `*` placeholder for an unknown account (F-079); `_arn_matches_param` matches
  `GetParametersByPath` ancestors only when asked; `_action_matches` treats `[`/`]` literally (IAM has no
  character classes).
- Expected diff: none on the committed scenarios except where a policy names a resource with different case or
  in reverse-wildcard form, or a bare account id (S3 `GRANTS_ACCESS` → `GRANTS_CROSS_ACCOUNT`).

## graph.json (v1, captured by I1 in Wave 3)
- Findings: F-012, F-016 (edges), F-071
- Goldens: `v1/**` (not captured yet)
- Change: the `principals` (PRINCIPALS) and `rules` (RULES) analyzers register natively; rule findings carry
  the fields above (targets restricted by the builder to `{node_id, tier, decision}`), and the rules emit
  `CAN_PASS_ROLE_TO`, `CAN_TAKEOVER`, `CAN_MODIFY_PERMISSIONS_OF`, `CAN_ESCALATE` (to
  `aws-enumerator:account-admin/<acct>`), `CAN_UPDATE_CODE` (PRIVESC-021) and `CAN_HIJACK` (PRIVESC-022/023)
  edges. Report-level gaps `org:scp-unknown` / `org:rcp-unknown` appear when organisation data is missing.
