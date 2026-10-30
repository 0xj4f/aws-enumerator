# Golden ledger: E-rules (Wave 2, 2026-10-16)

E-rules owns `engine/rules/**`, `engine/graph/closure.py` and the export writers. Goldens were **not** regenerated
(ownership.md §3.5); the golden tests that move are already failing for Wave 1 reasons and stay listed as expected
failures. Other Wave 2 streams (E-net, E-data, E-compute, E-k8s) change the same `findings.json` / `graph.json` /
relationship files; the entries below cover only the E-rules part.

Measured with a scratch comparison (not shipped) of the pre-Wave-2 tree (`$RUN/scratch/ck1b`) against the same
tree plus E-rules' paths only, on every registered scenario except `malformed*` (no rule input change there):

| Scenario | legacy `analyze()` rule findings (`findings.json`) | v2 `analyze_report` rule findings (`graph.json`) |
|---|---|---|
| all_mode | 64 → 54 | 64 → 6 |
| cross_account | 91 → 76 | 91 → 4 |
| data_services | 4 → 4 | 6 → 8 |
| eks_irsa | 30 → 25 | 30 → 1 |
| hostile_strings | 42 → 37 | 42 → 13 |
| ir_leaked_key / ir_leaked_key_quarantine | 120 → 100 | 124 → 5 / 123 → 4 |
| microbench | 83 → 85 | 83 → 46 |
| poweruser_notaction | 130 → 148 | 136 → 86 |
| public_exposure | 1 → 1 | 1 → 3 |
| single_region_minimal | 30 → 25 | 30 → 2 |

("rule findings" = PRIVESC-*, DANGER-*, ADMIN-001.)

## Rule catalogue: pathfinding.cloud import and new techniques
- Findings: F-011, F-069, F-113
- Goldens: `legacy/*/analysis/findings.json`, `legacy/*/analysis/summary.json`, `legacy/all_mode_main/**/findings.json`,
  `collectors-v0/*/**/analysis/{findings,graph,summary}.json`
- Change: `rules/data/privesc.json` grows from 23 to 67 rules (PRIVESC-024 .. 067; 40 derived from pathfinding.cloud).
  New PassRole rules fire where the old catalogue had no technique (EC2 Spot, Auto Scaling, Data Pipeline, EMR,
  SageMaker jobs, Step Functions, SSM Automation, Batch, Bedrock AgentCore, App Runner, Glue sessions, Cognito
  identity pools …); existing-resource rules fire on collected stacks, notebooks, Studio profiles, ECS Exec services,
  instances (SSM / Instance Connect / user data) and launch templates; PRIVESC-009 skips users that already hold two
  access keys (PRIVESC-024 covers them with DeleteAccessKey); PRIVESC-020 also accepts a notebook lifecycle
  configuration as the way into the notebook.
- Expected diff: new `PRIVESC-0xx` records (in the legacy permission-map path mostly INFO "no passable role" notes,
  because a permission map carries no collected resources); `rules_version` 2.0.0 → 2.1.0 (findings'
  `rule_version`, `graph.generator.rules_version`, `findings.json` `rules_version`).

## Severity: closure-aware tiers
- Findings: F-068, F-016
- Goldens: as above (`findings.json`, `graph.json`, `summary.json` severity counts)
- Change: a rule finding whose target reaches the account-admin node (closure, definite) is CRITICAL (conditional
  reach: at least HIGH); a modification of another principal the source can act as becomes CRITICAL with
  `evidence.closure`; LOW for the uncollected-resource notes.
- Expected diff: some MEDIUM/HIGH PassRole / takeover / modify findings become CRITICAL (e.g. poweruser_notaction
  CRITICAL 5 → 10 in graph.json); `base_severity` moves with them.

## Subsumption and group dedup (v2 pipeline only)
- Findings: F-018, F-012
- Goldens: `collectors-v0/*/**/analysis/{graph,findings,summary}.json` (the run-root analysis)
- Change: one ADMIN-001 CRITICAL per administrator-equivalent principal replaces its PRIVESC/DANGER rows (incl. the
  INFO "no passable role" notes); DANGER-002 / DANGER-001 subsume PRIVESC-001..013 / DANGER-003,004,007 on non-admins;
  members' findings that repeat a group's are dropped and listed in the group finding's `affected_members` (members
  gain `inherited_findings`); a principal's INFO no-candidate notes and LOW uncollected-type notes collapse to one
  each. `summary.json` `subsumed_count` becomes non-zero.
- Expected diff: rule findings drop sharply on admin-heavy scenarios (table above); new `ADMIN-001` records; new
  `IS_ADMIN_EQUIVALENT` edges for admin groups and full-IAM principals.

## Legacy entry points: no-candidate notes collapsed
- Findings: F-012, F-018
- Goldens: `legacy/*/analysis/findings.json`
- Change: `_detect_privesc_paths` keeps one INFO "no passable role" record per entity (the lowest rule id, the
  others in `subsumes`), as the v2 pipeline does.
- Expected diff: INFO counts drop (e.g. all_mode 14 → 2, ir_leaked_key 28 → 4).

## Finding records: targets and evidence
- Findings: F-016, F-071 (`requests/e-core-1.md` item 2)
- Goldens: `collectors-v0/*/**/analysis/{graph,findings}.json`, `legacy/*/analysis/findings.json`
- Change: `finding.targets` holds exactly `{node_id, tier (severity), decision}`; the ARN, the qualitative tier
  (`tier_class`), probe flags, the role a resource runs as and PassRole trust facts move to
  `evidence.targets_detail`; `evidence.rule_class` is added; `via_group` is set only when every granting statement
  came through that one group; `related_node_ids` also lists the role a target runs as.
- Expected diff: those keys in rule findings; the legacy `targets` list keeps its previous content.

## Closure edges
- Findings: F-016
- Goldens: `collectors-v0/*/**/analysis/graph.json`
- Change: `graph/closure.py` adds `CAN_ESCALATE` (evidence.chain, derived_by closure) for "modify a principal you can
  act as" and `props.reaches_admin` on nodes with a traversable path to the account admin.
- Expected diff: new `CAN_ESCALATE` edges and `reaches_admin` props where such chains exist.
