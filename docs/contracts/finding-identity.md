# Finding identity, `findings.json`, baselines and suppression

**Status:** frozen contract (Wave 0, stream contracts-engine; precision at the Wave 0/1 sync by
contract-arbiter in §1 `severity` and §3; Wave 3, I1 (i1-engine): the §2 discriminator rows of the D-52 findings, see [DECISIONS.md](DECISIONS.md)). Implements engine.md §6.5 (F-143, F-005,
F-163, F-074). Schema: `aws_enumerator/engine/schema/findings-1.0.schema.json` (`$id`
`urn:aws-enumerator:schema:findings:1.0`); its `$defs/finding` is byte-identical to the one in
`graph-1.0.schema.json` (a test enforces it). Reference fingerprint function:
`aws_enumerator.engine.graph.ids.finding_fingerprint`. Lifecycle code (`findings/fingerprint.py`,
`baseline.py`, `suppress.py`, `catalog.py`) is E-core's, Wave 1.

## 1. Finding record

Required keys (`model.FINDING_REQUIRED`): `fingerprint`, `id`, `legacy_ids`, `severity`, `base_severity`,
`confidence`, `node_id`, `title`, `description`, `evidence`, `remediation`, `reference`, `status`.
The record is closed (`additionalProperties: false`); domain-specific data goes in `evidence`.

| Key | Type | Meaning |
|---|---|---|
| `fingerprint` | 32 lower-case hex | Stable identity (§2). Unique within a run. |
| `id` | `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$` | Canonical finding id from `findings/catalog.py` (e.g. `PRIVESC-014`, `S3-PUBLIC-002`, `IAM-ROOT-MFA-001`, `COLLECTION-GAP-001`). |
| `legacy_ids` | array of ids | Former ids that alias this one (e.g. `SECRET-XACCT-001` ← old id). |
| `rule_version` | string, optional | `rules_version` of the rule that fired. |
| `severity` | `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` | Effective severity after the severity policy (engine.md §3.3). Always stored upper-case; consumers compare case-insensitively and exports copy it unchanged (exports.md §1). |
| `base_severity` | severity | Severity before conditional downgrades; equals `severity` when nothing was adjusted. |
| `confidence` | `definite` \| `conditional` | From the evaluator decision. |
| `category` | string, optional | Catalogue category. |
| `title`, `description` | strings | Raw text (rendered as text only). |
| `node_id` | node id | **Required.** The anchor node; it exists in `graph.json` (F-005). |
| `related_node_ids` | node ids, optional | Other nodes involved (targets, external principal…). |
| `account`, `region` | optional | Where the anchor lives (`null` region for global resources). |
| `matched_actions` | strings, optional | Rule actions that matched, sorted. |
| `evidence` | object | Provenance (engine.md §3.5): `steps[{rule_action, decision, granted[…], denies_considered}]`, `capability`, `facet`, … |
| `targets` | `[{node_id, tier, decision}]`, optional | Escalation targets and their tier. |
| `subsumes` | ids, optional | ADMIN-001 / DANGER subsumption (F-018). |
| `via_group`, `affected_members` | optional | Group findings and their members (members get `inherited_findings`). |
| `gaps` | strings, optional | Input gaps that could change the finding. |
| `remediation` | string | Remediation text from the catalogue. |
| `reference` | `https://…` or `null` | Version-pinned documentation link (F-163). |
| `detection_hint`, `validate_hint` | objects, optional | CloudTrail events; simulate/pacu hints. |
| `status` | `open` \| `suppressed` | `suppressed` requires `suppression` (§5). |
| `suppression` | `{reason, expires, owner, match}` | Present when suppressed; `match` is `fingerprint` or `rule`. |
| `baseline_state` | `new` \| `unchanged` \| `severity_changed`, optional | Set when `--baseline` is given. |
| `entity`, `entity_arn`, `source_policy`, `source_type`, `resource` | optional, legacy | Kept for one release for old consumers and exports. |

Order in files: severity rank (CRITICAL first), `id`, `node_id`, `fingerprint` (`graph.finding_sort_key`).

## 2. Fingerprint — algorithm `fp1`

```
fingerprint = sha256( "fp1" \x1f canonical_id \x1f account \x1f node_id \x1f discriminator ).hexdigest()[:32]
```

- Encoding UTF-8; `\x1f` (unit separator) between fields; lower-case hex; first 32 characters.
- `canonical_id`: the catalogue id after resolving aliases (`legacy_ids` never change a fingerprint).
- `account`: the **assessed** account (`run.account_id`), also for findings anchored at external nodes.
- `node_id`: the anchor node id, exactly (node-ids.md).
- `discriminator`: from the catalogue entry; empty for most ids. Defined so far:

  | Finding | Discriminator |
  |---|---|
  | `EBS-XACCT-001`, `RDS-XACCT-001` | the target account id |
  | `TRUST-002` | the trusted principal (normalised id) |
  | `COLLECTION-GAP-*` | `<facet>/<region>` |
  | `SUPPRESSION-EXPIRED-001` | the expired entry's fingerprint or `rule_id:node_id_glob` |
  | `EC2-EXPOSURE-001` | empty: merged per instance, security groups in evidence (removes the F-143 collision) |
  | `AMI-XACCT-001`, `LAMBDA-LAYER-XACCT-001` | the target account id (one finding per shared-with account; the matching `*_CROSS_ACCOUNT` edge starts at that account, DECISIONS.md D-52) |

  Every catalogue entry names its discriminator kind in `CatalogEntry.discriminator` (`target-account`,
  `principal`, `role-arn`, `qualifier`, …); the domain analyzers' catalogues (`FINDINGS` of each module in
  `pipeline.ANALYZER_MODULES`) are the complete list. `PARAM-XACCT-001` and `SSMDOC-XACCT-001` are one finding per
  parameter / document (empty discriminator, the accounts in `evidence.accounts`).

- A fingerprint never includes titles, severities, policy names, timestamps or run ids, so renames and
  re-runs keep it stable.

Vectors (must hold for every implementation):

| canonical_id | account | node_id | discriminator | fingerprint |
|---|---|---|---|---|
| `ADMIN-001` | `111122223333` | `arn:aws:iam::111122223333:role/admin/demo-admin-role` | `` | `0c80ca1a6b56b17fdb05e1f307aeafc5` |
| `TRUST-002` | `111122223333` | `arn:aws:iam::111122223333:role/demo-app-role` | `999999999999` | `09e028bbd285472f10764dc3807433c6` |
| `S3-PUBLIC-001` | `111122223333` | `arn:aws:s3:::demo-data-bucket` | `` | `d31b2b7fa68f40023b132034787e640e` |
| `EC2-EXPOSURE-001` | `111122223333` | `arn:aws:ec2:eu-west-2:111122223333:instance/i-0123456789abcdef0` | `` | `b6a6a7826f8360cc72068ed93b833a29` |

## 3. `analysis/findings.json`

```json
{"schema_version": "1.0.0", "tool_version": "0.3.0", "rules_version": "2.0.0",
 "account_id": "111122223333", "partition": "aws", "regions": ["eu-west-2"], "mode": "run",
 "run_id": "20260101T000000Z-a1b2c3", "generated_at": "2026-01-01T00:00:00Z",
 "findings": [ … the same records as graph.json findings[] … ]}
```

All ten keys required, no others. The `findings` key is unchanged from d13c215, so old readers that only
read `findings` keep working. `mode`/`run_id`/`regions` mirror `graph.json` `run`. `findings.json` and
`summary.json` are always written (they are not part of the legacy outputs that `legacy_outputs` controls;
graph-json.md §1).

## 4. Baseline — `--baseline <run dir | findings.json>` → `analysis/diff.json`

`$defs/diff` of the findings schema:

```json
{"schema_version": "1.0.0",
 "baseline": {"ref": "<path as given>", "schema_version": "1.0.0", "run_id": "…", "generated_at": "…Z"},
 "counts": {"new": 1, "resolved": 0, "unchanged": 7, "severity_changed": 0, "unknown": 0},
 "new":       [{"fingerprint", "id", "node_id", "severity"}],
 "resolved":  [{"fingerprint", "id", "node_id", "severity"}],
 "unchanged": [{"fingerprint", "id", "node_id", "severity"}],
 "severity_changed": [{"fingerprint", "id", "node_id", "from", "to"}],
 "unknown":   [{"fingerprint", "id", "node_id", "severity", "reason"}]}
```

Rules:

1. Match by `fingerprint` only. Suppressed findings take part like open ones.
2. In the baseline, not now → `resolved` — **unless** the finding's input facets were complete in the
   baseline and are incomplete now (denied, error, skipped…): then `unknown` with `reason` naming the facet.
   A missing permission must never look like a fix.
3. Now, not in the baseline → `new`. In both: `unchanged`, or `severity_changed` when `severity` differs.
4. Each current finding gets `baseline_state` (`new` / `unchanged` / `severity_changed`).
5. A baseline whose `schema_version` major differs, or a pre-1.0 bare `{"findings": [...]}` file, is
   **refused** with a message to re-run `aws-enumerator analyze` on the old report first.
6. Lists are sorted by (`id`, `node_id`, `fingerprint`).

## 5. Suppression — `--suppress <file>`

`$defs/suppressionFile`:

```json
{"version": 1,
 "suppressions": [
   {"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "reason": "Break-glass role, reviewed", "expires": "2027-01-31", "owner": "example-team"},
   {"rule_id": "S3-PUBLIC-001", "node_id_glob": "arn:aws:s3:::demo-public-*", "reason": "Static website buckets", "expires": "2026-12-31", "owner": null}]}
```

- Each entry has **either** `fingerprint` **or** (`rule_id` + `node_id_glob`), and requires `reason`
  (non-empty) and `expires` (`YYYY-MM-DD`). `owner` is optional.
- `rule_id` matches the canonical id or any of its `legacy_ids`. `node_id_glob` uses IAM glob semantics
  (`*` any run of characters including `:` and `/`, `?` one character, case-sensitive) against `node_id`.
- An entry is **expired** when `expires` is before the UTC date of `run.generated_at`. Expired entries are
  ignored and each produces an INFO `SUPPRESSION-EXPIRED-001` anchored at `aws-enumerator:account/<acct>`.
- Matching findings keep everything and get `status: "suppressed"` plus
  `suppression: {reason, expires, owner, match}`. They stay in `graph.json` and `findings.json`, are
  excluded from `max_severity`, from severity counts and from the exit-code decision, and are counted in
  `summary.suppressed_count`.
- A file that fails the schema is a usage error (exit 64), not a silent no-op.

## 6. Summary counts

`summary.json` keeps its legacy keys and adds `by_severity` with all five levels, `low_count`, `info_count`
(F-074), `suppressed_count`, `subsumed_count`, `unattached_count` (always 0, F-005), plus `analyzer_status`
and `evaluation_gaps` copies. Severity counts include open findings only and sum to `total_findings`.
