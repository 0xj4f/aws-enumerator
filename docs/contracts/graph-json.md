# `graph.json` 1.x — the graph contract (1.0; 1.1 adds `merge`)

**Status:** frozen contract (Wave 0, stream contracts-engine, 2026-10-16; prose precisions at the Wave 0/1
sync by contract-arbiter in §1, §4, §4.1, §10.1, §10.2, §11.7 and §15; **minor version 1.1** approved at the
Wave 1/2 sync by contract-arbiter (request `e-core-2`, D-42 to D-45): §1, §2, §4, new §4.2, §5, §10, §12, §14,
§16; the 1.0 schema and the table are unchanged; Wave 3, I1 (i1-engine): §3, §8.1, §10.2, §10.3, §12.1, §14 for
the table additions, the removal of the legacy adapter and the compiled schema check, D-52 to D-55; §4.2 and §16
say that the dashboard shows the merged view since Wave 3a). Changes go
through a change
request (`$RUN/requests/<stream>-<n>.md`). Where this page and a design document disagree, this page wins;
where it disagrees with `internal-docs/fix-plan/PLAN.md`, PLAN.md wins.

**Machine-readable sources (normative):**

| What | Where |
|---|---|
| Structural schema (JSON Schema draft 2020-12) | `aws_enumerator/engine/schema/graph-1.0.schema.json` (1.0.x documents); `aws_enumerator/engine/schema/graph-1.1.schema.json` (1.1.x: 1.0 plus the additive merge keys of §4.2; every 1.0 document is also a valid 1.1 document) |
| Semantic invariants the schema cannot express | `aws_enumerator.engine.graph.validate_graph()` (codes in §12) |
| Edge types, node types, traversability, weights | `aws_enumerator/engine/graph/edge_types.py` → [traversability-table.md](traversability-table.md) |
| Node, edge and finding identity | `aws_enumerator/engine/graph/ids.py` → [node-ids.md](node-ids.md), [finding-identity.md](finding-identity.md) |
| Python record types | `aws_enumerator/engine/model.py` (`Node`, `Edge`, `Finding`, `AnalyzerStatus`) → [engine-api.md](engine-api.md) |
| Path semantics (shared Python/JS vectors) | `tests/fixtures/graph/path_cases.json`, reference `tests/support/ref_paths.py` |
| Valid / invalid examples | `tests/fixtures/graph/`, `tests/fixtures/graph-invalid/` (+ `expectations.json`) |

A document is **valid** when it passes the schema **and** `validate_graph(doc)` returns no problems.
The engine's writer asserts both before it renames `analysis.tmp/` into place; the dashboard checks the
subset in §12.3 and degrades (never crashes) on anything else.

Contents: 1 [File](#1-file) · 2 [Top level](#2-top-level-object) · 3 [generator](#3-generator) ·
4 [run](#4-run) · 5 [meta](#5-meta) · 6 [Registries](#6-node_types-and-edge_types) · 7 [Nodes](#7-nodes) ·
8 [Edges](#8-edges) · 9 [Findings](#9-findings) · 10 [coverage, evaluation_gaps, analyzer_status](#10-coverage-evaluation_gaps-analyzer_status) ·
11 [Path semantics](#11-path-semantics-normative) · 12 [Validation](#12-validation) ·
13 [Determinism](#13-determinism) · 14 [Versioning](#14-versioning) · 15 [Reconciliation](#15-reconciliation-with-the-design-documents) ·
16 [Dashboard mapping](#16-what-the-dashboard-reads) · 17 [Security](#17-security-properties)

---

## 1. File

- **Location.** `<run_root>/analysis/graph.json`, where `<run_root>` is
  `<output>/<account>/<run_id>/` (report-layout contract). Analysis runs **once per run, after all
  collection**, at the run root; it is never written under `global/` or a region directory. For legacy
  layouts, `aws-enumerator analyze <dir>` writes `<dir>/analysis/graph.json` (see engine-api.md §3.2).
  `aws-enumerator merge` writes `<output>/merged/<run_id>/analysis/graph.json` (schema 1.1, §4.2), and that
  `analysis/` holds `graph.json` only (plus `exports/`); the companion table below applies to analyses.
- **Encoding.** UTF-8. The writer uses `json.dumps(doc, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False)`; readers must not depend on key order or whitespace (fixtures are pretty-printed).
- **Companions** in the same directory (the complete list; report-layout.md §1 shows the same set):

  | File | When |
  |---|---|
  | `graph.json`, `findings.json` (the same findings, wrapper in finding-identity.md §3), `summary.json` (finding-identity.md §6) | always |
  | `diff.json` (finding-identity.md §4) | with `--baseline` |
  | `permission_map.json`, `trust_relationships.json` and the ten per-domain files `s3_relationships.json`, `ec2_relationships.json`, `secrets_relationships.json`, `lambda_relationships.json`, `kms_relationships.json`, `compute_relationships.json`, `messaging_relationships.json`, `newsurface_relationships.json`, `extra_relationships.json`, `k8s_relationships.json` | the **legacy outputs**, in their d13c215 formats, while `AnalysisOptions.legacy_outputs` is true (the default, for one release; engine-api.md §3.3) |
  | `_provenance.json` (report-layout.md §8) | legacy layouts only (`run.mode` `legacy-all` / `legacy-single`) |
  | `exports/<file>` (exports.md §1) | written by `aws-enumerator export` or `AnalysisOptions.exports`; derived, never digested |

  Nothing else is written into `analysis/`. The dashboard reads only `graph.json`.
- **Never in the file:** secret values, policy documents in full, credential material, environment values.
  Evidence carries policy ARNs, statement ids, actions, resources and condition keys — not raw documents.

## 2. Top-level object

All twelve keys are required; no other keys are allowed in 1.0 or 1.1 (`additionalProperties: false`).

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | string `1.<minor>.<patch>` | This contract's version. Readers accept major 1 only (§14). Analyses write `1.0.0`; `merge` writes `1.1.0` (§4.2, §14). |
| `generator` | object (§3) | Which tool, engine and rule versions produced the file. |
| `run` | object (§4) | Which run of which account, and who ran it (`run.operator`). |
| `meta` | object (§5) | Default path sources and targets. |
| `node_types` | object (§6) | Registry entry for every node type present. |
| `edge_types` | object (§6) | Registry entry for every edge type present. |
| `nodes` | array of node (§7) | Sorted by `id`. |
| `edges` | array of edge (§8) | Sorted by (`source`, `type`, `target`). |
| `findings` | array of finding (§9) | Sorted by (severity rank, `id`, `node_id`, `fingerprint`). |
| `coverage` | object (§10.1) | What could and could not be collected. |
| `evaluation_gaps` | array (§10.2) | What the evaluator could not decide, report-wide. |
| `analyzer_status` | array (§10.3) | Per-analyzer outcome (F-061). |

Minimal valid document (`tests/fixtures/graph/minimal.json`, abridged): the engine **always** emits the
two synthetic nodes `aws-enumerator:anonymous` and `aws-enumerator:account-admin/<account>`.

```json
{"schema_version": "1.0.0",
 "generator": {"tool": "aws-enumerator", "version": "0.3.0", "engine_version": "1.0.0", "rules_version": "2.0.0", "git_sha": null},
 "run": {"run_id": "20260101T000000Z-a1b2c3", "account_id": "111122223333", "partition": "aws", "mode": "run",
         "regions": ["eu-west-2"], "generated_at": "2026-01-01T00:00:00Z", "source_manifest_sha256": "…",
         "operator": {"arn": null, "node_id": null, "resolution": "unavailable", "redacted": false}},
 "meta": {"default_sources": ["aws-enumerator:anonymous"],
          "default_targets": ["aws-enumerator:account-admin/111122223333"]},
 "node_types": {"account_admin": {…}, "anonymous": {…}}, "edge_types": {},
 "nodes": [{"id": "aws-enumerator:account-admin/111122223333", "type": "account_admin", …},
           {"id": "aws-enumerator:anonymous", "type": "anonymous", …}],
 "edges": [], "findings": [],
 "coverage": {"source": "ledger", "status": "complete", "modules": []},
 "evaluation_gaps": [], "analyzer_status": []}
```

## 3. `generator`

| Key | Type | Meaning |
|---|---|---|
| `tool` | `"aws-enumerator"` | Constant. |
| `version` | string | `aws_enumerator.__version__` (single source, F-122). |
| `engine_version` | string | `ENGINE_SCHEMA_VERSION` of the engine package: the generation of the traversability table and analyzer set (`1.1.0` since the Wave 3 table additions, D-52). |
| `rules_version` | string | `rules_version` of `rules/data/privesc.json`. |
| `git_sha` | string `[0-9a-f]{7,40}` or `null` | Source revision when known. |

## 4. `run`

| Key | Type | Meaning |
|---|---|---|
| `run_id` | string `^[A-Za-z0-9._-]{1,64}$` | The manifest's run id (`<UTC %Y%m%dT%H%M%SZ>-<6 hex>`). Legacy layouts: `legacy-<YYYYMMDD>` when the old report's date directory (`reports/<YYYYMMDD>/<acct>/…`: the parent of `<acct>/` for `legacy-all`, the grandparent of `<region>/` for `legacy-single`) is named with exactly 8 digits; otherwise `legacy-<name of the analysed directory>` with every character outside `[A-Za-z0-9._-]` replaced by `_`, truncated to 64 characters in total. |
| `account_id` | 12 digits | The assessed account. In a merge: the **primary** account, `sources[0].account_id` (§4.2). |
| `partition` | `aws`, `aws-cn`, `aws-us-gov`, … | From the manifest or the collected ARNs; never hard-coded (F-119). |
| `mode` | `run` \| `legacy-all` \| `legacy-single` \| `merge` (1.1) | `run`: a manifest-2.0 run root. `legacy-all`: an old `--all` account directory `<acct>/` with `global/` + regions. `legacy-single`: an old `reports/<date>/<acct>/<region>/`. Same names as `_provenance.json` `source_layout` (report-layout.md §8). `merge`: the output of `aws-enumerator merge` (schema 1.1 only, §4.2). |
| `regions` | array of region names | The **explicit** region list analysed (`manifest.target.regions`, or the legacy rules of report-layout.md §8). Never discovered by scanning sibling directories (F-010, F-025, F-063). `global` is not a region; a legacy single-region directory whose name is not a known region contributes no entry (gap `legacy:region-unknown`). In a merge: the sorted union of the sources' `regions`. |
| `generated_at` | UTC timestamp `…Z` or `…+00:00` | The only clock value in the file; honours `SOURCE_DATE_EPOCH` (F-171, F-162). In a merge: when the merge ran (each source's time is in `sources[]`). |
| `source_manifest_sha256` | 64 hex or `null` | SHA-256 of the `manifest.json` bytes that were analysed; `null` without a manifest, and `null` in a merge (each source's value is in `sources[]`). |
| `operator` | object | The canonical operator field (below). There is no `caller`, `meta.caller` or `mapping`. In a merge: `{arn: null, node_id: null, resolution: "unavailable", redacted}` (§4.2). |
| `sources` | array (1.1) | **Required when `mode` is `merge`, absent otherwise** (schema-enforced): the merged runs (§4.2). |

### 4.1 `run.operator` (F-146)

| Key | Type | Meaning |
|---|---|---|
| `arn` | string or `null` | The ARN that was resolved (rule below). With redaction the caller ARN is never published: this is then the manifest's `operator.principal_arn` (role or user ARN without the session name). |
| `node_id` | node id or `null` | The node the operator acts as. Must exist in `nodes` when not `null`. |
| `resolution` | enum below | How `node_id` was found. |
| `redacted` | boolean (optional, default `false`) | Identity redaction applied. |

`arn`, `node_id`, `resolution` are required; `redacted` is optional. **Which ARN is resolved (the only rule):**
`redacted = manifest.operator.redacted or AnalysisOptions.redact_identity`; then
`arn = principal_arn if redacted else (caller_arn or principal_arn)`, taken from the manifest's top-level
`operator` block (manifest.md §3.4). For legacy layouts `caller_arn` is the legacy manifest's
`run_metadata.caller_arn` and there is no `principal_arn`; without a manifest the resolution is `unavailable`.
This is exactly `ids.resolve_operator(caller_arn, index, account, principal_arn=…, redacted=…)`.

| `resolution` | Caller form | `node_id` |
|---|---|---|
| `exact` | `arn:<p>:iam::<acct>:user/<path><name>` or a role ARN that is a node id, exactly | that ARN |
| `assumed-role` | `arn:<p>:sts::<acct>:assumed-role/<RoleName>/<session>`, or (redacted) a `principal_arn` role ARN whose path the manifest did not know | the role node **of that name in the same account** (role names are unique per account; the session ARN has no path, so this is the only name-based lookup in the contract) |
| `sso` | as above with `RoleName` starting `AWSReservedSSO_` | same as `assumed-role` |
| `root` | `arn:<p>:iam::<acct>:root` | `aws-enumerator:account-admin/<acct>` |
| `federated` | `arn:<p>:sts::<acct>:federated-user/<name>` | `null` |
| `not-in-graph` | the user or role was not collected | `null` |
| `cross-account` | caller account ≠ `run.account_id` | `null` |
| `unavailable` | no operator in the manifest (legacy reports, failed STS) | `null` |

Reference implementation: `ids.resolve_operator()`. The dashboard pre-marks `node_id` as owned and makes
it the default Find Path source; when it is `null` it shows "caller not in graph (`resolution`)" (for a merge
it shows a merged-view note instead, §4.2).

### 4.2 Merged graphs (`run.mode: "merge"`, schema 1.1; F-126)

`aws-enumerator merge` ([cli.md](cli.md) §3.8; logic in `engine/merge.py`) joins the analysed graphs of two or
more runs of **different accounts** into one document with `schema_version` `1.1.0`, valid against
`graph-1.1.schema.json` and `validate_graph(strict_order=True)` with the merge rules of §12.2. It re-uses each
source's analysis: nothing is re-collected or re-evaluated. Single-account analyses keep writing `1.0.0`.

**Sources.** Each source is a directory whose `analysis/graph.json` has schema major 1 and a minor this build
knows (1.0 or 1.1), a `run.mode` other than `merge` (no nested merges), and passes the schema of its minor and
`validate_graph`. All sources share one `run.partition` and have distinct `run.account_id` values: two runs of
one account are not merged (their records of the same nodes would conflict; collect the regions in one run, or
use `--global-from`).

**`run`** (the §4 table gives the merged value of every key): `account_id` = the primary account,
`sources[0].account_id`; `mode` = `merge`; `regions` = the sorted union; `source_manifest_sha256` = `null`;
`operator` = `{arn: null, node_id: null, resolution: "unavailable", redacted}` with `redacted` true when any
source operator is redacted (nobody "ran" the merge against AWS; each source's operator is kept in its
`sources[]` record and its node is a default source, §5). `generator` is the merging build's.

`run.sources[]`: one record per source, sorted by (`account_id`, `run_id`), closed (`additionalProperties: false`),
every key required:

| Key | Value |
|---|---|
| `run_id`, `account_id`, `partition`, `mode`, `regions`, `generated_at`, `source_manifest_sha256` | copied from the source's `run` |
| `operator` | the source's `run.operator`, verbatim |
| `generator` | the source's `generator`, verbatim |
| `graph_sha256` | SHA-256 of the source's `graph.json` bytes (the merged manifest's `run.sources[].graph_sha256`, manifest.md §3.11) |

**Nodes.** Node ids are account-qualified ([node-ids.md](node-ids.md)), so records of different accounts only
share an id for the account-less synthetic ids (`aws-enumerator:anonymous`, `svc:*`, `aws-enumerator:idp/<host>`)
and for nodes one source knows only second-hand: an `external_principal`, `external_account` or foreign `idp`
node, or a `placeholder`. When several sources hold a record with the same id, **one record wins**: the one
with the smallest key (*second-hand*, *not-own-account*, *source index*), where *second-hand* means
`props.external` or `props.placeholder` is true and *not-own-account* means the record's `account` differs from
its source's `run.account_id`. So the account that collected a principal provides its record, and the other
accounts' references join it by id: `external_principal` `arn:aws:iam::<B>:role/<name>` in account A's graph
becomes B's `role` node when B is a source. The winning record is copied unchanged except `findings`,
`inherited_findings` and `max_severity` (recomputed, below). An `external_account` node
`arn:<p>:iam::<B>:root` stays as it is even when B is a source (a source never has a node for its own root,
node-ids.md §3). `node_types` / `edge_types` list every type present, from this build's table (§6).

**Edges.** The union of the sources' edges, one record per (`source`, `type`, `target`) with the §8 merging
rule (evidence `statements`, `actions` and `rule_ids` unioned, the more definite `confidence`, the minimum
`weight`; every other key from the first source in order). Edge ids depend only on (`source`, `type`, `target`)
and do not change. The merge never adds, removes, retypes or re-evaluates an edge: an edge that one account's
analysis left conditional because the other side was unknown (`external-identity-unknown`,
`resource-policy-unknown`) stays conditional, and an account reaches another account's nodes only through
edges its own analysis emitted to those ARNs. Re-evaluating cross-account decisions with both accounts'
policies is outside 1.1.

**Findings.** The union of the sources' findings, de-duplicated by `fingerprint` (the first source in order
wins; fingerprints include the account, [finding-identity.md](finding-identity.md) §2), sorted as §13. A finding
without `account` gets its source's `run.account_id`; nothing else in a finding changes. Node `findings` and
`inherited_findings` are recomputed from the merged findings exactly as the builder does (the anchor lists the
fingerprint in `findings`; every `affected_members` entry other than the anchor lists it in
`inherited_findings`; finding order), and `max_severity` from the open ones.

**`meta`:** §5 (every source's `aws-enumerator:account-admin/<acct>` is a default target; every source
operator node is a default source).

**`coverage`, `evaluation_gaps`, `analyzer_status`:** §10 (per-account keys).

**Not in a merged root:** `findings.json`, `summary.json`, `diff.json`, the legacy outputs and
`_provenance.json`. The 1.0 `findings.json` wrapper names one account and mode (finding-identity.md §3);
`aws-enumerator export` renders the merged findings instead ([exports.md](exports.md)).

**Readers.** The dashboard loads a merged graph with the 1.x reader: `operatorNode` gives `id: null`, Find Path
starts from `meta.default_sources` (which holds every source operator), and `run.mode` is `merge`. Since
Wave 3a the dashboard also shows `run.sources[]` (source accounts in the header, one coverage row per source
run) and the per-account `account` / `accounts` keys ([dashboard-core-api.md](dashboard-core-api.md) §2.2, §2.9).

## 5. `meta`

| Key | Rule |
|---|---|
| `default_sources` | Sorted, unique. **Exactly** the nodes with `props.entry_point = true`, plus `run.operator.node_id` when it is a node. In a merge, plus every `run.sources[].operator.node_id` that is a node. |
| `default_targets` | Sorted, unique, never empty. **Exactly** the nodes with `props.high_value = true`; always contains `aws-enumerator:account-admin/<account>` (in a merge: that node of every source account). |

The dashboard uses these when the user has marked no owned nodes (F-043). Data assets are an optional
extra target set (`props.data_asset`), never default targets.

## 6. `node_types` and `edge_types`

Registries keyed by type name, containing an entry for **every type present** in `nodes` / `edges` (extra
entries are allowed and ignored). Every entry must equal what `edge_types.node_type_entry(name)` /
`edge_type_entry(name)` return for that name — the table is the single source; the registry exists so the
dashboard needs no code for new types (F-090, F-038, F-094).

`node_types[<type>]`:

| Key | Type | Meaning |
|---|---|---|
| `label` | string | Display name. |
| `icon` | `[a-z0-9_-]+` | Key of `dashboard/icons/<icon>.svg`; unknown keys fall back to `generic`. The dashboard maps it through its own catalogue, never into a URL built from report data. |
| `group` | string | `identity`, `synthetic`, `compute`, `network`, `data`, `messaging`, `edge`, `kubernetes`, `posture`. |
| `order` | integer ≥ 1 | Selector sort order (read with `??`, F-095). |
| `is_compute_bridge` | boolean | Runs code as an identity; entered only through `control` edges (bridge invariant). |
| `default_source` | boolean | Nodes of this type may be entry points. |
| `data_asset` | boolean | A data target; no traversable edge leaves it. |
| `synthetic` | boolean | Created by the engine, not an AWS resource. |
| `description` | string | Help text. |

`edge_types[<TYPE>]`:

| Key | Type | Meaning |
|---|---|---|
| `category`, `category_label`, `category_order` | string, string, integer | Filter group (18 categories). |
| `traversal` | `control` \| `access` \| `exposure` \| `structural` \| `info` | Class of the type. |
| `traversable` | `true` \| `false` \| `"conditional"` | Whether edges of this type can be walked; `"conditional"` means per edge (see `traversable_rule`). |
| `traversable_rule` | string or `null` | `member-not-reduced`, `trust-verified` or `pool-auth-public`. |
| `base_weight` | number ≥ 0 | Weight of a definite edge. |
| `bridge` | boolean | Compute → identity edge. |
| `sources`, `targets` | arrays of node types | Allowed endpoint types (after direction normalisation). |
| `description` | string | Meaning. |
| `doc_anchor` | `#<lower-case type>` | Heading of this type in the generated edge reference. |
| `legacy_name` | string or `null` | Name under which the legacy files render this type. |

## 7. Nodes

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Opaque, unique; the scheme is in [node-ids.md](node-ids.md). Never `principal:*`. |
| `type` | `[a-z][a-z0-9_]*` | yes | A node type of the table (58 at 1.0). |
| `label` | string, non-empty | yes | Raw display text; may contain any character. The dashboard renders it as text only. |
| `account` | 12 digits or `null` | yes | Owning account; `null` for `anonymous` and service principals. External nodes carry the foreign account. |
| `region` | region or `null` | yes | `null` for global resources (IAM, Route 53, CloudFront). S3 buckets carry their normalised region (`EU` → `eu-west-1`, empty → `us-east-1`, F-138). |
| `partition` | partition or `null` | yes | `null` only for `anonymous` and service principals. |
| `props` | object | yes | Engine-defined properties (§7.1). |
| `tags` | array of `{key, value}` | yes | AWS resource tags, sorted by (key, value). A list, never an object: tag keys are data and may be `__proto__` (F-042). |
| `coverage` | `{status, gaps[]}` | yes | Collection status of this node's inputs (§7.2). |
| `findings` | array of fingerprints | yes | Findings anchored at this node (open and suppressed). |
| `inherited_findings` | array of fingerprints | yes | Group findings that apply to this member (engine.md §3.4). |
| `max_severity` | severity or `null` | yes | Highest severity among **open** findings in `findings` ∪ `inherited_findings`. |

### 7.1 `props`

Keys are engine-defined `snake_case` identifiers (`^[a-z][a-z0-9_]*$`, never `constructor` or
`prototype`); values are any JSON whose nested object keys are not `__proto__`, `constructor` or
`prototype`. **Report-derived strings are values, never keys.** Well-known keys:

| Key | Type | Rule |
|---|---|---|
| `high_value` | boolean | Path target. Set on `account_admin` (always), on admin-equivalent principals (ADMIN-001 by policy ARN, never by policy name), on crown-jewel data the analyzers designate, and on operator-marked nodes. Requires `high_value_reason`. |
| `high_value_reason` | `account-admin` \| `admin-equivalent` \| `crown-jewel` \| `operator-marked` | Why. |
| `entry_point` | boolean | Default path source. Only on types with `default_source` (anonymous, idp, external_account, external_principal, user). `anonymous` always; the others when the engine judges them reachable from outside (users: has an access key or console password, or credential data unknown). |
| `external` | boolean | `true` on every `external_account` / `external_principal` node (schema-enforced). |
| `data_asset` | boolean | `true` exactly when the type's `data_asset` flag is set. |
| `attached_policies_status` | coverage status (§7.2) | **Required** on `user`, `role`, `group`. `denied`/`error` means the attachments could not be read; the dashboard shows "unknown (<error>)" (F-006). |
| `attached_policies_error` | string or `null` | The error code behind a non-complete status. |
| `placeholder` | boolean | The node was referenced but not collected (for example a same-account role named in a policy). |

Type-specific keys used in the fixtures and expected from the analyzers (non-exhaustive, all optional):
`aliases` (kms), `qualifiers` (lambda), `provider` (idp: `github`, `eks`, `cognito`, `saml`, `google`,
`facebook`, `amazon`, `generic`), `igw_routed`, `imds_v1`, `state` (instance), `unresolved_alias` (kms
placeholder), `path` (IAM path), `auth_public` (cognito).

### 7.2 Coverage status vocabulary

`complete`, `partial`, `denied`, `error`, `throttled`, `skipped`, `not-collected`, `legacy-unknown` (an old
report without `_coverage.json`), `not-applicable` (synthetic nodes). `coverage.gaps` lists facet-level
gap codes such as `s3:GetBucketPolicy:denied`, `iam:inline-unknown`, `boundary:doc-missing`.

### 7.3 Synthetic nodes

| Id | Type | Always emitted | Props |
|---|---|---|---|
| `aws-enumerator:anonymous` | `anonymous` | yes | `entry_point: true` |
| `aws-enumerator:account-admin/<acct>` | `account_admin` | yes | `high_value: true`, `high_value_reason: "account-admin"` |
| `aws-enumerator:account/<acct>` | `account` | when a finding anchors there | — |
| `aws-enumerator:region/<acct>/<region>` | `region` | when a finding anchors there | — |
| `aws-enumerator:idp/<host>` | `idp` | for well-known web identity providers in trust policies | `provider` |
| `svc:<service principal>` | `service_principal` | when a trust or grant names a service | — |
| `arn:<p>:iam::<acct>:root` (foreign) | `external_account` | when a policy names a foreign account | `external: true` |

## 8. Edges

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | `e:` + 20 hex | yes | `ids.edge_id(source, type, target)` = `"e:" + sha256(source \x1f type \x1f target)[:20]`. Stable across runs. |
| `source`, `target` | node ids | yes | Must be nodes; never equal. Stored in the **attack direction** (traversability-table.md §1). |
| `type` | `[A-Z][A-Z0-9_]*` | yes | An edge type of the table (102 at 1.0). |
| `category` | string | yes | `EDGE_TYPES[type].category` (redundant, for filters). |
| `traversal` | class | yes | `EDGE_TYPES[type].traversal`; never varies per edge. |
| `traversable` | boolean | yes | `true` only if the type may be traversed **and** its conditional rule holds **and** the bridge invariant did not demote it. |
| `weight` | number ≥ 0 | yes | `base_weight + penalty(confidence, condition_strength) + weight_extra`; `0` is legal and real (F-040). Never below `base_weight`. |
| `confidence` | `definite` \| `conditional` | yes | From the evaluator decision (ALLOW → definite, CONDITIONAL → conditional). |
| `evidence` | object | yes (may be `{}`) | Why the edge exists (§8.1). |
| `props` | object | no | Edge facts that are not evidence: `cross_account`, `admits` (`any`/`pattern`/`specific`), `auth` (`none`/`any-aws-account`), `technique`. Same key rules as node props. |

**Merging.** One record per (`source`, `type`, `target`). When analyzers emit the same key twice the
builder unions `evidence.statements`, `actions` and `rule_ids`, keeps the more definite `confidence`, and
the minimum `weight`.

### 8.1 `evidence`

Engine-defined keys, same safety rules as `props`. Well-known keys (typed by the schema):

| Key | Meaning |
|---|---|
| `decision` | `allow` \| `conditional`. |
| `condition_strength` | `none` \| `weak` \| `strong`: strongest unresolved gate of a conditional decision. |
| `layers` | Per-layer outcome (`identity`, `boundary`, `scp`, `rcp`, `resource`, `key_policy`): `true`/`false`/`maybe`/`n/a`/`unknown`. |
| `actions` | Actions that matched. |
| `statements` | Provenance: `{policy_arn, policy_name, version_id, sid, statement_index, source_type, via_group, layer}`. |
| `conditions` | Condition notes (key, operator, values, class, strength, outcome). |
| `gaps` | Gap codes that could change this edge (`external-identity-unknown`, `iam:inline-unknown` …). |
| `rule_ids` | Rules that produced the edge (privesc edges). |
| `technique` | Short technique label. |
| `via` | Services involved (PassRole); for `VPC_CONNECTED` the links, `peering:<pcx id>` / `transit-gateway:<tgw id>`. |
| `chain` | Edge ids that justify a derived edge (CAN_ESCALATE). |
| `weight_extra` | Type-specific extra weight included in `weight` (CAN_REACH_NODE_IMDS hop limit). |
| `traversable_rule` | `{rule, holds}` — required, with `holds: true`, on a traversable edge of a conditionally traversable type. |
| `demoted_by` | `"bridge-invariant"` when the builder demoted the edge. |
| `legacy` | `{type, direction: forward\|reversed, file}` — how the legacy file renders the edge. |

## 9. Findings

The record is defined in [finding-identity.md](finding-identity.md) (`$defs/finding`, identical in both
schemas). Contract points that involve the graph:

- `node_id` is **required** and must be a node (F-005). A finding about something that is not otherwise a
  node creates that node (resource, account anchor, region anchor). Zero orphan findings.
- The anchor node lists the fingerprint in `findings`; group findings are listed in members'
  `inherited_findings`.
- `related_node_ids`, `affected_members` and `targets[].node_id` must be nodes.
- `status: suppressed` findings stay in the file (with `suppression`) and are excluded from `max_severity`.
- `reference` is an `https://` URL (version-pinned, F-163) or `null`; consumers still pass it through
  `safeHref()`.

## 10. `coverage`, `evaluation_gaps`, `analyzer_status`

### 10.1 `coverage`

| Key | Type | Meaning |
|---|---|---|
| `source` | `ledger` \| `legacy-unknown` | `ledger` for a v2 run (`run.mode = run`), `legacy-unknown` for legacy layouts. |
| `status` | `complete` \| `partial` \| `unknown` | Report-wide: `unknown` when `source` is `legacy-unknown`; else `complete` when every `modules` entry is `ok` or `skipped`; else `partial`. |
| `modules` | array of `{module, region, status, error_code?, detail?}` | One entry per manifest `modules[]` entry (manifest.md §3.7), in manifest order: `module` = `name`, `region` = `region` (`global` or the region), `status` = `status` **copied verbatim**, `error_code` = `error.code` (or `null`), `detail` = `status_reason`. For legacy layouts: one entry per module directory found, with status `legacy-unknown` and `region` = `global` or the name of the directory that holds it. The dashboard's coverage panel lists those not `ok`. |
| `denied_apis` | array of `{api, regions[]}` | Optional; copied from the manifest's `coverage_summary.denied_apis`. |
| `facets` | array of `{facet, region, status, detail?}` | Optional; analyzer input facets (engine.md §6.7) with the §7.2 vocabulary. |

**In a merge (1.1).** `source` is `ledger` when every source's `coverage.source` is `ledger`, else
`legacy-unknown`; `status` follows the rule above over the merged `modules`. `modules`, `denied_apis` and
`facets` are the sources' lists concatenated in source order (§4.2), each entry with an added `account` (the
source's `run.account_id`; required in merge mode, absent otherwise in what this build writes); `denied_apis` and
`facets` are omitted when empty.

**Status vocabularies.** `modules[].status` uses the **module** vocabulary of coverage-schema.md §4
(`ok`, `partial`, `denied`, `failed`, `skipped`, `interrupted`, `not_run`) plus `legacy-unknown`; `facets`,
node `coverage.status` and `props.attached_policies_status` use the **facet** vocabulary of §7.2; the two are
never mixed (coverage-schema.md §4.1 lists all three vocabularies). The schema also admits
`dependency_missing`: it is **reserved** and never emitted by 1.x producers (a module whose dependency is not
selected is `skipped` with the reason in `detail`); readers treat it like `skipped`.

### 10.2 `evaluation_gaps`

Array of `{code, detail, count?}`, sorted by `code`. Report-level limits of the evaluation (engine.md §2.7).
Always present: `external-identity`, `runtime-conditions`, `session-policies`. When they apply:
`org:scp-unknown`, `org:rcp-unknown`, `boundary:doc-missing` (count), `iam:legacy-layout`,
`kms:key-policy-unknown` (count), `coverage-not-recorded`, `legacy:region-unknown` (a `legacy-single`
directory whose name is not a known region; `run.regions` is then empty), `network:connectivity-unknown` (count:
peering, transit-gateway or VPN listings not read completely), `clock:reference-time-unknown` (the report records
no collection time, so ages were computed against the analysis clock; engine-api.md §6.1) and the domain
analyzers' own codes (`ebs:sharing-unknown`, `kms:grants-unknown`, …). `legacy:unknown-lists-as-empty` and
`legacy:edges-unmapped` were raised by the legacy adapter until Wave 3 and are no longer emitted (D-53). The
list is open: codes follow the schema pattern, and readers show an unknown code as text. A report-level gap
never downgrades individual edges.

**In a merge (1.1):** one entry per `code`, sorted by `code`: `detail` from the first source (in source order)
that reports it, `count` the sum of the sources' counts (absent when no source has one), and `accounts` the
sorted list of source accounts that report it (required in merge mode).

### 10.3 `analyzer_status`

Array of `{name, phase, status, duration_seconds?, error?, inputs_missing?}` in pipeline order.
`phase` ∈ `context, load, principals, identity, resources, rules, closure, postprocess, write`;
`status` ∈ `ok, error, skipped, not_implemented`; `error` is `{type, message}` or `null`. This is the
serialised `AnalysisResult.analyzer_status` (engine-api.md). A failing analyzer keeps its own `error` entry (its
partial output rolled back) and the analyzers that require it are `skipped`; a module with no analyzer is
`not_implemented`, one that cannot be imported is `error`. Until Wave 3 a failing native analyzer was followed by a
standby `<name>:fallback` entry running the d13c215 code; that fallback is gone (D-53), so no name ends in
`:fallback` any more (readers of older documents show such entries as any other).

**In a merge (1.1):** the sources' lists concatenated in source order, each entry with an added `account`
(required in merge mode).

## 11. Path semantics (normative)

Every implementation — `engine/graph/traverse.py` (Wave 1), the dashboard's `graph-core.js`, and the
test reference `tests/support/ref_paths.py` — must give the answers recorded in
`tests/fixtures/graph/path_cases.json`.

1. **Directed.** Walk an edge only from `source` to `target`.
2. **Traversable only.** Use only edges with `traversable === true`. Structural, info and non-traversable
   access/exposure edges are never walked.
3. **Weights.** Path cost is the sum of stored `weight`s. `0` is a real zero cost; read weights with
   `typeof w === "number" && isFinite(w) && w >= 0 ? w : 1` (the fallback only matters for invalid input).
4. **Self.** `source === target` is not a path query; zero-cost paths between different nodes are real paths
   and must be listed (no `distance === 0` filtering).
5. **Ties.** Lowest cost, then fewest hops, then the lexicographically smallest sequence of edge ids
   (code-unit order), as in dashboard-core-api.md §2.5.
6. **Options** (all default off):
   - `exclude_categories: [category]` — edges whose `category` is hidden are not used (dashboard filters,
     F-096);
   - `exclude_node_types: [type]` — an edge is used only if neither endpoint's type is hidden;
   - `definite_only: true` — edges with `confidence: "conditional"` are not used.
7. **Sources and targets.** With owned nodes (owned ids that are nodes of this graph): exactly those nodes.
   Otherwise `meta.default_sources`. Targets: `meta.default_targets`, optionally plus nodes with
   `props.data_asset`. (dashboard-core-api.md §2.7–§2.8 implement this.)

`path_cases.json` is an array of `{name, description, findings[], graph, source, target, options, expect}`
where `graph` is a full valid document and `expect` is `{reachable}` plus, when reachable, `cost`, `hops`,
`path` (node ids), `edge_types`, and optionally `must_not_traverse_types`. The vectors cover: no path between
members of a shared group or holders of a shared policy or bucket; normalised grant edges; reversed edges;
zero-weight edges and zero-cost paths; cost beats hop count; equal cost prefers fewer hops; equal cost and
hops break on the edge-id sequence; conditional
edges with and without `definite_only`; anonymous → public bucket; Lambda `CAN_INVOKE` does not reach the
execution role while `CAN_UPDATE_CODE` does; resource-policy invoke grants are not control; unverified
IRSA; pods sharing a cluster; K8s RBAC pivot; pod → node IMDS weight extra; hidden category and hidden
node type; escalation to the account admin; data assets are terminal; SSRF vs exposure.

## 12. Validation

### 12.1 Schema layer

`graph-1.0.schema.json` (draft 2020-12, `$id` `urn:aws-enumerator:schema:graph:1.0`) closes every
record (`additionalProperties: false`) except the free-form `props` / `evidence` objects, and forbids the
keys `__proto__`, `constructor`, `prototype` at any depth inside them.

`graph-1.1.schema.json` (`$id` `urn:aws-enumerator:schema:graph:1.1`) is the 1.0 schema plus: `run.mode`
`merge`; `run.sources[]` (`$defs/runSource`, at least 2) required when `run.mode` is `merge` and forbidden
otherwise; an optional `account` on `coverage.modules[]`, `coverage.denied_apis[]`, `coverage.facets[]` and
`analyzer_status[]` entries and an optional `accounts` list on `evaluation_gaps[]` entries, all four required
when `run.mode` is `merge`. Every other definition (`finding`, `node`, `edge`, `operator`, `generator`, …) is
identical to 1.0. **Which schema:** a writer validates with the schema of the version it writes (`1.0.0` for
analyses, `1.1.0` for merges); a reader that validates uses the schema of the document's minor (1.0 or 1.1),
and for a newer minor checks `validate_graph` only (§14). A 1.0 document claiming `run.mode: "merge"` therefore
fails the 1.0 schema. The engine checks the schema layer with its compiled validator
(`engine/graph/schema_check.py`, standard library only, proven equal to `jsonschema` by the test suite; engine-api.md
§6.3, D-55), so every install validates what it writes.

### 12.2 Semantic layer — `validate_graph(doc, *, check_table=True, strict_order=False, check_id_patterns=True)`

| Code | Meaning |
|---|---|
| `not-an-object` | The document is not a JSON object. |
| `schema-major` | `schema_version` major is not 1. |
| `duplicate-node-id` | Two nodes share an id. |
| `principal-wildcard-node` | A node id starts with `principal:`. |
| `node-type-unregistered` | A node's type has no `node_types` entry. |
| `unknown-node-type` | A node type is not in the table. |
| `node-id-pattern` | A node id does not follow the scheme for its type (node-ids.md). |
| `props-data-asset` | `props.data_asset` disagrees with the type's `data_asset` flag. |
| `props-entry-point` | `props.entry_point` on a type that is not a default source. |
| `duplicate-edge-id` | Two edges share an id. |
| `edge-id-mismatch` | `id` ≠ `ids.edge_id(source, type, target)`. |
| `dangling-edge-source` / `dangling-edge-target` | An edge endpoint is not a node. |
| `self-loop` | `source == target`. |
| `bad-weight` | Weight not a finite number ≥ 0. |
| `bad-traversable` | `traversable` not a boolean. |
| `edge-type-unregistered` | An edge's type has no `edge_types` entry. |
| `unknown-edge-type` | An edge type is not in the table. |
| `edge-category-mismatch` / `edge-traversal-mismatch` | Record disagrees with the table. |
| `edge-traversable-not-allowed` | `traversable: true` on a type that is never traversable. |
| `weight-below-base` | Weight below the type's base weight. |
| `edge-source-type` / `edge-target-type` | Endpoint type not allowed for the edge type. |
| `traversable-rule-missing` | Conditionally traversable edge marked traversable without `evidence.traversable_rule {rule, holds: true}`. |
| `data-asset-outgoing` | A traversable edge leaves a data asset. |
| `bridge-invariant` | A traversable non-control edge enters a compute bridge (F-004). |
| `node-registry-mismatch` / `edge-registry-mismatch` | A registry entry differs from the table. |
| `duplicate-finding-fingerprint` | Two findings share a fingerprint. |
| `finding-node-missing` | A finding's `node_id` is not a node (F-005). |
| `finding-not-on-node` | The anchor node does not list the finding. |
| `finding-ref-missing` | `related_node_ids`, `affected_members` or `targets[].node_id` names a missing node. |
| `node-finding-unknown` | A node lists a fingerprint that is not a finding. |
| `node-finding-elsewhere` | A node lists, in `findings`, a finding anchored at another node. |
| `max-severity-mismatch` | `max_severity` is not the highest open severity. |
| `operator-node-missing` | `run.operator.node_id` is not a node. |
| `synthetic-node-missing` | The anonymous or account-admin node is missing. |
| `meta-ref-missing` | A `meta` entry is not a node. |
| `meta-order` | A `meta` list is not sorted and unique. |
| `meta-sources-mismatch` / `meta-targets-mismatch` | `meta` disagrees with the §5 rules. |
| `order` | (`strict_order`) nodes, edges, findings or tags out of canonical order. |
| `merge-sources` | (1.1, `run.mode: "merge"`) `run.sources` has fewer than 2 entries, is not sorted by (`account_id`, `run_id`), repeats an `account_id`, has an entry whose `partition` differs from `run.partition` or whose `mode` is `merge`, or `run.account_id` ≠ `sources[0].account_id`. |

**Merge mode (1.1).** When `run.mode` is `merge`, three rules above read differently, and nothing else changes:

- `synthetic-node-missing`: the `account_admin` node of **every** `run.sources[].account_id` must exist (and the
  anonymous node).
- `meta-sources-mismatch`: `default_sources` must be the `entry_point` nodes plus every
  `run.sources[].operator.node_id` that is a node (plus `run.operator.node_id`, which is `null` in a merge).
- `edge-source-type` / `edge-target-type`: where the table allows `external_principal` for an endpoint, a
  `user` or `role` node is accepted too when its `account` differs from the other endpoint's `account` (a
  foreign principal resolved to the record of the account that collected it, §4.2; for example
  `GRANTS_CROSS_ACCOUNT` from account B's role to account A's bucket).

### 12.3 Reader tolerance (dashboard)

The dashboard implements the cheap subset: schema major, unique ids (first wins), dangling edges dropped and
counted, numeric weights ≥ 0 and boolean `traversable`, unattached findings listed with a warning,
non-object `props` treated as `{}`. All lookups use `Map`/`Object.create(null)`; report objects are never
spread or `Object.assign`ed (F-042). Problems go to a "Report problems" panel; only structural failures
are fatal.

## 13. Determinism

Nodes sorted by `id`; edges by (`source`, `type`, `target`); findings by (severity rank CRITICAL→INFO, `id`,
`node_id`, `fingerprint`); tags by (key, value); every list inside evidence sorted where order carries no
meaning; `meta` lists sorted. The only clock value is `run.generated_at`. Two analyses of the same input
with the same `SOURCE_DATE_EPOCH` produce byte-identical files (F-162). Sort keys:
`graph.node_sort_key`, `edge_sort_key`, `finding_sort_key`.

## 14. Versioning

- `schema_version` follows semver. **Major** changes (removing or renaming a key, changing a meaning,
  changing an id scheme) bump to 2 and ship a new schema file; readers refuse other majors with a visible
  message (dashboard: "unsupported version").
- **Minor** versions only add optional keys, node types, edge types, categories, enum values of
  `evaluation_gaps.code` or `run.mode`, or `props`/`evidence` keys. Readers of 1.x must ignore unknown keys,
  render unknown types through the registries and show an unknown `run.mode` as text. A 1.x minor ships
  `graph-1.<minor>.schema.json`.
- **Writers emit the lowest minor that can express the document:** `1.0.0` for every analysis, `1.1.0` for
  `merge` output. Shipped minors:

  | Version | Schema | Adds |
  |---|---|---|
  | 1.0 | `graph-1.0.schema.json` | the contract of this page without §4.2 |
  | 1.1 | `graph-1.1.schema.json` | `run.mode: "merge"`, `run.sources[]`, `account` on `coverage.modules[]` / `denied_apis[]` / `facets[]` and `analyzer_status[]`, `evaluation_gaps[].accounts` (§4.2, §10, §12.2 merge rules); DECISIONS.md D-42 |
- New edge or node types are added to `edge_types.py` (the generated table then changes) and need no
  dashboard code. The schema does not enumerate types, so a table addition does not change `schema_version`: a
  document still says `1.0.0`, and its `edge_types` registry carries the entry of every type it uses. Wave 3 added
  `PARAM_GRANTS_CROSS_ACCOUNT`, `AMI_SHARED_CROSS_ACCOUNT`, `SSMDOC_SHARED_CROSS_ACCOUNT`,
  `LAYER_GRANTS_CROSS_ACCOUNT` (F-116) and `VPC_CONNECTED` (F-105) this way (D-52), and `generator.engine_version`
  moved to `1.1.0` so readers can tell the table generations apart.

## 15. Reconciliation with the design documents

| Design text | Contract |
|---|---|
| engine.md §6.4 `run.caller {arn, node_id, mapping}`; engine.md §5 F-146 row `graph.meta.caller` | One canonical **`run.operator {arn, node_id, resolution, redacted}`**. No `caller` key anywhere. |
| dashboard-docs-tests.md A4/A5 `anon:internet` | **`aws-enumerator:anonymous`** (engine.md §4.1). |
| engine.md §6.1 node `tags: {owned, high_value, external}` | Flags live in **`props`** (`high_value`, `external`, `entry_point`, `data_asset`); `tags` is the AWS tag list `[{key, value}]`. `owned` is dashboard session state, never in the file. |
| engine.md §6.1 node `findings` / dashboard `finding_fingerprints` | `findings` (fingerprints) and `inherited_findings`. |
| engine.md §6.3 "unverified IRSA is info, F" | Class stays `control` (classes are per type); the edge is `traversable: false` with `evidence.traversable_rule.holds = false`. |
| engine.md §6.3 `traversable` T/F/T* | Records carry a boolean; registries carry `true`/`false`/`"conditional"` + `traversable_rule`. |
| engine.md §6.1 AMI id with account | AMI and EBS snapshot ids follow the AWS ARN format, which has an empty account field (`arn:<p>:ec2:<r>::image/ami-…`); the owner is in `node.account`. |
| engine.md §6.1 S3 `props.region` | `node.region` (normalised). |
| engine.md §6.8 `analysis/` "in the region directory in single mode" and the `global/analysis/` copy | Superseded by PLAN.md: one analysis per run at the run root; no per-region or `global/` analysis. |
| dashboard-docs-tests.md §0.5 optional `types` block | `node_types` / `edge_types` (required). |
| dashboard-docs-tests.md A4 "Targets: `props.high_value`" | `meta.default_targets` = high-value nodes (admin always included). |
| collectors-cli.md §9 "the dashboard … pre-marks the operator from `operator.principal_arn`" (of the manifest) | The engine resolves the operator (§4.1); the dashboard reads only `graph.run.operator`, never the manifest's `operator` block. |
| dashboard-docs-tests.md A5 coverage panel statuses "`denied`, `error`, `partial`, `skipped`, `dependency_missing`" | The module vocabulary of §10.1 (`error` is a call/facet status, not a module status; `dependency_missing` is reserved). |
| engine-api.md / report-layout.md "unknown" region for a legacy single-region directory | No region entry plus the `legacy:region-unknown` gap (§4, §10.2). |
| `requests/e-core-2.md` (graph-1.1): `run.sources[]` with six keys, `coverage.modules[].account`, "multiple account-admin default targets" | Approved and completed (§4.2): `sources[]` also carries `mode`, `graph_sha256`, `generator` and `operator`; `account` is also on `denied_apis`, `facets` and `analyzer_status` entries and `accounts` on `evaluation_gaps`; the default targets follow from the unchanged §5 rule; two validator rules change in merge mode (§12.2). |

## 16. What the dashboard reads

| Need | Field |
|---|---|
| Header: account, mode, regions, time, version, git sha, schema version | `run.*`, `generator.*`, `schema_version` |
| Pre-marked operator / default Find Path source (F-146) | `run.operator.node_id`, `run.operator.resolution` |
| Default sources / targets (F-043) | `meta.default_sources`, `meta.default_targets` |
| Data-asset target toggle | `props.data_asset` |
| Internet node (F-037) | node `aws-enumerator:anonymous` (type `anonymous`) |
| External principals | `props.external`, types `external_account` / `external_principal` |
| "unknown (AccessDenied)" for attachments (F-006) | `props.attached_policies_status`, `props.attached_policies_error` |
| Legend, filters, icons, sort order (F-090, F-095) | `node_types`, `edge_types` |
| Path finding (F-007, F-040, F-096) | `edges[].traversable`, `weight`, `category`, `confidence`; §11 |
| Findings panel and per-node findings (F-005, F-074) | `findings[]`, `nodes[].findings`, `max_severity` |
| Coverage panel | `coverage`, `evaluation_gaps`, `analyzer_status` |
| Merged view (1.1; shown since Wave 3a, dashboard-core-api.md §2.9) | `run.mode == "merge"`, `run.sources[]`, the per-account `account` / `accounts` keys of §10 |

## 17. Security properties

- Labels, ids, props, tags, evidence and finding texts are **raw strings** from the account; the engine
  never emits HTML. `tests/fixtures/graph/hostile.json` is valid and carries `window.__aeXssCanary` markup
  canaries and prototype names in every string field the dashboard renders (F-008, F-041, F-042).
- Object keys inside `props`/`evidence` are engine-chosen; `__proto__`, `constructor` and `prototype` are
  rejected by the schema at any depth; tags are a list of pairs.
- `reference` must be `https://` (schema); consumers still sanitise links.
- No credential material, secret values or environment values appear anywhere in the file.
