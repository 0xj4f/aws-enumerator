# Contract: run manifest (`manifest.json`, schema 2.0)

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; precisions at the Wave 0/1 sync by contract-arbiter in §1, §2, §3.4 and §3.8; at the Wave 1/2 sync in §3.2 (`argv`, request `r-3`) and the new §3.11 (merge manifests, request `e-core-2`); all listed in [DECISIONS.md](DECISIONS.md); the schema is unchanged; Wave 3a (I1, i1-runtime): §3.8 `engine` is `v2` only, the interim adapter is gone). Change it only through a change request.
**Schema:** `aws_enumerator/schemas/manifest-2.0.schema.json` (JSON Schema 2020-12, shipped as package data). Every manifest the tool writes must validate; the R stream's orchestration tests validate each one.
**Writer:** the R stream's `ManifestStore` (`output.py`), thread-safe, always through `fsio.atomic_write_json`. **Readers:** `analyze`, `verify`, `package`, `--resume`, the engine (run context for `graph.json`), the dashboard (run picker and digest badge only).
**Related:** [report-layout.md](report-layout.md), [coverage-schema.md](coverage-schema.md), [cli.md](cli.md).

Findings: F-061 (status per module, exit codes), F-122 (single version source), F-123 / F-146 (operator identity, redaction), F-155 (written on interrupt), F-168 (digests), F-171 (UTC).

---

## 1. Lifecycle

| When | What is written | `run.status` |
|---|---|---|
| Run start, after the run root is created and before any AWS call except STS | full document with `modules: []`, `analysis.status: "not_run"`, `files: []` | `in_progress` |
| After every unit finishes (global or one region) | the unit's module entries appended, `coverage_summary` recomputed | `in_progress` |
| Analysis starts / ends (only when every unit finished and `--no-analysis` is not given) | `analysis.status: "in_progress"`, then the mapped result (§3.8) | `in_progress` |
| `--no-analysis` | `analysis.status: "skipped"` | `in_progress` |
| Finalisation (normal end, fatal error, or SIGINT/SIGTERM) | `ended_at`, `duration_seconds`, `exit_code`, final `status`, `files` | final |
| `aws-enumerator analyze` on a v2 run | `analysis`, `files` | unchanged |
| `--resume` | `run.resumes[]` appended, re-run modules replaced (`resumed: true`), `files` | `in_progress`, then final |

Every write is atomic (temporary file + rename). A run killed with SIGKILL keeps the last `in_progress` manifest, which is how `--resume` and the dashboard recognise an unfinished run. `SHA256SUMS` is written after the final manifest ([report-layout.md](report-layout.md) §7).

## 2. Run status and exit code

`run.status` is derived once, at finalisation:

| `run.status` | Condition | Exit code |
|---|---|---|
| `interrupted` | SIGINT or SIGTERM was received | 130 (SIGINT) or 143 (SIGTERM) |
| `failed` | fatal: STS/credentials failed, the output is unwritable, a `RunAborted` (expired or invalid token, coverage-schema.md §2) stopped the run, or **every** selected module ended `failed` | 1 |
| `partial` | at least one module is `partial`, `denied` or `failed`, or `analysis.status` is `failed` or `partial` | 2 |
| `complete` | otherwise. Modules `skipped` by flags, by partition availability or as not implemented **never** make a run partial, and neither does `analysis.status` `skipped` (`--no-analysis`). | 0 |

`run.exit_code` records the code the process returned. It is `null` while the run is in progress.

## 3. Fields

The schema is authoritative; this section explains meaning. All timestamps are UTC `...Z`. Lists are sorted where an order is stated, so the document is deterministic apart from the clock fields.

### 3.1 `tool`

`{name: "aws-enumerator", version, git_sha, python, boto3, botocore, kubernetes}`

- `version` is `aws_enumerator._version.__version__` (the single source, F-122); the banner, `--version` and `graph.json` use the same value.
- `git_sha` comes from `$AWS_ENUMERATOR_GIT_SHA` (the Docker build argument), else from `git rev-parse --short=12 HEAD` with a 1 s timeout when the package directory is inside a work tree, else `null`.
- `kubernetes` is `null` when the package is not installed.
- There is no `author` field (F-144).

### 3.2 `run`

| Field | Meaning |
|---|---|
| `run_id` | [report-layout.md](report-layout.md) §1.2 |
| `kind` | `collect`, or `merge` for a document produced by `aws-enumerator merge` (then `sources[]` lists the merged runs and `target.region_source` is `merge`; §3.11) |
| `status`, `exit_code` | §2 |
| `started_at`, `ended_at`, `duration_seconds` | wall clock of the whole command |
| `argv` | the arguments after the program name, **after** legacy-flag translation (cli.md §4). The CLI never takes secrets as arguments, but local paths would leak the user name, so the value of every path-valued flag is recorded as `<redacted>` (`--flag <redacted>` or `--flag=<redacted>`): `--output`, `--log-file`, `--kubeconfig`, `--k8s-token-file`, `--k8s-ca-file`, `--iam-gaad-file`, `--scp-file`, `--global-from`, `--resume`, `--baseline`, `--suppress`; under `--redact-identity` the `--profile` value too. `merge` records each `RUN_DIR` as `<redacted>`. `resumes[].argv` follows the same rule (`cli.recorded_argv`). |
| `options` | the effective options after defaults. Required keys: `regions_requested` (as typed; `--all` records `["all"]`), `modules` (selected names, registry order), `skipped_modules` (`[{name, reason}]` from `registry.select`), `k8s` (default **true**), `k8s_secrets` (default **false**), `concurrency`, `rate_limit {enabled, default_rps, max_rps, overrides}`, `max_tier`, `deny_breaker`, `redact_identity`. Optional known keys: `iam_mode`, `zip`. Further keys may be added for later flags; readers must ignore unknown keys. The output path is **not** recorded (it would leak the local user name). |
| `resumes` | one `{resumed_at, argv, overrides}` per `--resume` |
| `global_source` | `null`, or `{run_id, account_id, manifest_sha256}` when `--global-from` copied `global/` from another run |

### 3.3 `target`

`{account_id, partition, home_region, global_region, regions, region_source, regions_skipped}`

- `partition` comes from the caller ARN; `global_region` is per partition (`aws` → `us-east-1`, `aws-us-gov` → `us-gov-west-1`, `aws-cn` → `cn-north-1`, `aws-iso` → `us-iso-east-1`, `aws-iso-b` → `us-isob-east-1`; `registry.global_region_for`).
- `regions` (sorted) is **the** list of regional units. The engine analyses exactly these, and nothing scans directories (F-010, F-025).
- `region_source`: `explicit` (`--region`/`--regions`), `profile` (single home region from the profile or environment), `describe_regions` (`--all`), `fallback:sts-probe` (`--all` when DescribeRegions was denied, F-064), `merge`.
- `regions_skipped`: `[{region, reason}]`, for example `--exclude-regions` or a region that failed the STS probe.

### 3.4 `operator` (F-123, F-146)

`{caller_arn, caller_user_id, caller_arn_sha256, principal_arn, principal_type, redacted}`

- `principal_arn` is the identity without the session: an `assumed-role` caller `arn:aws:sts::<acct>:assumed-role/<name>/<session>` becomes `arn:aws:iam::<acct>:role/<name>` (the path, when known from `iam:GetRole`, is included). `principal_type` is `assumed-role`, `user`, `root`, `federated-user` or `unknown`.
- `caller_arn_sha256` is the SHA-256 of the full caller ARN, so runs by the same session can be correlated without storing it.
- **`--redact-identity`** sets `redacted: true`, and then `caller_arn` and `caller_user_id` **must be `null`** (the schema enforces it). Coverage files never hold AWS error messages, which embed the caller ARN ([coverage-schema.md](coverage-schema.md) §6), so a redacted run carries the caller ARN nowhere.
- The engine maps this block to `graph.json`'s `run.operator` (graph-json.md §4.1, the only rule): with `redacted` (or `--redact-identity` given to `analyze`) it resolves `principal_arn`, otherwise `caller_arn` (falling back to `principal_arn`). There is no `caller` block in `graph.json`, and the dashboard never reads this block (report-layout.md §9).

### 3.5 `classification`

The constant `"CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt"`.

### 3.6 `preflight`

`null`, or `{mode: probe|simulate, ran_at, results: [{module, actions, result, error_code}]}` when `--preflight` ran (cli.md §3.4). Probe results use `ok|denied|error|skipped`; simulate results use `allowed|implicit_deny|explicit_deny`.

### 3.7 `modules`

One entry per **(module, unit)** that was selected, including the ones that did not run. Sorted by unit (`global` first, then regions in `target.regions` order), then registry order. The entry is exactly `collectors.base.ModuleResult.manifest_entry()`:

| Field | Meaning |
|---|---|
| `name`, `scope`, `region` | registry name, `global`/`regional`/`k8s`, and `"global"` or the region |
| `status` | `ok` \| `partial` \| `denied` \| `failed` \| `skipped` \| `interrupted` \| `not_run` (coverage-schema.md §4) |
| `status_reason` | short human text: the skip reason, `"primary call denied: s3:ListBuckets"`, the first degrading call, `"unhandled KeyError"` ... |
| `started_at`, `ended_at`, `duration_seconds` | `null` when the module did not run |
| `error` | `null`, or `{type, code, message}` for `failed` (no AWS error messages) |
| `coverage` | `null` when the module did not run, else the `_coverage.json` `summary`: `{calls, ok, denied, error, throttled, skipped, not_configured, item_errors}` |
| `throttle_events` | final throttles seen by this module (the rate limiter's own counters are in the run log) |
| `resumed` | `true` when `--resume` re-ran this entry |
| `dir` | module directory relative to the run root (`global/iam`, `eu-west-2/k8s`), or `null` when the module did not run |

Entries for modules that never ran:

- `skipped`: excluded by selection (`--skip`, `--no-k8s`, `--max-tier`, `--skip-global`), unavailable in the partition, a dependency not selected, or not implemented in this version. `status_reason` is the reason from `registry.select`. One entry per unit in which the module would have run.
- `not_run`: the run stopped (interrupt or fatal error) before the module's unit reached it.

### 3.8 `analysis`

`{status, engine, started_at, duration_seconds, error, dir: "analysis", graph_schema_version}`

- `status` (one meaning each):

  | `analysis.status` | Meaning | Makes the run `partial`? |
  |---|---|---|
  | `not_run` | Analysis has not run: the initial value, kept when the run stops (interrupt, fatal error) before every unit finished | no (the run is `interrupted` or `failed` anyway) |
  | `in_progress` | Analysis is running (a crash leaves it so, like `run.status`) | — |
  | `ok` | `AnalysisResult.status == "ok"` | no |
  | `partial` | `AnalysisResult.status == "partial"`: outputs written, at least one analyzer failed (`graph.json` `analyzer_status`) | yes |
  | `failed` | `AnalysisResult.status == "error"`, or the engine call raised: nothing usable written (a previous `analysis/` is kept) | yes |
  | `skipped` | Deliberately not run: `--no-analysis` | no |

- **Writer:** the R stream, never the engine: the runner after `collect`, and the `analyze` command when it re-analyses a v2 run (engine-api.md §3.1).
- `engine`: `v2` (`engine.analyze_run` / `analyze_report`); the writer sets `null` while no engine has run (`not_run`, `skipped`), and readers ignore `engine` for those statuses. The schema still admits `legacy`, which only the Wave 1 interim adapter wrote (removed in Wave 3a).
- `error`: a one-line message, never a traceback.
- `graph_schema_version`: the `schema_version` the engine wrote into `graph.json` (`1.0.0` for an analysis, `1.1.0` for a merge, §3.11); `null` while no engine has run.

### 3.9 `coverage_summary`

Recomputed from `modules` after every unit:

- `modules_by_status`: counts per status (only non-zero keys need to be present).
- `denied_apis`: `[{api, regions: [...]}]`, the union of every module's denied APIs, sorted by api; regions sorted with `global` first.
- `partial_modules`, `failed_modules`: `["<name>@<region>", ...]`, sorted.
- `throttled_calls`: total `throttled` calls; `item_errors`: total per-item failures (including entries beyond each module's cap).

### 3.10 `files`

`[{path, sha256, bytes}]`, sorted by path. The exclusions are in [report-layout.md](report-layout.md) §7. Written at finalisation, and rewritten by `analyze` and `--resume`.

### 3.11 Merge manifests (`run.kind: "merge"`)

`aws-enumerator merge` ([cli.md](cli.md) §3.8) writes one manifest, once, after `analysis/graph.json`; it is
never `in_progress`. It validates against the same 2.0 schema; collect-only fields carry neutral values that
readers ignore for `kind: "merge"`. The merged run's collection coverage is **not** summarised here: it travels
per account in `graph.json` (`coverage.modules[].account`, graph-json.md §10.1).

| Field | Value |
|---|---|
| `tool`, `classification` | as for `collect` (the merging build) |
| `run.run_id` | the merge's id (`--run-id` or generated) |
| `run.kind`, `run.status`, `run.exit_code` | `merge`, `complete`, `0` (a failing merge writes no manifest) |
| `run.started_at`, `ended_at`, `duration_seconds` | the command's wall clock |
| `run.argv` | §3.2 (`RUN_DIR`s and `--output` recorded as `<redacted>`) |
| `run.options` | the required keys with neutral values: `regions_requested: []`, `modules: []`, `skipped_modules: []`, `k8s: false`, `k8s_secrets: false`, `concurrency: 1`, `rate_limit: {enabled: false, default_rps: null, max_rps: null, overrides: {}}`, `max_tier: 2`, `deny_breaker: 0`, `redact_identity: false` |
| `run.resumes`, `run.global_source` | `[]`, `null` |
| `run.sources` | `[{run_id, account_id, graph_sha256}]`, sorted by (`account_id`, `run_id`): the same sources, in the same order, as `graph.json` `run.sources[]`; `graph_sha256` is the SHA-256 of the source's `graph.json` bytes |
| `target` | `account_id` = the primary account (`sources[0]`); `partition` = the common partition; `home_region` = `global_region` = the partition's global region (§3.3); `regions` = the sorted union of the sources' regions; `region_source: "merge"`; `regions_skipped: []` |
| `operator` | `{caller_arn: null, caller_user_id: null, caller_arn_sha256: null, principal_arn: null, principal_type: "unknown", redacted: false}`: the merge makes no AWS call. Each source's operator is in `graph.json` `run.sources[].operator` (graph-json.md §4.2). |
| `preflight`, `modules` | `null`, `[]` |
| `analysis` | `{status: "ok", engine: "v2", started_at, duration_seconds, error: null, dir: "analysis", graph_schema_version: "1.1.0"}` |
| `coverage_summary` | `{modules_by_status: {}, denied_apis: [], partial_modules: [], failed_modules: [], throttled_calls: 0, item_errors: 0}` |
| `files` | as §3.10 (`HANDLING.txt`, `analysis/graph.json`) |

## 4. Compatibility

- Readers check `schema_version`. `"2.0"` is this contract; a missing `schema_version` with a `run_metadata` key is the v0.2 legacy manifest, which is read-only ([report-layout.md](report-layout.md) §8).
- Adding an optional key is a minor change (`2.1`); removing or retyping a key is a major change (`3.0`), which readers refuse.

## 5. Example (redacted, abbreviated)

```json
{
  "schema_version": "2.0",
  "tool": {"name": "aws-enumerator", "version": "0.3.0", "git_sha": null, "python": "3.10.11",
           "boto3": "1.37.34", "botocore": "1.37.34", "kubernetes": "33.1.0"},
  "run": {"run_id": "20261015T101500Z-a1b2c3", "kind": "collect", "status": "complete",
          "started_at": "2026-10-15T10:15:00Z", "ended_at": "2026-10-15T10:17:31Z", "duration_seconds": 151.2,
          "exit_code": 0, "argv": ["collect", "--regions", "eu-west-2", "--no-k8s"],
          "options": {"regions_requested": ["eu-west-2"], "modules": ["iam", "s3"],
                      "skipped_modules": [{"name": "k8s", "reason": "disabled by --no-k8s"}],
                      "k8s": false, "k8s_secrets": false, "concurrency": 3,
                      "rate_limit": {"enabled": true, "default_rps": 5, "max_rps": null, "overrides": {}},
                      "iam_mode": "gaad", "max_tier": 2, "deny_breaker": 3, "redact_identity": true, "zip": false},
          "resumes": [], "global_source": null},
  "target": {"account_id": "111122223333", "partition": "aws", "home_region": "eu-west-2",
             "global_region": "us-east-1", "regions": ["eu-west-2"], "region_source": "explicit",
             "regions_skipped": []},
  "operator": {"caller_arn": null, "caller_user_id": null, "caller_arn_sha256": "<64 hex>",
               "principal_arn": "arn:aws:iam::111122223333:role/demo-operator",
               "principal_type": "assumed-role", "redacted": true},
  "classification": "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt",
  "preflight": null,
  "modules": [
    {"name": "s3", "scope": "global", "region": "global", "status": "ok", "status_reason": null,
     "started_at": "2026-10-15T10:15:02Z", "ended_at": "2026-10-15T10:15:05Z", "duration_seconds": 3.2,
     "error": null,
     "coverage": {"calls": 45, "ok": 45, "denied": 0, "error": 0, "throttled": 0, "skipped": 0,
                  "not_configured": 30, "item_errors": 0},
     "throttle_events": 0, "resumed": false, "dir": "global/s3"},
    {"name": "k8s", "scope": "k8s", "region": "eu-west-2", "status": "skipped",
     "status_reason": "disabled by --no-k8s", "started_at": null, "ended_at": null, "duration_seconds": null,
     "error": null, "coverage": null, "throttle_events": 0, "resumed": false, "dir": null}
  ],
  "analysis": {"status": "ok", "engine": "v2", "started_at": "2026-10-15T10:17:20Z", "duration_seconds": 11.0,
               "error": null, "dir": "analysis", "graph_schema_version": "1.0.0"},
  "coverage_summary": {"modules_by_status": {"ok": 1, "skipped": 1}, "denied_apis": [], "partial_modules": [],
                       "failed_modules": [], "throttled_calls": 0, "item_errors": 0},
  "files": [{"path": "global/s3/buckets.json", "sha256": "<64 hex>", "bytes": 1234}]
}
```

`tests/python/collectors/test_foundation_contract.py::test_manifest_example_validates` validates this example (with real digests) against the schema, and checks that a redacted manifest carrying a caller ARN is rejected.
