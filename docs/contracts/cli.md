# Contract: command-line interface

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; precisions at the Wave 0/1 sync by contract-arbiter in §3.1, §3.2, §3.3 and §3.8; at the Wave 1/2 sync by contract-arbiter in §2, §3.2–§3.5, §3.7, §3.8 (merge specified, graph 1.1) and §3.9, from requests `r-3` and `e-core-2`; all listed in [DECISIONS.md](DECISIONS.md); Wave 3a (I1, i1-runtime): §5 no longer mentions the removed legacy collector adapter; Wave 4 (w4-engine): §3.1 and §3.2 gain `--no-legacy-outputs`, DECISIONS.md D-58). Change it only through a change request.
**Implemented by:** the R stream (`aws_enumerator/cli.py`, `runner.py`, `aws_session.py`, `output.py`, `permissions.py`, `logging_setup.py`) in Wave 1; `dashboard` is wired to the Du stream's `serve_dashboard`; `export` and `merge` delegate to the engine. The README's CLI reference is generated from argparse and diffed against this document's flag tables by a docs test (Wave 3).
**Owner decisions applied:** K8s collection **on by default** (`--no-k8s`); Secret listing **off** by default (`--k8s-secrets`, metadata only); default `--output ~/.aws-enumerator/reports`; run-unique folders; analysis once, at the run root; writing inside a git work tree needs `--allow-in-repo`.
**Related:** [report-layout.md](report-layout.md), [manifest.md](manifest.md), [registry.md](registry.md), [logging.md](logging.md), [exports.md](exports.md), [dashboard-core-api.md](dashboard-core-api.md).

---

## 1. Shape

```
aws-enumerator <subcommand> [options]
aws-enumerator --version | -h | --help
```

| Subcommand | Purpose | Needs AWS credentials |
|---|---|---|
| `collect` | Enumerate an account and analyse it (the main run) | yes |
| `analyze <dir>` | (Re-)run analysis on a v2 run or a legacy report | no |
| `export <dir> --format sarif\|csv\|md\|asff\|opengraph` | Write findings / graph exports from `analysis/graph.json` | no |
| `merge <run> <run>...` | Merge the analysed graphs of runs of different accounts (multi-account view, graph 1.1, F-126) | no |
| `dashboard [path]` | Serve the dashboard locally | no |
| `preflight` | Check the permissions the selected modules need | yes |
| `permissions` | Print the IAM policy / K8s RBAC the selected modules need | no |
| `modules` | List the collector registry | no |
| `package <dir>` | Zip (and optionally encrypt/sign) a run after the fact (F-145) | no |
| `verify <dir\|zip>` | Check a run's digests (F-168) | no |
| `version` | Print the version | no |

- `prog` is always `aws-enumerator` (also under `python -m aws_enumerator`).
- `--version` works at the top level and on every subcommand and prints `aws-enumerator <version>` on stdout.
- `ArgumentParser.error` is overridden: usage errors print the usage and the message on stderr and exit **64** (argparse's own exit 2 would collide with "partial").
- Every subcommand accepts the logging options of §2.

## 2. Options common to every subcommand

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `-q`, `--quiet` | off | Only WARNING and above on stderr; no banner | F-169 |
| `-v`, `-vv` (`--verbose`, counted) | off | `-v`: DEBUG for `aws_enumerator.*`. `-vv`: also botocore/urllib3 at DEBUG (prints request parameters; for debugging only) | F-169 |
| `--log-format text\|json` | `text` | stderr format (logging.md §3) | F-169 |
| `--no-color` | off | No ANSI colours. Colours are also off when stderr is not a TTY or `NO_COLOR` is set | F-169 |
| `--log-file PATH` | `<run_root>/run.log` for `collect` (none elsewhere) | JSON-lines log file, mode 0600 | F-169 |

## 3. Subcommands

### 3.1 `collect`

Flags by group. "Manifest key" is where the effective value is recorded in `manifest.run.options` (manifest.md §3.2); option names in `RunInfo.options` are the flag names without the dashes, with `-` replaced by `_`.

**Identity**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--profile NAME` | env / default chain | `boto3.Session(profile_name=NAME)`. One session for the whole run: credentials are resolved once. An unknown profile exits 1 with a friendly message. | F-060, F-167 |

**Regions** (`--region`, `--regions` and `--all` are mutually exclusive)

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--region R` | — | Collect one region. | F-124 |
| `--regions a,b` | — | Collect these regions. | F-124 |
| `--all` | off | Collect every enabled region: `ec2:DescribeRegions` (opt-in filter) in the **home** region; if that is denied, botocore's region list for the partition filtered by a short regional `sts:GetCallerIdentity` probe (`region_source: "fallback:sts-probe"`). | F-064, F-119 |
| `--exclude-regions a,b` | — | Only with `--all`. Recorded in `target.regions_skipped`. | |

Home region (for STS and region discovery): `--region`, else the first of `--regions`, else the profile/environment region (`AWS_REGION`, `AWS_DEFAULT_REGION`, profile `region`). If none is available the command exits **64** with a hint. There is no hard-coded default region (F-124). Without `--region`/`--regions`/`--all`, the run collects the home region only (`region_source: "profile"`).

**Global services**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| (default) | | Global services (iam, organizations, s3, cloudfront, waf_cloudfront, route53) are collected **once per run**, in the `global` unit. | F-153 |
| `--skip-global` | off | Do not collect global services. | F-153 |
| `--global-from RUN_DIR` | — | Copy `global/` from another v2 run of the same account (digests checked) and record `run.global_source`. Implies `--skip-global`. | F-153 |

**Selection** (`registry.select`, registry.md §5)

| Flag | Default | Meaning | Manifest key |
|---|---|---|---|
| `--modules a,@group,...` | every implemented default module | Names, aliases or groups; repeatable or comma-separated. Unknown names exit 64 with a suggestion. | `modules` |
| `--skip a,@group,...` | — | Remove modules after expansion. | `skipped_modules` |
| `--max-tier 1\|2` | `2` | `1` excludes tier-2 modules, whose APIs return secret-bearing configuration (lambda, ecs, cloudformation, glue, codebuild). | `max_tier` |

**Kubernetes** (owner decision: on by default)

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--no-k8s` | K8s **on** | Do not query the Kubernetes API of EKS clusters. `--modules k8s` together with `--no-k8s` exits 64. | F-062 |
| `--k8s` | — | Explicitly on (the default). Accepted for compatibility; mutually exclusive with `--no-k8s`. | |
| `--k8s-secrets` | **off** | List Secret **metadata only** (name, namespace, type via `fieldSelector`), never values, with `Accept: ...PartialObjectMetadataList`. Prints a WARNING that list-secrets RBAC still means read-all-values. Without it no `/secrets` request is made; Secret nodes come from pod references. | F-009, F-150 |
| `--k8s-auth eks-token\|kubeconfig\|token\|in-cluster` | `eks-token` | How to authenticate to clusters. | F-152 |
| `--kubeconfig PATH`, `--kube-context NAME` | — | For `kubeconfig` auth; clusters are matched by server URL. | F-152 |
| `--k8s-token-file PATH`, `--k8s-ca-file PATH` | — | For `token` auth. | F-152 |
| `--k8s-clusters a,b` | all clusters from eks | Restrict to these cluster names. | |
| `--k8s-timeout CONNECT,READ` | `5,60` | Seconds per request (a private endpoint gets 3 s connect plus a hint). | F-120 |
| `--no-k8s-self-review` | review on | Skip `SelfSubjectRulesReview` (the only non-GET request; non-persistent). | F-152 |

**Output**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--output DIR` | `$AWS_ENUMERATOR_OUTPUT`, else `~/.aws-enumerator/reports` | Output root; the run goes to `<DIR>/<account>/<run_id>/`. | F-063 |
| `--allow-in-repo` | off | Allow an output inside a git work tree (otherwise exit 64). | F-066 |
| `--run-id ID` | `<UTC ts>-<6 hex>` | `^[A-Za-z0-9._-]{1,64}$`; an existing id exits 64 unless `--resume`. | F-063 |
| `--resume RUN_DIR\|RUN_ID` | — | Re-run units that are not `ok`/`skipped` or whose digests changed; always re-run analysis. The account is verified through STS (mismatch: exit 1). | F-127 |
| `--retry-denied` | off | With `--resume`, also re-run `denied` modules. | F-127 |
| `--no-analysis` | analysis on | Collect only; `analysis.status: "skipped"` (manifest.md §3.8; never makes the run partial). Run `aws-enumerator analyze` later. | |
| `--zip` | off | Write `<output>/<account>/<run_id>.zip` (report-layout.md §10). | F-168 |
| `--encrypt age:RECIPIENT\|gpg:RECIPIENT` | — | Encrypt the zip (implies `--zip`); external binary, no Python dependency. | F-123 |
| `--sign gpg:KEYID\|minisign:KEY` | — | Sign the (encrypted) archive. | F-168 |
| `--redact-identity` | off | Drop `caller_arn`/`caller_user_id` from the manifest; keep `principal_arn` and `caller_arn_sha256`. | F-123, F-146 |
| `--shutdown-grace SECONDS` | `20` | After SIGINT/SIGTERM, how long running units may take to write partial data and coverage. | F-155 |

**Analysis** (passed to the engine as `AnalysisOptions`, engine-api.md §3.3; the same flags exist on `analyze`)

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--baseline PATH` | — | A previous run directory or `findings.json`; writes `analysis/diff.json` (finding-identity.md §4). | F-143 |
| `--suppress FILE` | — | Suppression file (finding-identity.md §5). An invalid file exits 64 before any collection. | F-143 |
| `--no-legacy-outputs` | off (the files are written) | Leave the twelve d13c215 legacy files (`permission_map.json`, `trust_relationships.json`, the ten `*_relationships.json`) out of `analysis/` (`AnalysisOptions.legacy_outputs = false`). They are kept for one release (DECISIONS.md D-22) and written as compact JSON; `graph.json` holds the same edges. | F-022 |

**Load and resilience**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--concurrency N` | `3` (max 16) | Units (global + each region) run in parallel; modules inside a unit run sequentially. | F-127 |
| `--max-rps N` | — | Cap every rate-limit bucket at `min(default, N)`. | F-154 |
| `--rate-limit SVC=RPS` | per-service defaults (collectors-cli.md §4) | Override one service; repeatable. | F-154 |
| `--no-rate-limit` | limiter on | For labs. | F-154 |
| `--retry-mode legacy\|standard\|adaptive` | user's config, else `adaptive` | botocore retry mode. The user's `AWS_RETRY_MODE` / profile setting wins unless this flag is given. | F-125 |
| `--max-attempts N` | user's config, else `5` | botocore total attempts (same precedence). | F-125 |
| `--deny-breaker N` | `3` | Consecutive per-item denials of one API before the rest are skipped; `0` disables (coverage-schema.md §3). | F-125 |

**Collector tuning** (read by the collector streams through `ctx.option(...)`)

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--iam-mode gaad\|per-entity` | `gaad` | IAM via `GetAccountAuthorizationDetails`, or the per-entity fallback. | F-052, F-109 |
| `--iam-gaad-file PATH` | — | Import an exported GAAD JSON instead of calling the API. | F-109 |
| `--no-credential-report` | report on | Skip `GenerateCredentialReport` (a write-like call). | F-167 |
| `--iam-user-details` / `--no-iam-user-details` | on | Per-user access keys, SSH keys, service credentials, signing certificates. | F-109 |
| `--s3-subresources basic\|full` | `basic` | Per-bucket calls (7 in basic). | F-105 |
| `--ecs-max-revisions K` | `5` (`0` = all) | Task-definition revisions described per family. | F-049 |
| `--ebs-share-check all\|none\|cap:N` | `cap:1000` | `DescribeSnapshotAttribute` budget. | F-104 |
| `--lambda-versions` | off | Also list versions and their policies. | F-055 |
| `--ec2-userdata-check` | off | Record UserData presence, SHA-256 and length (never content). | F-116 |
| `--full-dns` | off | Keep TXT/MX/SRV/CAA/SPF values and private-zone A/AAAA values. | F-112 |
| `--keep-sensitive-metadata` | off | Keep descriptions and tags that may hold secrets (Secrets Manager, SSM). | F-112 |
| `--scp-file PATH` | — | Import SCPs/RCPs for accounts that cannot read Organizations. | F-126 |

**User agent**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--ua-app-id STR` | `aws-enumerator/<version>/<run_id[-6:]>` | botocore `user_agent_appid` (rendered `app/aws-enumerator-0.3.0-a1b2c3`). Not set when the user already has `AWS_SDK_UA_APP_ID` / `sdk_ua_app_id`, unless this flag is given. | F-170 |
| `--no-ua-tag` | tag on | No app id (documented red-team opt-out). | F-170 |

**Preflight**

| Flag | Default | Meaning | Findings |
|---|---|---|---|
| `--preflight` | off | Run `preflight --mode probe` first and record it in `manifest.preflight`. | F-161 |
| `--preflight-only` | off | Run the preflight, print it, write nothing, exit 0 (all ok) or 2 (some denied). | F-161 |

**Run sequence** (R stream): logging and `umask 077` → AWS context (STS in the home region; failure exits 1) → selection → output root and git guard → run root, `manifest.json` (`in_progress`), `HANDLING.txt` → banner on stderr (product, version, account, partition, regions, run id, output, and "Authorized use only: run only against accounts you have written permission to assess", F-172) → optional preflight → units (`global` + each region) → **analysis once, after every unit** (F-010; not with `--no-analysis`) → manifest, digests, zip/encrypt/sign → summary on stderr → the run root on stdout → exit code.

### 3.2 `analyze <dir>`

```
aws-enumerator analyze <dir> [--force] [--allow-in-repo] [--baseline PATH] [--suppress FILE] [--redact-identity]
                       [--no-legacy-outputs]
```

Recognises the layouts of [report-layout.md](report-layout.md) §8 (v2 run, v0.2 `--all`, v0.2 single region) through `engine.analyze_report` (engine-api.md §3.2). The engine writes `<dir>/analysis/` through `analysis.tmp/`. A v2 run that is `in_progress` is refused unless `--force`. For a v2 run this command (not the engine) then updates `manifest.analysis` (manifest.md §3.8) and the digests; it never touches a legacy manifest. A merged run root (`manifest.run.kind == "merge"`, §3.8) is refused with exit 64 ("a merged run cannot be re-analysed; run `aws-enumerator merge` on its sources again"). `--baseline` / `--suppress` / `--no-legacy-outputs` as for `collect`; `--redact-identity` publishes `principal_arn` instead of the caller ARN in `graph.json` (redaction also applies when the manifest is redacted, graph-json.md §4.1). stdout: the analysis directory. Exit 0 (ok), 2 (engine reported failed analyzers), 1 (analysis failed), 64 (not a report / usage, including an invalid suppression or baseline file).

### 3.3 `export <dir>`

```
aws-enumerator export <dir> --format sarif|csv|md|asff|opengraph [--output PATH|-]
                      [--min-severity critical|high|medium|low|info] [--include-suppressed] [--all-edges]
                      [--allow-in-repo]
```

Reads `<dir>/analysis/graph.json` only (a legacy report must be analysed first: exit 64 with the hint); any 1.x graph, merged ones included (graph-json.md §4.2). `--allow-in-repo` lifts the git guard of [report-layout.md](report-layout.md) §2 for an output inside a work tree (without it: exit 64). Mapping and file names: [exports.md](exports.md). The bytes come from the engine's writer API `aws_enumerator.engine.writers.export(graph, fmt, ...)` (engine-api.md §6.3); this command only resolves the output, applies the git guard and writes atomically. Default output `<dir>/analysis/exports/<file>`; `--output -` writes to stdout. stdout: the written path (or the content with `-`). Exit 0, 1 (unreadable/invalid graph, or a format whose writer is not available in this build), 64.

### 3.4 `preflight`

```
aws-enumerator preflight [--profile NAME] [--region R|--regions A,B|--all] [--exclude-regions A,B]
                         [--modules A,@GROUP] [--skip A,@GROUP] [--max-tier 1|2] [--no-k8s|--k8s]
                         [--mode probe|simulate] [--format text|json]
```

- The identity, region and selection flags mean what they mean for `collect` (§3.1). The command is implemented as `collect --preflight-only` with `--mode` and `--format`: it writes nothing. `collect --preflight` and `--preflight-only` always use `probe`.
- `probe` (default): one cheap call per selected module (`spec.probe`) in the home or global region. The probes are visible in CloudTrail (documented in docs/detection.md).
- `simulate`: resolve the principal (assumed role → `iam:GetRole`), then `iam:SimulatePrincipalPolicy` over every action of the selected modules, in batches; report `allowed` / `implicit_deny` / `explicit_deny`.
- stdout: the result table (text) or JSON. Exit 0 (all ok), 2 (something denied), 1 (credentials), 64.

### 3.5 `permissions`

```
aws-enumerator permissions [--format iam|k8s|markdown] [--modules] [--skip] [--no-k8s|--k8s] [--k8s-secrets]
                           [--max-tier] [--partition aws|aws-us-gov|aws-cn|...] [--include-optional] [--guardrail]
```

Offline. Builds from `SPEC.actions` / `optional_actions` / `resource_scoped` / `k8s_rbac` of the selected modules and the active flags. `iam`: a policy with statements `AwsEnumeratorTier1` (also holds the runner's own `ec2:DescribeRegions`, region discovery for `--all`), `AwsEnumeratorApiGatewayRead` (resource-scoped; other resource-scoped actions get one statement each), `AwsEnumeratorTier2SecretBearingConfig` (omitted with `--max-tier 1`), `AwsEnumeratorOptional` (only with `--include-optional`; holds the modules' `optional_actions` plus `iam:GetRole` and `iam:SimulatePrincipalPolicy` for `preflight --mode simulate`); `--guardrail` adds the data-plane Deny statement `AwsEnumeratorDenyDataPlane`. `k8s`: ClusterRole, kube-system Role for `aws-auth`, bindings to group `aws-enumerator-readers`, an `aws eks create-access-entry` example; Secret listing only with `--k8s-secrets`. `markdown`: regenerates `docs/permissions.md`. stdout: the document. Exit 0 / 64.

### 3.6 `modules`

```
aws-enumerator modules [--format table|json]
```

The registry (registry.md §4): name, scope, default, tier, cost, noise, groups, actions count, state (planned / implemented). `json` is `[spec.to_json(), ...]`. stdout. Exit 0.

### 3.7 `dashboard`

```
aws-enumerator dashboard [PATH] [--host 127.0.0.1] [--port 8000] [--no-browser] [--allowed-host H]...
```

- Calls `aws_enumerator.dashboard.server.serve_dashboard(host="127.0.0.1", port=8000, open_browser=True, allowed_hosts=(), on_listening=None)` (Du stream, Wave 2; request `r-1`). The server calls `on_listening(url)` exactly once, after the socket is bound, with the **bound** port (for example `http://127.0.0.1:54321/index.html`); the CLI's callback writes that URL to stdout, so the server itself never prints (F-169). The server returns `False` (or raises `OSError`) when no port can be bound. `PATH` (a run directory or zip) is optional and only printed as a hint; the browser loads files through the page's own picker (the server never serves report files).
- `--port` accepts 0–65535 only (`port_type`); `0` picks a free port and the **bound** port is printed and opened (F-139). Retries `port..port+9` when the port is busy and not 0.
- `--host` other than loopback prints a WARNING and never opens a browser; the Host-header allow-list is `127.0.0.1`, `localhost`, `::1`, the bind host and every `--allowed-host` (F-128, F-129).
- stdout: one line, the URL, once listening. Exit 0 on SIGINT/SIGTERM, 1 when no port can be bound, 64.

### 3.8 `merge`

```
aws-enumerator merge RUN_DIR RUN_DIR [RUN_DIR ...] [--output DIR] [--run-id ID] [--allow-in-repo]
```

A multi-account view (F-126): joins the analysed graphs of runs of **different accounts** into one `graph.json` of schema **1.1** (graph-json.md §4.2, [DECISIONS.md](DECISIONS.md) D-42 to D-45; this replaces D-32's "not available").

- **Inputs:** two or more `RUN_DIR`s, each a directory holding `analysis/graph.json`: an analysed v2 run root, or a legacy report directory after `aws-enumerator analyze`. Command-line order does not matter (sources are sorted by account, then run id). Each graph must be schema major 1 with a minor this build knows (1.0, 1.1), not itself a merge, and valid (its schema and `validate_graph`); all sources share one partition; no account appears twice.
- **Who does what.** `aws_enumerator/engine/merge.py` (E-core) checks the inputs (`plan_merge`), builds the merged document by the rules of graph-json.md §4.2 and validates it (`graph-1.1.schema.json` + `validate_graph(strict_order=True)`) **in memory**, then writes `<merged root>/analysis/graph.json` through `analysis.tmp/` like `analyze_run` (engine-api.md §3.5). This command (R) resolves the output root (`--output`, `$AWS_ENUMERATOR_OUTPUT`, `~/.aws-enumerator/reports`; [report-layout.md](report-layout.md) §2), applies `umask 077` and the git guard, picks the run id (`--run-id` or `<UTC ts>-<6 hex>`, report-layout.md §1.2), creates the run root `<output>/merged/<run_id>/` (0700) only after the merged document validated, and writes `manifest.json` ([manifest.md](manifest.md) §3.11), `HANDLING.txt` and, last, `SHA256SUMS` (D-17). A merge that fails before the run root exists writes nothing.
- **Output:** the merged run root holds exactly `manifest.json` (`run.kind: "merge"`), `HANDLING.txt`, `analysis/graph.json` (`schema_version` `1.1.0`) and `SHA256SUMS`: no `global/`, region directories, `run.log` (`--log-file PATH` logs to `PATH` only), `findings.json` or `summary.json`. `export`, `verify`, `package` and the dashboard accept it; `analyze` refuses it (§3.2).
- **stdout:** the merged run root.
- **Exit codes:**

  | Code | When |
  |---|---|
  | 0 | merged. Also when sources are partial: their module coverage and analyzer status travel per account in the merged graph (graph-json.md §10). |
  | 64 | fewer than two `RUN_DIR`s; a `RUN_DIR` that is not a directory or has no `analysis/graph.json` (hint: `aws-enumerator analyze <dir>`); a source that is itself a merge; two sources of the same account; sources of different partitions; an invalid or existing `--run-id` (`<output>/merged/<ID>/` exists); an output inside a git work tree without `--allow-in-repo` |
  | 1 | a source `graph.json` that cannot be read or parsed, whose major is not 1 or whose minor is newer than this build knows, or that fails its schema or `validate_graph`; the merged document fails validation (for example sources analysed with a different traversability table: re-run `aws-enumerator analyze` on them with this version); the output cannot be written |

### 3.9 `package`

```
aws-enumerator package RUN_DIR [--output PATH] [--encrypt ...] [--sign ...] [--allow-in-repo] [--force]
```

Builds the deterministic zip of [report-layout.md](report-layout.md) §10 (default next to the run root), then optionally encrypts and signs it. Refuses an `in_progress` run unless `--force`. stdout: the final archive path. Exit 0, 1 (external tool failed), 64.

### 3.10 `verify`

```
aws-enumerator verify RUN_DIR|ZIP
```

Recomputes `SHA256SUMS` and `manifest.files` ([report-layout.md](report-layout.md) §7), validates `manifest.json` against the schema, and lists mismatching, missing and unlisted files. stdout: `OK <n> files` or one line per problem (`MISMATCH <path>`, `MISSING <path>`, `UNLISTED <path>`). Exit 0 (all good), 1 (any problem), 64.

### 3.11 `version`

```
aws-enumerator version [--json]
```

stdout: `aws-enumerator 0.3.0`; with `--json`, `{"version", "git_sha", "python", "boto3", "botocore", "kubernetes"}` (the manifest's `tool` block). Exit 0.

## 4. Legacy invocation (one release, F-061 compatibility)

If the first argument is not a subcommand and not `-h`/`--help`/`--version`, the CLI translates the old flags and prints a deprecation WARNING on stderr (`'aws-enumerator --all' is deprecated; use 'aws-enumerator collect --all' (removed in 0.4.0)`):

| Old invocation | Translated to |
|---|---|
| `--dashboard [--port N]` | `dashboard [--port N]` (other old flags are ignored with a warning) |
| `--region R [--zip]` | `collect --region R [--zip]` |
| `--all [--zip]` | `collect --all [--zip]` |
| (no arguments) | `collect` (home region from the profile/environment; exit 64 if there is none) |

Behaviour changes users will notice: no default region (`eu-west-2` was hard-coded, F-124); output under `~/.aws-enumerator/reports/<account>/<run_id>/` instead of `./reports/<date>/...`; K8s on by default; exit code 2 on partial runs. The translated argv is what `manifest.run.argv` records.

## 5. stdout and stderr

- **stdout carries only the command's result**, so wrappers can capture it:

  | Command | stdout |
  |---|---|
  | `collect` | exactly one line: the absolute run root (also for partial and interrupted runs once the run root exists; nothing when the run fails before that) |
  | `analyze` | the analysis directory |
  | `export` | the written file, or the content with `--output -` |
  | `merge`, `package` | the merged run root / the archive path |
  | `verify` | `OK <n> files` or the problem lines |
  | `dashboard` | the URL |
  | `modules`, `permissions`, `preflight`, `version` | their output |

- **stderr carries everything else:** the banner, progress, the end-of-run summary, warnings, deprecation notices, errors, and the dashboard hint ("dashboard: `aws-enumerator dashboard`, then load `<run>.zip` (`aws-enumerator package <run>`) or the folder", F-145).
- No `print()` outside `cli.py` and `logging_setup.py`, and no direct `sys.stdout` / `sys.stderr` writes in runtime code (F-169; `tests/python/quality/test_r_quality_codebase.py` enforces both).

## 6. Exit codes

| Code | Meaning | Examples |
|---|---|---|
| 0 | complete | every selected module `ok` or `skipped`, analysis `ok` or `skipped` (`--no-analysis`) |
| 2 | partial | some module ended `partial`, `denied` or `failed`, or analysis failed or was partial; `preflight` found denials |
| 1 | fatal | STS/credentials failed, unknown profile, output unwritable, expired token during the run (`RunAborted`), every module `failed`; `verify` mismatch |
| 64 | usage | argparse errors, unknown module/group (`SelectionError`), conflicting flags, no home region, output inside a git work tree without `--allow-in-repo`, existing `--run-id`, not a report; `merge` inputs that cannot be merged (§3.8) |
| 130 | SIGINT | the manifest is finalised as `interrupted` first; a second SIGINT writes a best-effort manifest and calls `os._exit(130)` |
| 143 | SIGTERM | as SIGINT |

Explicit skips (flags, partition availability, not implemented) never make a run partial. The mapping from `run.status` is in [manifest.md](manifest.md) §2.

## 7. Environment variables

| Variable | Effect |
|---|---|
| `AWS_ENUMERATOR_OUTPUT` | default output root (§3.1) |
| `AWS_ENUMERATOR_GIT_SHA` | `tool.git_sha` (set by the Docker build) |
| `AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_*` credentials | standard botocore resolution (one session per run) |
| `AWS_RETRY_MODE`, `AWS_MAX_ATTEMPTS` | respected; the tool only sets its retry defaults when neither these nor the profile set them (F-125). The tool never writes `os.environ`. |
| `AWS_SDK_UA_APP_ID` | respected; see `--ua-app-id` |
| `NO_COLOR` | any non-empty value disables colours (logging.md §4) |
| `SOURCE_DATE_EPOCH` | the engine's `generated_at` (reproducible analysis) |
| `KUBECONFIG` | used by `--k8s-auth kubeconfig` when `--kubeconfig` is not given |
