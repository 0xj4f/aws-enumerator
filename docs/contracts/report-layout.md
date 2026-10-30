# Contract: report layout

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; precisions at the Wave 0/1 sync by contract-arbiter in §1, §1.3, §8 and §9; at the Wave 1/2 sync in §1 (merged run roots) and §1.3 (state note); all listed in [DECISIONS.md](DECISIONS.md); Wave 3a (I1, i1-runtime): §1.3 no longer describes the removed interim adapter). Change it only through a change request (`$RUN/requests/`).
**Owner decisions applied (PLAN.md):** default output `~/.aws-enumerator/reports`; run-unique folders; `0700` directories and `0600` files; analysis runs once, after all collection, at the run root; writing inside a git work tree needs `--allow-in-repo`.
**Implemented by:** `aws_enumerator/util/fsio.py` (atomic private writes, digests, the git guard; done), `aws_enumerator/collectors/base.py` (module directories and `_coverage.json`; done), and the R stream's `output.py` / `runner.py` (run root, manifest, `HANDLING.txt`, `SHA256SUMS`, zip; Wave 1).
**Related contracts:** [manifest.md](manifest.md), [coverage-schema.md](coverage-schema.md), [collector-context.md](collector-context.md), [cli.md](cli.md), [logging.md](logging.md). The engine's `graph-json.md` defines what goes inside `analysis/`.

Findings this layout addresses, once the R stream wires it in: F-010, F-025, F-063 (run isolation), F-066 (reports in a work tree), F-123 (permissions), F-153 (globals once per run), F-155 (manifest on interrupt), F-159 (handling notice), F-168 (digests), F-171 (UTC).

---

## 1. The tree

Every mode produces the same shape. Single-region mode is a run with one region (F-153).

```
<output>/                                  0700  default ~/.aws-enumerator/reports (see §2)
  <account_id>/                            0700  12 digits
    <run_id>/                              0700  THE RUN ROOT, e.g. 20261015T101500Z-a1b2c3
      manifest.json                        0600  schema 2.0 (manifest.md); written first, rewritten after every unit
      HANDLING.txt                         0600  data-handling notice (§6)
      run.log                              0600  JSON lines (logging.md §5)
      SHA256SUMS                           0600  written last (§7)
      global/                              0700  global services, collected once per run
        iam/            _coverage.json + data files
        organizations/  s3/  cloudfront/  waf_cloudfront/  route53/
      <region>/                            0700  one directory per collected region, e.g. eu-west-2
        vpc/  sg/  ec2/  ebs/  flowlogs/  cloudtrail/  waf/  elb/  apigateway/  eks/
        k8s/                                     _coverage.json + one directory per cluster
          <cluster>/  cluster_info.json  pods.json ...
        secretsmanager/  ssm/  lambda/  kms/  ecs/  cloudformation/  glue/  codebuild/  sagemaker/
        sns/  sqs/  ecr/  rds/  dynamodb/  cognito/
        guardduty/  securityhub/  config/  accessanalyzer/
      analysis/                            0700  written ONCE, after all units, by the engine (graph-json.md §1 is the file list)
        graph.json                               schema 1.x (engine contract graph-json.md); the dashboard's only input
        findings.json  summary.json              always
        diff.json                                only with --baseline
        permission_map.json  trust_relationships.json
        s3_relationships.json  ec2_relationships.json  secrets_relationships.json  lambda_relationships.json
        kms_relationships.json  compute_relationships.json  messaging_relationships.json
        newsurface_relationships.json  extra_relationships.json  k8s_relationships.json
                                                 the 12 legacy outputs (d13c215 formats), kept for one release
        exports/                                 optional; `aws-enumerator export` / AnalysisOptions.exports output (exports.md)
    <run_id>.zip                           0600  optional (--zip or `aws-enumerator package`), NEXT TO the run root
  merged/                                  0700  only `aws-enumerator merge`: merged/<run_id>/ is a run root (cli.md §3.8)
```

`merged/` is the only directory at the account level whose name is not a 12-digit account id. A merged run root
`merged/<run_id>/` holds exactly `manifest.json` (`run.kind: "merge"`, manifest.md §3.11), `HANDLING.txt`,
`SHA256SUMS` and `analysis/graph.json` (schema 1.1, graph-json.md §4.2), plus `analysis/exports/` once
`export` ran on it; never `global/`, region directories or the other `analysis/` files.

Module directory names are `CollectorSpec.output_dir` ([registry.md](registry.md)); the names above are the registry as of Wave 0. A module that did not run (skipped, not implemented, `not_run`) has **no** directory. A module that ran **always** has a directory containing `_coverage.json`, even if it wrote nothing else.

### 1.1 Rules for the run root

1. **Only these entries may exist** directly under the run root: `manifest.json`, `HANDLING.txt`, `run.log`, `SHA256SUMS`, `global/`, region directories, `analysis/`, plus the transient names in rule 5. No `logs/`, no `tmp/`, no per-module files at the root.
2. **Region directories** are named exactly as the region (`eu-west-2`, `us-gov-west-1`, `cn-north-1`) and must match `^[a-z]{2}(-[a-z]+)+-[0-9]+$`.
3. **The set of regions is `manifest.target.regions`.** Nothing discovers regions by listing directories: not the engine (no sibling scans, F-010, F-025), not the dashboard, not `verify`. A directory that is not in the manifest is ignored by analysis and reported by `verify`.
4. **Each unit writes only its own directory.** The `global` unit writes `global/`; the unit for region R writes `R/`. Units can therefore run concurrently, and the output is deterministic.
5. **Transient names**, which never survive a successful command:
   - `analysis.tmp/` while analysis runs; it is renamed to `analysis/` when complete. A previous `analysis/` is first renamed to `analysis.prev/` and deleted after the swap.
   - `<unit>.stale-<n>/` during `--resume` (the old copy of a unit being re-run; deleted when the unit completes).
   - `.<name>.tmp-<pid>-<hex>` files from atomic writes (§4).
6. **The run is in progress** while `manifest.run.status == "in_progress"`. After SIGKILL or OOM it stays that way; `--resume` and the dashboard detect it.

### 1.2 Run id

- Format: `<UTC %Y%m%dT%H%M%SZ>-<6 lowercase hex>`, for example `20261015T101500Z-a1b2c3`. The hex comes from `secrets.token_hex(3)`.
- `--run-id ID` overrides it. It must match `^[A-Za-z0-9._-]{1,64}$` and must not be `.` or `..`. An existing `<output>/<account>/<ID>/` is refused (exit 64) unless `--resume` is given.
- Lexical order equals chronological order for generated ids.

### 1.3 Analysis location

- **v2 runs:** `<run_root>/analysis/`. The engine is given the run root, the manifest and the explicit region list; it reads `global/` and each `<region>/` named in `manifest.target.regions`.
- **No `global/analysis/` in a v2 run.** The runner and `analyze` call `engine.analyze_run(<run_root>, regions=...)` once, after all collection (`manifest.analysis.engine: "v2"`); it reads only the units named in `manifest.target.regions`, never sibling or `.stale-*` directories (F-010, F-025, F-063). The per-domain `*_relationships.json` files are written into `<run_root>/analysis/` by the engine's native writers while `AnalysisOptions.legacy_outputs` is true (graph-json.md §1, D-22). The Wave 1 interim adapter (the d13c215 `analyze(<run_root>/global)` plus a `global/analysis/` swap) was removed in Wave 3a.
- `analysis/exports/` holds files written by `aws-enumerator export` or by `AnalysisOptions.exports` (exports.md). They are derived, are **not** listed in `manifest.files` or `SHA256SUMS`, and `verify` ignores them.
- **Who writes what.** The engine (`analyze_run` / `analyze_report`) writes only `analysis.tmp/` → `analysis/` (and, for legacy layouts, `_provenance.json` and the `analysis.orig/` rename of §8). Everything else at the run root (`manifest.json` including `manifest.analysis`, `HANDLING.txt`, `run.log`, `SHA256SUMS`, the zip) is written by the R stream's `output.py` / `runner.py`, or by its `analyze` / `export` / `package` commands; after an analysis of a v2 run, the R code that called the engine updates `manifest.analysis`, `manifest.files` and `SHA256SUMS` (engine-api.md §3.1).

---

## 2. Output root

Resolution order:

1. `--output PATH`
2. `$AWS_ENUMERATOR_OUTPUT` (the Docker image sets `/reports`)
3. `~/.aws-enumerator/reports` (`~` expanded with `Path.expanduser`)

**Git guard (F-066).** Before anything is created, `fsio.find_git_worktree(<output>)` walks from the output path (or its closest existing ancestor) up to `/`, looking for a `.git` directory or file. If one is found and `--allow-in-repo` is not given, the command stops with exit code **64** and this message on stderr:

```
error: output directory <path> is inside the git work tree <worktree>; reports are confidential.
       Use --output outside the repository, or pass --allow-in-repo if you really mean it.
```

The guard applies to every command that writes report data: `collect`, `analyze` (its output goes next to its input, so analysing a report that sits in a repository also needs `--allow-in-repo`), `merge`, `package` and `export` (when its output path is inside a work tree).

---

## 3. Permissions (F-123)

| Object | Mode | How |
|---|---|---|
| process umask | `077` | `os.umask(0o077)` at the start of `collect`, `analyze`, `merge`, `package`, `export` |
| directories the tool creates | `0700` | `fsio.ensure_dir`: `os.mkdir(d, 0o700)` then an explicit `os.chmod(d, 0o700)` for **every component it creates**. Pre-existing parents such as the `--output` directory are left alone. |
| files | `0600` | `fsio.atomic_write_*`: `os.open(tmp, O_CREAT\|O_EXCL\|O_WRONLY\|O_NOFOLLOW\|O_CLOEXEC, 0o600)`, then `os.fchmod(fd, 0o600)`, then `os.replace(tmp, final)` |
| zip archive | `0600` | the same primitive |
| `run.log` | `0600` | opened by `logging_setup` with `os.open(..., 0o600)` before the handler attaches |

Legacy-style collectors (not yet migrated) write with plain `open()`. Under the `077` umask their files are still `0600` and their directories `0700`. The collector streams move them to `ctx.out.write` in Wave 1.

---

## 4. Writing files

- **Always atomic.** A file is written to `.<name>.tmp-<pid>-<hex>` in the same directory and renamed into place, so a reader (the dashboard, `verify`, a resumed run) never sees half a file.
- **JSON** goes through `fsio.dumps_json`: `indent=2`, `ensure_ascii=True` (every non-ASCII byte of hostile input is escaped), `allow_nan=False`, and `fsio.json_default`:
  - `datetime` becomes UTC ISO-8601 with `Z` (`2026-10-15T10:15:02Z`; microseconds kept when present). Naive datetimes are taken to be UTC already (F-171).
  - `date`/`time` become ISO strings; `Decimal` becomes `int` or `float`; sets become sorted lists; tuples become lists; `Path` becomes `str`.
  - `bytes`, `bytearray` and `memoryview` **raise `TypeError`**, so binary data (for example the IAM credential report CSV) is never dumped by accident. Serialisation happens before the temporary file is created, so a `TypeError` leaves no file behind.
  - Anything else becomes `str(obj)`.
- **File names** inside a module directory are validated by `fsio.validate_relpath`: relative, `/`-separated, no `.`/`..`/empty segments, each segment `^[A-Za-z0-9._+=,@-]{1,255}$`. That covers IAM entity names, S3 bucket names and KMS key ids, which keep their raw names because the engine keys on them.
- **Collision-free item names (F-114).** Items whose names may collide or contain `/` (Secrets Manager secrets, Lambda resource policies, IAM policy documents, SSM parameter policies) use `fsio.hashed_filename(key, hint)`, which gives `f"{slug(hint)[:48]}-{sha256(key)[:12]}.json"` with `key` the ARN. `prod/db` and `prod_db` therefore get different files.
- **Reserved names.** In a module directory, names starting with `_` belong to the runtime: `_coverage.json` ([coverage-schema.md](coverage-schema.md)), and `_provenance.json` in `analysis/` (§8).
- **Never written inside** the directories the legacy engine lists: `policy_documents/`, `inline_policies/*/`, `resource_policies/`, `key_policies/`. `_coverage.json` sits at the module directory root.

---

## 5. Timestamps

Every timestamp in every file the tool writes is UTC with a `Z` suffix (F-171): the manifest, `_coverage.json`, log lines and data files. The only clock values in a run are:

- `manifest.run.started_at` / `ended_at` / `duration_seconds` and `analysis.started_at` / `duration_seconds`;
- the per-module `started_at` / `ended_at` / `duration_seconds`, in the manifest and in `_coverage.json`;
- the engine's `graph.json` generation time (which honours `SOURCE_DATE_EPOCH`).

Golden tests mask exactly these.

---

## 6. HANDLING.txt (F-159)

It is written at run start, before any collection, so even an interrupted run carries it, and it is included in the zip. The text is fixed apart from the three placeholders:

```
aws-enumerator report: CONFIDENTIAL

Run:      {run_id}
Account:  {account_id}
Created:  {started_at}

This directory is a pre-computed attack map of the AWS account above: identities and
their effective permissions, trust relationships, network exposure, and resource policies.
Treat it like a credential.

  - Keep it encrypted at rest and in transit (aws-enumerator package --encrypt ...).
  - Do not commit it to version control or attach it to tickets or chat.
  - Share it only with people covered by the written authorisation for this assessment.
  - Delete it when the engagement's retention period ends.
  - Open the dashboard only on this machine (aws-enumerator dashboard binds 127.0.0.1),
    and open reports you did not produce only in an isolated browser profile.

The collectors are designed to leave out secret values (no S3 objects, no secret or parameter
values, no Kubernetes Secret data, no environment-variable values), but names, tags, policy
documents and configuration are copied as they are and may hold more than intended.
```

---

## 7. Digests: manifest.files and SHA256SUMS (F-168)

- **`manifest.files`** lists every regular file under the run root, sorted by POSIX path, **except** `manifest.json`, `SHA256SUMS`, `run.log` (still being written), `*.zip`, transient names (§1.1 rule 5) and `analysis/exports/**`. Each entry is `{path, sha256, bytes}`. Symlinks are never followed or listed (`fsio.iter_files`).
- **`SHA256SUMS`** is written last, after the final manifest. It covers the same set as `manifest.files` **plus `manifest.json`**: one line per file in GNU coreutils format (`<64 hex><two spaces><relative path>\n`), sorted by path. From the run root, `shasum -a 256 -c SHA256SUMS` verifies the run.
- `aws-enumerator analyze` and `--resume` rewrite both after they change files. `aws-enumerator verify <run>` recomputes both and exits 1 on any mismatch, missing file, or file not listed (outside the exclusions above).

---

## 8. Layouts that `analyze` recognises

`aws-enumerator analyze <dir>` classifies `<dir>` in this order:

| # | Layout | Detected by | Global data | Regions | Analysis written to |
|---|---|---|---|---|---|
| 1 | **v2 run** | `<dir>/manifest.json` whose `schema_version` has major `2` (`"2.0"`, later `"2.x"`; manifest.md §4) | `<dir>/global/` | `manifest.target.regions` | `<dir>/analysis/` (via `analysis.tmp/`); `manifest.analysis` and the digests are updated by the `analyze` command |
| 2 | **v0.2 `--all`** | `<dir>/global/` is a directory (manifest absent, or legacy with `run_metadata.mode == "all_regions"`). Path shape `reports/<date>/<acct>/` | `<dir>/global/` | children of `<dir>` whose name is a region known to botocore in any partition (covers `us-gov-*`, `cn-*`, `us-iso*`) | `<dir>/analysis/` |
| 3 | **v0.2 single region** | `<dir>/iam/` is a directory. Path shape `reports/<date>/<acct>/<region>/` | `<dir>` itself (it holds `iam/`, `s3/` ...) | one region: the directory name if it is a known region; otherwise **none** (`graph.run.regions` is empty and the `legacy:region-unknown` evaluation gap is added, graph-json.md §10.2) | `<dir>/analysis/` |
| — | anything else | | | | exit 64: "not an aws-enumerator report" |

For layouts 2 and 3:

- The legacy manifest is **never** modified.
- `<dir>/analysis/_provenance.json` records `{schema_version: 1, source_layout: "legacy-all" | "legacy-single", analyzed_at, tool_version, git_sha, regions, account_id, input_files}`. `regions` equals `graph.run.regions`; `account_id` comes from the legacy manifest or the directory name, else `null`; `input_files` is a count. The engine writes it (engine-api.md §3.2).
- In layout 3 the old engine already wrote `<dir>/analysis/`. If that directory holds no `_provenance.json`, it is renamed once to `<dir>/analysis.orig/` (never overwritten) before the new analysis is moved into place.
- `analyze` refuses a v2 run whose status is `in_progress` unless `--force` is given.

---

## 9. How the dashboard finds `graph.json`

The dashboard's loader ([dashboard-core-api.md](dashboard-core-api.md) §3) works on a map of relative paths (a zip, a folder, or a single `graph.json`):

1. **Candidate roots** are the directories that contain `analysis/graph.json` or `manifest.json`. A v2 zip has exactly one, `<run_id>/`. If there are several (for example a folder of runs), the user picks one; labels come from each manifest's `run.run_id`, `target.account_id` and `run.started_at`.
2. **Exact reads only (F-093).** The loader reads `<root>/analysis/graph.json` and, optionally, `<root>/manifest.json`. It never suffix-matches and never inflates any other zip entry.
3. **Classification**, first match wins:
   - `ok`: `<root>/analysis/graph.json` is present and its `schema_version` major is 1.
   - `unsupported-version`: `graph.json` is present with another major version.
   - `legacy`: no `graph.json`, but `<root>/analysis/findings.json`, `<root>/analysis/*_relationships.json`, `<root>/global/analysis/`, or a manifest without `schema_version` exists. The banner says "This report predates graph.json. Run `aws-enumerator analyze <path>` and reload." Nothing is rendered.
   - `missing`: no candidate root, or a candidate root that matches none of the above, for example a v2 run (manifest `schema_version` 2.x) whose analysis has not run yet (`--no-analysis`, an interrupted or still running collection). The message names `manifest.analysis.status` when the manifest is readable and suggests `aws-enumerator analyze <path>`.
4. **Manifest use** is limited to the run picker and an integrity badge: if `manifest.files` lists `analysis/graph.json`, its SHA-256 is compared (verified / mismatch / n/a). The dashboard reads the operator and run metadata from `graph.json` (`run`), not from the manifest.

Legacy reports become loadable after `aws-enumerator analyze`. Layout 2 gets `<acct>/analysis/graph.json` next to `<acct>/manifest.json`, and layout 3 gets `<region>/analysis/graph.json`; in both cases the root is the directory that holds the manifest.

---

## 10. Zip archive

- Created by `collect --zip` at the end of the run, or later by `aws-enumerator package <run_dir>` (F-145).
- Location: `<output>/<account>/<run_id>.zip`, next to the run root, mode `0600`.
- Entries are `<run_id>/<relative path>` for every file in `manifest.files`, plus `manifest.json`, `HANDLING.txt`, `SHA256SUMS` and `run.log`. Entries are sorted by path, timestamps are fixed to the manifest's `run.started_at`, and permissions in the archive are `0600` / `0700`, so the archive is deterministic.
- The zip's SHA-256 is printed on stderr and logged. Encryption and signing (`--encrypt age:<recipient>|gpg:<recipient>`, `--sign gpg:<keyid>|minisign:<key>`) run as subprocesses on the finished zip; the plain zip is removed after successful encryption.
