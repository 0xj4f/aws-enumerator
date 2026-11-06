# Golden ledger: stream R (CLI, runner, session, output layout, manifest, logging; Wave 1)

R regenerated nothing (ownership.md §3.5). The entries below explain the diffs I1 will see in the goldens that
run the console entry point. Collector data inside the trees also changes because of the collector streams
(C-A, C-B, C-K8s ledgers) and analysis output because of the engine streams; those parts are theirs.

## collect: one run-unique layout for every mode
- Findings: F-063, F-025, F-153, F-010, F-159, F-168, F-123, F-171
- Goldens: collectors-v0/single/**, collectors-v0/all/** (`test_report_tree_matches_golden[single|all]`)
- Change: the old flags are translated (`--region R` -> `collect --region R`, `--all` -> `collect --all`) and a run
  writes `<output>/<account>/<run_id>/` instead of `reports/<date>/<account>[/<region>]/`. The legacy harness points
  `$AWS_ENUMERATOR_OUTPUT` at `<workdir>/reports/<UTC date>`, so paths become `<account>/<run_id>/...`.
- Expected diff:
  - every path gains a `<run_id>/` segment (`<UTC %Y%m%dT%H%M%SZ>-<6 hex>`, random); single-region mode is a
    run with one region, so global modules move from `<region>/<module>/` to `global/<module>/` (collected
    once per run, F-153) and `waf/` (both scopes) splits into `global/waf_cloudfront/` + `<region>/waf/`;
  - new run-root files: `HANDLING.txt` (fixed text, F-159), `SHA256SUMS` (F-168), `run.log` (JSON lines,
    timestamps and run id per record, F-169); every module directory gains `_coverage.json` (contract of
    Wave 0, written by `run_collector`);
  - `manifest.json` is schema 2.0 (manifest.md): `tool`, `run` (run id, status, exit code, argv, options),
    `target` (regions, region_source), `operator`, `classification`, `preflight`, per-module `modules[]` entries,
    `analysis`, `coverage_summary`, `files[]` digests; no `author`, no `modules_executed`, UTC `...Z`
    timestamps (F-061, F-122, F-144, F-168, F-171);
  - analysis output moves from `global/analysis/` (all mode) or `<region>/analysis/` (single) to
    `<run_root>/analysis/` and is produced once after every unit (F-010) by `engine.analyze_run`
    (graph.json, findings.json, summary.json plus the legacy relationship files: engine streams' content);
  - `--all` collects the regions found by `ec2:DescribeRegions` in the home region; with the harness's patched
    discovery the regions are unchanged (eu-west-1, eu-west-2).
- Determinism (`test_golden_run_is_deterministic[single|all]`): two runs now differ in the run-id path segment and
  in `run.log` / `_coverage.json` / manifest clock fields. A stable golden needs the run invoked with a fixed
  `--run-id` (for example `collect --run-id golden-v1 ...`) and `run.log` excluded or masked by the canonicaliser.

## call log, console and canary inventories
- Findings: F-010, F-064, F-119, F-124, F-169, F-061
- Goldens: collectors-v0/calls-single.json, collectors-v0/calls-all.json, collectors-v0/console-all.json
  (`test_call_log_matches_golden`, `test_console_failures_match_golden[all]`)
- Change and expected diff:
  - `analyze_calls`: one call per run, to `analyze_run` on the run root with the explicit region list (was
    `analyze` on `global/` before any region existed, F-010); the harness records `entry_point` and `regions`;
  - `region_discovery_calls`: the home region (from `AWS_DEFAULT_REGION` / the profile, F-124), not a session in a
    hard-coded us-east-1 (F-119);
  - `<orchestrator>` calls: `sts:GetCallerIdentity` in the home region (regional STS endpoint) instead of
    eu-west-2/us-east-1 by default; with `--all` and real discovery, `ec2:DescribeRegions` in the home region;
  - module failures are no longer printed as `[-] <label> module failed: ...` console lines (`run_module` is gone,
    F-169): failures are manifest statuses (`partial`/`failed`) and WARNING/ERROR log records on stderr, so
    `module_failures` becomes `[]` and `collector_warnings` lists only what legacy-style collectors still print;
  - the canary inventory (`test_canary_leak_inventory`) changes with the collector streams' redactions (not R).

## legacy/all_mode_main and the F-010 characterisation
- Findings: F-010, F-063, F-153, F-061, F-171
- Goldens: legacy/all_mode_main/{orchestration.json, manifest.json, global/analysis/**}
  (`test_legacy_main_all_mode_golden`, `test_all_mode_regional_relationships_are_empty_characterisation`)
- Change: these two tests drive the d13c215 `main()` through patch points that no longer exist
  (`main_patch_points()["session_factory"]` and `["datetime"]`; the CLI has no `get_boto3_session` /
  `get_enabled_regions` / `datetime`: FakeAWS.install() patches `boto3.Session`, which `AwsContext` uses, and region
  discovery is `aws_session.describe_enabled_regions(aws, region)`). They now fail with `KeyError` before running.
  The second one asserts the F-010 bug itself ("analysis ran before any region directory existed") and must be
  retired; the first needs a v2 rewrite: analysis at `<run_root>/analysis/`, one analyze call after every unit,
  regional relationship files non-empty, manifest schema 2.0.
- Expected diff: replace `global/analysis/**` with `analysis/**` at the run root; `orchestration.json`
  `analyze_calls` = one `analyze_run` call listing `global` and both regions; `manifest.json` = schema 2.0.
