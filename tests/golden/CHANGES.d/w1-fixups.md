# Golden ledger: w1-fixups (sync fixups agent between Wave 1 and Wave 2, 2026-10-16)

Nothing was regenerated (ownership.md §3.5). These entries explain what I1 will see when it regenerates the
collectors-v0 goldens in Wave 3 (`requests/r-2.md`).

## collectors-v0: run-unique values masked by the harness normalisation
- Findings: F-063, F-162, F-171 (determinism of the v2 run layout)
- Goldens: collectors-v0/single/**, collectors-v0/all/**, collectors-v0/calls-{single,all}.json
  (`test_report_tree_matches_golden[single|all]`, `test_call_log_matches_golden[single|all]`)
- Change: `tests/python/collectors/legacy_harness.py` `LegacyRun.normalised_tree()` now masks what differs between
  two runs of the same world: the generated run id becomes `<RUN_ID>` in paths and contents; `ended_at`
  (manifest and every `_coverage.json`) and `graph.json` `run.source_manifest_sha256` are `<stripped>` like the
  other clock keys; the manifest `files[]` `sha256` / `bytes` of the files that embed the run id or the clock
  (`HANDLING.txt`, `analysis/*`, `*/_coverage.json`) are `<stripped>`. `date_free()` also turns a generated run id
  into `<RUN_ID>`, so `calls-*.json` `analyze_calls[].path` is `reports/<date>/<account>/<RUN_ID>`.
- Expected diff: on top of R's layout entry (`CHANGES.d/r.md`), every path segment `<run_id>` reads `<RUN_ID>`; the
  masked keys read `"<stripped>"`. `test_golden_run_is_deterministic[single|all]` passes again without a fixed
  `--run-id` (the alternative r-2 proposed); the remaining run.log masking of r-2 is moot because
  `canonical_tree` reads `*.json` only.
