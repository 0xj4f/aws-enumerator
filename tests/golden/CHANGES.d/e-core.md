# Golden change ledger: E-core (Wave 1)

E-core changed only shared helpers that the d13c215 `legacy_api.analyze()` still calls, plus the run-root
analysis the runner now gets from `engine.analyze_run`. The legacy goldens also change because of other Wave 1
streams (E-policy's permission map and rule records, the collectors' new shapes, R's run layout); those diffs
are theirs to ledger. Every E-core diff is listed here.

## Version-pinned finding references
- Findings: F-163
- Goldens: `legacy/<every scenario>/analysis/findings.json` (13 scenarios),
  `legacy/all_mode_main/global/analysis/findings.json`
- Change: `findings/references.py` builds `DOC_BASE` from the release tag of the running version.
- Expected diff: every `reference` value changes from
  `https://github.com/0xj4f/aws-enumerator/blob/main/docs/attack_paths.md#…` to
  `https://github.com/0xj4f/aws-enumerator/blob/v0.3.0/docs/attack_paths.md#…` (same anchors; ELB findings now
  carry `#resource-exposure--external-access-findings` instead of the bare document, F-088).

## Every severity in summary.json
- Findings: F-074
- Goldens: `legacy/<every scenario>/analysis/summary.json`, `legacy/all_mode_main/global/analysis/summary.json`
- Change: `findings/summary.py::_generate_summary` always lists the five severities in `by_severity` and adds
  `low_count` / `info_count`; counts include open findings only (legacy records have no `status`, so all count).
- Expected diff: `by_severity` gains the missing levels with `0` (e.g. `"INFO": 0, "LOW": 0`); new keys
  `low_count` and `info_count`; `total_findings`, `unique_findings`, `by_category` and the other counts unchanged.

## Sorted directory reads in the legacy IAM loaders
- Findings: F-162
- Goldens: none expected (`tests/support/canonical.py` sorts every list); listed for completeness.
- Change: `_load_policy_documents` / `_load_inline_policies` iterate `ls_sorted(...)`. Only a scenario with two
  policy documents of the same `PolicyName` could change its keyed-overwrite winner; none of the 13 has one.

## Analysis after collection at the run root (`main()` / runner golden)
- Findings: F-010, F-025, F-063 (engine side; the orchestration half is R's)
- Goldens: `legacy/all_mode_main/orchestration.json`, `legacy/all_mode_main/global/analysis/*`,
  `legacy/all_mode_main/manifest.json`; test `test_all_mode_regional_relationships_are_empty_characterisation`
- Change: the runner calls `engine.analyze_run(run_root, regions=manifest.target.regions)` once after every unit;
  it writes `<run_root>/analysis/` (graph.json, findings.json, summary.json, the 12 legacy files), not
  `global/analysis/`, and reads exactly the listed regions through the legacy adapter's view.
- Expected diff: no `global/analysis/` directory; the regional legacy relationship files (ec2, lambda, kms,
  secrets, k8s …) are **non-empty** for the acme regions; `orchestration.json` records one `analyze_run` call with
  the region list; the F-010 characterisation test (regional files empty) no longer holds and is replaced by
  `tests/python/regressions/test_e_core.py::test_f010_legacy_all_layout_analysis_has_regional_edges` and the R
  orchestration tests.

## Not a golden change (for the record)
- `legacy/malformed/outcome.json` still records the d13c215 `AttributeError`: `legacy_api.analyze()` keeps the
  d13c215 orchestration for one release. The F-002 fix (per-analyzer isolation) is in `analyze_report` /
  `analyze_run`, proved by `test_e_core.py::test_f002_malformed_report_still_writes_every_output`.
- `tests/golden/v1/**` (graph.json goldens) is captured by I1 in Wave 3 (D-36); E-core's tests validate every
  emitted graph with the schema and `validate_graph(strict_order=True)` instead.

## Analysis files inside the collector run goldens
- Findings: F-010, F-025, F-063, F-005, F-162 (engine side; the run-root layout itself is R's entry)
- Goldens: `collectors-v0/single/**/analysis/*`, `collectors-v0/all/**/global/analysis/*` (removed) →
  `collectors-v0/{single,all}/<account>/<run_id>/analysis/*`
- Change: the analysis of a collector run is `engine.analyze_run` at the run root: `graph.json`, `findings.json`
  (wrapper with run context), `summary.json` (five severities, analysis status, ignored_dirs, legacy edge counts)
  and the 12 legacy files (legacy lists sorted canonically; managed policies shown by name with
  `source_policy_arn` beside them). Regional relationship files are filled for every region of the run.
- Expected diff: new `graph.json`; `findings.json` gains the wrapper keys and per-finding `fingerprint`,
  `node_id`, `legacy_ids`, `base_severity`, `confidence`, `evidence`, `status`; `summary.json` gains the keys
  above; the legacy relationship files gain the acme regions' edges (ec2, lambda, kms, secrets, k8s, compute).
