# Golden change ledger

Every intentional change to a file under `tests/golden/**` needs a ledger entry in
`tests/golden/CHANGES.d/<stream>.md` (one file per stream, so streams never edit the
same file). Goldens are regenerated with `pytest --update-golden` and every diff is
checked against these entries; an unexplained diff is a bug.

## Golden sets

| Path | What it holds | Test |
|---|---|---|
| `v1/<scenario>/` | `graph.json`, `findings.json`, `summary.json` and `outcome.json` of `engine.analyze_report` (= `aws-enumerator analyze`) on each `tests/fixtures/scenarios/<scenario>/tree`, from its old-layout root (account directory for `all_mode`, region directory otherwise) | `tests/python/golden/test_v1_goldens.py` |
| `collectors-v2/{single,all}/`, `collectors-v2/{calls,console}-{single,all}.json` | The v2 run tree of `aws-enumerator collect` against the acme fake world (`--region eu-west-2` / `--all`, fixed run ids), the AWS / Kubernetes call inventory and the degraded-module / warning inventory | `tests/python/collectors/test_collectors_v2_golden.py` |
| `legacy-dashboard/` | The d13c215 dashboard's graph build, loaded through `git show d13c215:…` (characterisation; never changes) | `tests/js/legacy/characterize.test.js` |
| `d13c215-relationship-edge-types.json` | The (legacy file, edge type) pairs d13c215 wrote, kept from the retired `legacy/` goldens | `tests/python/engine/core/test_contracts_engine.py` |

Retired in Wave 3a (DECISIONS.md D-53; review in `i1-reconcile.md`): `legacy/<scenario>/` and
`legacy/all_mode_main/` (the d13c215 `analyze()` / `main()` characterisation) and `collectors-v0/` (the d13c215
collectors). The older entries in this directory describe the changes against those sets.

Canonical forms:

- `v1/`: the engine's own list order (the output is deterministic), keys sorted, `generated_at` and
  `duration_seconds` replaced by `"<stripped>"`;
- `collectors-v2/` (`tests/support/canonical.py` plus `legacy_harness.LegacyRun.normalised_tree`): sorted keys;
  edges sorted by (source, target, type); findings by (id, entity); every other list sorted; clock keys and the
  manifest digests of run-unique files replaced by `"<stripped>"`; the build sha pinned; the interpreter and
  library versions of the manifest `tool` block masked.

## Entry format

```markdown
## <short title>
- Findings: F-010, F-025
- Goldens: collectors-v2/all/111122223333/golden-all/analysis/ec2_relationships.json, v1/all_mode/graph.json
- Change: regional edges now present in --all mode because analysis runs after collection.
- Expected diff: +N edges in ec2/lambda/secrets/kms/k8s relationship files; analyze_calls lists both regions.
```

## Regenerating

```sh
.venv/bin/python -m pytest -m golden --update-golden   # rewrite
.venv/bin/python -m pytest -m golden                   # prove stable (includes a run under another PYTHONHASHSEED)
git diff --stat tests/golden                          # review against the ledger
```
