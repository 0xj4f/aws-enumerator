# dashboard-merge: a committed merged run (graph.json 1.1)

`merged/20260101T000000Z-0e0e0e/` is the output of `aws-enumerator merge` on two synthetic, analysed runs.
It is a complete merged run folder (`manifest.json`, `HANDLING.txt`, `SHA256SUMS`, `analysis/graph.json`)
for the dashboard tests. The page can then be tested on a real merge output without running Python at test
time (`tests/js/ui/merged-view.test.js` builds a merge with the engine on every run instead).

- Accounts: the placeholders `123456789012` (run `20260101T000000Z-a1a1a1`, region `eu-west-2`) and
  `111122223333` (run `20260101T000000Z-b2b2b2`, regions `eu-west-1`, `eu-west-2`, with `sns` partial in
  `eu-west-1`). All names are `demo-*`. The runs come from `tests/fixtures/e-core/merge_runs.py`
  (`two_accounts`): account A's KMS key grants `kms:Decrypt` to B's role `demo-reader`.
- The finding `reference` links point at the project's public repository, as every engine output does.
- Checked by `tests/python/dashboard/test_merge_fixture.py`: it validates against
  `aws_enumerator/engine/schema/graph-1.1.schema.json`, checks that the manifest digests and `SHA256SUMS`
  match the files, and checks that only placeholder account ids appear. It is **not** compared with what the
  current engine would produce (the engine changes in parallel), so a schema change is the only reason this
  folder must be regenerated.
- Used by `tests/js/ui/merged-fixture.test.js`: the loader (folder and zip, digest verified) and the page
  (merge header, per-account coverage, findings of both accounts, Discover from the default sources).

## Regenerating

Run from the repository root. The scratch directory is any empty directory outside the git work tree.

```sh
SCRATCH="$(mktemp -d)"
SOURCE_DATE_EPOCH=1767225600 PYTHONHASHSEED=0 .venv/bin/python -B - "$SCRATCH" <<'EOF'
import importlib, sys
from pathlib import Path
sys.path.insert(0, ".")
importlib.import_module("tests.fixtures.e-core.merge_runs").two_accounts(Path(sys.argv[1]))
EOF
.venv/bin/aws-enumerator merge -q --no-color --output "$SCRATCH/out" --run-id 20260101T000000Z-0e0e0e \
  "$SCRATCH/in/123456789012/20260101T000000Z-a1a1a1" "$SCRATCH/in/111122223333/20260101T000000Z-b2b2b2"
rm -rf tests/fixtures/dashboard-merge/merged
mkdir -p tests/fixtures/dashboard-merge/merged
cp -R "$SCRATCH/out/merged/20260101T000000Z-0e0e0e" tests/fixtures/dashboard-merge/merged/
.venv/bin/python scripts/scan_sensitive.py --paths tests/fixtures/dashboard-merge/merged/*/manifest.json \
  tests/fixtures/dashboard-merge/merged/*/analysis/graph.json
```

Then run `.venv/bin/python -m pytest -q tests/python/dashboard/test_merge_fixture.py` and
`node --test tests/js/ui/merged-fixture.test.js`. The manifest's `started_at`, tool versions and `git_sha`,
and therefore the digests, change with every regeneration; the tests read them from the files rather than
pinning them. If the counts asserted in the tests change (nodes, findings, modules not ok), check the new
output by hand before updating them.
