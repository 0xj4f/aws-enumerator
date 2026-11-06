# Golden ledger: Dc (dashboard core JS, Wave 1)

No entries. The Dc stream changes no file under `tests/golden/**` and breaks no golden test:

- `tests/golden/legacy-dashboard/*` characterise the d13c215 dashboard, loaded from git history
  (`git show d13c215:app/dashboard/index.html`), so the new `js/{graph-core,loader,exports,catalog}.js`
  cannot change them.
- The Python goldens (`legacy/`, `collectors-v0/`) do not read the dashboard JavaScript.
- The new parity tests in `tests/js/golden/` compare against live references (the engine's `edge_types.py`,
  `tests/support/ref_paths.py`, the vendored Cytoscape and Python's `csv` module) and store no golden files.
