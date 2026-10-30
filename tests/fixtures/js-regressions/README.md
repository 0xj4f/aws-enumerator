# js-regressions fixtures

Owned by the regressions-js stream. Used by `tests/js/regressions/support.test.js` only.

| Path | What |
|---|---|
| `harness-page/` | A tiny page (index.html + js/ui.js) that exercises `tests/js/regressions/lib/ui-harness.js`: script order, page-realm objects, headless Cytoscape, fake timers, file pickers. It is a test fixture, **not** the dashboard. |

The dashboard regression tests themselves read the shared graph fixtures in `tests/fixtures/graph/`
(`example.json`, `hostile.json`, `minimal.json`, `path_cases.json`) and build variants in code.
