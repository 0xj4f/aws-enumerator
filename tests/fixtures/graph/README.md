# Graph fixtures (`graph.json` 1.0)

Shared by the Python tests and the dashboard's `node:test` suites. Contract: `docs/contracts/graph-json.md`.
Placeholder accounts only (`111122223333`, `999999999999`, `123456789012`).

| File | What |
|---|---|
| `minimal.json` | Smallest valid document: the two synthetic nodes the engine always emits. |
| `example.json` | A realistic small graph: every common node and edge family, findings (one suppressed, one inherited), operator, partial coverage, evaluation gaps, analyzer status. |
| `hostile.json` | Valid, but every rendered string carries `window.__aeXssCanary` markup canaries or a JS prototype name (`constructor`, `__proto__`, `hasOwnProperty`, `toString`): labels, IAM paths in ids, props, tags, evidence, finding texts, coverage, operator. For the XSS / F-042 tests. |
| `path_cases.json` | Normative path vectors `[{name, description, findings, graph, source, target, options, expect}]` (graph-json.md §11). `options`: `exclude_categories`, `exclude_node_types`, `definite_only`. `expect`: `reachable`, and when reachable `cost`, `hops`, `path`, `edge_types`, optional `must_not_traverse_types`. Python reference: `tests/support/ref_paths.py`. |
| `gen_large.py` | Deterministic large-graph generator for perf budgets (`generate(scale, seed)`; ~21 edges per scale unit). |
| `build_fixtures.py` | Regenerates every JSON file here and in `../graph-invalid/` from hand-written content (`--write` / `--check`). |

`../graph-invalid/` holds documents that must be rejected, each for one stated reason; `expectations.json`
lists `{file, layer: "schema", errors: [[keyword, pointer]]}` or `{file, layer: "semantic", codes: [...],
strict_order?}`.

Every valid file passes `aws_enumerator/engine/schema/graph-1.0.schema.json` and
`aws_enumerator.engine.graph.validate_graph(doc, strict_order=True)`.
