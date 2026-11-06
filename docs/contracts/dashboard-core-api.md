# Contract: dashboard core JavaScript API (`graph-core.js`, `loader.js`, `exports.js`)

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; revised at the Wave 0/1 sync by contract-arbiter, 2026-10-16: §2.2–§2.9, §3, §4 precisions and the new §5 UI hooks contract; at the Wave 1/2 sync a note on merged graphs in §2.9; every change is listed in [DECISIONS.md](DECISIONS.md); Wave 3a (I1, i1-runtime): §2.2 and §2.9 describe the graph 1.1 reading, additive fields only, no API change, D-41). Change it only through a change request.
**Stub:** `aws_enumerator/dashboard/js/graph-core.js`. `safeHref`, `severityClass` and `edgeWeight` are implemented; every other function throws `new Error('NotImplemented: <name>')`, so xfail-first tests fail for the right reason until the Dc stream lands. `loader.js` and `exports.js` have no stub yet (Dc creates them against §3 and §4).
**Implemented by:** Dc (`frontend/src/core/{graph-core,loader,exports,catalog}.js` since D-57, `dashboard/js/` before; `tests/js/core/**`). **Used by:** the Vue page (`frontend/src`, which implements §5), the JS tests, the end-to-end test (`tests/js/helpers/load-zip-cli.js`).
**Input contract:** `analysis/graph.json` as defined by the engine's `docs/contracts/graph-json.md` and `aws_enumerator/engine/graph/edge_types.py` (node and edge types, traversal classes). Where this document names a `graph.json` field, graph-json.md is authoritative.
**Shared vectors:** `tests/fixtures/graph/path_cases.json` (path semantics; `dijkstra` must reproduce every vector, §2.4–§2.5), `tests/fixtures/graph/hostile.json` (a **valid** graph full of XSS canaries and prototype names, for the render-safety tests), `tests/fixtures/graph-invalid/` with `expectations.json` (documents to reject).
**Regression tests:** `tests/js/regressions/` (xfail-first; ownership and flipping in [ownership.md](ownership.md) §4). The tests' readings of the open points of this contract are confirmed in [DECISIONS.md](DECISIONS.md) D-06 to D-14.
**Related:** [report-layout.md](report-layout.md) §9 (how the loader finds `graph.json`), [exports.md](exports.md) (CSV parity with Python).

---

## 1. Conventions for all three modules

- **The modules:** `graph-core.js`, `loader.js`, `exports.js`, `catalog.js` and, since D-58, `attack.js` (`AEAttack`: the MITRE ATT&CK tables, a mirror of `aws_enumerator/engine/attack.py` kept equal by `tests/js/golden/attack-parity.test.js`).
- **UMD, classic scripts.** Each file is `(function (root, factory) { ... }(typeof self !== 'undefined' ? self : this, function () { 'use strict'; ... }))`. As a classic script it sets `window.AEGraphCore`, `window.AELoader`, `window.AEExports`; under node it sets `module.exports`. No npm dependencies. Since D-57 the page imports the files through the `ae-umd` transform of `frontend/vite.config.js` (it gives the factory a CommonJS `module` and exports what it assigns), so the files stay byte-for-byte what node:test requires.
- **Pure.** No DOM, no `window`/`document` access, no network, no timers (the UI drives chunking), no `eval`/`new Function`. `loader.js` receives JSZip and `crypto.subtle` by injection.
- **Exports are frozen** (`Object.freeze({...})`).
- **Prototype safety (F-042).** Report objects are never spread (`{...x}`) or `Object.assign`ed. All lookups keyed by report data use `Map`/`Set`; any object built from report data is `Object.create(null)`. IDs or labels such as `constructor`, `__proto__`, `toString`, `hasOwnProperty` behave like any other string.
- **Determinism.** Every list a function returns has a documented order; ties break on ids (code-unit comparison, never `localeCompare`).
- **Tests** `require()` the files through `tests/js/helpers/targets.js` (`dashboardDir()`) and tag finding IDs in test names (`[F-007] ...`).

## 2. `graph-core.js` (`AEGraphCore`)

### 2.1 Constants

- `SCHEMA_MAJOR = 1`: the `graph.json` major version understood.
- `SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']` (most severe first).

### 2.2 `validateGraph(raw) -> { graph, problems }`

Validates parsed `graph.json` and returns a **fresh, normalised copy**; `raw` is never mutated or reused.

- **Fatal** (then `graph === null`): `raw` is not a plain object; `schema_version` missing or with a major other than `SCHEMA_MAJOR`; `nodes` or `edges` is not an array.
- **Non-fatal problems** (recorded, the item is dropped or repaired):

  | `code` | Rule |
  |---|---|
  | `node-invalid` | a node without a string `id` or `type`: dropped |
  | `duplicate-node` | a repeated node `id`: the first wins |
  | `edge-invalid` | an edge without string `id`/`source`/`target`/`type`: dropped |
  | `duplicate-edge` | a repeated edge `id`: the first wins |
  | `dangling-edge` | `source` or `target` not a node: dropped (counted) |
  | `bad-weight` | `weight` missing or not a finite number ≥ 0 (negative, `NaN`, `±Infinity`, a string, a boolean, `null`): kept, `weight` set to 1 (F-040) |
  | `bad-traversable` | `traversable` not a boolean: kept, set to `false` |
  | `bad-props` | `props` not a plain object: replaced by an empty object |
  | `unattached-finding` | a finding whose `node_id` is not a node: moved to `graph.unattachedFindings` (the engine contract says there are none, F-005) |
  | `finding-invalid` | a finding without string `id`: dropped |

- `problems` is an array of `{ level: 'error' | 'warning', code, message, ref }` in input order. `ref` is the offending record's id when there is one: the node id for node problems and `bad-props` on a node, the edge id for edge problems (`bad-weight`, `bad-traversable`, `dangling-edge`, `bad-props` on an edge), the finding's `fingerprint` (else its `id`) for finding problems; otherwise `null`. The UI shows them in the "Report problems" panel.
- **Unattached findings are never dropped and never duplicated:** `graph.findings` holds exactly the findings whose `node_id` is a node, `graph.unattachedFindings` the others. Consumers that list every finding (the findings panel, `exports.js`) concatenate the two.
- The returned `graph` holds only the documented fields of graph-json.md: `schemaVersion`, `generator`, `run`, `meta`, `nodeTypes` (`Map`), `edgeTypes` (`Map`), `nodes`, `edges`, `findings`, `unattachedFindings`, `coverage`, `evaluationGaps`, `analyzerStatus`.
- **graph 1.1 (merged graphs, graph-json.md §4.2, §10).** `run.sources` is a list (empty for a 1.0 graph) of `{run_id, account_id, partition, mode, regions, generated_at, source_manifest_sha256, operator, generator, graph_sha256}` records (`operator` and `generator` normalised like the top-level ones; entries that are not objects are dropped). Every `coverage.modules[]`, `coverage.denied_apis[]`, `coverage.facets[]` and `analyzerStatus[]` record has `account` (`null` when absent) and every `evaluationGaps[]` record has `accounts` (`[]` when absent). Readers of 1.0 graphs see the defaults. Node, edge and finding records keep graph-json.md's snake_case field names; `props`, `evidence` and similar free-form objects are copied into null-prototype objects (own enumerable keys only).
- Finding `severity` is upper-case in `graph.json` (`CRITICAL` … `INFO`, graph-json.md §9); graph-core compares severities case-insensitively through `severityClass` and never rewrites the stored value.

### 2.3 `buildIndex(graph) -> Index`

One O(V+E) pass (F-038). The index is read-only after construction.

```
Index {
  graph,
  nodesById: Map<id, Node>, edgesById: Map<id, Edge>,
  out: Map<id, Edge[]>, in: Map<id, Edge[]>,            // every node has an entry (possibly [])
  findingsByNode: Map<id, Finding[]>,                     // severity order (case-insensitive), then id, then fingerprint
  unattachedFindings: Finding[],                          // = graph.unattachedFindings
  typesPresent: Set<string>, categoriesPresent: Set<string>, traversalClassesPresent: Set<string>,
  nodeTypes: Map<string, NodeType>, edgeTypes: Map<string, EdgeType>,
  meta: { defaultSources: string[], defaultTargets: string[] }
}
```

Adjacency lists are sorted by (`type`, `target`/`source`, `id`).

### 2.4 `activeSubgraph(index, opts) -> Active`

The edges path finding may use (F-096).

`opts` (all optional): `categories: Set|null` (enabled edge categories; `null` = all), `nodeTypes: Set|null` (visible node types; `null` = all), `respectFilters: true` (when false, node-type visibility does not restrict paths), `includeConditional: true` (when false, edges with `confidence === 'conditional'` are excluded).

```
Active { opts, edgeAllowed(edge) -> boolean, nodeAllowed(id) -> boolean }
```

An edge is allowed only if **all** hold: `edge.traversable === true`; its `category` is enabled; when `respectFilters`, both endpoint node types are visible; when `!includeConditional`, it is not conditional. Any filter change in the UI builds a new `Active` and clears or re-runs the displayed path.

**Mapping of the shared path vectors (normative).** The `options` of a `tests/fixtures/graph/path_cases.json` vector (graph-json.md §11.6) translate to `activeSubgraph` options exactly as follows, and `dijkstra(index, source, target, { active })` must then reproduce the vector's `expect`:

| Vector option | `activeSubgraph` option |
|---|---|
| (always) | `respectFilters: true` |
| `exclude_categories: [c...]` | `categories` = `index.categoriesPresent` minus the listed categories (`null` when the option is absent or empty) |
| `exclude_node_types: [t...]` | `nodeTypes` = `index.typesPresent` minus the listed types (`null` when absent or empty) |
| `definite_only: true` | `includeConditional: false` (absent or `false`: `true`) |

The reference implementation of this mapping is `activeOptionsFor` in `tests/js/regressions/lib/common.js`.

### 2.5 `dijkstra(index, source, target, opts) -> { cost, hops, path, edges } | null`

- **Directed** (F-007): walks `index.out` from `source` only; never walks an edge backwards.
- Uses only edges allowed by `opts.active` (default `activeSubgraph(index, {})`).
- Edge cost is `edgeWeight(edge)`; zero-cost edges are legal and zero-cost paths are returned (F-040).
- `source === target` returns `null` (the self-path is excluded by identity, not by cost). Unknown ids return `null`.
- `opts.maxCost` (default `Infinity`) prunes.
- Binary heap. Ties break deterministically by (cost, hops, the sequence of edge ids compared lexicographically in code-unit order), exactly as graph-json.md §11.5; the vector `equal_cost_and_hops_breaks_tie_on_edge_ids` distinguishes this from a node-id tie-break.
- Result: `cost` (number), `hops` (= `edges.length`), `path` (node ids, `source` … `target`), `edges` (edge ids, `path.length - 1` of them).
- Must reproduce every vector of `tests/fixtures/graph/path_cases.json` through the §2.4 mapping.

### 2.6 `discoverAll(index, opts)` (generator)

Finds the cheapest path from every source to every target, in chunks the UI can interleave with rendering (F-038, F-043).

`opts`: `sources` (default `defaultSources(index, opts.owned, opts.operator)`), `targets` (default `defaultTargets(index, opts)`), `owned` (Set of ids), `operator` (id or null), `active` (default `activeSubgraph(index, {})`), `perSourceCap` (default 10), `chunkSize` (default 25 sources or targets per chunk).

- When `targets.length < sources.length` it runs one reverse Dijkstra per target over the reversed active graph; otherwise one forward Dijkstra per source. Results are identical either way.
- **Yields** `{ kind: 'progress', done, total }` after each chunk and `{ kind: 'path', result }` for each kept path, where `result = { source, target, cost, hops, path, edges }`.
  - `total` is the number of Dijkstra runs: `targets.length` in reverse mode (`targets.length < sources.length`), else `sources.length`. `done` strictly increases from one progress event to the next, and the last progress event has `done === total`.
  - `path` events are emitted **only for kept paths** (after the per-source cap), exactly once each: the multiset of yielded `result`s equals the returned `paths`. A path that a later, cheaper path evicts is never yielded. In reverse mode the cap is only final at the end, so the `path` events may all follow the last `progress` event; their order is unspecified (the order of the returned `paths` is specified below).
- Each source keeps at most `perSourceCap` paths (cheapest first). There is no global top-N: paging (50 at a time, "Show more") is the UI's job.
- **Returns** (the generator's return value) `{ paths, truncatedSources }`. `paths` is sorted with owned sources first, then by cost, hops, source id, target id; `truncatedSources` lists sources that hit the cap.
- Cancellation: the consumer calls `generator.return()`; no work continues afterwards.

### 2.7 `defaultSources(index, owned, operator) -> string[]`

- If `owned` (Set or array) holds any id present in the index: exactly the owned ids that are present in the index, in the given order, of **any** node type (F-043). Owned ids that are not nodes of this graph (for example from a session of an edited report) are dropped silently here; the UI may report them.
- Otherwise: the operator id (if present in the index) first, then `index.meta.defaultSources` (graph-json.md `meta.default_sources`) in order, then nodes with `props.entry_point === true` and nodes of type `anonymous` (the internet / anyone, F-037), sorted by id. Duplicates are removed (first occurrence wins). For a valid graph the resulting set equals `meta.default_sources` (graph-json.md §5); the extra steps only make an incomplete `meta` harmless.

### 2.8 `defaultTargets(index, opts) -> string[]`

- `index.meta.defaultTargets` (for example the `account_admin` node) in order, then nodes with `props.high_value === true`, sorted by id. Classification flags live only in `props` (graph-json.md §7.1); `tags` is the AWS tag **list** `[{key, value}]` and is never read as a map (F-042). "High value" is computed by the engine from policy ARNs, never from names.
- `opts.includeDataAssets === true` adds nodes whose node type has `data_asset: true` in `nodeTypes`, or whose `props.data_asset === true`.
- Duplicates are removed.

### 2.9 `operatorNode(graph) -> { id, resolution }`

Takes the **validated** graph (the `graph` returned by `validateGraph`, not the raw document) and reads the operator mapping written by the engine: `graph.run.operator`, the one canonical operator field `{arn, node_id, resolution, redacted?}` of graph-json.md §4.1 (there is no `run.caller`, `meta.caller` or `mapping`; the manifest's top-level `operator` block is never read by the dashboard). `id` is `run.operator.node_id` when that node exists in the graph, else `null` (also when `node_id` names a node that is not in `graph.nodes`); `resolution` is the engine's resolution string, or `'missing'` when the graph has no operator block. The UI pre-adds `id` to the owned set and makes it the default Find Path source, or shows "caller not in graph (`resolution`)" (F-146). **Merged graphs** (`graph.run.mode === 'merge'`, graph-json.md §4.2, schema 1.1) have no single operator: `run.operator` is `{arn: null, node_id: null, resolution: 'unavailable'}` by design, so `operatorNode` returns `{id: null, resolution: 'unavailable'}` and every source run's operator node is in `meta.default_sources` instead. The UI then says "merged view" rather than "caller not in graph"; this API is unchanged (D-41). Since Wave 3a the core keeps `run.sources` and the per-account keys (§2.2), and the UI shows the source accounts in the header and, in the coverage panel, one row per source run (account, run id, regions, the account's coverage status by graph-json.md §10.1's rule, operator, `generated_at`, `graph_sha256` prefix) plus the account of every module, denied API, gap and analyzer entry.

### 2.10 `selectorSort(nodes, typeOrder) -> Node[]`

Returns a **new** array (the input is not mutated) sorted by: `typeOrder` rank of `node.type` (a `Map` or null-prototype object, ranks are integers starting at **1**, read with `??` so no rank is mistaken for a missing one; unknown types sort last), then `label` (code-unit order), then `id` (F-095).

### 2.11 Implemented now

| Function | Contract |
|---|---|
| `safeHref(url) -> string \| null` | Only absolute `https:` URLs with a host and without user name or password, at most 2,048 characters, become links (returns the normalised `href`); `javascript:`, `data:`, `http:`, relative, malformed and non-string input give `null` (F-097). Links are rendered with `rel="noopener noreferrer"` and `referrerpolicy="no-referrer"` by the UI. |
| `severityClass(sev) -> 'critical'\|'high'\|'medium'\|'low'\|'info'` | Case-insensitive allow-list (whitespace trimmed); anything else, including non-strings, gives `'info'`. The only way a severity reaches `className`. |
| `edgeWeight(edge) -> number` | `edge.weight` when it is a finite number ≥ 0 (0 is legal), else `1` (F-040). Never `edge.weight \|\| 1`. |

## 3. `loader.js` (`AELoader`), no stub yet

Turns user input into a validated graph, with limits and exact paths (F-091, F-092, F-093, F-145, F-168).

```
LIMITS = { maxArchiveBytes, maxEntries, maxEntryBytes, maxTotalInflatedBytes }   // frozen; values chosen and tested by Dc
class LoaderError extends Error { code }   // 'unsupported-input' | 'too-large' | 'too-many-entries' |
                                           // 'entry-too-large' | 'bad-json' | 'no-report' | 'ambiguous'
sniff(bytes: Uint8Array) -> 'zip' | 'json' | 'unknown'      // 'PK\x03\x04' -> zip; first non-space '{' -> json
async fromZip(arrayBuffer, { JSZip, limits }) -> FileSet     // reads the central directory only; inflates nothing yet
fromFolder(files: Iterable<File>) -> FileSet                 // uses webkitRelativePath
fromGraphText(text: string, name = 'graph.json') -> FileSet  // a bare graph.json
findRoots(fileSet) -> Array<{ root, hasGraph, hasManifest }> // report-layout.md §9; sorted by root
async classify(fileSet, root) -> { kind: 'ok'|'legacy'|'unsupported-version'|'missing', schemaMajor }
async load(fileSet, root, { subtle }) -> { raw, manifest, integrity: 'verified'|'mismatch'|'n/a', problems }
async sha256Hex(bytes, subtle) -> string
```

- `FileSet = { kind: 'zip'|'folder'|'single', paths: string[] (sorted), async read(path) -> Uint8Array | null }`.
- **Roots.** A root is the path prefix of a run directory **including its trailing `/`** (`'run-1/'`, `'demo-runs/111122223333/run-a/'`), or `''` for the top level. Files are addressed as `root + 'manifest.json'` and `root + 'analysis/graph.json'`. `findRoots` returns every directory that contains `analysis/graph.json` or `manifest.json`, sorted by `root` (code-unit order), with `hasGraph` / `hasManifest`; an empty FileSet gives `[]`.
- **`fromGraphText(text, name)`** builds `{ kind: 'single', paths: ['analysis/graph.json'] }` (`name` is display-only), so `findRoots` returns exactly `[{ root: '', hasGraph: true, hasManifest: false }]`, whatever the text contains. Bad JSON is reported when the text is parsed (`classify` or `load`), never by `fromGraphText`.
- **Only allow-listed exact paths are ever inflated or read:** `<root>/manifest.json` and `<root>/analysis/graph.json`. `permission_map.json` and policy dumps are never inflated. The per-entry uncompressed size is checked from the zip directory (JSZip 3.10.1 `_data.uncompressedSize`, pinned by a test) before inflating.
- `classify` follows report-layout.md §9 (precedence: a `graph.json` decides `ok` / `unsupported-version`; otherwise legacy markers give `legacy`; otherwise `missing`). A `legacy` result carries no graph; the UI shows the "run `aws-enumerator analyze`" banner. `classify` of a root whose `graph.json` is not JSON rejects with `bad-json`.
- `load` parses the manifest (optional) and `graph.json`, computes the digest badge when `manifest.files` lists `analysis/graph.json`, and returns `raw` for `AEGraphCore.validateGraph`. It does not check the schema version (the UI calls `classify` first, and `validateGraph` is fatal on another major). Every failure rejects with a `LoaderError`; the UI awaits it and shows the message (no "Loading…" hang).
- **`LoaderError`.** `new LoaderError(code, message)`; `.name === 'LoaderError'`, `.code` is one of the codes above, `.message` is a non-empty sentence the UI can show. Which code each failure gets:

  | Failure | `code` |
  |---|---|
  | `fromZip` on bytes that are not a zip (no `PK\x03\x04` magic) | `unsupported-input` |
  | archive larger than `maxArchiveBytes`; the sum of the uncompressed sizes of the entries to be inflated larger than `maxTotalInflatedBytes` | `too-large` |
  | more entries than `maxEntries` | `too-many-entries` |
  | one entry larger than `maxEntryBytes` | `entry-too-large` |
  | a truncated or corrupt zip | `unsupported-input` |
  | `manifest.json` or `graph.json` is not valid JSON | `bad-json` |
  | `load` of a root that is not in `findRoots`, or of a root without `analysis/graph.json` (the message carries the `aws-enumerator analyze <path>` hint for a legacy root) | `no-report` |
  | `load` called without a root while several roots exist | `ambiguous` |

- `fromZip(arrayBuffer, { JSZip, limits })`: `limits` overrides `LIMITS` key by key (tests use small limits instead of huge archives); `LIMITS` itself is frozen and satisfies `maxEntryBytes <= maxTotalInflatedBytes`.

## 4. `exports.js` (`AEExports`), no stub yet

What only the browser knows: the current view and the paths the user found (F-165). Findings exports in SARIF/ASFF/OpenGraph are CLI-only ([exports.md](exports.md)).

```
csvCell(value) -> string                       // exports.md §3: quote always, double quotes, neutralise = + - @ \t \r
toCsv(header: string[], rows: any[][]) -> string   // CRLF, no BOM, a trailing CRLF
findingsCsv(findings, index) -> string         // exports.md §3 columns; unfiltered output byte-identical to Python
findingsMarkdown(findings, index, meta) -> string
mdEscape(text) -> string                       // exports.md §4
pathsCsv(paths, index) -> string; pathsMarkdown(paths, index) -> string; pathsJson(paths, index, meta) -> string
sessionJson({ runId, owned, paths, expected? }) -> string
parseSession(text, runId) -> { owned, paths, expected, problems }   // schema-checked; refuses another run's session
```

- `paths` are `discoverAll`/`dijkstra` results. A path row lists source, target, cost, hops, and the node labels and edge types joined by ` -> `.
- **`csvCell(value)`** (exports.md §3): every cell is quoted, so `null` and `undefined` give `""` (two quote characters); a number gives its `String(n)` quoted (`42` → `"42"`); a boolean gives `"true"` / `"false"`; an array gives its elements' cells joined with `;` before quoting; any other object gives its `JSON.stringify`. The formula-prefix rule applies to the final text.
- **`findingsCsv(findings, index)` / `findingsMarkdown(findings, index, meta)`** take every finding to export (attached and unattached, §2.2); an unattached finding has empty node label and type. `meta = { run, generator, schemaVersion }` taken from the validated graph (`graph.run`, `graph.generator`, `graph.schemaVersion`). The `severity` column carries the stored value (upper-case) unchanged (exports.md §1).
- **`pathsJson(paths, index, meta)`** returns the JSON text of an object `{ "run_id": meta.runId ?? null, "paths": [ { source, target, cost, hops, path, edges, edge_types } ] }` (`edge_types` = the type of each edge in `edges`); `meta = { runId }`.
- **`sessionJson({ runId, owned, paths, expected })`** returns `{ "version": 1, "run_id": runId, "owned": [...ids], "paths": [...] }`, plus `"expected": [...marks]` when `expected` has entries (D-58: the routes and entry points marked expected, `route:<route id>` / `entry:<node id>`; without marks the output is byte-identical to before). `parseSession` returns `expected` (`[]` when absent); a non-list `expected` or a non-text entry adds a problem and is dropped. **`parseSession(text, runId)`** never throws: malformed JSON, a non-object, a `version` other than `1` (a missing one included), a `run_id` other than `runId`, or a non-array `owned` gives `{ owned: [], paths: [], problems: [≥ 1 message] }`; otherwise `owned` keeps the string entries and `paths` the well-formed path records, and each dropped entry adds a problem. Parsed objects are read through own-property checks into `Map`s and arrays, so keys such as `__proto__` or `constructor` are inert data (F-042).
- Downloads (Blob, `<a download>`, revoked object URLs) and PNG export (`cy.png`) live in `ui.js`.

## 5. UI hooks contract (the Vue page, D-57)

Since D-57 the page is the Vue app in `frontend/src`; the hooks below replace P1–P8 of the hand-written page. The
Vitest suites (`frontend/src/**/*.test.js`), the Playwright suite (`frontend/e2e/`) and the static checks
(`tests/js/static/page.test.js`) use them.

| # | Hook |
|---|---|
| H1 | The built `index.html` has the CSP `<meta>` of server.py before anything it loads, then one stylesheet (`css/app.css`) and one classic deferred script (`js/app.js`), both with `integrity="sha384-..."`. No inline script or style, no `style=""`, no `on*=` attribute. |
| H2 | `window.AEDashboard` is a frozen, read-only handle: `state()` (status, run id, owned ids, operator, route count, whether the breach search is running, problems) and `loadGraphObject(raw)`, which resolves once the graph or the error is shown and starts with the same reset as Clear (F-094, F-098). |
| H3 | File pickers: `#file-input` (a zip or a bare `graph.json`; the content decides, F-145) and `#folder-input` (`webkitdirectory`); `#session-input` opens a session. Loading starts on `change`; files can also be dropped anywhere on the page. |
| H4 | Routes (hash history): `#/` Brief, `#/paths` Attack paths, `#/map` the kill-chain map (D-59), `#/principals`, `#/data` (both with `?filter=`), `#/findings` (a rule is `?sel=rule:<id>`), `#/explore?node=<id>`, `#/audit` the operator's audit (D-59), `#/health`. The selected row (or card) of a page is `?sel=<id>` and opens the bottom drawer. Audit and Report health are reached through the nav's More menu. |
| H5 | `data-testid` hooks: `header`, `run-meta`, `integrity`, `coverage-badge`, `operator-menu`, `open-menu`, `export-menu`, `clear`, `search`, `nav` and `nav-<page>`, `load-screen` (with `data-status` empty / busy / error / legacy / picker), `verdict`, `tile-<key>`, `top-path`, `exposure`, `posture`, `paths-table`, `findings-table`, `row`, `drawer`, `drawer-title`, `drawer-tab-<key>`, `drawer-close`, `path-canvas`, `explore-canvas` (with `data-cards`), `card`, `node-detail`, `sev-<severity>`, `findings-filter`, `include-conditional`, `lens-admin`, `lens-context-nodes`, `lens-context-edges`. Since D-58: `nav-principals`, `nav-data`, `principals-table`, `data-table`, `principals-<filter>`, `data-<filter>`, `tactic-filter`, `findings-tactic`, `hide-expected`, `mark-suggested`, `toggle-expected`, `toggle-entry-expected`, `expected`, `plumbing-hint`, `group-by-rule`, `one-per-resource`, `group-resources`, `tactics`, `techniques`, `technique-ids`, `relations`, `drawer-tab-become`, `drawer-tab-reaches`, `drawer-tab-readers`. Since D-59: `nav-map`, `nav-more` (a `<details>` menu), `nav-audit`, `brief-map-link`, `brief-audit-link`, `view-map`, `map-canvas` (with `data-cards`), `map-scope`, `map-include-expected`, `map-count`, `map-empty`, `pivots`, `pivot` (with `data-node-id`; `data-action="open-pivot"` opens its drawer), `drawer-tab-routes`, `route-through`, `view-audit`, `detection-map`, `detection-cell` (with `data-control`, `data-region`, `data-state` watching / blind / unknown / n/a), `quietest`, `surface-matrix`, `surface-category` and `surface-cell` (with `data-category`, `data-sev`), `findings-category`. Highlighted canvas cards and links carry the class `hl`, the others `dim`. Run-picker entries carry `data-action="pick-run"` and `data-root`. |
| H6 | Rows are opened by click, or with `j`/`k` (or the arrow keys) and Enter while the table has focus; Esc closes the drawer. |

Page rules the tests rely on (unchanged in substance):

- **Text only.** Report strings reach the DOM only as text (Vue template interpolation), allow-listed classes
  (`severityClass`, fixed badge and edge classes) and `safeHref` links (`rel="noopener noreferrer"`,
  `referrerpolicy="no-referrer"`); no `v-html`, `innerHTML`, inline handlers or `eval` in the page code.
- **Coverage.** Report health lists every `graph.coverage.modules` entry whose `status` is not `ok`, every
  `evaluation_gaps` entry, the denied APIs and the analyzers that are not ok, with the account of each in a merged
  graph and one row per source run.
- **Findings.** The Findings page shows a tile per severity (LOW and INFO included; INFO starts hidden), the total
  and "N unattached" (§2.2).
- **CSP.** Exactly server.py's policy; no host sources and no scheme source other than `data:` in `img-src`.
