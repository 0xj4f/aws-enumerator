# Engine API

**Status:** frozen contract (Wave 0, stream contracts-engine; precisions at the Wave 0/1 sync by
contract-arbiter in §3.1–§3.3, §5, §6.3, §7 and §8; at the Wave 1/2 sync the new §3.5 (merge, graph 1.1) and
§7; in Wave 3 by I1 (i1-engine) in §1, §5, §6.1 and §6.3: the d13c215 entry point, `legacy_api`, the legacy adapter
and the standby fallback removed, the reference time, compiled schema validation; all listed in
[DECISIONS.md](DECISIONS.md), D-52 to D-55; in Wave 3b by w3b-tidy in §1, §7 and §8, which no longer name removed
modules or the retired goldens, D-56). Signatures here are what Wave 1/2 streams
code against; implementations may add keyword-only parameters with defaults, but must not change or remove
anything listed without a change request. Types: `aws_enumerator/engine/model.py` (implemented now).
Related: [graph-json.md](graph-json.md), [traversability-table.md](traversability-table.md),
[node-ids.md](node-ids.md), [finding-identity.md](finding-identity.md), [ownership.md](ownership.md)
(every path of the repository and its Wave 1/2 owner), engine.md (design).

## 1. Package surface

`aws_enumerator.engine` (`engine/__init__.py`, E-core) exports exactly:

| Name | Signature | Notes |
|---|---|---|
| `analyze_run` | `analyze_run(run_root, *, regions, account_id=None, partition=None, manifest=None, options=None) -> AnalysisResult` | The collector run's analysis (§3.1). |
| `analyze_report` | `analyze_report(report_dir, options=None) -> AnalysisResult` | `aws-enumerator analyze <dir>`: v2 runs and legacy layouts (§3.2). |
| `ENGINE_SCHEMA_VERSION` | `str` | Written to `graph.generator.engine_version`. |
| `AnalysisOptions`, `AnalysisResult` | re-exported from `model` | |

Old report layouts (the d13c215 `--region` and `--all` trees) are analysed by `analyze_report`, which is what
`aws-enumerator analyze <dir>` calls; there is no separate entry point for them (the d13c215 Python API was removed
in Wave 3a, D-53). The permission-map entry points of the rules engine (`rules.legacy_rules._detect_privesc_paths` /
`_detect_dangerous_permissions`) and the `permission_map.json` builder (`iam.principals._build_permission_map`)
keep their d13c215 names.

## 2. Data model (`engine/model.py`)

Exactly engine.md §2.1, plus the graph and pipeline records. All are dataclasses (frozen where marked) with
docstrings in the module.

| Type | Kind | Purpose |
|---|---|---|
| `Tri` | Enum `TRUE/FALSE/MAYBE` | Kleene logic: `and_`, `or_`, `not_`, `all_`, `any_`, `of(bool)`. |
| `Decision` | Enum `ALLOW/CONDITIONAL/DENY/NOT_ALLOWED` (values `allow`…) | `.rank` (ALLOW 3 > CONDITIONAL 2 > NOT_ALLOWED 1 > DENY 0), `.grants`. |
| `Strength` | Enum `NONE/WEAK/STRONG` | `.rank`, `Strength.strongest(iterable)`. |
| `KeyClass` | Enum | `IDENTITY PROBE RESOURCE REQUEST NETWORK SERVICE SESSION TIME UNKNOWN` (engine.md §2.3). |
| `Known`, `ABSENT`, `Unknown` | `KeyValue` union | Request-context key values. |
| `PolicySource` | frozen, slots | layer, policy_arn, policy_name, version_id, source_type, via_group, statement_index, sid; `.to_json()` (evidence statements). |
| `Condition` | frozen, slots | operator, qualifier, if_exists, negated, key (lower-case), values, key_class. |
| `Principal` | frozen, slots | kind, raw, arn, account, partition, name. |
| `ActionMatcher` | frozen, slots | exact, prefixes, globs, any; `.matches(action)`. Built by `policy.glob`. |
| `Statement` | frozen, slots | effect, actions, not_actions, resources, not_resources, principals, not_principals, conditions, source, action_matcher, service_prefixes. |
| `PolicyDoc` | frozen, slots | layer, statements, policy_arn, policy_name, version_id, is_default_version. |
| `ActionIndex` | frozen, slots | by_service, wildcard; `.may_cover(service)`. |
| `PrincipalModel` | mutable | id, principal, identity, boundary (`tuple`/`None`/`"missing"`), groups, tags, scp_chain, is_service_linked, action_index, gaps. |
| `RequestContext` | frozen | principal, keys. |
| `ConditionNote`, `LayerResult` | frozen | Evaluation notes and per-layer result. |
| `EvalResult` | frozen | decision, reason, layers, allow_refs, deny_refs, condition_notes, strength, gaps; `.confidence` (`conditional` iff CONDITIONAL). |
| `Grant`, `Capability` | frozen | Resource-policy grant; DANGER/ADMIN probe (exactly one of `action_glob`/`actions_any`). |
| `EvaluatorAPI` | `typing.Protocol` | The frozen evaluator signatures (§4). |
| `Tag`, `Node`, `Edge`, `Finding` | mutable | Graph records; `.to_json()` gives exactly the graph.json record shape. |
| `Phase` | IntEnum 1–9 | Pipeline phases (§5). |
| `AnalyzerSpec`, `AnalyzerStatus` | frozen | Registry entry and outcome (`.to_json()` = `analyzer_status[]` entry). |
| `AnalysisOptions`, `AnalysisResult` | frozen | §3. |

Constants: `SEVERITIES`, `SEVERITY_RANK` (0 = CRITICAL), `COVERAGE_STATUSES`, `FINDING_REQUIRED`,
`FORBIDDEN_KEYS`.

## 3. Entry points

### 3.1 `analyze_run(run_root, *, regions, account_id=None, partition=None, manifest=None, options=None)`

Called once by the runner **after all collection** (F-010), on the run root
`<output>/<account>/<run_id>/`.

| Parameter | Meaning |
|---|---|
| `run_root` | `str` or `Path` of the run root. |
| `regions` | **Required.** The explicit region list that was collected (`manifest.target.regions`). The engine never scans for sibling directories (F-010, F-025, F-063); directories not in the list are reported in `summary.ignored_dirs`. |
| `account_id`, `partition` | Default to the manifest's `target.account_id` / `target.partition`. |
| `manifest` | The parsed manifest (`dict`) if the caller has it; else `<run_root>/manifest.json` is read. Its SHA-256 goes to `run.source_manifest_sha256`. |
| `options` | `AnalysisOptions` (§3.3) or `None`. |

Behaviour:

- Writes into `<run_root>/analysis.tmp/`, validates `graph.json` (schema + `validate_graph`), then swaps it
  in exactly as report-layout.md §1.1 rule 5 says (a previous `analysis/` is renamed to `analysis.prev/`,
  `analysis.tmp/` is renamed to `analysis/`, then `analysis.prev/` is deleted). Files are created 0600,
  directories 0700 (`util/fsio`). The set of files written is graph-json.md §1.
- **The engine writes nothing outside `analysis.tmp/` / `analysis/`** (plus, for legacy layouts only, the
  `analysis.orig/` rename and `_provenance.json` of report-layout.md §8). It never writes `manifest.json`,
  `SHA256SUMS`, `HANDLING.txt` or `run.log`; those belong to the R stream (`output.py` `ManifestStore`).
- **Never raises for analyzer failures.** Each `AnalyzerSpec` runs in isolation (F-002); failures become
  `analyzer_status` entries and `status = "partial"`. Raises only for usage errors: `run_root` missing
  (`FileNotFoundError`), a manifest with `run.status = "in_progress"` without `options.force`, an invalid
  suppression or baseline file (`AnalysisUsageError`, a `ValueError` subclass, exit 64 in the CLI).
- On `status = "error"` (nothing usable, for example IAM unreadable) the engine removes `analysis.tmp/`,
  leaves any previous `analysis/` untouched and returns `graph_path = None`.
- Returns `AnalysisResult`. **The caller** (the R stream's runner after `collect`, or its `analyze` command for
  a v2 run) fills `manifest.analysis` (manifest.md §3.8) with `engine: "v2"`,
  `graph_schema_version = result.graph_schema_version` and `status` mapped as `ok → ok`,
  `partial → partial`, `error → failed`, then rewrites `manifest.files` and `SHA256SUMS`. A `collect` run
  whose `analysis.status` is `partial` or `failed` is a partial run (exit 2, manifest.md §2), and
  `aws-enumerator analyze` exits 0 / 2 / 1 for `ok` / `partial` / `error` (cli.md §3.2).

### 3.2 `analyze_report(report_dir, options=None)`

The `aws-enumerator analyze <dir>` entry point; lets operators re-analyse old reports (F-010).

| `report_dir` contains | Mode | Regions | Output |
|---|---|---|---|
| `manifest.json` with `schema_version` major 2 (`2.x`) | `run` | `manifest.target.regions` | delegates to `analyze_run` |
| `global/` plus region directories (old `--all` layout `<acct>/`) | `legacy-all` | child directories whose names are in botocore's region lists for **all** partitions (covers `us-gov-*`, `cn-*`) | `<report_dir>/analysis/` |
| `iam/` directly (old single-region `reports/<date>/<acct>/<region>/`) | `legacy-single` | the directory's own name when it is a known region, else none (and the `legacy:region-unknown` gap) | `<report_dir>/analysis/` |

Layout detection, `_provenance.json` (`source_layout: "legacy-all" | "legacy-single"`), the
`analysis.orig/` rename of an old single-region `analysis/` and "never mutate a legacy manifest" are defined
by report-layout.md §8; the engine implements them as written there. In addition, for legacy modes the engine
sets `run.mode` to the `source_layout` value, `run.run_id` by the legacy rule of graph-json.md §4,
`run.operator` from the legacy manifest's `run_metadata.caller_arn` when present (graph-json.md §4.1), uses
`coverage.source = "legacy-unknown"` (graph-json.md §10.1), and adds the `coverage-not-recorded` and
`iam:legacy-layout` evaluation gaps.

`analyze_report` never writes a manifest or digests: for a v2 run its caller (the CLI `analyze` command, R
stream) updates `manifest.analysis`, `manifest.files` and `SHA256SUMS` afterwards (§3.1); a legacy manifest
is never modified.

### 3.3 `AnalysisOptions`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `baseline` | path or `None` | `None` | Previous run dir or `findings.json`; writes `diff.json` (finding-identity.md §4). |
| `suppress` | path or `None` | `None` | Suppression file (finding-identity.md §5). |
| `strict_catalog` | bool | `False` | An unknown finding id or edge type raises instead of becoming an analyzer error. Tests and CI set it. |
| `legacy_outputs` | bool | `True` | Also write the legacy outputs (one release): `permission_map.json`, `trust_relationships.json` and the ten per-domain `*_relationships.json` files listed in graph-json.md §1. |
| `exports` | tuple | `()` | Extra export formats written during the WRITE phase: any of `sarif`, `csv`, `md`, `asff`, `opengraph` (exports.md), each to `analysis/exports/<default file>` through the §6.3 writer API with default filters. |
| `force` | bool | `False` | Analyse a run whose manifest is `in_progress`. |
| `source_date_epoch` | int or `None` | `$SOURCE_DATE_EPOCH` | Fixed `generated_at`. |
| `redact_identity` | bool | `False` | Publish `operator.principal_arn` instead of the caller ARN. Redaction applies when this **or** the manifest's `operator.redacted` is true (graph-json.md §4.1). |

### 3.4 `AnalysisResult`

| Field | Meaning |
|---|---|
| `status` | `ok` (every analyzer `ok`/`skipped`/`not_implemented`), `partial` (at least one `error`; outputs written), `error` (nothing usable written, e.g. IAM unreadable). |
| `analyzer_status` | `tuple[AnalyzerStatus, ...]` in pipeline order. |
| `outputs` | Paths written, relative to `analysis_dir`. |
| `graph_path` | Absolute path of `graph.json`, or `None` when not written. |
| `graph_schema_version` | The `schema_version` written into `graph.json` (`None` when not written); copied to `manifest.analysis.graph_schema_version`. |
| `analysis_dir` | The final `analysis/` directory. |
| `counts` | `nodes`, `edges`, `findings`, and one key per severity. |

### 3.5 Merge (`aws_enumerator.engine.merge`, E-core; graph 1.1, D-42 to D-45)

`aws-enumerator merge` ([cli.md](cli.md) §3.8) calls three functions; the rules they implement are
[graph-json.md](graph-json.md) §4.2. The module is not re-exported by `aws_enumerator.engine` (§1 stays exact).

```python
plan_merge(run_roots) -> tuple[MergeSource, ...]
    # MergeSource(run_root, account_id, run_id, partition, graph: dict, graph_sha256: str), sorted by
    # (account_id, run_id). Usage problems (fewer than 2 roots, no analysis/graph.json, a merge as input,
    # an account twice, mixed partitions) raise AnalysisUsageError (exit 64); an unreadable or invalid source
    # graph, or a major/minor this build does not know, raises MergeInvalid (exit 1).
merge_graphs(sources, *, run_id, generated_at=None) -> dict
    # Pure: the merged schema-1.1 document; generated_at defaults to SOURCE_DATE_EPOCH / now (UTC "Z").
    # Validates it (graph-1.1 schema + validate_graph(strict_order=True)) and raises MergeInvalid otherwise.
write_merged(doc, run_root) -> pathlib.Path
    # Writes <run_root>/analysis/graph.json (0600) through analysis.tmp/ (report-layout.md §1.1 rule 5) and
    # returns its path. Writes nothing else: manifest.json, HANDLING.txt and SHA256SUMS are the CLI's (D-17).
```

`MergeInvalid` is a `ValueError` whose message names the first problems (like `writers.graph_json.GraphInvalid`).
`MergeUnavailable` / `MERGE_UNAVAILABLE` (the Wave 1 placeholder of D-32) are removed. Implementations may add
keyword-only parameters with defaults. `GRAPH_SCHEMA_VERSION` stays `"1.0.0"` (what analyses write); the merge
version `"1.1.0"` gets its own constant, and `graph.SCHEMA_FILES` / `load_schema` gain the 1.1 schema next to
the 1.0 one (graph-json.md §12.1).

## 4. Evaluator API (implemented by E-policy, `engine/policy/evaluator.py`)

```python
class Evaluator:  # satisfies model.EvaluatorAPI
    def __init__(self, ctx: AnalysisContext, principals: PrincipalIndex,
                 resources: ResourcePolicyIndex, org: OrgModel | None): ...
    def evaluate(self, principal: str | PrincipalModel | Principal, action: str, resource: str,
                 *, context: Mapping[str, str | tuple[str, ...]] | None = None) -> EvalResult
    def evaluate_any(self, principal, action, resource_template: str, *, context=None) -> EvalResult
        # existential: Allow needs glob_overlap; a Deny removes everything only if glob_covers(deny, template);
        # partial denies are recorded as notes, not as DENY
    def evaluate_capability(self, principal, capability: Capability) -> EvalResult
        # "covers": an Allow statement must cover action_glob AND the template; any overlapping Deny breaks it
    def best(self, principal, actions: Iterable[str], resource: str, **kw) -> tuple[str | None, EvalResult]
        # best decision over actions (ALLOW > CONDITIONAL > NOT_ALLOWED > DENY) and the action that achieved it
    def can_assume(self, caller, role_arn: str, *, protocol: "AWS" | "WebIdentity" | "SAML" = "AWS",
                   claims: Mapping[str, str] | None = None) -> EvalResult
    def resource_policy_grants(self, policy: PolicyDoc, resource_arn: str) -> list[Grant]

def stmt_applies(stmt: Statement, action: str, resource: str, rc: RequestContext) -> Tri   # pure, exported
def eval_layer(stmts, action, resource, rc) -> LayerResult                                 # pure, exported
```

Semantics are engine.md §2.2–2.4 (explicit deny first; RCP; SCP; identity ∩ boundary; same-account union
vs cross-account intersection; KMS key-policy-first; trust). Decisions map to edges as: ALLOW → definite
edge, CONDITIONAL → conditional edge with `evidence.condition_strength = result.strength`, DENY /
NOT_ALLOWED → no edge. The rule "no raw `stmt['actions']` loops outside `policy/`" (R-13) applies to all
analyzers.

## 5. Pipeline (`engine/pipeline.py`, E-core)

| Phase | `Phase` | Work |
|---|---|---|
| 1 | `CONTEXT` | `build_context(...) -> AnalysisContext` (§6) |
| 2 | `LOAD` | One isolated loader per domain (`io/loaders/*`), each returning `(data, status)` |
| 3 | `PRINCIPALS` | Principal models (`iam/principals.py`) and the `Evaluator` |
| 4 | `IDENTITY` | `iam/trust.py`, `iam/assume.py`, `iam/hygiene.py` |
| 5 | `RESOURCES` | Domain analyzers (`analyzers/*`) |
| 6 | `RULES` | `rules/runner.py` (needs resources and trust) |
| 7 | `CLOSURE` | `graph/closure.py`: reachability, CAN_ESCALATE, `reaches_admin`, severity derivation |
| 8 | `POSTPROCESS` | Subsume, attach to nodes, fingerprint, suppress, baseline |
| 9 | `WRITE` | `writers/*` into `analysis.tmp/`, then rename |

**Registration.** Every analyzer module exports `ANALYZERS: tuple[AnalyzerSpec, ...]`. `pipeline.py` holds a
static `ANALYZER_MODULES` list with every analyzer module (since Wave 3 every one of them registers native
specs; `analyzers/network.py` was added after `posture`, D-52). A module that lacks `ANALYZERS` yields one
`AnalyzerStatus(status="not_implemented")`; a module that cannot be imported yields one `AnalyzerStatus(status=
"error")` with the exception type (an engine defect, never silently skipped; the result is `partial`). There is no
fallback to the d13c215 analyzers and no standby `<name>:fallback` run any more (D-53): a failing spec is isolated
(`error`, its partial output rolled back), the specs that `require` it are `skipped`, every other spec runs.
Within a phase, specs run in `ANALYZER_MODULES` order, then in tuple order; `requires` names must run
earlier. A spec whose non-optional `inputs` facets are all unavailable is `skipped` with `inputs_missing`.

```python
AnalyzerSpec(name: str, phase: Phase, run: Callable[[AnalysisContext, GraphBuilder], None],
             inputs: tuple[str, ...] = (), requires: tuple[str, ...] = (),
             legacy_files: tuple[str, ...] = (), optional: bool = False)
```

**Finding catalogue registration** (same principle, so Wave 2 streams never edit a shared catalogue file).
`findings/catalog.py` (E-core) holds the core entries (ids that no analyzer module owns, for example
`COLLECTION-GAP-*` and `SUPPRESSION-EXPIRED-001`) and merges (a) the ids the rule catalogue defines
(`rules/data/*.json`, loaded through `rules/`) and (b) the module-level `FINDINGS: tuple[CatalogEntry, ...]` of
every module in `ANALYZER_MODULES` that defines it (a missing attribute contributes nothing). A finding id or a
`legacy_ids` alias declared twice raises `ValueError` when the catalogue is built (`build_catalog`), so the first
test that builds it fails fast; a non-`strict_catalog` analysis then keeps the first declaration
(`build_catalog_lenient`) and records the gap `catalog:conflict`. The d13c215 fallback table (`LEGACY_FALLBACK`) is
gone: every emitted id is declared by its owner. `CatalogEntry` is defined by E-core in
`findings/catalog.py` (Wave 1) with at least `id`, `severity`, `category`, `title`, `remediation`,
`doc_anchor`, `legacy_ids`, `discriminator`, `detection_hint`, `validate_hint` (engine.md §1, finding-identity.md
§1–§2). `strict_catalog` checks emitted ids against the merged catalogue.

## 6. Services E-core provides to analyzers

### 6.1 `AnalysisContext` (`engine/context.py`)

Read-only attributes analyzers may rely on:

| Attribute | Meaning |
|---|---|
| `run_root: Path`, `analysis_dir: Path` | Input root and final output directory. |
| `mode`, `run_id`, `account_id`, `partition`, `regions: tuple[str, ...]` | As in `graph.run`. |
| `global_dir: Path` | `<run_root>/global` (or the region dir itself in `legacy-single`). |
| `region_dirs: Mapping[str, Path]` | Exactly the explicit regions. |
| `reference_time: datetime` | UTC; the instant the collected data describes: `SOURCE_DATE_EPOCH` when set, else the manifest `run.started_at` (then `ended_at`), for old layouts `run_metadata.timestamp_start` (naive, read as UTC) then the `YYYYMMDD` date directory. Only when none is recorded does the wall clock stand in, with the gap `clock:reference-time-unknown`. Ages (access keys) and time conditions use it, never the wall clock, so two analyses of one report differ only in `run.generated_at` and analyzer durations (F-162, D-54). |
| `manifest: Mapping \| None`, `options: AnalysisOptions` | |
| `coverage: CoverageLedger` | `facet(service, facet, region, item=None) -> status` (graph-json.md §7.2 vocabulary). |
| `evaluator: EvaluatorAPI`, `principals: Mapping[str, PrincipalModel]` | Available from phase 4. |
| `data: Mapping[str, Any]` | Loader outputs by domain (phase 2). |

### 6.2 `GraphBuilder` (`engine/graph/builder.py`)

```python
class GraphBuilder:
    def add_node(self, node_id: str, node_type: str, label: str, *, account: str | None = ...,
                 region: str | None = None, partition: str | None = ..., props: Mapping | None = None,
                 tags: Iterable[tuple[str, str]] = (), coverage_status: str | None = None,
                 coverage_gaps: Iterable[str] = ()) -> str          # idempotent; props merged
    def ensure_principal(self, raw: str, *, principal_type: str = "AWS") -> PrincipalRef
        # ids.resolve_principal + creates the placeholder / external / anonymous / service node
    def add_edge(self, source: str, edge_type: str, target: str, *, result: EvalResult | None = None,
                 confidence: str | None = None, strength: str | None = None, holds: bool | None = None,
                 weight_extra: float = 0, evidence: Mapping | None = None, props: Mapping | None = None) -> str
        # stamps category/traversal/traversable/weight from edge_types; merges on (source, type, target)
    def add_finding(self, finding_id: str, node_id: str, *, severity: str, title: str, description: str,
                    remediation: str | None = None, evidence: Mapping | None = None, discriminator: str = "",
                    confidence: str = "definite", base_severity: str | None = None, **optional) -> str
        # returns the fingerprint; creates the anchor node if needed (F-005)
    def finalize(self) -> dict    # invariants, bridge demotion, registries, meta, operator, sort -> graph.json dict
```

Rules for analyzers: never build ids by hand (use `ids.node_id_for`, `ensure_principal`,
`kms_key_node_id`); never set `traversable`/`weight`/`category` yourself; emit grants in the normalised
direction (grantee → resource); public grants from `aws-enumerator:anonymous`.

### 6.3 Export writer API (`engine/writers/`)

One interface for the CLI `export` command (R), `AnalysisOptions.exports` (E-core's WRITE phase) and the
tests, so the formats of exports.md have exactly one implementation each:

```python
# engine/writers/__init__.py (E-core, Wave 1)
EXPORT_FORMATS: Mapping[str, tuple[str, str, str]]   # format -> (module, default file name, media type)
#   "sarif" -> ("sarif", "findings.sarif", ...), "csv" -> ("csv", "findings.csv", ...),
#   "md" -> ("markdown", "findings.md", ...), "asff" -> ("asff", "findings.asff.json", ...),
#   "opengraph" -> ("opengraph", "opengraph.json", ...)            (exports.md §1 table)
def export(graph: Mapping, fmt: str, *, min_severity: str | None = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes
    # imports aws_enumerator.engine.writers.<module> and returns its render(...); an unknown format raises
    # ValueError; a module without render raises NotImplementedError (CLI: exit 1). Every format ships its
    # module, so an import failure propagates as itself (F-121, Wave 3)

# engine/writers/{sarif,csv,markdown,asff,opengraph}.py (E-rules, Wave 2)
def render(graph: Mapping, *, min_severity: str | None = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes          # pure: no file system, no clock, no network
```

`graph` is a parsed, valid `graph.json` document. Writers only render; **files are written by the
caller**: the R stream's `export` command resolves the output path, applies the git guard and writes
atomically with `fsio`; the WRITE phase writes `analysis.tmp/exports/<default file>`.

**Validation of what the engine writes** (graph-json.md §12.1, D-55). `writers.graph_json.checked(doc)` validates
with the JSON Schema of the document's minor through `engine/graph/schema_check.py`: the engine's schemas compiled
**once** into Python closures (standard library only, so every install validates, with or without the
`jsonschema` dev dependency), then `validate_graph(strict_order=True)`. On a 65,000-edge graph the schema check
takes about 2 s (``jsonschema``: about 35 s). The compiled validator supports exactly the keywords the engine
schemas use and refuses any other keyword at compile time; `tests/python/engine/core/test_schema_check.py` proves it
gives the same verdict and failing locations as `jsonschema` on every fixture and a 1,200-document mutation corpus.

## 7. Module ownership (Waves 1 and 2)

Paths are under `aws_enumerator/engine/`. Tests: each stream owns `tests/python/engine/domains/<x>/**` or
`tests/python/engine/{eval,core}/**` as listed, plus its `tests/python/regressions/test_<slug>.py`, its
`tests/fixtures/<stream>/**` and `tests/golden/CHANGES.d/<stream>.md`. [ownership.md](ownership.md) is the
complete map (every repository path, including tests and fixtures); this table is its engine part.

| Stream | Wave | Owns | Tests |
|---|---|---|---|
| **E-policy** | 1 | `policy/**` (parse, glob, arn, conditions, evaluator, resource_policy — including `Evaluator.resource_policy_grants`, onto which E-data moved `analyzers/data_stores.py` in Wave 2, D-39), `rules/**` (Wave 1 only: `rules/__init__.py`, `rules/schema.json`, `rules/legacy_rules.py`, catalogue loading), `iam/principals.py` | `tests/python/engine/eval/**` (in Wave 2 `eval/test_characterize_rules.py` passes to E-rules) |
| **E-core** | 1 | `__init__.py`, `pipeline.py`, `context.py`, `model.py` (add-only), `console.py`, `merge.py` (F-126, §3.5; implemented at the Wave 1/2 sync by the sync fixups agent, D-42), `io/**` (creates a loader stub per domain), `graph/**` except the frozen `edge_types.py` and E-rules' `closure.py` (`builder.py`, `traverse.py`, `__init__.py`, and `ids.py`, whose scheme node-ids.md freezes), `findings/**` (incl. `catalog.py`, §5), `writers/{__init__,graph_json,findings,summary,legacy}.py` (incl. the §6.3 dispatcher), `analyzers/__init__.py`, `iam/__init__.py`, `iam/trust.py`, `iam/assume.py`; `schema/**` is frozen | `tests/python/engine/core/**`, including `test_contracts_engine.py`; `tests/support/ref_paths.py` |
| **E-net** | 2 | `analyzers/{s3,ec2,edge_services,posture}.py`, `io/loaders/{s3,ec2,edge_services,posture}.py` | `tests/python/engine/domains/{s3,ec2,edge_services,posture}/**` |
| **E-k8s** | 2 | `analyzers/k8s/**`, `io/loaders/k8s.py` | `tests/python/engine/domains/k8s/**` |
| **E-data** | 2 | `analyzers/{kms,secrets,data_stores}.py`, `io/loaders/{kms,secrets,data_stores}.py` | `tests/python/engine/domains/{kms,secrets,data_stores}/**` |
| **E-compute** | 2 | `analyzers/{lambda_,compute,messaging,coverage_gaps,cognito}.py`, `iam/hygiene.py`, `io/loaders/{lambda_,compute,messaging}.py` | `tests/python/engine/domains/{lambda_,compute,messaging,cognito,hygiene,coverage}/**` |
| **E-rules** | 2 | all of `rules/**` in Wave 2 (`rules/data/**` incl. `NOTICE`, `rules/{runner,severity,subsume}.py`, and the Wave 1 E-policy files `rules/{__init__,schema.json,legacy_rules.py}` and catalogue loading), `graph/closure.py`, the export writers `writers/{sarif,csv,markdown,asff,opengraph}.py` (exports.md names E-rules / E8; interface §6.3) | `tests/python/engine/domains/rules/**`, `tests/python/engine/bench/**`, `tests/python/exports/**`, `tests/python/engine/eval/test_characterize_rules.py` |

Wave 3a (I1) added `analyzers/network.py` (after `posture` in `ANALYZER_MODULES`, D-52) and
`graph/schema_check.py` (D-55); [ownership.md](ownership.md) §9 records the Wave 3 state.

Decisions recorded here:

- **IAM hygiene has one owner: E-compute** (`iam/hygiene.py`), following PLAN.md Wave 2 ("E-compute …
  IAM hygiene"). E-core provides the credential-report, password-policy and identity-provider data through
  `io/loaders/iam.py` in Wave 1 and lists `aws_enumerator.engine.iam.hygiene` in `ANALYZER_MODULES`.
- **Cognito moves to its own module** `analyzers/cognito.py`, owned by E-compute (PLAN.md Wave 2).
  E-net removed the Cognito block from `edge_services.py` in Wave 2: `cognito.py` registers the analyzer named
  `cognito`, and `edge_services.py` emits nothing for identity pools.
- **Rules hand-over:** E-policy owns all of `rules/**` in Wave 1; in Wave 2 E-rules owns all of `rules/**`
  (E-policy does not run in Wave 2, so nothing under `rules/` is left without an owner). `graph/closure.py`
  is E-rules' (Wave 2); E-core does not create it.
- **Wave 1 streams are not active in Wave 2.** In Wave 2, E-policy's and E-core's paths (other than the
  domain loaders handed over below) are frozen; a Wave 2 stream that needs a change there writes a change
  request (ownership.md §1 rule 2).
- **Loaders hand-over:** E-core owns `io/**` in Wave 1 and creates every domain loader with today's
  legacy-layout behaviour; from Wave 2 each domain loader belongs to the domain stream listed above.
  `io/fs.py`, `io/coverage.py` and `io/loaders/{iam,org}.py` stay with E-core.
- **Frozen in both waves:** `graph/edge_types.py`, `schema/*.json` (`graph-1.1.schema.json` was added by
  contract-arbiter at the Wave 1/2 sync, D-42), the `docs/contracts/*` pages. A new
  edge or node type is a change request to edge_types.py plus a regenerated traversability-table.md.

## 8. Testing contract

- `tests/python/engine/core/test_contracts_engine.py` (this stream) validates the fixtures, the table, the
  ids helpers and the reference traversal; E-core extends `tests/python/engine/core/**`.
- Every stream's emitted `graph.json` must pass the schema and `validate_graph(strict_order=True)`; each
  stream asserts this in its own tests, and the WRITE phase validates every document it writes (§6.3, D-55).
- The v1 goldens `tests/golden/v1/<scenario>/{graph,findings,summary,outcome}.json` (captured in Wave 3a by I1,
  stream i1-reconcile; ownership.md §3.4–§3.5) hold `analyze_report` of every committed scenario tree from its
  old-layout root; `tests/python/golden/test_v1_goldens.py` (marker `golden`, `scripts/check.sh golden`) compares
  them and checks that the output is identical across hash seeds. An intended change regenerates them with
  `--update-golden` and a ledger entry (`tests/golden/CHANGES.d/README.md`).
- `engine/graph/traverse.py` must pass every vector in `tests/fixtures/graph/path_cases.json`
  (`tests/support/ref_paths.py` is the test-only reference).
- Tests reach production code only through `tests/support/targets.py` (engine accessors requested in
  `requests/contracts-engine-1.md`; `tests/support/ref_paths.engine_module` is the interim indirection).
