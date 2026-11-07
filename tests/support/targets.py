"""The single indirection point between the test suite and production code.

Every test reaches production code through the helpers in this module and never
imports ``app.*`` / ``aws_enumerator.*`` directly. When the package is renamed
(``app/`` -> ``aws_enumerator/``) and ``policy_parser.py`` is split into
``aws_enumerator/engine/*``, the rename agent edits **only this file**.

Baseline: d13c215 (package ``app``). Since the Wave 0b rename/split the package is
``aws_enumerator`` (old path -> new path: docs/contracts/path-map.md).

Accessor groups:

* baseline / legacy: ``legacy_fn``, ``main_*``, ``runner_module``, ``collector_*``,
  ``dashboard_*``, ``regions_json_path``;
* runtime contracts (requests contracts-runtime-1): ``coverage_module``, ``registry_module``,
  ``registry_names``, ``collector_base_module``, ``fsio_module``, ``schema_path``, ``dashboard_js_path``;
* engine contracts (request contracts-engine-1): ``engine_module(name)``, ``engine_schema_dir``,
  ``engine_schema_path``, ``any_schema_path``;
* repository locations: ``CONTRACTS_DIR``, ``GRAPH_FIXTURES_DIR``, ``GRAPH_INVALID_FIXTURES_DIR``,
  ``SCENARIO_FIXTURES_DIR``, ``GOLDEN_DIR``.

Tests never build ``f"{PACKAGE_NAME}.<module>"`` names themselves; ask for an accessor instead.
Owner: the harness stream (harness-engine in Wave 0a, harness-maintainer since the Wave 0/1 sync).
Other streams: request additions via ``$RUN/requests/<stream>-<n>.md``.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]

# ── Locations that move during the rename / split ────────────────────────────
PACKAGE_NAME = "aws_enumerator"
PACKAGE_DIR = REPO_ROOT / "aws_enumerator"

# The d13c215 private engine helpers that still exist, by their baseline name, and the module that defines each
# (legacy_fn(name)). Baseline: app.components.policy_parser; the Wave 0b split re-exported all 99 old names from
# aws_enumerator.engine.legacy_api; Wave 3 removed that module, the d13c215 ``analyze(report_path)`` and the d13c215
# analyzer bodies (DECISIONS.md D-53). Old report layouts are analysed with engine_module("").analyze_report.
LEGACY_ENGINE_NAMES: Dict[str, str] = {
    "_build_permission_map": "aws_enumerator.engine.iam.principals",
    "_detect_privesc_paths": "aws_enumerator.engine.rules.legacy_rules",
    "_detect_dangerous_permissions": "aws_enumerator.engine.rules.legacy_rules",
    "_action_matches": "aws_enumerator.engine.policy.glob",
    "_normalize_to_list": "aws_enumerator.engine.policy.parse",
    "_extract_statements": "aws_enumerator.engine.policy.parse",
    "_generate_summary": "aws_enumerator.engine.findings.summary",
}

# Module holding ``main(argv=None)`` (reads sys.argv; returns the exit code; cli.md). Baseline: app.main.
# Since the Wave 1 R rewrite the subcommands live in RUNNER_MODULE (collect, preflight) and
# COMMANDS_MODULE (analyze, export, package, verify ...); AWS access goes through AWS_SESSION_MODULE.
MAIN_MODULE = "aws_enumerator.cli"
MAIN_ENTRY = "main"
RUNNER_MODULE = "aws_enumerator.runner"
COMMANDS_MODULE = "aws_enumerator.commands"
AWS_SESSION_MODULE = "aws_enumerator.aws_session"
# Patch points of a collect run (main_patch_points()):
# * region discovery: aws_session.describe_enabled_regions(aws, region) -> [region, ...] (ec2:DescribeRegions in
#   the home region; looked up at call time). Baseline: app.main.get_enabled_regions(session).
# * analysis: the engine entry point the runner calls once after every unit (engine_adapter looks it up on the
#   engine package at call time): ``analyze_run(run_root, regions=...)``. The Wave 1 interim fallback to the
#   d13c215 ``analyze(<run_root>/global)`` is gone (0.3.0). Baseline: app.main.policy_parser.analyze.
# The baseline's get_boto3_session and datetime patch points are gone: FakeAWS.install() patches boto3.Session,
# which AwsContext uses for every session, and timestamps are UTC from aws_enumerator.output.utc_now().
REGION_DISCOVERY_ATTR = "describe_enabled_regions"
ENGINE_ANALYZE_ATTRS = ("analyze_run",)

COLLECTORS_PACKAGE = "aws_enumerator.collectors"
COLLECTOR_ENTRY = "collect"  # baseline: "enumerate" (renamed in the Wave 0b split, F-166)

DASHBOARD_SERVER_MODULE = "aws_enumerator.dashboard.server"
# EKS/Kubernetes authentication (partition-aware token, kubeconfig/token/in-cluster; C-K8s, request c-k8s-2).
# The baseline's aws_enumerator/k8s/eks_auth.py (app/utils/eks_auth.py) was replaced by k8s/auth.py in Wave 1.
EKS_AUTH_MODULE = "aws_enumerator.k8s.auth"
# The Kubernetes support package (auth, options, transport, reader, projections, rbac): k8s_module(name).
K8S_PACKAGE = "aws_enumerator.k8s"
K8S_MODULES: Tuple[str, ...] = ("auth", "options", "projections", "rbac", "reader", "transport")
# `aws-enumerator merge` (graph 1.1; engine-api.md §3.5, D-42 to D-45): plan_merge, merge_graphs, write_merged.
MERGE_MODULE = "aws_enumerator.engine.merge"

# DASHBOARD_DIR is parsed by tests/js/helpers/targets.js: keep the `NAME = BASE / "seg" / "seg"` form,
# with BASE = REPO_ROOT or a name assigned above (e.g. PACKAGE_DIR). Baseline: REPO_ROOT / "app" / "dashboard".
DASHBOARD_DIR = REPO_ROOT / "aws_enumerator" / "dashboard"
DASHBOARD_INDEX = DASHBOARD_DIR / "index.html"
# Since DECISIONS.md D-57 the page is built from frontend/ (npm run build) into DASHBOARD_DIR; the hand-vendored
# JSZip, the pure core modules and the icons are sources under frontend/.
FRONTEND_DIR = REPO_ROOT / "frontend"
DASHBOARD_VENDOR_DIR = FRONTEND_DIR / "vendor"
VENDOR_SCRIPT = REPO_ROOT / "scripts" / "vendor_dashboard_libs.py"
REGIONS_JSON = REPO_ROOT / "aws_enumerator" / "util" / "regions.json"

# The 30 collector modules in the order the baseline main() runs them
# (single-region order). Names are module names, so ``lambda_`` keeps its underscore.
COLLECTOR_NAMES: Tuple[str, ...] = (
    "iam", "vpc", "sg", "ec2", "s3", "flowlogs", "cloudtrail", "cloudfront", "waf",
    "eks", "k8s", "secretsmanager", "ssm", "lambda_", "kms", "ecs", "cloudformation",
    "glue", "codebuild", "sagemaker", "sns", "sqs", "ecr", "rds", "dynamodb",
    "apigateway", "cognito", "ebs", "elb", "route53",
)
# Collector modules added in Wave 1 (docs/contracts/registry.md §5): the WAF split and the five new
# posture collectors. ``config``'s module file is ``config_service.py``. All of them exist since Wave 1
# (registry.md §4: no PLANNED entry is left, D-51).
NEW_COLLECTOR_NAMES: Tuple[str, ...] = (
    "waf_cloudfront", "organizations", "guardduty", "securityhub", "config_service", "accessanalyzer",
)

# ── Wave 0 contracts: runtime (docs/contracts/{coverage-schema,registry,collector-context,report-layout}.md)
# Requested by contracts-runtime-1.
COVERAGE_MODULE = "aws_enumerator.coverage"
REGISTRY_MODULE = "aws_enumerator.registry"
COLLECTOR_BASE_MODULE = "aws_enumerator.collectors.base"
FSIO_MODULE = "aws_enumerator.util.fsio"
SCHEMAS_DIR = REPO_ROOT / "aws_enumerator" / "schemas"     # coverage-1 / manifest-2.0 JSON Schemas
DASHBOARD_JS_DIR = DASHBOARD_DIR / "js"                     # the built bundle: app.js
DASHBOARD_CORE_DIR = FRONTEND_DIR / "src" / "core"         # graph-core.js, loader.js, exports.js, catalog.js

# ── Wave 0 contracts: engine (docs/contracts/{graph-json,node-ids,engine-api}.md) ──
# Requested by contracts-engine-1.
ENGINE_PACKAGE = "aws_enumerator.engine"
ENGINE_SCHEMA_DIR = REPO_ROOT / "aws_enumerator" / "engine" / "schema"   # graph-1.0/1.1, findings-1.0 schemas

# ── Repository locations tests share ─────────────────────────────────────────
CONTRACTS_DIR = REPO_ROOT / "docs" / "contracts"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
SCENARIO_FIXTURES_DIR = FIXTURES_DIR / "scenarios"
GRAPH_FIXTURES_DIR = FIXTURES_DIR / "graph"
GRAPH_INVALID_FIXTURES_DIR = FIXTURES_DIR / "graph-invalid"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"

# Output directory name each collector writes in the baseline layout.
COLLECTOR_OUTPUT_DIR: Dict[str, str] = {name: name for name in COLLECTOR_NAMES}
COLLECTOR_OUTPUT_DIR["lambda_"] = "lambda"

# Analysis files the baseline engine writes into <report>/analysis/.
LEGACY_ANALYSIS_FILES: Tuple[str, ...] = (
    "compute_relationships.json", "ec2_relationships.json", "extra_relationships.json",
    "findings.json", "k8s_relationships.json", "kms_relationships.json",
    "lambda_relationships.json", "messaging_relationships.json",
    "newsurface_relationships.json", "permission_map.json", "s3_relationships.json",
    "secrets_relationships.json", "summary.json", "trust_relationships.json",
)


# ── Accessors ────────────────────────────────────────────────────────────────
def _import(name: str) -> ModuleType:
    return importlib.import_module(name)


def package_name() -> str:
    return PACKAGE_NAME


def package_dir() -> Path:
    return PACKAGE_DIR


def legacy_fn(name: str) -> Callable:
    """A d13c215 engine helper that still exists, by its baseline name, e.g. ``_action_matches``.

    Raises ``LookupError`` for a baseline name that was removed with the d13c215 engine (Wave 3, D-53).
    """
    module = LEGACY_ENGINE_NAMES.get(name)
    if module is None:
        raise LookupError(f"the d13c215 engine helper {name!r} was removed in Wave 3 (DECISIONS.md D-53)")
    return getattr(_import(module), name)


def engine_analyze() -> Callable[[str], None]:
    """The d13c215 ``analyze(report_path)``: removed in Wave 3 (D-53); raises ``LookupError``.

    Old report layouts are analysed with ``engine_module("").analyze_report(report_dir)``.
    """
    raise LookupError("the d13c215 analyze(report_path) was removed in Wave 3 (DECISIONS.md D-53); "
                      "use engine_module('').analyze_report")


def main_module() -> ModuleType:
    return _import(MAIN_MODULE)


def main_entry() -> Callable[[], None]:
    """The console-script entry point; reads ``sys.argv``."""
    return getattr(main_module(), MAIN_ENTRY)


def runner_module() -> ModuleType:
    """``aws_enumerator.runner``: ``run_collect(CollectRequest)`` (collect and preflight)."""
    return _import(RUNNER_MODULE)


def commands_module() -> ModuleType:
    """``aws_enumerator.commands``: analyze, export, merge, dashboard, permissions, modules, package, verify."""
    return _import(COMMANDS_MODULE)


def aws_session_module() -> ModuleType:
    """``aws_enumerator.aws_session``: AwsContext, identity, partition, regions (cli.md §3.1)."""
    return _import(AWS_SESSION_MODULE)


#: Runtime modules of the R stream reachable through runtime_module(name).
RUNTIME_MODULES: Tuple[str, ...] = (
    "archive", "aws_session", "buildinfo", "cli", "commands", "engine_adapter", "execution", "iam_actions",
    "integrity", "logging_setup", "output", "permissions", "ratelimit", "resume", "runner", "_version",
)


def runtime_module(name: str) -> ModuleType:
    """An R-stream runtime module by short name (``output``, ``ratelimit``, ``logging_setup`` ...)."""
    if name not in RUNTIME_MODULES:
        raise KeyError(f"unknown runtime module {name!r}")
    return _import(f"{PACKAGE_NAME}.{name}")


def engine_analyze_attr() -> str:
    """The engine entry point the runner calls after collection (``analyze_run``)."""
    engine = engine_module("")
    return next(attr for attr in ENGINE_ANALYZE_ATTRS if callable(getattr(engine, attr, None)))


def main_patch_points() -> Dict[str, Tuple[object, str]]:
    """(owner, attribute) pairs an orchestration test patches with monkeypatch.setattr.

    ``region_discovery``: ``describe_enabled_regions(aws, region) -> list``; ``analyze``: the engine entry point
    ``analyze_run(run_root, *, regions, ...)``.
    """
    return {
        "region_discovery": (aws_session_module(), REGION_DISCOVERY_ATTR),
        "analyze": (engine_module(""), engine_analyze_attr()),
    }


def collector_names() -> List[str]:
    """The 30 baseline collector module names, in baseline main() order."""
    return list(COLLECTOR_NAMES)


def collector_module(name: str) -> ModuleType:
    """A collector module by module name (``iam``, ``lambda_``, ``config_service`` ...).

    Accepts the 30 baseline names and the Wave 1 additions in :data:`NEW_COLLECTOR_NAMES`.
    """
    if name not in COLLECTOR_NAMES and name not in NEW_COLLECTOR_NAMES:
        raise KeyError(f"unknown collector {name!r}")
    return _import(f"{COLLECTORS_PACKAGE}.{name}")


def collector_entry(name: str) -> Callable:
    return getattr(collector_module(name), COLLECTOR_ENTRY)


def collector_patch_point(name: str) -> Tuple[object, str]:
    """(module, attribute) the runner calls for this collector (``collect``), for monkeypatch.setattr."""
    return collector_module(name), COLLECTOR_ENTRY


def collector_output_dir(name: str) -> str:
    return COLLECTOR_OUTPUT_DIR[name]


def dashboard_server_module() -> ModuleType:
    return _import(DASHBOARD_SERVER_MODULE)


def eks_auth_module() -> ModuleType:
    return _import(EKS_AUTH_MODULE)


def k8s_module(name: str) -> ModuleType:
    """``aws_enumerator.k8s.<name>`` (``auth``, ``options``, ``projections``, ``rbac``, ``reader``, ``transport``)."""
    if name not in K8S_MODULES:
        raise KeyError(f"unknown k8s module {name!r}")
    return _import(f"{K8S_PACKAGE}.{name}")


def merge_module() -> ModuleType:
    """``aws_enumerator.engine.merge``: ``plan_merge``, ``merge_graphs``, ``write_merged``, ``MergeInvalid``."""
    return _import(MERGE_MODULE)


def dashboard_dir() -> Path:
    return DASHBOARD_DIR


def dashboard_index_path() -> Path:
    return DASHBOARD_INDEX


def dashboard_vendor_dir() -> Path:
    return DASHBOARD_VENDOR_DIR


def vendor_script_path() -> Path:
    return VENDOR_SCRIPT


def regions_json_path() -> Path:
    return REGIONS_JSON


def legacy_analysis_files() -> List[str]:
    return list(LEGACY_ANALYSIS_FILES)


# ── Runtime contract modules (contracts-runtime-1) ───────────────────────────
def coverage_module() -> ModuleType:
    """``aws_enumerator.coverage``: classify, CallResult, Coverage (docs/contracts/coverage-schema.md §7)."""
    return _import(COVERAGE_MODULE)


def registry_module() -> ModuleType:
    """``aws_enumerator.registry``: CollectorSpec, get_registry, select (docs/contracts/registry.md)."""
    return _import(REGISTRY_MODULE)


def collector_base_module() -> ModuleType:
    """``aws_enumerator.collectors.base``: CollectContext, run_collector, ModuleResult (collector-context.md)."""
    return _import(COLLECTOR_BASE_MODULE)


def fsio_module() -> ModuleType:
    """``aws_enumerator.util.fsio``: atomic private writes, digests, the git guard (report-layout.md)."""
    return _import(FSIO_MODULE)


def registry_names() -> List[str]:
    """Registry module names in registry order (implemented and planned), e.g. ``iam``, ``config``."""
    return list(registry_module().get_registry().names())


def schemas_dir() -> Path:
    return SCHEMAS_DIR


def schema_path(name: str) -> Path:
    """A runtime JSON Schema by file name: ``coverage-1.schema.json``, ``manifest-2.0.schema.json``."""
    return SCHEMAS_DIR / name


def dashboard_js_dir() -> Path:
    return DASHBOARD_JS_DIR


def dashboard_js_path(name: str) -> Path:
    """A pure core module of the dashboard by file name, e.g. ``graph-core.js`` (frontend/src/core since D-57)."""
    return DASHBOARD_CORE_DIR / name


# ── Engine contract modules (contracts-engine-1) ─────────────────────────────
def engine_module(name: str = "") -> ModuleType:
    """``aws_enumerator.engine.<name>``, e.g. ``graph.edge_types``, ``graph.ids``, ``model``, ``analyzers.s3``.

    ``engine_module("")`` is the engine package itself (``analyze_run``, ``analyze_report``).
    """
    return _import(f"{ENGINE_PACKAGE}.{name}" if name else ENGINE_PACKAGE)


def engine_schema_dir() -> Path:
    return ENGINE_SCHEMA_DIR


def engine_schema_path(name: str) -> Path:
    """An engine JSON Schema by file name: ``graph-1.0.schema.json``, ``graph-1.1.schema.json``,
    ``findings-1.0.schema.json``."""
    return ENGINE_SCHEMA_DIR / name


def any_schema_path(name: str) -> Path:
    """Runtime schemas live in SCHEMAS_DIR, engine schemas in ENGINE_SCHEMA_DIR; find ``name`` in either."""
    runtime = SCHEMAS_DIR / name
    return runtime if runtime.exists() else ENGINE_SCHEMA_DIR / name


# ── Shared repository locations ──────────────────────────────────────────────
def contracts_dir() -> Path:
    return CONTRACTS_DIR


def contract_path(name: str) -> Path:
    """A contract document, e.g. ``node-ids.md``."""
    return CONTRACTS_DIR / name


def graph_fixtures_dir() -> Path:
    return GRAPH_FIXTURES_DIR


def graph_invalid_fixtures_dir() -> Path:
    return GRAPH_INVALID_FIXTURES_DIR


def scenario_fixtures_dir() -> Path:
    return SCENARIO_FIXTURES_DIR
