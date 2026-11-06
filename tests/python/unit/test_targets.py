"""tests/support/targets.py: every accessor resolves (requests contracts-engine-1, contracts-runtime-1).

targets.py is the only indirection between tests and production code; a broken accessor would make many
streams' tests fail for the wrong reason, so each one is pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.support import targets


def test_runtime_contract_modules():
    assert targets.coverage_module().__name__ == targets.COVERAGE_MODULE
    assert hasattr(targets.coverage_module(), "Coverage")
    assert hasattr(targets.registry_module(), "CollectorSpec")
    assert hasattr(targets.collector_base_module(), "run_collector")
    assert hasattr(targets.fsio_module(), "hashed_filename")
    names = targets.registry_names()
    assert names[0] == "iam" and {"config", "k8s", "lambda"} <= set(names)


def test_runtime_schemas_and_dashboard_js():
    for name in ("coverage-1.schema.json", "manifest-2.0.schema.json"):
        assert targets.schema_path(name).is_file()
        assert targets.any_schema_path(name) == targets.schema_path(name)
    assert targets.schemas_dir() == targets.SCHEMAS_DIR
    assert targets.dashboard_js_path("graph-core.js").is_file()
    assert targets.dashboard_js_dir() == targets.dashboard_dir() / "js"
    assert (targets.dashboard_js_dir() / "app.js").is_file()


def test_engine_contract_modules_and_schemas():
    assert targets.engine_module().__name__ == targets.ENGINE_PACKAGE
    for name in ("graph.edge_types", "graph.ids", "graph", "model"):
        assert targets.engine_module(name).__name__ == f"{targets.ENGINE_PACKAGE}.{name}"
    for name in ("graph-1.0.schema.json", "findings-1.0.schema.json"):
        assert targets.engine_schema_path(name).is_file()
        assert targets.any_schema_path(name) == targets.engine_schema_path(name)
    assert targets.engine_schema_dir() == targets.ENGINE_SCHEMA_DIR


def test_repository_locations():
    assert targets.contract_path("node-ids.md").is_file()
    assert targets.contracts_dir() == targets.CONTRACTS_DIR
    assert (targets.graph_fixtures_dir() / "minimal.json").is_file()
    assert (targets.graph_invalid_fixtures_dir() / "expectations.json").is_file()
    assert targets.scenario_fixtures_dir().is_dir()
    assert targets.GOLDEN_DIR.is_dir()


def test_collector_module_accepts_baseline_and_wave1_names():
    assert targets.collector_module("lambda_").__name__.endswith(".lambda_")
    with pytest.raises(KeyError):
        targets.collector_module("not_a_collector")
    for name in targets.NEW_COLLECTOR_NAMES:
        try:
            module = targets.collector_module(name)
        except ModuleNotFoundError:
            continue  # planned module, not written yet (registry.md PLANNED)
        assert module.__name__ == f"{targets.COLLECTORS_PACKAGE}.{name}"


def test_no_test_builds_production_module_names_in_harness_files():
    """Harness-owned files use the accessors, never f"{targets.PACKAGE_NAME}.<module>" (request contracts-*-1)."""
    root = Path(targets.REPO_ROOT) / "tests"
    harness = [*(root / "support").glob("*.py"), root / "conftest.py",
               *(p for d in ("unit", "golden", "orchestration") for p in (root / "python" / d).glob("*.py")),
               *(root / "python" / "collectors").glob("*.py")]
    owned_elsewhere = {"test_coverage.py", "test_registry.py", "test_foundation_contract.py", "targets.py",
                       "test_targets.py"}
    pattern = re.compile(r"PACKAGE_NAME\}\.|PACKAGE_DIR \/ \"(?:schemas|engine)\"")
    offenders = [p.name for p in harness if p.name not in owned_elsewhere and pattern.search(p.read_text())]
    assert offenders == []
