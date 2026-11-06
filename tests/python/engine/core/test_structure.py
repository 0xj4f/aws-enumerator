"""Structure rules for E-core's modules (F-084): small functions, no print, sorted directory reads."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parents[4] / "aws_enumerator" / "engine"
E_CORE_FILES = (
    "__init__.py", "pipeline.py", "context.py", "console.py", "merge.py",
    "graph/builder.py", "graph/traverse.py", "findings/catalog.py", "findings/fingerprint.py",
    "findings/baseline.py", "findings/suppress.py", "findings/summary.py", "findings/references.py",
    "findings/lifecycle.py", "writers/__init__.py", "writers/graph_json.py",
    "writers/findings.py", "writers/summary.py", "writers/legacy.py", "io/fs.py", "io/coverage.py",
    "io/loaders/__init__.py", "io/loaders/iam.py", "io/loaders/org.py", "iam/__init__.py", "iam/trust.py",
    "iam/assume.py", "analyzers/__init__.py",
)
MAX_LINES = 120


def _functions(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


@pytest.mark.finding("F-084")
@pytest.mark.parametrize("rel", E_CORE_FILES)
def test_no_function_is_longer_than_the_limit(rel):
    path = ENGINE / rel
    long = [(f.name, f.end_lineno - f.lineno + 1) for f in _functions(path)
            if f.end_lineno - f.lineno + 1 > MAX_LINES]
    assert long == []


@pytest.mark.finding("F-084")
@pytest.mark.parametrize("rel", E_CORE_FILES)
def test_no_print_and_no_unsorted_listing(rel):
    tree = ast.parse((ENGINE / rel).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            assert name != "print", f"{rel}:{node.lineno} print()"
            if name in ("listdir", "scandir") and rel != "io/fs.py":
                pytest.fail(f"{rel}:{node.lineno} unsorted directory listing (use io.fs.ls_sorted, F-162)")


@pytest.mark.finding("F-084", "F-137")
def test_the_d13c215_engine_and_its_adapter_are_gone(h):
    """Wave 3 (DECISIONS.md D-53): no legacy_api, no legacy adapter, no standby fallback, no d13c215 bodies."""
    import importlib

    for gone in ("legacy_api", "findings.legacy", "analyzers.k8s.legacy"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(f"aws_enumerator.engine.{gone}")
    adapter = h.engine("analyzers")
    for name in ("LEGACY_DOMAINS", "LEGACY_FALLBACKS", "NULLABLE_LIST_KEYS", "legacy_report_path", "remove_view",
                 "run_legacy_domain", "LegacyResolver"):
        assert not hasattr(adapter, name), name
    assert not hasattr(h.engine(""), "analyze")
    assert not hasattr(h.engine("iam"), "PRINCIPALS_FALLBACK")
    assert not hasattr(h.engine("findings.catalog"), "LEGACY_FALLBACK")
    specs, missing = h.engine("pipeline").collect_specs()
    assert missing == [] and {r.origin for r in specs} == {"native"}
    sources = "\n".join(p.read_text(encoding="utf-8") for p in sorted(ENGINE.rglob("*.py")))
    for marker in ("def _analyze_s3_relationships", "def _analyze_k8s_relationships", "def analyze(report_path)",
                   "def _resource_policy_grants", "def run_legacy_entry", ".legacy-view"):
        assert marker not in sources, marker
