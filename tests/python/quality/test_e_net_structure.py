"""Structure rules for E-net's modules (F-084): small functions, no print, sorted listings, no raw policy-statement
loops in the native code (engine-api.md §4 R-13), native registration and catalogue entries (D-33)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.support import targets

ENGINE = Path(targets.engine_module("").__file__).resolve().parent
E_NET_FILES = ("analyzers/s3.py", "analyzers/ec2.py", "analyzers/edge_services.py", "analyzers/posture.py",
               "io/loaders/s3.py", "io/loaders/ec2.py", "io/loaders/edge_services.py", "io/loaders/posture.py")
#: The d13c215 bodies once kept at the end of the modules (removed in Wave 3, DECISIONS.md D-53).
LEGACY_BODIES = {"_analyze_s3_relationships", "_classify_s3_access", "_analyze_ec2_relationships", "_load_ec2_data",
                 "_classify_ec2_access", "_check_sg_public_access", "_describe_port", "_analyze_extra_relationships",
                 "_load_extra_data", "_load_region"}
MAX_LINES = 120


def _native_functions(rel: str):
    """Every function of ``rel`` (one parse); no d13c215 body may remain (F-137)."""
    tree = ast.parse((ENGINE / rel).read_text(encoding="utf-8"))
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert not {f.name for f in functions} & LEGACY_BODIES, f"{rel}: d13c215 body left"
    return functions


@pytest.mark.finding("F-084")
@pytest.mark.parametrize("rel", E_NET_FILES)
def test_no_native_function_is_longer_than_the_limit(rel):
    long = [(f.name, f.end_lineno - f.lineno + 1) for f in _native_functions(rel)
            if f.end_lineno - f.lineno + 1 > MAX_LINES]
    assert long == []


@pytest.mark.finding("F-084", "F-162")
@pytest.mark.parametrize("rel", E_NET_FILES)
def test_no_print_no_unsorted_listing_and_no_raw_statement_loops(rel):
    for f in _native_functions(rel):
        for node in ast.walk(f):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                assert name != "print", f"{rel}:{node.lineno} print()"
                assert name not in ("listdir", "scandir"), f"{rel}:{node.lineno} unsorted listing (F-162)"
                if name == "get" and node.args and isinstance(node.args[0], ast.Constant):
                    assert node.args[0].value not in ("actions", "effective_statements"), \
                        f"{rel}:{node.lineno} raw policy-statement loop (R-13)"
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                assert node.slice.value not in ("actions", "effective_statements"), f"{rel}:{node.lineno} (R-13)"


@pytest.mark.finding("F-002", "F-084")
def test_native_analyzers_are_registered_with_their_legacy_files():
    expected = {"s3": ("s3", ("s3_relationships.json",)), "ec2": ("ec2", ("ec2_relationships.json",)),
                "edge_services": ("edge_services", ("extra_relationships.json",)), "posture": ("posture", ())}
    for module, (name, files) in expected.items():
        specs = targets.engine_module(f"analyzers.{module}").ANALYZERS
        assert [(s.name, s.legacy_files, s.phase.name) for s in specs] == [(name, files, "RESOURCES")]
    pipeline = targets.engine_module("pipeline")
    specs, _missing = pipeline.collect_specs()
    origins = {r.spec.name: r.origin for r in specs}
    assert {origins[n] for n in ("s3", "ec2", "edge_services", "posture")} == {"native"}


def test_finding_ids_are_declared_once_in_the_merged_catalogue():
    catalog = targets.engine_module("findings.catalog").build_catalog()
    for module in ("s3", "ec2", "edge_services", "posture"):
        for entry in targets.engine_module(f"analyzers.{module}").FINDINGS:
            assert catalog.get(entry.id) is entry, entry.id
