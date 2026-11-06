"""Structure rules for E-data's modules (F-084, R-13): small functions, no print, sorted listings, every policy
decision through the evaluator (no raw ``stmt['actions']`` walkers), and no d13c215 entry point left (Wave 3:
``legacy_api`` and the thin adapters were removed, DECISIONS.md D-53)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.support import targets

ENGINE = Path(targets.package_dir()) / "engine"
E_DATA_FILES = ("analyzers/kms.py", "analyzers/secrets.py", "analyzers/data_stores.py", "io/loaders/kms.py",
                "io/loaders/secrets.py", "io/loaders/data_stores.py")
ANALYZERS = E_DATA_FILES[:3]
MAX_LINES = 120

#: d13c215 statement walking: raw action/resource lists of the permission map or of policy documents.
RAW_WALKERS = re.compile(r"""\[['"]actions['"]\]|\.get\(['"](?:actions|resources|Statement|Effect)['"]|"""
                         r"""effective_statements|_extract_principals|_normalize_to_list|_action_matches|"""
                         r"""_arn_matches_(?:kms|secret|param|simple)""")


def _tree(rel: str) -> ast.AST:
    return ast.parse((ENGINE / rel).read_text(encoding="utf-8"))


@pytest.mark.finding("F-084")
@pytest.mark.parametrize("rel", E_DATA_FILES)
def test_no_function_is_longer_than_the_limit(rel):
    long = [(f.name, f.end_lineno - f.lineno + 1) for f in ast.walk(_tree(rel))
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.end_lineno - f.lineno + 1 > MAX_LINES]
    assert long == []


@pytest.mark.finding("F-084", "F-162")
@pytest.mark.parametrize("rel", E_DATA_FILES)
def test_no_print_and_no_unsorted_listing(rel):
    for node in ast.walk(_tree(rel)):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            assert name not in ("print", "listdir", "scandir", "glob", "iterdir"), f"{rel}:{node.lineno} {name}()"


@pytest.mark.finding("F-001", "F-002", "F-031")
@pytest.mark.parametrize("rel", ANALYZERS)
def test_every_policy_decision_goes_through_the_evaluator(rel):
    text = (ENGINE / rel).read_text(encoding="utf-8")
    hits = [m.group(0) for m in RAW_WALKERS.finditer(text)]
    assert hits == [], f"{rel}: d13c215 statement walking left: {sorted(set(hits))}"


@pytest.mark.finding("F-031", "F-137")
def test_the_private_walker_its_alias_and_the_d13c215_entry_points_are_gone():
    gone = {"analyzers.data_stores": ("_resource_policy_grants", "_analyze_newsurface_relationships",
                                      "_load_newsurface_data", "run_legacy_entry", "legacy_units",
                                      "NEWSURFACE_WEIGHTS"),
            "analyzers.kms": ("_analyze_kms_relationships", "_classify_kms_access", "_load_kms_data",
                              "KMS_ACCESS_WEIGHTS"),
            "analyzers.secrets": ("_analyze_secrets_relationships", "_classify_param_access",
                                  "_classify_secret_access", "_load_secrets_data", "_looks_sensitive_param_name",
                                  "SECRETS_ACCESS_WEIGHTS")}
    for module, names in gone.items():
        mod = targets.engine_module(module)
        for name in names:
            assert not hasattr(mod, name), f"{module}.{name}"
    called = {getattr(n.func, "attr", getattr(n.func, "id", "")) for rel in ANALYZERS for n in ast.walk(_tree(rel))
              if isinstance(n, ast.Call)}
    assert "resource_policy_grants" in called           # the one shared walker (D-39)


@pytest.mark.finding("F-088")
def test_e_data_analyzers_register_natively_with_their_findings():
    for module, name, ids in (("analyzers.kms", "kms", {"KMS-PUB-001", "KMS-XACCT-001"}),
                              ("analyzers.secrets", "secrets", {"SECRET-PUB-001", "SECRET-XACCT-001",
                                                                "PARAM-PLAIN-001", "SSMDOC-PUB-001"}),
                              ("analyzers.data_stores", "data_stores", {"ECR-PUB-001", "RDS-XACCT-001",
                                                                        "APIGW-AUTH-001"})):
        mod = targets.engine_module(module)
        assert [s.name for s in mod.ANALYZERS] == [name]
        assert ids <= {e.id for e in mod.FINDINGS}
    catalog = targets.engine_module("findings.catalog").build_catalog()
    assert catalog.canonical("SECRET-XAUTH-001") == "SECRET-XACCT-001"
