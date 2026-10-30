"""Quality gates for the whole analysis engine (``aws_enumerator/engine/**``), Wave 3 integration.

* F-084: no function longer than 120 lines anywhere in the engine (the 456-line K8s function, the 187-line
  ``analyze()`` and the other d13c215 bodies are gone, DECISIONS.md D-53);
* F-137: no d13c215 code path is left (``legacy_api``, the legacy adapter, the standby fallback, the verbatim bodies);
* F-169: no ``print`` (progress goes through :mod:`logging`); only the developer generator ``edge_types.py`` writes a
  generated artefact to stdout when run as a script;
* F-162: every directory listing is sorted (or only counted);
* F-164: the chronological ``newsurface`` / ``extra`` groupings appear only as the two documented legacy file names;
* R-13 (engine-api.md §4): no raw policy-statement loops outside ``engine/policy`` (decisions come from the
  evaluator), apart from the producer and reader of the legacy ``permission_map.json`` view.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pytest

from tests.support import targets

ENGINE = Path(targets.package_dir()) / "engine"
MAX_LINES = 120
#: Developer entry points that write a generated artefact to stdout (``python -m ... --write`` / no args).
STDOUT_SCRIPTS = {"graph/edge_types.py"}
#: Aggregations whose result does not depend on the order of a directory listing.
ORDER_FREE = {"sorted", "sum", "len", "any", "all", "set", "frozenset"}
LISTINGS = {"listdir", "scandir", "iterdir", "glob", "rglob", "walk"}
#: Raw IAM statement fields (policy documents and the legacy permission-map view).
STATEMENT_KEYS = {"actions", "Action", "NotAction", "resources", "Resource", "NotResource", "Statement",
                  "effective_statements", "deny_statements"}
#: The legacy ``permission_map.json`` view is built and read outside ``engine/policy`` (no decision is taken there).
PERMISSION_MAP_VIEW = {"iam/principals.py", "io/loaders/iam.py"}
LEGACY_FILE_NAMES = {"newsurface_relationships.json", "extra_relationships.json"}


def _modules() -> List[Tuple[str, ast.AST]]:
    out = []
    for path in sorted(ENGINE.rglob("*.py")):
        if "__pycache__" not in path.parts:
            out.append((path.relative_to(ENGINE).as_posix(), ast.parse(path.read_text(encoding="utf-8"))))
    return out


MODULES = _modules()


def _parents(tree: ast.AST) -> Dict[int, ast.AST]:
    return {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _call_name(node: ast.Call) -> str:
    fn = node.func
    return fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")


def _calls(tree: ast.AST) -> Iterator[ast.Call]:
    return (n for n in ast.walk(tree) if isinstance(n, ast.Call))


@pytest.mark.finding("F-084")
def test_no_engine_function_is_longer_than_120_lines():
    long = [f"{rel}:{f.lineno} {f.name} ({f.end_lineno - f.lineno + 1} lines)" for rel, tree in MODULES
            for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
            and f.end_lineno - f.lineno + 1 > MAX_LINES]
    assert long == []


@pytest.mark.finding("F-084", "F-137")
def test_no_d13c215_code_path_is_left():
    names = {node.name for _rel, tree in MODULES for node in ast.walk(tree)
             if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    legacy = sorted(n for n in names if re.fullmatch(r"_analyze_\w+_relationships|_load_\w+_data|_classify_\w+_access"
                                                    r"|run_legacy_\w+|legacy_report_path|_resource_policy_grants", n))
    assert legacy == []
    files = {rel for rel, _tree in MODULES}
    assert not files & {"legacy_api.py", "findings/legacy.py", "analyzers/k8s/legacy.py"}


@pytest.mark.finding("F-169")
def test_the_engine_never_prints_or_writes_to_the_standard_streams():
    offenders = []
    for rel, tree in MODULES:
        offenders += [f"{rel}:{c.lineno} print()" for c in _calls(tree) if _call_name(c) == "print"]
        if rel in STDOUT_SCRIPTS:
            continue
        offenders += [f"{rel}:{n.lineno} sys.{n.attr}" for n in ast.walk(tree)
                      if isinstance(n, ast.Attribute) and n.attr in ("stdout", "stderr")
                      and isinstance(n.value, ast.Name) and n.value.id == "sys"]
    assert offenders == []


def _walk_prunes_sorted(function: Optional[ast.AST]) -> bool:
    """``os.walk`` is deterministic when the loop prunes and sorts ``dirnames`` in place."""
    if function is None:
        return False
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and _call_name(node.value) == "sorted":
            if any(isinstance(t, ast.Subscript) for t in node.targets):
                return True
    return False


def _enclosing_function(node: ast.AST, parents: Dict[int, ast.AST]) -> Optional[ast.AST]:
    while id(node) in parents:
        node = parents[id(node)]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


@pytest.mark.finding("F-162")
def test_every_directory_listing_is_sorted_or_only_counted():
    offenders = []
    for rel, tree in MODULES:
        parents = _parents(tree)
        for call in _calls(tree):
            name = _call_name(call)
            if name not in LISTINGS or (name == "glob" and isinstance(call.func, ast.Name)):
                continue
            parent = parents.get(id(call))
            if name == "walk":
                ok = _walk_prunes_sorted(_enclosing_function(call, parents))
            else:
                if isinstance(parent, ast.comprehension):          # sum(1 for _ in p.rglob(...)) and similar
                    parent = parents.get(id(parents.get(id(parent))))
                ok = isinstance(parent, ast.Call) and _call_name(parent) in ORDER_FREE
            if not ok:
                offenders.append(f"{rel}:{call.lineno} {name}()")
    assert offenders == [], "unsorted directory listing (use io.fs.ls_sorted)"


@pytest.mark.finding("F-164")
def test_newsurface_and_extra_survive_only_as_the_legacy_file_names():
    offenders = []
    for rel, tree in MODULES:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if ("newsurface" in text or "extra_relationships" in text) and text not in LEGACY_FILE_NAMES \
                        and "\n" not in text and " " not in text:
                    offenders.append(f"{rel}:{node.lineno} {text!r}")
                if text in ("newsurface", "extra"):
                    offenders.append(f"{rel}:{node.lineno} {text!r}")
    assert offenders == []
    et = targets.engine_module("graph.edge_types")
    vocab = set(et.CATEGORIES) | set(et.NODE_GROUPS) | {e.legacy_category or "" for e in et.EDGE_TYPES.values()}
    specs, _missing = targets.engine_module("pipeline").collect_specs()
    vocab |= {r.spec.name for r in specs}
    vocab |= {e.category for e in targets.engine_module("findings.catalog").build_catalog()}
    assert not [v for v in vocab if "newsurface" in v or v == "extra" or v.startswith("extra_")]
    legacy = targets.engine_module("writers.legacy")
    assert dict(legacy.DOMAIN_OF_FILE) == {"newsurface_relationships.json": "data_stores",
                                           "extra_relationships.json": "edge_services"}


def _statement_key(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return node.slice.value if isinstance(node.slice.value, str) else None
    if isinstance(node, ast.Call) and _call_name(node) == "get" and node.args \
            and isinstance(node.args[0], ast.Constant):
        return node.args[0].value if isinstance(node.args[0].value, str) else None
    if isinstance(node, ast.BoolOp):
        return next((k for k in map(_statement_key, node.values) if k), None)
    return None


@pytest.mark.finding("F-001", "F-002")
def test_no_raw_policy_statement_loops_outside_engine_policy():
    """R-13: decisions come from ``ctx.evaluator``; statements are parsed by ``engine/policy`` only."""
    offenders = []
    for rel, tree in MODULES:
        if rel.startswith("policy/") or rel in PERMISSION_MAP_VIEW:
            continue
        for node in ast.walk(tree):
            iters = [node.iter] if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) else []
            offenders += [f"{rel}:{it.lineno} loop over {_statement_key(it)!r}" for it in iters
                          if _statement_key(it) in STATEMENT_KEYS]
    assert offenders == []
