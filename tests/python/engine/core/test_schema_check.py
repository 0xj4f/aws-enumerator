"""The compiled schema validator agrees with ``jsonschema`` (graph-json.md §12.1; perf of the WRITE phase).

The engine validates every ``graph.json`` it writes with :mod:`aws_enumerator.engine.graph.schema_check` (compiled
once, standard library only) instead of ``jsonschema`` (a dev dependency, about 40 s on a 65,000-edge graph). These
tests pin that the two give the same verdict and fail at the same locations: on every valid and invalid fixture,
on a merged (1.1) document, and on a deterministic mutation corpus of the example and hostile graphs.
"""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import jsonschema
import pytest

from tests.support import targets

SC = targets.engine_module("graph.schema_check")
GRAPH = targets.engine_module("graph")

#: Replacement values a mutation writes over a field: every JSON type, plus hostile strings.
WRONG: Tuple[Any, ...] = (None, True, 0, -1, 1.5, "", "x", "<script>", [], [1], {}, {"__proto__": 1}, {"a b": 1})


def _reference_paths(doc: Any, name: str) -> Set[Tuple[str, ...]]:
    validator = jsonschema.Draft202012Validator(GRAPH.load_schema(name))
    return {tuple(str(p) for p in e.absolute_path) for e in validator.iter_errors(doc)}


def _compiled_paths(doc: Any, name: str) -> Set[Tuple[str, ...]]:
    return {tuple(str(p) for p in path) for path, _msg in SC.compiled(name).errors(doc)}


def _assert_same(doc: Any, name: str, label: str) -> None:
    assert _compiled_paths(doc, name) == _reference_paths(doc, name), label


def _fixtures() -> List[Path]:
    return sorted(targets.GRAPH_FIXTURES_DIR.glob("*.json")) + sorted(targets.GRAPH_INVALID_FIXTURES_DIR.glob("*.json"))


def _graph_docs() -> List[Tuple[str, Dict[str, Any]]]:
    out = []
    for path in _fixtures():
        doc = json.loads(path.read_text(encoding="utf-8"))
        if path.name == "path_cases.json":
            out += [(f"path_cases[{i}]", case["graph"]) for i, case in enumerate(doc) if isinstance(case, dict)]
        elif path.name != "expectations.json":
            out.append((path.name, doc))
    return out


@pytest.mark.finding("F-142")
@pytest.mark.parametrize("name", ["graph", "graph-1.1"])
def test_every_fixture_gets_the_jsonschema_verdict_and_locations(name):
    docs = _graph_docs()
    assert len(docs) > 30
    for label, doc in docs:
        _assert_same(doc, name, f"{name}: {label}")


def _leaves(value: Any, path: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
    out = [path]
    if isinstance(value, dict):
        for k, v in value.items():
            out += _leaves(v, path + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out += _leaves(v, path + (i,))
    return out


def _set(doc: Any, path: Tuple[Any, ...], value: Any) -> Any:
    if not path:
        return value
    node = doc
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    return doc


def _mutations(doc: Dict[str, Any], seed: int, count: int) -> List[Tuple[str, Any]]:
    """``count`` deterministic single-field mutations: wrong-typed values, deleted keys, unknown keys."""
    rng = random.Random(seed)
    paths = [p for p in _leaves(doc) if p]
    out = []
    for i in range(count):
        path = rng.choice(paths)
        new = copy.deepcopy(doc)
        kind = i % 3
        if kind == 0:
            out.append((f"{path}={WRONG[i % len(WRONG)]!r}", _set(new, path, copy.deepcopy(WRONG[i % len(WRONG)]))))
            continue
        parent = new
        for part in path[:-1]:
            parent = parent[part]
        if kind == 1 and isinstance(parent, dict):
            del parent[path[-1]]
            out.append((f"del {path}", new))
        elif isinstance(parent, dict):
            parent["zz_unknown key"] = WRONG[i % len(WRONG)]
            out.append((f"add under {path[:-1]}", new))
    return out


@pytest.mark.finding("F-142")
@pytest.mark.parametrize("fixture", ["example.json", "hostile.json", "minimal.json"])
def test_mutated_documents_get_the_jsonschema_verdict_and_locations(fixture):
    doc = json.loads((targets.GRAPH_FIXTURES_DIR / fixture).read_text(encoding="utf-8"))
    mutations = _mutations(doc, seed=len(fixture), count=400)
    invalid = 0
    for label, mutated in mutations:
        ref = _reference_paths(mutated, "graph")
        assert _compiled_paths(mutated, "graph") == ref, label
        invalid += bool(ref)
    assert invalid > 100                                     # the corpus really exercises the failure paths


@pytest.mark.finding("F-142")
def test_a_merged_document_is_checked_with_the_11_schema():
    doc = json.loads((targets.GRAPH_FIXTURES_DIR / "example.json").read_text(encoding="utf-8"))
    merged = copy.deepcopy(doc)
    merged["run"]["mode"] = "merge"                          # 1.1 requires run.sources in merge mode
    _assert_same(merged, "graph-1.1", "merge mode without sources")
    assert SC.compiled("graph-1.1").errors(merged) and not SC.compiled("graph-1.1").errors(doc)


def test_unsupported_keywords_and_remote_references_are_refused():
    with pytest.raises(SC.SchemaError):
        SC.CompiledSchema({"type": "string", "format": "email"})
    with pytest.raises(SC.SchemaError):
        SC.CompiledSchema({"$ref": "https://example.invalid/schema.json"})
    with pytest.raises(SC.SchemaError):
        SC.CompiledSchema({"$ref": "#/$defs/missing"})


@pytest.mark.parametrize("schema,good,bad", [
    ({"type": "integer"}, [1, 1.0, -3], [True, 1.5, "1"]),
    ({"type": "number"}, [0, 2.5], [False, None]),
    ({"enum": [1, "a"]}, [1, 1.0, "a"], [True, "b"]),
    ({"const": False}, [False], [0, None]),
    ({"uniqueItems": True}, [[1, True], ["a", "b"]], [[1, 1.0], [{"a": 1}, {"a": 1}]]),
    ({"pattern": "^a"}, ["abc", 3], ["ba"]),
    ({"minimum": 0}, [0, "x", True], [-1, -0.5]),
    ({"if": {"const": 1}, "then": {"type": "integer"}, "else": {"type": "string"}}, [1, "x"], [2.5, None]),
    ({"oneOf": [{"type": "string"}, {"minLength": 2}]}, ["a", 5], ["ab"]),
])
def test_json_semantics_match_jsonschema(schema, good, bad):
    compiled = SC.CompiledSchema(schema)
    reference = jsonschema.Draft202012Validator(schema)
    for value in good:
        assert compiled.is_valid(value) and reference.is_valid(value), value
    for value in bad:
        assert not compiled.is_valid(value) and not reference.is_valid(value), value
