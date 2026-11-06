"""The analyzers never crash on the ``null`` (= unknown) fields of the migrated collectors (request ``c-b-1``;
coverage-schema.md §1). Until Wave 3 a sanitising view (``NULLABLE_LIST_KEYS``) protected the d13c215 analyzers;
the native analyzers read ``null`` as unknown themselves, so the view is gone (DECISIONS.md D-53).

* end to end: ``collect --regions eu-west-1,eu-west-2`` against the acme fake world with the real engine gives
  analysis status ``ok``, no analyzer ``error`` and a valid ``graph.json``;
* worst case: every field a collector can write as ``None`` set to ``null`` at once in that run, re-analysed:
  still ``ok``, and the unknowns are disclosed as node coverage gaps (never as empty lists);
* drift guard: no engine module reads a collector-nullable key with ``.get(key, [])`` (which returns ``None``,
  not the default, when the collector wrote ``null``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

REGIONS = "eu-west-1,eu-west-2"
#: Identity keys a collector sets to None only before filling them (never left null in a written record).
_IDENTITY_KEYS = {"Arn", "Id", "Name", "Type", "Region", "KeyId"}


def _collector_nullable_keys():
    """Record keys the collectors (and the k8s projections) can write as ``None``."""
    keys = set()
    sources = sorted((targets.package_dir() / "collectors").glob("*.py"))
    sources.append(targets.package_dir() / "k8s" / "projections.py")
    for path in sources:
        text = path.read_text(encoding="utf-8")
        keys |= set(re.findall(r'"([A-Za-z][A-Za-z_]+)": None', text))
        keys |= set(re.findall(r'\["([A-Za-z][A-Za-z_]+)"\] = None', text))
        keys |= set(re.findall(r"\b([A-Z][A-Za-z]+)=None", text))
    return keys - _IDENTITY_KEYS


def _nullify(value, keys):
    if isinstance(value, list):
        return [_nullify(v, keys) for v in value]
    if isinstance(value, dict):
        return {k: (None if k in keys else _nullify(v, keys)) for k, v in value.items()}
    return value


def _errors(graph):
    return [(s["name"], s.get("error")) for s in graph["analyzer_status"] if s["status"] == "error"]


@pytest.fixture
def acme_run(tmp_path, monkeypatch):
    return R.collect(["collect", "--regions", REGIONS], tmp_path, monkeypatch)


@pytest.mark.finding("F-059", "F-002")
def test_acme_two_region_run_analyses_cleanly(acme_run):
    manifest = acme_run.manifest()
    assert acme_run.exit_code in (0, 2), acme_run.err[-2000:]          # acme denies some APIs: partial is 2
    assert manifest["analysis"]["status"] == "ok" and manifest["analysis"]["engine"] == "v2"
    assert manifest["target"]["regions"] == ["eu-west-1", "eu-west-2"]
    graph = json.loads((acme_run.run_root / "analysis" / "graph.json").read_text(encoding="utf-8"))
    assert _errors(graph) == []
    assert targets.engine_module("writers.graph_json").problems(graph) == []
    assert graph["run"]["regions"] == ["eu-west-1", "eu-west-2"]


@pytest.mark.finding("F-059", "F-002")
def test_every_collector_nullable_field_null_at_once_never_crashes_an_analyzer(tmp_path, monkeypatch):
    run = R.collect(["collect", "--regions", REGIONS, "--no-analysis"], tmp_path, monkeypatch)
    root, keys = run.run_root, _collector_nullable_keys()
    changed = 0
    for path in sorted(root.rglob("*.json")):
        if path.name in ("manifest.json", "_coverage.json") or "analysis" in path.parts:
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        new = _nullify(doc, keys)
        if new != doc:
            path.write_text(json.dumps(new), encoding="utf-8")
            changed += 1
    assert changed > 50                                     # the acme run really exercises the null shapes
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    result = targets.engine_module().analyze_run(str(root), regions=manifest["target"]["regions"], manifest=manifest)
    graph = json.loads(Path(result.graph_path).read_text(encoding="utf-8"))
    assert result.status == "ok" and _errors(graph) == []
    assert targets.engine_module("writers.graph_json").problems(graph) == []
    codes = {g["code"] for g in graph["evaluation_gaps"]}
    assert "legacy:unknown-lists-as-empty" not in codes                # no sanitising view any more
    partial = [n for n in graph["nodes"] if n["coverage"]["status"] == "partial" and n["coverage"]["gaps"]]
    assert len(partial) > 10                                           # disclosed per node, never silent


@pytest.mark.finding("F-059")
def test_no_engine_module_defaults_a_collector_nullable_list_with_get():
    """``rec.get("Grants", [])`` is ``None`` when the collector wrote ``null``: read it as unknown instead."""
    nullable = _collector_nullable_keys()
    risky = []
    for path in sorted((targets.package_dir() / "engine").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for key in re.findall(r"""\.get\(['"]([A-Za-z_]+)['"],\s*(?:\[\]|\(\))\)""", text):
            if key in nullable:
                risky.append(f"{path.name}: {key}")
    assert risky == [], f"collector-nullable lists defaulted with .get(key, []): {sorted(risky)}"
