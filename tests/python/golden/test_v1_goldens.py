"""v1 goldens: the native analysis of every committed scenario tree (``tests/golden/v1/<scenario>/``).

They replace the d13c215 characterisation goldens (``tests/golden/legacy/<scenario>/``, retired in Wave 3a with the
d13c215 engine, DECISIONS.md D-53; the review of every difference is in the golden ledger
``tests/golden/CHANGES.d/i1-reconcile.md``). ``aws-enumerator analyze <dir>`` is the one path for old report layouts,
so each tree of ``tests/fixtures/scenarios`` is analysed with ``engine.analyze_report`` from its old-layout root:
the account directory for the old ``--all`` layout (``legacy-all``: global plus every region directory), the region
directory for the old ``--region`` layout (``legacy-single``).

Golden files per scenario: ``graph.json``, ``findings.json`` and ``summary.json`` (graph-json.md §1, D-22) plus
``outcome.json`` (input root, layout, analysis status, the files written). The canonical form keeps the engine's
own list order (the output is deterministic, F-162: :func:`test_v1_output_is_identical_across_hash_seeds`), sorts
keys and masks the wall-clock values (``generated_at``, ``duration_seconds``). The analysis records no absolute
path, which is asserted.

An intended change: re-run with ``--update-golden`` and add an entry to ``tests/golden/CHANGES.d/<stream>.md``
naming the finding ids (tests/golden/CHANGES.d/README.md).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Mapping

import pytest

from tests.support import canonical, targets
from tests.support import report_builder as rb

pytestmark = pytest.mark.golden

GOLDEN_ROOT = targets.REPO_ROOT / "tests" / "golden" / "v1"
GOLDEN_FILES = ("graph.json", "findings.json", "summary.json")
#: Wall-clock values; everything else in the analysis depends on the report alone (D-54).
VOLATILE_KEYS = frozenset({"generated_at", "duration_seconds"})
MASK = canonical.STRIPPED
#: d13c215 node names that the legacy relationship files keep (writers/legacy.py ``legacy_ref``).
LEGACY_NODEGROUP = re.compile(r"^nodegroup:[^/]+/[^/]+$")
LEGACY_CLUSTER = re.compile(r"^cluster:[^/:]+$")


def analysis_root(name: str, tree: Path) -> Path:
    """The directory ``aws-enumerator analyze`` is pointed at for scenario ``name`` (materialised in ``tree``)."""
    report_dir = rb.materialize(name, tree)[0]
    return report_dir.parent if rb.get(name).layout == "all_mode" else report_dir


def masked(obj: Any) -> Any:
    """``obj`` with the wall-clock values replaced; list order untouched."""
    if isinstance(obj, dict):
        return {k: (MASK if k in VOLATILE_KEYS else masked(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [masked(v) for v in obj]
    return obj


def canonical_text(obj: Any) -> str:
    return json.dumps(masked(obj), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def analyse(name: str, workdir: Path) -> Dict[str, str]:
    """Analyse scenario ``name`` natively; return ``{golden file: canonical text}``."""
    engine = targets.engine_module()
    root = analysis_root(name, workdir)
    result = engine.analyze_report(str(root))
    analysis = Path(result.analysis_dir)
    texts = {f: canonical_text(json.loads((analysis / f).read_text(encoding="utf-8"))) for f in GOLDEN_FILES}
    outcome = {"scenario": name, "input": root.relative_to(workdir).as_posix(), "status": result.status,
               "analysis_files": sorted(p.name for p in analysis.iterdir())}
    texts["outcome.json"] = canonical_text(outcome)
    for text in texts.values():
        assert str(workdir) not in text and os.path.realpath(workdir) not in text, "absolute path in the analysis"
    return texts


def analyse_all(base: Path) -> Dict[str, Dict[str, str]]:
    return {name: analyse(name, base / name) for name in rb.scenario_names()}


@pytest.fixture(scope="module")
def v1_outputs(tmp_path_factory) -> Dict[str, Dict[str, str]]:
    """One native analysis per scenario, shared by the checks below (about 2 s in all)."""
    return analyse_all(tmp_path_factory.mktemp("v1-goldens"))


@pytest.mark.parametrize("name", rb.scenario_names())
def test_v1_golden(name: str, v1_outputs: Mapping[str, Mapping[str, str]], update_golden: bool):
    """graph.json, findings.json, summary.json and the outcome equal tests/golden/v1/<scenario>/."""
    actual = v1_outputs[name]
    outcome = json.loads(actual["outcome.json"])
    assert outcome["status"] == "ok", outcome
    problem = canonical.check_or_update(GOLDEN_ROOT / name, actual, update_golden)
    if problem:
        pytest.fail(problem, pytrace=False)


@pytest.mark.finding("F-002")
def test_single_object_statements_analyse_exactly_like_statement_lists(v1_outputs):
    """``malformed`` writes its policies with single-object ``Statement`` values (d13c215 raised AttributeError and
    wrote nothing); ``malformed_stubs`` holds the same policies as lists. The analyses are identical."""
    for golden_file in GOLDEN_FILES:
        assert v1_outputs["malformed"][golden_file] == v1_outputs["malformed_stubs"][golden_file], golden_file


#: Analyzers that run only when an option asks for them (``--baseline``, ``--suppress``).
OPTION_GATED = frozenset({"baseline", "suppression"})


@pytest.mark.finding("F-065")
def test_every_registered_analyzer_runs_on_the_scenarios(v1_outputs):
    """Every analyzer of every module in ``ANALYZER_MODULES`` finishes ``ok`` on at least one scenario tree or acme
    collect run, and none ever reports ``error`` or ``not_implemented`` (the d13c215 analysers had never been run end
    to end). ``coverage-gaps`` needs ``_coverage.json`` files, which only v2 runs have (collectors-v2 goldens)."""
    import importlib

    pipeline = targets.engine_module("pipeline")
    registered = {spec.name for module in pipeline.ANALYZER_MODULES
                  for spec in getattr(importlib.import_module(module), "ANALYZERS", ())}
    graphs = [json.loads(texts["graph.json"]) for texts in v1_outputs.values()]
    runs = sorted((GOLDEN_ROOT.parent / "collectors-v2").glob("*/*/*/analysis/graph.json"))
    assert len(runs) == 2
    graphs += [json.loads(p.read_text(encoding="utf-8")) for p in runs]
    statuses: Dict[str, set] = {}
    for graph in graphs:
        for entry in graph["analyzer_status"]:
            statuses.setdefault(entry["name"], set()).add(entry["status"])
    assert {n for n, s in statuses.items() if s & {"error", "not_implemented"}} == set()
    assert sorted(n for n in registered if "ok" not in statuses.get(n, set())) == []
    assert {n for n in statuses if not n.startswith("load:")} - registered <= OPTION_GATED | {"write"}


def test_every_scenario_has_a_golden_and_nothing_else():
    """No stale golden directory survives a removed scenario."""
    assert sorted(p.name for p in GOLDEN_ROOT.iterdir() if p.is_dir()) == rb.scenario_names()


#: Child process: analyse every scenario under a fixed hash seed and print the canonical texts as JSON.
_CHILD = ("import json, sys, tempfile, pathlib; from tests.python.golden import test_v1_goldens as m; "
          "base = pathlib.Path(tempfile.mkdtemp(dir=sys.argv[1])); print(json.dumps(m.analyse_all(base)))")


@pytest.mark.finding("F-162")
@pytest.mark.parametrize("seed", ["0", "4242"])
def test_v1_output_is_identical_across_hash_seeds(seed: str, v1_outputs, tmp_path):
    """Set iteration order never leaks into the output: another PYTHONHASHSEED gives byte-identical goldens."""
    env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(targets.REPO_ROOT), PYTHONDONTWRITEBYTECODE="1")
    env.pop("SOURCE_DATE_EPOCH", None)
    proc = subprocess.run([sys.executable, "-c", _CHILD, str(tmp_path)], cwd=str(targets.REPO_ROOT), env=env,
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.returncode == 0, proc.stderr[-3000:]
    child = json.loads(proc.stdout)
    assert sorted(child) == sorted(v1_outputs)
    for name in sorted(child):
        assert child[name] == dict(v1_outputs[name]), f"{name} differs under PYTHONHASHSEED={seed}"


def test_legacy_relationship_files_keep_the_d13c215_node_names(tmp_path):
    """The legacy files rendered from graph.json name EKS clusters and node groups as d13c215 did
    (``cluster:<name>``, ``nodegroup:<cluster>/<name>``: no ARN uuid suffix)."""
    seen = []
    for name in ("eks_irsa", "all_mode"):
        engine = targets.engine_module()
        result = engine.analyze_report(str(analysis_root(name, tmp_path / name)))
        doc = json.loads((Path(result.analysis_dir) / "k8s_relationships.json").read_text(encoding="utf-8"))
        for edge in doc["edges"]:
            for ref in (edge["source"], edge["target"]):
                if ref.startswith("nodegroup:"):
                    assert LEGACY_NODEGROUP.match(ref), ref
                    seen.append(ref)
                elif ref.startswith("cluster:"):
                    assert LEGACY_CLUSTER.match(ref), ref
    assert "nodegroup:demo-eks/demo-ng" in seen
