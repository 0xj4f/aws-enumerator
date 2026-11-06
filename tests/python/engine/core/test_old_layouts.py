"""Old (v0.2 / d13c215) report layouts stay analysable after the d13c215 engine was removed (DECISIONS.md D-53).

``aws-enumerator analyze <dir>`` (``engine.analyze_report`` and the loaders' old-shape handling) is the one path for
old reports now: no ``legacy_api.analyze()``, no legacy adapter, no standby fallback. Every committed scenario tree
of ``tests/fixtures/scenarios`` analyses to a valid ``graph.json`` with every analyzer ``ok``, the ``analysis/`` file
set of graph-json.md §1 (D-22) and ``_provenance.json``; the CLI analyses an old ``--all`` account directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.support import report_builder as rb
from tests.support import targets

GRAPH_FILES = {"graph.json", "findings.json", "summary.json", "_provenance.json"}


def _legacy_outputs() -> set:
    return set(targets.engine_module("writers.legacy").LEGACY_OUTPUTS)


@pytest.mark.finding("F-010", "F-025", "F-002")
@pytest.mark.parametrize("name", rb.scenario_names())
def test_every_scenario_tree_analyses_natively(name, tmp_path):
    engine = targets.engine_module()
    for report_dir in rb.materialize(name, tmp_path):
        result = engine.analyze_report(str(report_dir))
        assert result.status == "ok", (name, [(s.name, s.status, s.error_message) for s in result.analyzer_status
                                              if s.status == "error"])
        graph = json.loads(Path(result.graph_path).read_text(encoding="utf-8"))
        assert targets.engine_module("writers.graph_json").problems(graph) == [], name
        assert graph["run"]["mode"].startswith("legacy-")
        assert not [s for s in graph["analyzer_status"] if s["name"].endswith(":fallback")]
        files = {p.name for p in Path(result.analysis_dir).iterdir()}
        assert files == GRAPH_FILES | _legacy_outputs(), name


@pytest.mark.finding("F-010")
def test_the_cli_analyses_an_old_all_regions_account_directory(tmp_path):
    rb.materialize("all_mode", tmp_path)
    account_dir = tmp_path / "111122223333"
    env = dict(os.environ, SOURCE_DATE_EPOCH="1767225600", PYTHONPATH=str(targets.REPO_ROOT))
    proc = subprocess.run([sys.executable, "-m", "aws_enumerator", "analyze", str(account_dir)], cwd=tmp_path,
                          env=env, capture_output=True, text=True, timeout=300, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip().endswith(str(account_dir / "analysis"))
    graph = json.loads((account_dir / "analysis" / "graph.json").read_text(encoding="utf-8"))
    assert graph["run"]["mode"] == "legacy-all" and graph["run"]["regions"] == ["eu-west-1", "eu-west-2"]
    assert graph["run"]["generated_at"] == "2026-01-01T00:00:00Z"
    assert {p.name for p in (account_dir / "analysis").iterdir()} == GRAPH_FILES | _legacy_outputs()
