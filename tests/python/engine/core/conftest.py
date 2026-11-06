"""Fixtures for E-core's tests (context, loaders, builder, pipeline, writers, trust/assume).

Production code is reached through :mod:`tests.support.targets` (``engine_module``). Trees are built with
``tests.support.report_builder`` (placeholder accounts only, ``demo-*`` names, hex resource ids).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional, Sequence

import pytest

from tests.support import targets
from tests.support import report_builder as rb

ACCT = "123456789012"
FOREIGN = "999999999999"
REGION = "eu-west-2"
OTHER = "eu-west-1"
EPOCH = "1767225600"  # 2026-01-01T00:00:00Z


def engine(name: str = ""):
    return targets.engine_module(name)


def load(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def graph_problems(graph: Dict[str, Any]) -> list:
    return engine("writers.graph_json").problems(graph)


def nodes_by_id(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph["nodes"]}


def edges(graph: Dict[str, Any], edge_type: Optional[str] = None, source: Optional[str] = None,
          target: Optional[str] = None) -> list:
    return [e for e in graph["edges"] if (edge_type is None or e["type"] == edge_type)
            and (source is None or e["source"] == source) and (target is None or e["target"] == target)]


def findings(graph: Dict[str, Any], fid: str, node_id: Optional[str] = None) -> list:
    return [f for f in graph["findings"] if f["id"] == fid and (node_id is None or f["node_id"] == node_id)]


def iam_arn(kind: str, name: str, account: str = ACCT, path: str = "/") -> str:
    return f"arn:aws:iam::{account}:{kind}{path}{name}"


class Tree:
    """A legacy single-region report ``<root>/<acct>/<region>/`` built from an :class:`rb.Iam`."""

    def __init__(self, root: Path, region: str = REGION, account: str = ACCT):
        self.scope = rb.Scope(root, account, region)
        self.iam = rb.Iam(account)
        self.account = account

    @property
    def path(self) -> Path:
        return self.scope.path

    def write(self, layout: str = "legacy", regional: bool = True) -> Path:
        self.iam.write(self.scope, layout=layout)
        if regional:
            rb.write_empty_regional(self.scope)
        rb.write_manifest(self.scope.path, account=self.account, mode="single_region", region=self.scope.region)
        return self.scope.path

    def analyze(self, **options: Any) -> SimpleNamespace:
        opts = engine("model").AnalysisOptions(**options) if options else None
        result = engine().analyze_report(str(self.path), opts)
        graph = load(Path(result.graph_path)) if result.graph_path else None
        return SimpleNamespace(result=result, graph=graph, dir=Path(result.analysis_dir or self.path / "analysis"))


class Run:
    """A v2 run root ``<root>/<acct>/<run_id>/`` (manifest 2.0)."""

    def __init__(self, root: Path, regions: Sequence[str] = (REGION,), account: str = ACCT,
                 run_id: str = "20261015T101500Z-a1b2c3"):
        from tests.fixtures.regressions import support as S

        self.v2 = S.V2Run(root, account=account, run_id=run_id, regions=regions)
        self.iam = rb.Iam(account)

    @property
    def path(self) -> Path:
        return self.v2.path

    def scope(self, unit: str) -> rb.Scope:
        return self.v2.scope(unit)

    def manifest(self, **changes: Any) -> Dict[str, Any]:
        doc = self.v2.manifest()
        for key, value in changes.items():
            doc[key] = value
        return doc

    def write(self, layout: str = "legacy", manifest: Optional[Dict[str, Any]] = None) -> Path:
        g = self.scope("global")
        self.iam.write(g, layout=layout)
        for region in self.v2.regions:
            rb.write_empty_regional(self.scope(region))
        self.path.mkdir(parents=True, exist_ok=True)
        rb.dump_json(self.path / "manifest.json", manifest or self.v2.manifest())
        return self.path

    def analyze(self, regions: Optional[Sequence[str]] = None, **options: Any) -> SimpleNamespace:
        opts = engine("model").AnalysisOptions(**options) if options else None
        result = engine().analyze_run(str(self.path), regions=list(regions or self.v2.regions), options=opts)
        graph = load(Path(result.graph_path)) if result.graph_path else None
        return SimpleNamespace(result=result, graph=graph, dir=self.path / "analysis")


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


@pytest.fixture
def run(tmp_path: Path) -> Run:
    return Run(tmp_path)


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    return EPOCH


@pytest.fixture
def h() -> SimpleNamespace:
    """The helpers above as one namespace (test modules cannot import each other under importlib mode)."""
    return SimpleNamespace(
        ACCT=ACCT, FOREIGN=FOREIGN, REGION=REGION, OTHER=OTHER, EPOCH=EPOCH, rb=rb, engine=engine, load=load,
        graph_problems=graph_problems, nodes_by_id=nodes_by_id, edges=edges, findings=findings, iam_arn=iam_arn,
        Tree=Tree, Run=Run)
