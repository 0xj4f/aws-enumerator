"""Shared helpers for E-compute's tests (Lambda, compute, messaging, Cognito, IAM hygiene, coverage gaps).

Trees are built with ``tests/support/report_builder`` (placeholder accounts only, ``demo-*`` names) and analysed
with the real engine through ``tests/support/targets`` (``engine.analyze_report`` / ``analyze_run``), so every test
also proves the emitted ``graph.json`` is schema-valid and ``validate_graph(strict_order=True)``-clean.

Two layouts:

* :class:`LegacyTree` -- an old single-region report ``<root>/<acct>/<region>/`` (d13c215 shapes, no
  ``_coverage.json``); ``write()`` fills every other regional module with empty files.
* :class:`RunTree` -- a v2 run root built on :class:`report_builder.V2Run`, with ``_coverage.json`` per module
  (``coverage(...)``) so collection gaps and ``null`` = unknown can be exercised.

Import with ``importlib.import_module("tests.fixtures.e-compute.kit")``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb
from tests.support import targets

ACCT = rb.ACCT_MAIN           # 123456789012
FOREIGN = rb.ACCT_EXT         # 999999999999
REGION = "eu-west-2"
OTHER = "eu-west-1"
EPOCH = "1767225600"          # 2026-01-01T00:00:00Z
ANON = "aws-enumerator:anonymous"


def engine(name: str = "") -> Any:
    return targets.engine_module(name)


def iam_arn(kind: str, name: str, account: str = ACCT) -> str:
    return f"arn:aws:iam::{account}:{kind}/{name}"


def fn_arn(name: str, region: str = REGION, account: str = ACCT) -> str:
    return f"arn:aws:lambda:{region}:{account}:function:{name}"


def queue_arn(name: str, region: str = REGION, account: str = ACCT) -> str:
    return f"arn:aws:sqs:{region}:{account}:{name}"


def topic_arn(name: str, region: str = REGION, account: str = ACCT) -> str:
    return f"arn:aws:sns:{region}:{account}:{name}"


def load(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


#: The analyzers this stream owns; a test analysis fails when one of them ends ``error`` (an unknown finding id
#: or edge type is a CatalogError, i.e. an ``error`` status, since other streams' ids are not checked strictly).
OWN_ANALYZERS = ("lambda", "compute", "messaging", "cognito", "iam-hygiene", "coverage-gaps")


def _result(result: Any, fallback_dir: Path) -> SimpleNamespace:
    graph = load(Path(result.graph_path)) if result.graph_path else None
    failed = [(s.name, s.error_type, s.error_message) for s in result.analyzer_status
              if s.name.split(":")[0] in OWN_ANALYZERS and s.status == "error"]
    assert not failed, failed
    return SimpleNamespace(result=result, graph=graph, dir=Path(result.analysis_dir or fallback_dir / "analysis"))


def _with_epoch(fn: Any) -> Any:
    old = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = EPOCH
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = old


class LegacyTree:
    """A d13c215 single-region report; ``scope.write(rel, data)`` adds module files before :meth:`write`."""

    def __init__(self, root: Path, region: str = REGION, account: str = ACCT):
        self.scope = rb.Scope(root, account, region)
        self.iam = rb.Iam(account)
        self.account = account
        self.written: set = set()

    @property
    def path(self) -> Path:
        return self.scope.path

    def put(self, rel: str, data: Any) -> None:
        self.scope.write(rel, data)
        self.written.add(rel.split("/", 1)[0])

    def write(self, layout: str = "legacy") -> Path:
        self.iam.write(self.scope, layout=layout)
        rb.write_empty_regional(self.scope, skip=self.written)
        rb.write_manifest(self.scope.path, account=self.account, mode="single_region", region=self.scope.region)
        return self.scope.path

    def analyze(self, **options: Any) -> SimpleNamespace:
        self.write()
        opts = engine("model").AnalysisOptions(**options)
        return _with_epoch(lambda: _result(engine().analyze_report(str(self.path), opts), self.path))


class RunTree:
    """A v2 run root with ``_coverage.json`` per module (report-layout.md §1, coverage-schema.md §5)."""

    def __init__(self, root: Path, regions: Sequence[str] = (REGION,), account: str = ACCT):
        self.v2 = rb.V2Run(root, account=account, regions=regions)
        self.iam = rb.Iam(account)
        self.account = account
        self.covered: set = set()

    @property
    def path(self) -> Path:
        return self.v2.path

    def unit(self, name: str) -> rb.Scope:
        return self.v2.unit(name)

    def put(self, unit: str, rel: str, data: Any, **coverage: Any) -> None:
        """Write a module file and (once per module and unit) its ``_coverage.json`` (``coverage`` kwargs)."""
        self.unit(unit).write(rel, data)
        module = _module_of(rel)
        if (module, unit) not in self.covered:
            self.v2.coverage(module, unit, **coverage)
            self.covered.add((module, unit))

    def coverage(self, module: str, unit: str, **coverage: Any) -> Dict[str, Any]:
        self.covered.add((module, unit))
        return self.v2.coverage(module, unit, **coverage)

    def analyze(self, **options: Any) -> SimpleNamespace:
        g = self.unit("global")
        self.iam.write(g, layout="gaad")
        if ("iam", "global") not in self.covered:
            self.coverage("iam", "global")
        self.v2.finalize()
        opts = engine("model").AnalysisOptions(**options)
        run = lambda: engine().analyze_run(str(self.path), regions=list(self.v2.regions), options=opts)  # noqa: E731
        return _with_epoch(lambda: _result(run(), self.path))


_DIR_TO_MODULE = {"lambda": "lambda", "sns": "sns", "sqs": "sqs", "ecs": "ecs", "glue": "glue",
                  "codebuild": "codebuild", "sagemaker": "sagemaker", "cloudformation": "cloudformation",
                  "cognito": "cognito", "iam": "iam", "s3": "s3", "kms": "kms", "dynamodb": "dynamodb"}


def _module_of(rel: str) -> str:
    return _DIR_TO_MODULE.get(rel.split("/", 1)[0], rel.split("/", 1)[0])


# ── graph queries ───────────────────────────────────────────────────────────

def nodes(graph: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph["nodes"]}


def edges(graph: Mapping[str, Any], edge_type: Optional[str] = None, source: Optional[str] = None,
          target: Optional[str] = None) -> List[Dict[str, Any]]:
    return [e for e in graph["edges"] if (edge_type is None or e["type"] == edge_type)
            and (source is None or e["source"] == source) and (target is None or e["target"] == target)]


def edge_types(graph: Mapping[str, Any], source: str, target: str) -> set:
    return {e["type"] for e in edges(graph, source=source, target=target)}


def findings(graph: Mapping[str, Any], fid: Optional[str] = None, node_id: Optional[str] = None) -> List[Dict]:
    return [f for f in graph["findings"] if (fid is None or f["id"] == fid)
            and (node_id is None or f["node_id"] == node_id)]


def finding_ids(graph: Mapping[str, Any]) -> set:
    return {f["id"] for f in graph["findings"]}


def path(graph: Mapping[str, Any], source: str, target: str) -> Any:
    """Directed shortest path over traversable edges (graph-json.md §11 reference)."""
    return S.path(graph, source, target)


def problems(graph: Mapping[str, Any]) -> List[str]:
    """Schema errors + ``validate_graph(strict_order=True)`` codes (must be empty)."""
    out = list(S.graph_problems(graph))
    validate = targets.engine_module("graph").validate_graph
    out += [str(getattr(p, "code", p)) for p in validate(graph, strict_order=True)]
    return out


def status_of(graph: Mapping[str, Any], name: str) -> Optional[str]:
    for s in graph["analyzer_status"]:
        if s["name"] == name:
            return s["status"]
    return None


def legacy_edges(out: SimpleNamespace, name: str) -> List[Dict[str, Any]]:
    doc = load(out.dir / f"{name}_relationships.json")
    return list(doc.get("edges", []))


def only(items: Iterable[Any]) -> Any:
    items = list(items)
    assert len(items) == 1, items
    return items[0]


def without_analyzer_modules(monkeypatch: Any, *suffixes: str) -> None:
    """Run the pipeline without the analyzer modules whose dotted name ends with one of ``suffixes``.

    Isolates an E-compute analyzer from another stream's module that emits overlapping edges (for example the
    d13c215 Cognito block of ``analyzers/edge_services.py`` while it still runs through the legacy adapter).
    """
    pipeline = targets.engine_module("pipeline")
    original = pipeline.collect_specs

    def collect(modules: Sequence[str] = pipeline.ANALYZER_MODULES) -> Any:
        return original(tuple(m for m in modules if not m.endswith(tuple(suffixes))))

    monkeypatch.setattr(pipeline, "collect_specs", collect)
