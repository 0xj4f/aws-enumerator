"""Synthetic IAM worlds for the E-rules tests (rules, subsumption, severity, closure, exports, benchmarks).

A :class:`World` is a single-region report in the d13c215 layout (``<root>/<account>/<region>/``) built with
``tests.support.report_builder``; :meth:`World.analyze` runs the product's ``analyze_report`` (the v2 pipeline)
and returns an :class:`Analysed` view of ``graph.json``. Only placeholder accounts and ``demo-*`` names are used.
"""

from __future__ import annotations

import contextlib
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from tests.support import ref_paths
from tests.support import report_builder as rb

ACCT = rb.ACCT_MAIN
REGION = "eu-west-2"
ADMIN_POLICY = "AdministratorAccess"
ADMIN_NODE = f"aws-enumerator:account-admin/{ACCT}"


def arn(kind: str, name: str, account: str = ACCT) -> str:
    return f"arn:aws:iam::{account}:{kind}/{name}"


def trusts_service(*services: str) -> Dict[str, Any]:
    return rb.trust({"Service": list(services) if len(services) > 1 else services[0]})


def trusts_account(account: str = ACCT) -> Dict[str, Any]:
    return rb.trust({"AWS": f"arn:aws:iam::{account}:root"})


def policy(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return rb.doc(*statements)


allow = rb.allow
deny = rb.deny


@dataclass
class Analysed:
    """``graph.json`` of one analysis with small query helpers."""

    dir: Path
    result: Any
    graph: Dict[str, Any]

    def findings(self, fid: Optional[str] = None, node: Optional[str] = None) -> List[Dict[str, Any]]:
        return [f for f in self.graph["findings"]
                if (fid is None or f["id"] == fid) and (node is None or f["node_id"] == node)]

    def ids_at(self, node: str) -> List[str]:
        return sorted({f["id"] for f in self.findings(node=node)})

    def finding(self, fid: str, node: str) -> Dict[str, Any]:
        found = self.findings(fid, node)
        assert len(found) == 1, f"{fid} at {node}: {len(found)} findings ({self.ids_at(node)})"
        return found[0]

    def edges(self, edge_type: Optional[str] = None, source: Optional[str] = None,
              target: Optional[str] = None) -> List[Dict[str, Any]]:
        return [e for e in self.graph["edges"]
                if (edge_type is None or e["type"] == edge_type) and (source is None or e["source"] == source)
                and (target is None or e["target"] == target)]

    def node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return next((n for n in self.graph["nodes"] if n["id"] == node_id), None)

    def path(self, source: str, target: str = ADMIN_NODE, **opts: Any) -> Any:
        """The reference directed shortest path over traversable edges (graph-json.md §11), or ``None``."""
        return ref_paths.shortest_path(self.graph, source, target, **opts)

    def path_types(self, source: str, target: str = ADMIN_NODE) -> Optional[List[str]]:
        p = self.path(source, target)
        return list(p.edge_types) if p is not None else None

    def summary(self) -> Dict[str, Any]:
        with open(self.dir / "summary.json", encoding="utf-8") as fh:
            return json.load(fh)


class World:
    """One synthetic single-region report under construction."""

    def __init__(self, root: Path, *, account: str = ACCT, region: str = REGION):
        self.root = Path(root)
        self.scope = rb.Scope(self.root, account, region)
        self.iam = rb.Iam(account)
        self.account, self.region = account, region
        self.files: Dict[str, Any] = {}

    # entities (thin wrappers over report_builder.Iam) --------------------------
    def user(self, name: str, *statements: Dict[str, Any], **kw: Any) -> str:
        if statements:
            kw.setdefault("inline", {"p": policy(*statements)})
        return self.iam.user(name, **kw)

    def role(self, name: str, *statements: Dict[str, Any], trust: Optional[Dict[str, Any]] = None, **kw: Any) -> str:
        if statements:
            kw.setdefault("inline", {"p": policy(*statements)})
        return self.iam.role(name, trust or trusts_service("ec2.amazonaws.com"), **kw)

    def group(self, name: str, *statements: Dict[str, Any], **kw: Any) -> str:
        if statements:
            kw.setdefault("inline", {"p": policy(*statements)})
        return self.iam.group(name, **kw)

    def admin_role(self, name: str, trust: Dict[str, Any]) -> str:
        return self.iam.role(name, trust, attached=[ADMIN_POLICY])

    def admin_user(self, name: str, **kw: Any) -> str:
        return self.iam.user(name, attached=[ADMIN_POLICY], **kw)

    def customer_policy(self, name: str, *statements: Dict[str, Any]) -> Dict[str, str]:
        return self.iam.managed(name, policy(*statements), customer=True)

    def write(self, rel: str, data: Any) -> None:
        """A regional collector file (``ec2/instances.json``, ``lambda/functions.json`` …)."""
        self.files[rel] = data

    # analysis -----------------------------------------------------------------
    def build(self) -> Path:
        rb.write_empty_regional(self.scope)
        for rel, data in sorted(self.files.items()):
            self.scope.write(rel, data)
        self.iam.write(self.scope)
        rb.write_manifest(self.scope.path, account=self.account, mode="single_region", region=self.region)
        return self.scope.path

    def analyze(self) -> Analysed:
        report_dir = self.build()
        from aws_enumerator.engine import analyze_report

        with contextlib.redirect_stdout(io.StringIO()):
            result = analyze_report(str(report_dir))
        out = Path(result.analysis_dir or report_dir / "analysis")
        with open(out / "graph.json", encoding="utf-8") as fh:
            graph = json.load(fh)
        return Analysed(out, result, graph)


def graph_problems(graph: Mapping[str, Any]) -> List[str]:
    """Schema errors plus ``validate_graph(strict_order=True)`` problem codes (graph-json.md §12)."""
    import jsonschema

    schema = json.loads((ref_paths.engine_schema_dir() / "graph-1.0.schema.json").read_text(encoding="utf-8"))
    problems = [f"schema: {e.message[:160]}" for e in jsonschema.Draft202012Validator(schema).iter_errors(graph)]
    validate = ref_paths.engine_module("graph").validate_graph
    problems += [str(getattr(p, "code", p)) for p in validate(graph, strict_order=True)]
    return problems


def admin_share(graph: Mapping[str, Any], admin_ids: Iterable[str]) -> float:
    """Share of open findings anchored at (or inherited by) administrator-equivalent principals."""
    admins = set(admin_ids)
    findings = [f for f in graph["findings"] if f.get("status") == "open"]
    if not findings:
        return 0.0
    on_admins = [f for f in findings if f["node_id"] in admins or admins & set(f.get("affected_members") or ())]
    return len(on_admins) / len(findings)


def lambda_function(name: str, role: Optional[str], *, region: str = REGION) -> Dict[str, Any]:
    return rb.lambda_function(name, account=ACCT, region=region, role=role)


def ids_of(findings: Sequence[Mapping[str, Any]]) -> List[str]:
    return sorted({f["id"] for f in findings})
