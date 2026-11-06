"""Test kit for E-net's domain tests (S3, EC2, edge services, posture analyzers and loaders).

Production code is reached through :mod:`tests.support.targets` only. Trees are built with
``tests.support.report_builder`` (placeholder accounts, ``demo-*`` names, hexadecimal resource ids):

* :class:`Tree` — an old single-region report ``<root>/<acct>/<region>/`` (legacy layout, ``analyze_report``);
* :class:`Run` — a v2 run root (``report_builder.V2Run``: manifest 2.0, ``_coverage.json``), ``analyze_run``.

Every analysis result keeps ``graph`` (the parsed ``graph.json``) and ``dir``; :func:`problems` is the schema +
``validate_graph(strict_order=True)`` check each stream asserts on its emitted graph (DECISIONS.md D-36).
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Sequence

from tests.support import report_builder as rb
from tests.support import targets

ACCT = rb.ACCT_MAIN            # 123456789012
FOREIGN = rb.ACCT_EXT          # 999999999999
REGION = "eu-west-2"
OTHER = "eu-west-1"
ANON = "aws-enumerator:anonymous"
EC2_TRUST = rb.trust({"Service": "ec2.amazonaws.com"})
VPC, IGW = "vpc-0a1b2c3d4e5f6aaaa", "igw-0a1b2c3d4e5f6c01"
PUB, PRIV = "subnet-0a1b2c3d4e5f6b001", "subnet-0a1b2c3d4e5f6b002"


def engine(name: str = "") -> Any:
    return targets.engine_module(name)


def load(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def problems(graph: Dict[str, Any]) -> List[str]:
    """Schema problems plus ``validate_graph(strict_order=True)`` problems of a graph document."""
    return engine("writers.graph_json").problems(graph)


def nodes_by_id(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph["nodes"]}


def edges(graph: Dict[str, Any], edge_type: Optional[str] = None, source: Optional[str] = None,
          target: Optional[str] = None) -> List[Dict[str, Any]]:
    return [e for e in graph["edges"] if (edge_type is None or e["type"] == edge_type)
            and (source is None or e["source"] == source) and (target is None or e["target"] == target)]


def types_between(graph: Dict[str, Any], source: str, target: str) -> List[str]:
    return sorted(e["type"] for e in edges(graph, source=source, target=target))


def findings(graph: Dict[str, Any], fid: Optional[str] = None, node_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return [f for f in graph["findings"] if (fid is None or f["id"] == fid)
            and (node_id is None or f["node_id"] == node_id)]


def iam_arn(kind: str, name: str, account: str = ACCT, path: str = "/", partition: str = "aws") -> str:
    return f"arn:{partition}:iam::{account}:{kind}{path}{name}"


def bucket(name: str, partition: str = "aws") -> str:
    return f"arn:{partition}:s3:::{name}"


def instance(iid: str, region: str = REGION, account: str = ACCT) -> str:
    return f"arn:aws:ec2:{region}:{account}:instance/{iid}"


def sg_arn(gid: str, region: str = REGION, account: str = ACCT) -> str:
    return f"arn:aws:ec2:{region}:{account}:security-group/{gid}"


def statuses(result: Any) -> Dict[str, str]:
    return {s.name: s.status for s in result.analyzer_status}


def _result(result: Any, fallback_dir: Path) -> SimpleNamespace:
    graph = load(Path(result.graph_path)) if result.graph_path else None
    out = Path(result.analysis_dir or fallback_dir)
    return SimpleNamespace(result=result, graph=graph, dir=out,
                           legacy=lambda name: load(out / name) if (out / name).exists() else None)


class Tree:
    """A legacy single-region report ``<root>/<acct>/<region>/`` (d13c215 collector layout)."""

    def __init__(self, root: Path, region: str = REGION, account: str = ACCT):
        self.scope = rb.Scope(Path(root), account, region)
        self.iam = rb.Iam(account)
        self.account = account

    @property
    def path(self) -> Path:
        return self.scope.path

    def write(self, *, skip: Iterable[str] = ()) -> Path:
        self.iam.write(self.scope)
        rb.write_empty_regional(self.scope, skip=set(skip))
        rb.write_manifest(self.scope.path, account=self.account, mode="single_region", region=self.scope.region)
        return self.scope.path

    def analyze(self, **options: Any) -> SimpleNamespace:
        opts = engine("model").AnalysisOptions(**options) if options else None
        with contextlib.redirect_stdout(io.StringIO()):
            result = engine().analyze_report(str(self.path), opts)
        return _result(result, self.path / "analysis")


class PartitionIam(rb.Iam):
    """``report_builder.Iam`` whose user, role and group ARNs use ``partition`` (GovCloud / China runs)."""

    def __init__(self, account: str, partition: str = "aws"):
        super().__init__(account)
        self.partition = partition

    def arn(self, kind: str, name: str, path: str = "/") -> str:
        return f"arn:{self.partition}:iam::{self.account}:{kind}{path}{name}"


class Run:
    """A v2 run root ``<root>/<acct>/<run_id>/`` with ``_coverage.json`` per module (report_builder.V2Run)."""

    def __init__(self, root: Path, regions: Sequence[str] = (REGION,), account: str = ACCT,
                 partition: str = "aws"):
        self.v2 = rb.V2Run(Path(root), account=account, regions=regions, partition=partition)
        self.iam: rb.Iam = PartitionIam(account, partition)
        self.account = account
        self.partition = partition
        self._covered: set = set()

    @property
    def path(self) -> Path:
        return self.v2.path

    def unit(self, name: str) -> rb.Scope:
        return self.v2.unit(name)

    def write_json(self, unit: str, rel: str, data: Any, *, module: Optional[str] = None,
                   calls: Optional[Sequence[Any]] = None) -> None:
        """Write ``<unit>/<rel>``; the first file of a module also gets its ``_coverage.json``."""
        self.unit(unit).write(rel, data)
        mod = module or rel.split("/", 1)[0]
        if (unit, mod) not in self._covered or calls is not None:
            self._covered.add((unit, mod))
            self.v2.coverage(mod, unit, calls=calls)

    def finish(self) -> Path:
        g = self.unit("global")
        self.iam.write(g, layout="gaad")
        if ("global", "iam") not in self._covered:
            self.v2.coverage("iam", "global")
        self.v2.finalize()
        return self.path

    def analyze(self, **options: Any) -> SimpleNamespace:
        opts = engine("model").AnalysisOptions(**options) if options else None
        with contextlib.redirect_stdout(io.StringIO()):
            result = engine().analyze_run(str(self.path), regions=list(self.v2.regions), options=opts)
        return _result(result, self.path / "analysis")


# ── S3 records ────────────────────────────────────────────────────────────────

SUBS = ("policy", "policy_status", "acl", "public_access_block", "encryption", "notifications",
        "ownership_controls", "versioning", "tagging", "logging", "cors", "website", "replication")
_SUBDIR = {"policy": "policies", "policy_status": "policy_status", "acl": "acls",
           "public_access_block": "public_access_block", "encryption": "encryption",
           "notifications": "notifications", "ownership_controls": "ownership_controls", "website": "website",
           "tagging": "tagging"}


def v2_bucket(run: Run, name: str, *, region: str = REGION, statuses_: Optional[Dict[str, str]] = None,
              policy_is_public: Optional[bool] = None, **content: Any) -> Dict[str, Any]:
    """A Wave 1 (C-A) ``buckets.json`` record; ``content`` (``policy=…``, ``acl=…``) writes the per-bucket files."""
    subs = {s: "absent" for s in SUBS}
    for sub, doc in content.items():
        subs[sub] = "present"
        run.unit("global").write(f"s3/{_SUBDIR[sub]}/{name}.json", doc)
    subs.update(statuses_ or {})
    rec = {"Name": name, "Arn": f"arn:{run.partition}:s3:::{name}", "CreationDate": rb.TS_Z, "Region": region,
           "SubResources": subs, "PolicyStatus": subs["policy"],
           "PolicyIsPublic": policy_is_public if subs["policy"] == "present" else
           (False if subs["policy"] == "absent" else None)}
    return rec


def account_pab(configured: Optional[bool] = True, **flags: Optional[bool]) -> Dict[str, Any]:
    names = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if configured is None:
        return {"Configured": None, **{k: None for k in names}}
    if configured is False:
        return {"Configured": False, **{k: False for k in names}}
    return {"Configured": True, **{k: bool(flags.get(k, False)) for k in names}}


def public_policy(name: str, actions: Any = "s3:GetObject", cond: Optional[Dict[str, Any]] = None,
                  principal: Any = "*", partition: str = "aws") -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": actions,
                            "Resource": [f"arn:{partition}:s3:::{name}", f"arn:{partition}:s3:::{name}/*"]}
    if cond:
        stmt["Condition"] = cond
    return {"Version": "2012-10-17", "Statement": [stmt]}


def acl_grant(uri_group: str, permission: str) -> Dict[str, Any]:
    return {"Grantee": {"Type": "Group", "URI": f"http://acs.amazonaws.com/groups/global/{uri_group}"},
            "Permission": permission}


def acl(*grants: Dict[str, Any]) -> Dict[str, Any]:
    owner = {"ID": "a" * 64}
    return {"Owner": owner, "Grants": [{"Grantee": {"ID": "a" * 64, "Type": "CanonicalUser"},
                                         "Permission": "FULL_CONTROL"}, *grants]}


__all__ = [
    "ACCT", "ANON", "EC2_TRUST", "FOREIGN", "IGW", "OTHER", "PRIV", "PUB", "PartitionIam", "REGION", "Run", "Tree",
    "VPC", "account_pab",
    "acl", "acl_grant", "bucket", "edges", "engine", "findings", "iam_arn", "instance", "load", "nodes_by_id",
    "problems", "public_policy", "rb", "sg_arn", "statuses", "types_between", "v2_bucket",
]
