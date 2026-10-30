"""Test kit for E-data's domain tests (KMS, Secrets Manager / SSM, ECR / DynamoDB / RDS / API Gateway).

Production code is reached through :mod:`tests.support.targets` only. Trees are built with
``tests.support.report_builder`` (placeholder accounts, ``demo-*`` names, hexadecimal resource ids):

* :class:`Tree` — an old single-region report ``<root>/<acct>/<region>/`` (d13c215 layout, ``analyze_report``);
* :class:`Run` — a v2 run root (``report_builder.V2Run``: manifest 2.0, ``_coverage.json``, ``analyze_run``),
  with record builders in the Wave 1 (C-B) collector shapes (``PolicyStatus``, ``CollectionErrors``, ``null`` for
  unknown values).

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
LAMBDA_TRUST = rb.trust({"Service": "lambda.amazonaws.com"})
KEY_ID = "7b8c9d0e-aaaa-4bbb-8ccc-1f2a3b4c5d6e"
KEY_ID_2 = "8c9d0e1f-bbbb-4ccc-8ddd-2a3b4c5d6e7f"
AWS_KEY_ID = "0a1b2c3d-cccc-4ddd-8eee-3b4c5d6e7f80"


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


def gaps(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {g["code"]: g for g in graph["evaluation_gaps"]}


def statuses(result: Any) -> Dict[str, str]:
    return {s.name: s.status for s in result.analyzer_status}


def iam_arn(kind: str, name: str, account: str = ACCT, path: str = "/", partition: str = "aws") -> str:
    return f"arn:{partition}:iam::{account}:{kind}{path}{name}"


def key_arn(key_id: str = KEY_ID, region: str = REGION, account: str = ACCT, partition: str = "aws") -> str:
    return f"arn:{partition}:kms:{region}:{account}:key/{key_id}"


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
        self.region = region

    @property
    def path(self) -> Path:
        return self.scope.path

    def write_json(self, rel: str, data: Any) -> None:
        self.scope.write(rel, data)

    def write(self, *, skip: Iterable[str] = ()) -> Path:
        self.iam.write(self.scope)
        rb.write_empty_regional(self.scope, skip=set(skip))
        rb.write_manifest(self.scope.path, account=self.account, mode="single_region", region=self.region)
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
                   calls: Optional[Sequence[Any]] = None, status: Optional[str] = None) -> None:
        """Write ``<unit>/<rel>``; the first file of a module also gets its ``_coverage.json``."""
        self.unit(unit).write(rel, data)
        mod = module or rel.split("/", 1)[0]
        if (unit, mod) not in self._covered or calls is not None or status is not None:
            self._covered.add((unit, mod))
            self.v2.coverage(mod, unit, calls=calls, status=status)

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


# ── v2 record builders (C-B collector shapes, coverage-schema.md §1) ─────────

def mark(record: Dict[str, Any], *errors: Dict[str, Any], policy_status: Optional[str] = None,
         unknown: Iterable[str] = ()) -> Dict[str, Any]:
    return rb.mark_item(record, *errors, policy_status=policy_status, unknown=unknown)


def denied(api: str) -> Dict[str, Any]:
    return rb.collection_error(api, "denied")


def kms_grant(grantee: str, operations: Sequence[str], grant_id: str = "a1b2c3d4e5f60718", *,
              constraints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"GrantId": grant_id, "Name": "", "GranteePrincipal": grantee, "RetiringPrincipal": None,
            "Operations": list(operations), "Constraints": constraints, "IssuingAccount": f"arn:aws:iam::{ACCT}:root"}


def v2_key(key_id: str = KEY_ID, *, region: str = REGION, account: str = ACCT, manager: str = "CUSTOMER",
           aliases: Optional[Sequence[str]] = (), grants: Optional[Sequence[Dict[str, Any]]] = (),
           policy_status: str = "present", partition: str = "aws", multi_region: bool = False) -> Dict[str, Any]:
    rec = {"KeyId": key_id, "Arn": key_arn(key_id, region, account, partition), "KeyManager": manager,
           "KeyState": "Enabled", "Origin": "AWS_KMS", "Description": "demo key", "Enabled": True,
           "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": multi_region,
           "MultiRegionConfiguration": None,
           "Aliases": list(aliases) if aliases is not None else None,
           "Grants": [dict(g) for g in grants] if grants is not None else None,
           "PolicyStatus": policy_status}
    if aliases is None:
        rec.setdefault("CollectionErrors", []).append(denied("kms:ListAliases"))
    if grants is None:
        rec.setdefault("CollectionErrors", []).append(denied("kms:ListGrants"))
    return rec


def key_policy_file(key: Dict[str, Any], policy: Any) -> Dict[str, Any]:
    return {"KeyId": key["KeyId"], "Arn": key["Arn"], "Policy": policy}


def root_delegation(account: str = ACCT, partition: str = "aws") -> Dict[str, Any]:
    """The console's default "Enable IAM User Permissions" statement (delegation to the account)."""
    return rb.grant({"AWS": f"arn:{partition}:iam::{account}:root"}, "kms:*", sid="EnableIAMUserPermissions")


def v2_secret(name: str, *, region: str = REGION, account: str = ACCT, policy_status: str = "absent",
              kms_key: Optional[str] = None, deleted: bool = False, partition: str = "aws") -> Dict[str, Any]:
    rec = rb.secret(name, account=account, region=region, kms_key=kms_key)
    rec.pop("Description", None)
    rec.pop("Tags", None)
    rec["ARN"] = rec["ARN"].replace("arn:aws:", f"arn:{partition}:", 1)
    rec.update({"OwningService": None, "PrimaryRegion": None, "DeletedDate": rb.TS_Z if deleted else None,
                "PolicyStatus": "skipped" if deleted else policy_status})
    return rec


def secret_policy_file(secret: Dict[str, Any], policy: Any) -> Dict[str, Any]:
    return {"SecretArn": secret["ARN"], "SecretName": secret["Name"], "ResourcePolicy": policy}


def v2_param(name: str, *, region: str = REGION, account: str = ACCT, ptype: str = "String",
             key_id: Optional[str] = None, tier: str = "Standard", policy_status: str = "absent",
             partition: str = "aws") -> Dict[str, Any]:
    return {"Name": name, "ARN": f"arn:{partition}:ssm:{region}:{account}:parameter/{name.lstrip('/')}",
            "Type": ptype, "KeyId": key_id, "Tier": tier, "DataType": "text", "Version": 1,
            "LastModifiedDate": rb.TS_Z, "PolicyStatus": policy_status}


def param_policy_file(param: Dict[str, Any], *policies: Any) -> Dict[str, Any]:
    return {"ParameterArn": param["ARN"], "ParameterName": param["Name"],
            "Policies": [{"PolicyId": f"p{i}", "PolicyHash": f"h{i}", "Policy": p} for i, p in enumerate(policies)]}


def v2_document(name: str, *, region: str = REGION, account: str = ACCT, public: Optional[bool] = False,
                shared: Optional[Sequence[str]] = ()) -> Dict[str, Any]:
    rec = {"Name": name, "Arn": f"arn:aws:ssm:{region}:{account}:document/{name}", "DocumentType": "Command",
           "DocumentFormat": "JSON", "DocumentVersion": "1", "PlatformTypes": ["Linux"], "Public": public,
           "SharedAccounts": list(shared) if shared is not None else None}
    if public is None or shared is None:
        rec["CollectionErrors"] = [denied("ssm:DescribeDocumentPermission")]
    return rec


def v2_policy_resource(kind: str, name: str, *, region: str = REGION, account: str = ACCT, policy: Any = None,
                       policy_status: Optional[str] = None) -> Dict[str, Any]:
    arn = (f"arn:aws:ecr:{region}:{account}:repository/{name}" if kind == "ecr"
           else f"arn:aws:dynamodb:{region}:{account}:table/{name}")
    status = policy_status or ("present" if policy is not None else "absent")
    rec: Dict[str, Any] = {"Type": kind, "Arn": arn, "Name": name, "Policy": policy, "PolicyStatus": status}
    if kind == "ecr":
        rec.update({"RegistryId": account, "ImageTagMutability": "MUTABLE", "ScanOnPush": False,
                    "EncryptionType": "AES256", "KmsKey": None})
    if status in ("denied", "error"):
        rec["CollectionErrors"] = [rb.collection_error(
            "ecr:GetRepositoryPolicy" if kind == "ecr" else "dynamodb:GetResourcePolicy", status)]
    return rec


def rds_snapshot(name: str, *, region: str = REGION, account: str = ACCT, kind: str = "snapshot",
                 public: Optional[bool] = False, shared: Optional[Sequence[str]] = (), encrypted: bool = False,
                 kms_key: Optional[str] = None) -> Dict[str, Any]:
    sep = "snapshot" if kind == "snapshot" else "cluster-snapshot"
    rec: Dict[str, Any] = {"Type": "rds", "Kind": kind, "Arn": f"arn:aws:rds:{region}:{account}:{sep}:{name}",
                           "Name": name, "PublicSnapshot": public,
                           "SharedAccounts": list(shared) if shared is not None else None,
                           "Encrypted": encrypted, "KmsKeyId": kms_key}
    rec["DBInstanceIdentifier" if kind == "snapshot" else "DBClusterIdentifier"] = "demo-db"
    if public is None or shared is None:
        rec["CollectionErrors"] = [rb.collection_error(
            "rds:DescribeDBSnapshotAttributes" if kind == "snapshot" else "rds:DescribeDBClusterSnapshotAttributes")]
    return rec


def rds_database(name: str, *, region: str = REGION, account: str = ACCT, kind: str = "instance",
                 public: Optional[bool] = False, encrypted: Optional[bool] = True, kms_key: Optional[str] = None,
                 cluster: Optional[str] = None, members: Sequence[str] = ()) -> Dict[str, Any]:
    sep = "db" if kind == "instance" else "cluster"
    rec: Dict[str, Any] = {"Type": "rds", "Kind": kind, "Arn": f"arn:aws:rds:{region}:{account}:{sep}:{name}",
                           "Name": name, "Public": public, "Encrypted": encrypted, "KmsKeyId": kms_key,
                           "IAMAuth": False, "Engine": "aurora-postgresql" if kind == "cluster" else "postgres"}
    if kind == "instance":
        rec["DBClusterIdentifier"] = cluster
    else:
        rec["Members"] = list(members)
    return rec


def v2_api(api_id: str, *, name: str = "demo-api", region: str = REGION, protocol: str = "REST",
           integrations: Optional[Sequence[Dict[str, Any]]] = (),
           endpoint_types: Optional[Sequence[str]] = ("REGIONAL",), resource_policy: Any = None,
           partition: str = "aws") -> Dict[str, Any]:
    """A C-B ``apigateway/resources.json`` record; ``LambdaTargets`` / ``UnauthenticatedLambdaRoutes`` are derived
    from ``integrations`` the way the collector derives them (``None`` integrations = unknown)."""
    kind = "restapis" if protocol == "REST" else "apis"
    rec: Dict[str, Any] = {"Type": "apigw", "Arn": f"arn:{partition}:apigateway:{region}::/{kind}/{api_id}",
                           "Name": name, "ApiId": api_id, "Protocol": protocol,
                           "EndpointTypes": list(endpoint_types) if endpoint_types is not None else None,
                           "ResourcePolicy": resource_policy, "DisableExecuteApiEndpoint": False,
                           "Authorizers": [], "HasAuthorizer": False, "Stages": [{"StageName": "prod",
                                                                                 "VariableNames": []}]}
    if integrations is None:
        rec.update({"Integrations": None, "LambdaTargets": None, "UnauthenticatedLambdaRoutes": None,
                    "CollectionErrors": [denied("apigateway:GetResources")]})
        return rec
    routed = [i for i in integrations if (i.get("Method") or i.get("RouteKey")) and not i.get("Unresolved")
              and i.get("LambdaArn")]
    rec["Integrations"] = [dict(i) for i in integrations]
    rec["LambdaTargets"] = sorted({i["LambdaArn"] for i in routed})
    rec["UnauthenticatedLambdaRoutes"] = [
        {k: i.get(k) for k in ("Method", "RouteKey", "Path", "LambdaArn", "Qualifier", "Stage") if k in i}
        for i in routed if i.get("EffectiveAuthorizationType") == "NONE"]
    return rec


def integration(method: str, path: str, fn_arn: Optional[str], *, auth: str = "NONE",
                qualifier: Optional[str] = None, stage: Optional[str] = None,
                unresolved: bool = False) -> Dict[str, Any]:
    return {"Method": method, "Path": path, "AuthorizationType": auth, "EffectiveAuthorizationType": auth,
            "AuthorizerId": None, "ApiKeyRequired": False, "IntegrationType": "AWS_PROXY",
            "LambdaArn": None if unresolved else fn_arn, "Qualifier": qualifier, "Stage": stage,
            "Unresolved": unresolved}


__all__ = [
    "ACCT", "ANON", "AWS_KEY_ID", "EC2_TRUST", "FOREIGN", "KEY_ID", "KEY_ID_2", "LAMBDA_TRUST", "OTHER",
    "PartitionIam", "REGION", "Run", "Tree", "denied", "edges", "engine", "findings", "gaps", "iam_arn",
    "integration", "key_arn", "key_policy_file", "kms_grant", "load", "mark", "nodes_by_id", "param_policy_file",
    "problems", "rb", "rds_database", "rds_snapshot", "root_delegation", "secret_policy_file", "statuses",
    "types_between", "v2_api", "v2_document", "v2_key", "v2_param", "v2_policy_resource", "v2_secret",
]
