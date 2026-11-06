"""ECR, RDS, API Gateway and DynamoDB loader (F-044, F-056, F-082, F-099, F-116).

Reads only the explicit units of the analysis context, never sibling directories (F-010, F-025, F-063), in both
layouts:

* **v2**: items carry ``PolicyStatus`` / ``CollectionErrors`` and ``null`` for unknown values. RDS records
  ``SharedAccounts`` on snapshots and cluster snapshots (``Kind`` ``snapshot`` / ``cluster_snapshot``) and
  ``cluster`` items; API Gateway records per-method / per-route authorisation (``Integrations``,
  ``UnauthenticatedLambdaRoutes``), unqualified ``LambdaTargets``, ``EndpointTypes`` and the parsed
  ``ResourcePolicy``; ECR adds ``registry_policy.json`` and ``registry.json``.
* **legacy** (d13c215): ``LambdaTargets`` may keep an alias/version qualifier or a ``${stageVariables.x}``
  placeholder, only ``HasAuthorizer`` says anything about authorisation, and failures were swallowed.

The collected Lambda function ARNs (``lambda/functions.json``) are read too, only to tell an API Gateway target
that was collected from one that was not (a placeholder node).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.fs import read_list, read_map, stub_status
from aws_enumerator.engine.io.loaders import LoadResult, read_scoped
from aws_enumerator.engine.io.loaders.kms import (
    ItemErrors, is_v2, iter_units, merge_results, policy_status, record_account, str_tuple, unit_region,
    usable_policy,
)

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES = {
    "ecr": "ecr/resources.json",
    "rds": "rds/resources.json",
    "apigw": "apigateway/resources.json",
    "dynamodb": "dynamodb/resources.json",
}
#: Read only to know which Lambda functions were collected (errors are the Lambda loader's to report).
LAMBDA_FUNCTIONS = "lambda/functions.json"
REGISTRY_FILES = {"registry_policy": "ecr/registry_policy.json", "registry": "ecr/registry.json"}

#: A Lambda function ARN inside an integration target (any partition), with an optional qualifier (F-099).
LAMBDA_ARN = re.compile(r"arn:(aws[\w-]*):lambda:([a-z0-9-]+):(\d{12}):function:([^:/]+)(?::([^/]+))?")
STAGE_VARIABLE = "${stageVariables."


@dataclass(frozen=True)
class PolicyResource:
    """An ECR repository or DynamoDB table and its resource-based policy."""

    kind: str                      # "ecr" | "dynamodb"
    arn: str
    name: str
    region: str
    account: str
    policy: Optional[Mapping[str, Any]]
    policy_status: str
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False
    props: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RdsResource:
    """An RDS DB instance, cluster, snapshot or cluster snapshot (F-056)."""

    kind: str                      # instance | cluster | snapshot | cluster_snapshot
    arn: str
    name: str
    region: str
    account: str
    public: Optional[bool]
    encrypted: Optional[bool]
    kms_key_id: Optional[str]
    public_snapshot: Optional[bool]
    shared_accounts: Optional[Tuple[str, ...]]
    engine: Optional[str]
    members: Optional[Tuple[str, ...]]
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False

    @property
    def is_snapshot(self) -> bool:
        return self.kind in ("snapshot", "cluster_snapshot")


@dataclass(frozen=True)
class ApiRoute:
    """One method (REST) or route (HTTP/WebSocket) integration with a Lambda function (or unresolved)."""

    key: Optional[str]             # HTTP method or route key
    path: Optional[str]
    effective_auth: Optional[str]  # what a caller must pass (NONE = unauthenticated)
    lambda_arn: Optional[str]      # unqualified function ARN
    qualifier: Optional[str]
    stage: Optional[str]
    unresolved: bool = False


@dataclass(frozen=True)
class Api:
    """One API Gateway API (REST, HTTP or WebSocket)."""

    arn: str
    api_id: str
    name: str
    region: str
    account: str
    protocol: str
    endpoint_types: Optional[Tuple[str, ...]]
    resource_policy: Optional[Mapping[str, Any]]
    execute_api_disabled: Optional[bool]
    has_authorizer: Optional[bool]
    routes: Optional[Tuple[ApiRoute, ...]]          # None = unknown (legacy layout or collection failure)
    targets: Tuple[ApiRoute, ...] = ()              # every Lambda target (resolved or not)
    unauthenticated: Optional[Tuple[ApiRoute, ...]] = None
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False

    @property
    def private(self) -> bool:
        return bool(self.endpoint_types) and set(self.endpoint_types) == {"PRIVATE"}


@dataclass(frozen=True)
class EcrRegistry:
    """One Region's ECR registry: its permission policy and replication rules (F-116)."""

    region: str
    registry_id: str
    policy: Optional[Mapping[str, Any]]
    policy_status: str
    replication_accounts: Optional[Tuple[str, ...]]     # destination registries in other accounts; None = unknown
    errors: ItemErrors = field(default_factory=ItemErrors)


@dataclass
class DataStoresInventory:
    ecr: Tuple[PolicyResource, ...] = ()
    dynamodb: Tuple[PolicyResource, ...] = ()
    rds: Tuple[RdsResource, ...] = ()
    apis: Tuple[Api, ...] = ()
    registries: Tuple[EcrRegistry, ...] = ()
    lambda_functions: FrozenSet[str] = frozenset()


# ── parsing ──────────────────────────────────────────────────────────────────

def lambda_target(value: Any) -> Optional[ApiRoute]:
    """An integration target as ``(unqualified ARN, qualifier)``; stage-variable targets are unresolved."""
    if not isinstance(value, str) or not value:
        return None
    if STAGE_VARIABLE in value:
        return ApiRoute(None, None, None, None, None, None, unresolved=True)
    m = LAMBDA_ARN.search(value)
    if not m:
        return None
    partition, region, account, name, qualifier = m.groups()
    arn = f"arn:{partition}:lambda:{region}:{account}:function:{name}"
    return ApiRoute(None, None, None, arn, qualifier or None, None)


def _policy_resource(kind: str, unit: str, rec: Mapping[str, Any], account: str) -> Optional[PolicyResource]:
    arn = rec.get("Arn")
    if not isinstance(arn, str) or not ids.node_id_matches(kind, arn):
        return None
    region = unit_region(unit, arn)
    if region is None:
        return None
    raw_policy = rec.get("Policy")
    props = {}
    if kind == "ecr":
        for src, dst in (("ImageTagMutability", "image_tag_mutability"), ("ScanOnPush", "scan_on_push"),
                         ("EncryptionType", "encryption_type")):
            if rec.get(src) is not None:
                props[dst] = rec[src]
    return PolicyResource(kind, arn, str(rec.get("Name") or arn.rsplit("/", 1)[-1]), region,
                          record_account(arn, account), usable_policy(raw_policy), policy_status(rec, raw_policy),
                          ItemErrors.of(rec), not is_v2(rec), props)


def _bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _rds(unit: str, rec: Mapping[str, Any], account: str) -> Optional[RdsResource]:
    arn, kind = rec.get("Arn"), rec.get("Kind")
    if not isinstance(arn, str) or kind not in ("instance", "cluster", "snapshot", "cluster_snapshot"):
        return None
    node_type = "rdssnapshot" if kind in ("snapshot", "cluster_snapshot") else "rds"
    region = unit_region(unit, arn)
    if region is None or not ids.node_id_matches(node_type, arn):
        return None
    # d13c215 records have neither the sharing list nor the cluster fields of the v2 collector
    legacy = ("SharedAccounts" not in rec and "DBInstanceIdentifier" not in rec) if kind == "snapshot" else \
        ("DBClusterIdentifier" not in rec and kind == "instance")
    shared = None if legacy else str_tuple(rec.get("SharedAccounts"))
    kms = rec.get("KmsKeyId") if isinstance(rec.get("KmsKeyId"), str) and rec.get("KmsKeyId") else None
    return RdsResource(kind=kind, arn=arn, name=str(rec.get("Name") or arn.rsplit(":", 1)[-1]), region=region,
                       account=record_account(arn, account), public=_bool(rec.get("Public")),
                       encrypted=_bool(rec.get("Encrypted")), kms_key_id=kms,
                       public_snapshot=_bool(rec.get("PublicSnapshot")), shared_accounts=shared,
                       engine=rec.get("Engine") if isinstance(rec.get("Engine"), str) else None,
                       members=str_tuple(rec.get("Members")) if "Members" in rec else None,
                       errors=ItemErrors.of(rec), legacy=legacy)


def _v2_routes(rec: Mapping[str, Any]) -> Tuple[Optional[Tuple[ApiRoute, ...]], Tuple[ApiRoute, ...]]:
    """(invocable Lambda routes or None, every Lambda target) from v2 ``Integrations``."""
    integrations = rec.get("Integrations")
    if not isinstance(integrations, list):
        return None, ()
    routes: List[ApiRoute] = []
    for i in integrations:
        if not isinstance(i, Mapping):
            continue
        key = i.get("Method") if i.get("Method") is not None else i.get("RouteKey")
        if i.get("Unresolved"):
            routes.append(ApiRoute(key, i.get("Path"), i.get("EffectiveAuthorizationType"), None, None,
                                   i.get("Stage"), unresolved=True))
            continue
        target = lambda_target(i.get("LambdaArn"))
        if target is None or target.lambda_arn is None:
            continue
        qualifier = i.get("Qualifier") if isinstance(i.get("Qualifier"), str) else target.qualifier
        routes.append(ApiRoute(key, i.get("Path"), i.get("EffectiveAuthorizationType"), target.lambda_arn,
                               qualifier, i.get("Stage") if isinstance(i.get("Stage"), str) else None))
    invocable = tuple(r for r in routes if r.key is not None)
    return invocable, tuple(routes)


def _unauthenticated(rec: Mapping[str, Any]) -> Optional[Tuple[ApiRoute, ...]]:
    raw = rec.get("UnauthenticatedLambdaRoutes")
    if not isinstance(raw, list):
        return None
    out = []
    for r in raw:
        if not isinstance(r, Mapping):
            continue
        target = lambda_target(r.get("LambdaArn"))
        if target is None or target.lambda_arn is None:
            continue
        key = r.get("Method") if r.get("Method") is not None else r.get("RouteKey")
        out.append(ApiRoute(key, r.get("Path"), "NONE", target.lambda_arn,
                            r.get("Qualifier") if isinstance(r.get("Qualifier"), str) else target.qualifier,
                            r.get("Stage") if isinstance(r.get("Stage"), str) else None))
    return tuple(out)


def _legacy_targets(rec: Mapping[str, Any]) -> Tuple[ApiRoute, ...]:
    out = []
    for value in rec.get("LambdaTargets") or ():
        target = lambda_target(value)
        if target is not None:
            out.append(target)
    return tuple(out)


def _api(unit: str, rec: Mapping[str, Any], account: str) -> Optional[Api]:
    arn = rec.get("Arn")
    if not isinstance(arn, str) or not ids.node_id_matches("apigw", arn):
        return None
    region = unit_region(unit, arn)
    if region is None:
        return None
    v2 = "Integrations" in rec or "UnauthenticatedLambdaRoutes" in rec
    if v2:
        routes, targets = _v2_routes(rec)
        if routes is None and isinstance(rec.get("LambdaTargets"), list):
            targets = _legacy_targets(rec)
        unauth = _unauthenticated(rec)
    else:
        routes, targets, unauth = None, _legacy_targets(rec), None
    policy = rec.get("ResourcePolicy") if isinstance(rec.get("ResourcePolicy"), Mapping) else None
    return Api(arn=arn, api_id=str(rec.get("ApiId") or arn.rsplit("/", 1)[-1]),
               name=str(rec.get("Name") or arn.rsplit("/", 1)[-1]), region=region, account=account,
               protocol=str(rec.get("Protocol") or "REST").upper(), endpoint_types=str_tuple(rec.get("EndpointTypes")),
               resource_policy=policy, execute_api_disabled=_bool(rec.get("DisableExecuteApiEndpoint")),
               has_authorizer=_bool(rec.get("HasAuthorizer")), routes=routes, targets=targets,
               unauthenticated=unauth, errors=ItemErrors.of(rec), legacy=not v2)


def _registry(region: str, policy_doc: Mapping[str, Any], registry: Mapping[str, Any],
              account: str) -> Optional[EcrRegistry]:
    if not policy_doc and not registry:
        return None
    registry_id = str(policy_doc.get("RegistryId") or registry.get("RegistryId") or account)
    raw_policy = policy_doc.get("Policy")
    policy = usable_policy(raw_policy)
    status = policy_status(policy_doc, raw_policy, legacy_missing="unknown") if policy_doc else "unknown"
    rules = registry.get("ReplicationRules") if registry else None
    accounts: Optional[Tuple[str, ...]] = None
    if isinstance(rules, list):
        dests = {str(d.get("RegistryId")) for r in rules if isinstance(r, Mapping)
                 for d in r.get("Destinations") or () if isinstance(d, Mapping) and d.get("RegistryId")}
        accounts = tuple(sorted(a for a in dests if a != registry_id))
    errors = ItemErrors(tuple(sorted(set(ItemErrors.of(policy_doc).gaps) | set(ItemErrors.of(registry).gaps))))
    return EcrRegistry(region, registry_id, policy, status, accounts, errors)


def _registries(units: Mapping[str, Any], account: str) -> Tuple[Tuple[EcrRegistry, ...], Dict[str, str]]:
    out: List[EcrRegistry] = []
    gaps: Dict[str, str] = {}
    for unit, base in sorted(units.items()):
        docs: Dict[str, Mapping[str, Any]] = {}
        for key, rel in REGISTRY_FILES.items():
            data, res = read_map(Path(base) / rel)
            docs[key] = data
            if not res.ok and res.status != "missing":
                status = stub_status(res.error_code) if res.status == "error-stub" else "error"
                gaps[f"{rel}:{status}"] = f"{unit}/{rel} could not be read ({res.error_code or res.status})"
        reg = _registry(unit, docs["registry_policy"], docs["registry"], account)
        if reg is not None:
            out.append(reg)
    return tuple(out), gaps


def _collected_functions(units: Mapping[str, Any]) -> FrozenSet[str]:
    out = set()
    for _unit, base in sorted(units.items()):
        items, _res = read_list(Path(base) / LAMBDA_FUNCTIONS)
        for rec in items:
            target = lambda_target(rec.get("FunctionArn")) if isinstance(rec, Mapping) else None
            if target is not None and target.lambda_arn:
                out.add(target.lambda_arn)
    return frozenset(out)


def build_inventory(data: Mapping[str, Mapping[str, Sequence[Any]]], *, account: str) -> DataStoresInventory:
    def collect(key: str, fn: Any) -> Tuple[Any, ...]:
        found: Dict[str, Any] = {}
        for unit, rec in iter_units(data.get(key, {})):
            item = fn(unit, rec)
            if item is not None:
                found.setdefault(item.arn, item)
        return tuple(found[k] for k in sorted(found))

    return DataStoresInventory(
        ecr=collect("ecr", lambda u, r: _policy_resource("ecr", u, r, account)),
        dynamodb=collect("dynamodb", lambda u, r: _policy_resource("dynamodb", u, r, account)),
        rds=collect("rds", lambda u, r: _rds(u, r, account)),
        apis=collect("apigw", lambda u, r: _api(u, r, account)))


def load(ctx: Any) -> LoadResult:
    """Phase LOAD: the list files per unit plus ``"inventory"`` (:class:`DataStoresInventory`)."""
    base = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    data = dict(base.data)
    inv = build_inventory(data, account=ctx.account_id)
    inv.registries, gaps = _registries(dict(ctx.region_dirs), ctx.account_id)
    inv.lambda_functions = _collected_functions(dict(ctx.region_dirs))
    data["inventory"] = inv
    return merge_results(LoadResult(data, base.status, dict(base.gaps), base.files), gaps)


def data_stores_inventory(ctx: Any) -> DataStoresInventory:
    data = (getattr(ctx, "data", None) or {}).get("data_stores")
    inv = data.get("inventory") if isinstance(data, Mapping) else None
    return inv if isinstance(inv, DataStoresInventory) else DataStoresInventory()


__all__ = [
    "Api", "ApiRoute", "DataStoresInventory", "EcrRegistry", "LAMBDA_ARN", "PolicyResource", "RdsResource",
    "build_inventory", "data_stores_inventory", "lambda_target", "load",
]
