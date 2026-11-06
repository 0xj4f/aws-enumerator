"""ECS: task-definition families grouped by role set, and services (ECS Exec, launch type, networking).

Container definitions are never stored (their ``environment`` holds secrets).

Output (``<region>/ecs/``):

* ``resources.json`` (list): one item per (family, task role, execution role) among the newest
  ``--ecs-max-revisions`` ACTIVE revisions of each family (option ``ecs_max_revisions``, default 5,
  ``0`` = all), sorted by (``Family``, ``Arn``)::

    {Type: "ecstask", Arn: <newest revision ARN in the group>, Name: <family>, Family,
     Revisions: [int], RevisionsTruncated: bool, TaskRole: arn|null, ExecutionRole: arn|null,
     Roles: [arn]|null, CollectionErrors?}

  The task role is what the containers' code runs as; the execution role is used by the ECS agent
  only (image pulls, log delivery, secrets injection) and the containers never receive its
  credentials, so both are recorded separately (F-004) and ``Roles`` (the roles the resource's code
  runs as, the field every compute collector shares) holds the task role only. Grouping replaces
  one node per revision (thousands in CI/CD accounts) with one per distinct role set (F-049).
  ``RevisionsTruncated`` says older ACTIVE revisions exist that were not described. A revision whose
  describe fails is kept as its own item with ``null`` roles and ``CollectionErrors`` (F-102).
* ``services.json`` (list), sorted by ``ServiceArn``::

    {ClusterArn, ServiceArn, Name, TaskDefinition, EnableExecuteCommand: bool|null, LaunchType,
     AssignPublicIp, Subnets, SecurityGroups}

  ``EnableExecuteCommand`` services can be entered with ``ecs:ExecuteCommand`` as their task role (F-113).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.coverage import CallResult
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="ecs", scope="regional", output_dir="ecs", services=("ecs",),
    tier=2, cost="medium", noise="medium", default=True, groups=("@compute",),
    actions=("ecs:ListTaskDefinitionFamilies", "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
             "ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices"),
    probe=("ecs", "ListTaskDefinitionFamilies", (("maxResults", 1),)),
    outputs=(("resources.json", "list"), ("services.json", "list")),
    description="ECS task-definition families (task and execution roles) and services (ECS Exec)",
)

DEFAULT_MAX_REVISIONS = 5
_DESCRIBE_SERVICES_BATCH = 10
_LIST_PAGE = 100


def _revision(arn: str) -> int:
    tail = arn.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def _family_arn(ctx: Any, family: str) -> str:
    return ctx.arn("ecs", f"task-definition/{family}")


def _newest_revisions(ctx: Any, ecs: Any, family: str, limit: int) -> Tuple[List[str], bool, Optional[CallResult]]:
    """The newest ``limit`` ACTIVE revision ARNs (all when ``limit`` is 0), whether more exist, and a failure."""
    arns: List[str] = []
    token: Optional[str] = None
    while True:
        params: Dict[str, Any] = {"familyPrefix": family, "status": "ACTIVE", "sort": "DESC",
                                  "maxResults": min(_LIST_PAGE, limit - len(arns)) if limit else _LIST_PAGE}
        if token:
            params["nextToken"] = token
        result = ctx.call(ecs, "list_task_definitions", item=_family_arn(ctx, family), **params)
        if not result.ok:
            return arns, bool(arns), result
        arns.extend(result.get("taskDefinitionArns") or [])
        token = result.get("nextToken")
        if not token:
            return arns, False, None
        if limit and len(arns) >= limit:
            return arns[:limit], True, None


def _describe(ctx: Any, ecs: Any, arn: str) -> Tuple[Optional[Dict[str, Any]], CallResult]:
    result = ctx.call(ecs, "describe_task_definition", item=arn, taskDefinition=arn)
    return (result.get("taskDefinition") if result.ok else None), result


def _group_family(ctx: Any, ecs: Any, family: str, limit: int) -> List[Dict[str, Any]]:
    arns, truncated, failure = _newest_revisions(ctx, ecs, family, limit)
    groups: Dict[Tuple[Optional[str], Optional[str]], Dict[str, Any]] = {}
    items: List[Dict[str, Any]] = []
    for arn in sorted(arns, key=_revision, reverse=True):
        td, result = _describe(ctx, ecs, arn)
        if td is None:
            item = {"Type": "ecstask", "Arn": arn, "Name": family, "Family": family, "Revisions": [_revision(arn)],
                    "RevisionsTruncated": truncated, "TaskRole": None, "ExecutionRole": None, "Roles": None}
            add_error(item, result)
            items.append(item)
            continue
        task_role, exec_role = td.get("taskRoleArn"), td.get("executionRoleArn")
        group = groups.get((task_role, exec_role))
        if group is None:
            group = {"Type": "ecstask", "Arn": td.get("taskDefinitionArn") or arn, "Name": family, "Family": family,
                     "Revisions": [], "RevisionsTruncated": truncated, "TaskRole": task_role,
                     "ExecutionRole": exec_role, "Roles": [task_role] if task_role else []}
            groups[(task_role, exec_role)] = group
            items.append(group)
        group["Revisions"].append(int(td.get("revision") or _revision(arn)))
    if failure is not None:
        item = {"Type": "ecstask", "Arn": _family_arn(ctx, family), "Name": family, "Family": family,
                "Revisions": [], "RevisionsTruncated": True, "TaskRole": None, "ExecutionRole": None, "Roles": None}
        add_error(item, failure)
        items.append(item)
    for item in items:
        item["Revisions"] = sorted(item["Revisions"], reverse=True)
    return items


def _task_definitions(ctx: Any, ecs: Any, out: List[Dict[str, Any]]) -> None:
    limit = max(0, int(ctx.option("ecs_max_revisions", DEFAULT_MAX_REVISIONS)))
    families = ctx.paginate(ecs, "list_task_definition_families", "families", page_size=_LIST_PAGE,
                            primary=True, status="ACTIVE")
    for family in sorted(set(families.value)):
        out.extend(_group_family(ctx, ecs, family, limit))


def _service_item(svc: Dict[str, Any]) -> Dict[str, Any]:
    net = ((svc.get("networkConfiguration") or {}).get("awsvpcConfiguration")) or {}
    return {"ClusterArn": svc.get("clusterArn"), "ServiceArn": svc.get("serviceArn"), "Name": svc.get("serviceName"),
            "TaskDefinition": svc.get("taskDefinition"), "EnableExecuteCommand": svc.get("enableExecuteCommand"),
            "LaunchType": svc.get("launchType"), "AssignPublicIp": net.get("assignPublicIp"),
            "Subnets": sorted(net.get("subnets") or []), "SecurityGroups": sorted(net.get("securityGroups") or [])}


def _cluster_services(ctx: Any, ecs: Any, cluster: str, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(ecs, "list_services", "serviceArns", page_size=_LIST_PAGE, item=cluster, cluster=cluster)
    arns = sorted(set(listed.value))
    for start in range(0, len(arns), _DESCRIBE_SERVICES_BATCH):
        batch = arns[start:start + _DESCRIBE_SERVICES_BATCH]
        result = ctx.call(ecs, "describe_services", item=cluster, cluster=cluster, services=batch)
        if not result.ok:
            out.extend({"ClusterArn": cluster, "ServiceArn": arn, "Name": arn.rsplit("/", 1)[-1],
                        "TaskDefinition": None, "EnableExecuteCommand": None, "LaunchType": None,
                        "AssignPublicIp": None, "Subnets": None, "SecurityGroups": None,
                        "CollectionErrors": [result.collection_error()]} for arn in batch)
            continue
        out.extend(_service_item(svc) for svc in result.get("services") or [])


def _services(ctx: Any, ecs: Any, out: List[Dict[str, Any]]) -> None:
    clusters = ctx.paginate(ecs, "list_clusters", "clusterArns", page_size=_LIST_PAGE)
    for cluster in sorted(set(clusters.value)):
        _cluster_services(ctx, ecs, cluster, out)


def collect(ctx: Any) -> None:
    ecs = ctx.client("ecs")
    tasks: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    with ctx.section("task_definitions"):
        _task_definitions(ctx, ecs, tasks)
    tasks.sort(key=lambda t: (t["Family"], t["Arn"]))
    ctx.out.write("resources.json", tasks)
    with ctx.section("services"):
        _services(ctx, ecs, services)
    services.sort(key=lambda s: str(s["ServiceArn"]))
    ctx.out.write("services.json", services)
    ctx.log.info("%d task-definition groups, %d services", len(tasks), len(services))
