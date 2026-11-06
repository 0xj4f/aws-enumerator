"""CloudFormation: stacks and StackSets with the IAM roles they run as.

A stack's service role (``RoleARN``) is assumed during stack operations, and a self-managed
StackSet's administration role is assumed to deploy it, so controlling the stack (set) wields the
role (PRIVESC-016, F-113). Parameter values and outputs are **never** stored: they routinely hold
secrets.

Output (``<region>/cloudformation/``):

* ``resources.json`` (list), sorted by (``Type``, ``Arn``):

  - stacks: ``{Type: "cfnstack", Arn, Name, Roles: [RoleARN], StackStatus}``;
  - StackSets: ``{Type: "stackset", Arn, Name, StackSetId, Roles: [AdministrationRoleARN]|null,
    AdministrationRoleARN, ExecutionRoleName, PermissionModel, Status, CollectionErrors?}``
    (``Roles`` is ``null`` when ``DescribeStackSet`` fails).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="cloudformation", scope="regional", output_dir="cloudformation", services=("cloudformation",),
    tier=2, cost="low", noise="low", default=True, groups=("@compute",),
    actions=("cloudformation:DescribeStacks", "cloudformation:ListStackSets", "cloudformation:DescribeStackSet"),
    probe=("cloudformation", "DescribeStacks", ()),
    outputs=(("resources.json", "list"),),
    description="CloudFormation stacks and StackSets and the roles they run as (never parameters or outputs)",
)


def _stacks(ctx: Any, cfn: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(cfn, "describe_stacks", "Stacks", primary=True)
    for st in listed.value:
        role = st.get("RoleARN")
        out.append({"Type": "cfnstack", "Arn": st.get("StackId"), "Name": st.get("StackName"),
                    "Roles": [role] if role else [], "StackStatus": st.get("StackStatus")})


def _stack_set(ctx: Any, cfn: Any, summary: Dict[str, Any]) -> Dict[str, Any]:
    name, set_id = summary.get("StackSetName"), summary.get("StackSetId")
    item: Dict[str, Any] = {
        "Type": "stackset", "Arn": ctx.arn("cloudformation", f"stackset/{set_id or name}"), "Name": name,
        "StackSetId": set_id, "Roles": None, "AdministrationRoleARN": None, "ExecutionRoleName": None,
        "PermissionModel": summary.get("PermissionModel"), "Status": summary.get("Status"),
    }
    result = ctx.call(cfn, "describe_stack_set", item=item["Arn"], StackSetName=name)
    if not result.ok:
        add_error(item, result)
        return item
    ss = result.get("StackSet") or {}
    admin = ss.get("AdministrationRoleARN")
    item.update({"Arn": ss.get("StackSetARN") or item["Arn"], "AdministrationRoleARN": admin,
                 "ExecutionRoleName": ss.get("ExecutionRoleName"),
                 "PermissionModel": ss.get("PermissionModel") or item["PermissionModel"],
                 "Status": ss.get("Status") or item["Status"], "Roles": [admin] if admin else []})
    return item


def _stack_sets(ctx: Any, cfn: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(cfn, "list_stack_sets", "Summaries", page_size=100, Status="ACTIVE")
    for summary in sorted(listed.value, key=lambda s: str(s.get("StackSetId"))):
        out.append(_stack_set(ctx, cfn, summary))


def collect(ctx: Any) -> None:
    cfn = ctx.client("cloudformation")
    resources: List[Dict[str, Any]] = []
    with ctx.section("stacks"):
        _stacks(ctx, cfn, resources)
    with ctx.section("stack_sets"):
        _stack_sets(ctx, cfn, resources)
    resources.sort(key=lambda r: (r["Type"], str(r["Arn"])))
    ctx.out.write("resources.json", resources)
    ctx.log.info("%d stacks and StackSets", len(resources))
